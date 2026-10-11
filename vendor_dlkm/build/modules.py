"""vendor_dlkm 内核模块注入：产物发现 + 索引重建 + debugfs 命令清单/回读校验。

移植自 popsicle-16（note13 范式）的同名模块，三星侧原委（实测 2026-10-10）：
旧编排只做 `rm + write` 的 .ko 注入，既不清出空间也不重建索引，结果两处实测故障：
  1. 基座 `lineage-rom/lineage-23/super/vendor_dlkm_a.img` 只有 16 个空闲 inode、
     12 个空闲块（`dumpe2fs -h`），11 个模块里 **7 个 write 报
     `Could not allocate block`**（cdh_device_info/cdh_goodix_fingerprint/cdh_media/
     cdh_virt_wifi/mac80211/mac80211_hwsim/virtio_console），旧编排忽略 debugfs 的
     stderr 直接打印「注入 11 个」，镜像里那 7 个其实是基座陈件（`cmp` 与
     `out/dist/kernel/modules/*.ko` 逐一比对实证）；
  2. 基座 `modules.load` 内容是 `btusb / cfg80211 / virt_wifi`（lineage 自留清单），
     与本盘模块集不符：libmodprobe 先在 `/system/lib/modules`（三星官方内核编译）里
     解析同名件 → `Failed to insmod '/system/lib/modules/rfkill.ko': Exec format error`，
     而 virtio_console 根本不在清单里 → 永不加载 → **/dev/hvc* 全缺** →
     guest daemon 的 `adbkey: 握手失败 open /dev/hvc2: No such file or directory`，
     宿主 `adb` 永远 offline（`hvc-event: open /dev/hvc7` 同错，投屏事件通道亦断）。

本模块按产物目录实际 .ko 重建 modules.load/dep/alias/options（清单不硬编码），
并先 rm 基座的 kunit/测试件腾出 inode/块；写入后逐件 dump+cmp 回读校验，不一致即退出。
"""

import os
import re
import subprocess
import sys

from buildenv import KERNEL_MODULES_DIR
from debugfs import DEBUGFS, cat, path_exists, run

# 镜像内模块目录：lineage 基座无 kver 子目录，模块平铺 /lib/modules
MOD_DIR_IN_IMG = "/lib/modules"
# lineage modules.dep 使用 /vendor_dlkm/lib/modules/ 作为前缀（note13 实测口径，
# 内核 CDH 白名单把 /vendor_dlkm/lib 重定向到 /mnt/vendor/vendor_dlkm/lib）
DEP_PREFIX = "/vendor_dlkm/lib/modules"

# SELinux label：vendor_dlkm 分区 .ko 统一 vendor_file 域
MODULE_SELABEL = "u:object_r:vendor_file:s0"

# 注入前先 rm 的基座测试/kunit/tipc 模块：基座几乎写满（16 inode / 12 块空闲），
# 不先回收就有 7 个 .ko 写不进去（见模块说明 §1；rm 前以 debugfs stat 探测，
# 与基座实际内容差异自动跳过）。
RECLAIM_MODULES = [
    "clk-gate_test.ko",
    "clk_kunit_helpers.ko",
    "clk-test.ko",
    "dev_addr_lists_test.ko",
    "ext4-inode-test.ko",
    "fat_test.ko",
    "hid-uclogic-test.ko",
    "iio-test-format.ko",
    "input_test.ko",
    "kheaders.ko",
    "kunit-example-test.ko",
    "kunit-test.ko",
    "kunit.ko",
    "lib_test.ko",
    "of_kunit_helpers.ko",
    "platform-test.ko",
    "regmap-kunit.ko",
    "regmap-ram.ko",
    "regmap-raw-ram.ko",
    "soc-topology-test.ko",
    "soc-utils-test.ko",
    "time_test.ko",
    "tipc.ko",
    "tipc_diag.ko",
]


def _modinfo(ko_path):
    """用 strings 提取 .modinfo 段 name=/depends=/vermagic=。返回 (name, deps, ver)。"""
    out = subprocess.run(["strings", ko_path],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    text = out.stdout.decode("latin1", "replace")
    m_name = re.search(r"\bname=(\S+)", text)
    m_deps = re.search(r"\bdepends=(\S*)", text)
    m_ver = re.search(r"\bvermagic=(\S+)", text)
    name = m_name.group(1) if m_name else None
    deps = [d for d in m_deps.group(1).split(",") if d] if m_deps else []
    ver = m_ver.group(1) if m_ver else None
    return name, deps, ver


def _modinfo_aliases(ko_path):
    """用 strings 提取 .modinfo 段所有 alias= 行。"""
    out = subprocess.run(["strings", ko_path],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    text = out.stdout.decode("latin1", "replace")
    return [m.group(1) for m in re.finditer(r"\balias=(\S+)", text)]


def _cat_lines(work_img, img_file):
    """读镜像内文本文件（缺失返回空列表），按行去空白。"""
    data = cat(work_img, img_file)
    if data is None:
        return []
    return [ln for ln in data.decode("utf8", "replace").splitlines() if ln]


def _write_host(work_dir, tmp_name, lines):
    """把索引内容写成宿主临时文件，返回绝对路径。"""
    p = os.path.join(work_dir, tmp_name)
    with open(p, "w") as f:
        f.write("\n".join(lines) + "\n")
    return p


def discover_modules():
    """扫描内核模块产物目录，返回 [(fn, src, name, deps)]；未就位返回 []。"""
    if not (os.path.isdir(KERNEL_MODULES_DIR) and os.listdir(KERNEL_MODULES_DIR)):
        return []
    kois = []
    for fn in sorted(os.listdir(KERNEL_MODULES_DIR)):
        src = os.path.join(KERNEL_MODULES_DIR, fn)
        if not fn.endswith(".ko") or not (os.path.isfile(src) and os.path.getsize(src) > 0):
            continue
        name, deps, ver = _modinfo(src)
        if not name:
            name = fn[:-3]
        print(f"[..] {fn}: modinfo name={name}, vermagic={ver}")
        kois.append((fn, src, name, deps))
    return kois


def inject_cmds(work_img, kois, work_dir):
    """生成注入 debugfs 命令清单：先 rm 基座测试模块腾 inode/块，再写 .ko 与四类索引。

    只读基座索引后返回命令，由编排层合并为一次 debugfs 会话执行。
    """
    img_load = f"{MOD_DIR_IN_IMG}/modules.load"
    img_dep = f"{MOD_DIR_IN_IMG}/modules.dep"
    img_alias = f"{MOD_DIR_IN_IMG}/modules.alias"
    img_opts = f"{MOD_DIR_IN_IMG}/modules.options"

    # 基座 modules.dep 中仍存在的模块名（用于过滤缺失依赖）+ 注入覆盖/回收剔除
    base_names = {l.split("/")[-1].removesuffix(".ko")
                  for l in _cat_lines(work_img, img_dep)}
    inject_fns = {fn for fn, _, _, _ in kois}
    reclaimed = {fn[:-3] for fn in RECLAIM_MODULES}
    names = [name for _, _, name, _ in kois]
    available = set(names) | {
        n for n in base_names if f"{n}.ko" not in inject_fns and n not in reclaimed
    }

    # modules.load：全量重建（virtio 云手机场景自编译模块均需加载；依赖自动解析）
    load_host = _write_host(work_dir, "modules.load", names)

    # modules.dep：全量重建，依赖按 modinfo depends= 解析并过滤不存在项
    dep_lines = []
    for _fn, _src, name, deps in kois:
        resolved = [f"{DEP_PREFIX}/{d}.ko" for d in deps if d in available]
        dep_lines.append(f"{DEP_PREFIX}/{name}.ko"
                         + (": " + " ".join(resolved) if resolved else ":"))
    dep_host = _write_host(work_dir, "modules.dep", dep_lines)

    # modules.alias：基座清单对本盘无用（指向 /system/lib/modules 的官方件），
    # 与 load/dep 一样全量重建为注入件自带的 modinfo alias。
    # 必须是 depmod 的 `alias <模式> <模块名>` 三字段格式：libkmod 逐行校验首 token
    # 为 "alias"，否则整行丢弃（实测旧写法只写模式串，dlkm_loader 打
    # `non-alias line encountered in modules.alias, found virtio:d00000003v*`，
    # 别名索引为空，LoadWithAliases 的别名回退全部失效）。
    alias_lines = []
    seen = set()
    for _fn, src, name, _deps in kois:
        for a in _modinfo_aliases(src):
            if (a, name) not in seen:
                alias_lines.append(f"alias {a} {name}")
                seen.add((a, name))
    alias_host = _write_host(work_dir, "modules.alias", alias_lines)

    # modules.options：cdh_media 的加载参数。
    # allow_userptr=1 是 Android Codec2 走 USERPTR 队列的前提（见 virtio_media
    # README）：驱动默认关闭该参数时会把 V4L2_BUF_CAP_SUPPORTS_USERPTR 清位，而
    # DMABUF 恒被拒，v4l2_codec2 解码器因「输入队列既不支持 DMABUF 也不支持
    # USERPTR」直接拒绝启动。libmodprobe 的 Insmod() 会把此处选项作为
    # finit_module 的 args 下发（libmodprobe_ext.cpp），故写在这里即随模块加载生效。
    opts_lines = list(_cat_lines(work_img, img_opts))
    if "options cdh_media allow_userptr=1" not in " ".join(opts_lines):
        opts_lines.append("options cdh_media allow_userptr=1")
    opts_host = _write_host(work_dir, "modules.options", opts_lines)

    cmds = []
    for fn in RECLAIM_MODULES:
        img_path = f"{MOD_DIR_IN_IMG}/{fn}"
        if path_exists(work_img, img_path):
            cmds.append(f"rm {img_path}")

    plan = [(src, f"{MOD_DIR_IN_IMG}/{fn}") for fn, src, _, _ in kois] + [
        (load_host, img_load),
        (dep_host, img_dep),
        (alias_host, img_alias),
        (opts_host, img_opts),
    ]
    for src, img_path in plan:
        if path_exists(work_img, img_path):
            cmds.append(f"rm {img_path}")
        cmds += [
            f"write {src} {img_path}",
            f"sif {img_path} mode 0x81a4",
            f"sif {img_path} uid 0",
            f"sif {img_path} gid 0",
            f"ea_set {img_path} security.selinux {MODULE_SELABEL}",
        ]
    return cmds


def verify(work_img, kois, work_dir):
    """回读校验：ko 用 dump+cmp 严格比对，不一致即报错退出。"""
    ok = True
    for fn, src, _name, _deps in kois:
        dump = os.path.join(work_dir, f"readback_{fn}")
        target = f"{MOD_DIR_IN_IMG}/{fn}"
        r = run([DEBUGFS, "-R", f"dump {target} {dump}", work_img],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if r.returncode != 0 or not os.path.isfile(dump):
            print(f"    回读缺失: {target}")
            ok = False
            continue
        if open(src, "rb").read() != open(dump, "rb").read():
            print(f"    回读内容不匹配: {target}")
            ok = False
        os.remove(dump)
    if not ok:
        print("[err] 回读校验失败")
        sys.exit(1)
    print("[ok] 回读校验通过")
