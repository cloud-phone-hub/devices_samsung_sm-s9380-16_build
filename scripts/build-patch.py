#!/usr/bin/env python3
"""构建 patch.img：修补后的 vendor/vendor_dlkm 内容打包为 ext4，供 vdc 挂载到 /mnt/vendor。

结构：patch.img（ext4）的 **root 就是 vendor 树**（运行态 /mnt/vendor/etc、
/mnt/vendor/lib64 …），root 下另有 vendor_dlkm/ 子树与少量自供目录
（VENDOR_SKELETON_DIRS：EFI/persist/shared 三个 mount_all 挂载点 + mi_ext 分区挂载点）。
内容、mode/uid/gid、security.selinux 标签全部自 **out/dist/rom 下 build-vendor /
build-vendor_dlkm 产物**（lineage 基座 + CDH 注入 + 自编译内核模块）逐文件提取
（debugfs stat/ea_get），与源分区逐字节一致（标签含 NUL 结尾），保证与"修补后 vendor
直接作 /vendor"的运行态等价。

mke2fs -d 不保留 uid/gid（实测按宿主当前用户），故回填分两步：
  1. mke2fs -d 导入内容与 mode；
  2. debugfs -w 批量 sif uid/gid + ea_set security.selinux（-f 值文件，含 NUL）。

依赖：先跑 build-vendor / build-vendor_dlkm（产物 out/dist/rom/vendor.img、
out/dist/rom/vendor_dlkm.img 就位）。

用法（可在任何目录）：
  python3 build/scripts/build-patch.py              # 构建 out/dist/rom/patch.img
  python3 build/scripts/build-patch.py --dry-run    # 只打印不执行
  python3 build/scripts/build-patch.py --size 512   # 指定 patch.img 大小（MiB）
"""

import argparse
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from buildenv import (  # noqa: E402
    DIST_DIR, LINEAGE_SUPER_DIR, PATCH_DIST, TMP_DIR, VENDOR_DIST, VENDOR_DLKM_DIST,
)
from buildenv import e2fs_tools  # noqa: E402

DEBUGFS, E2FSCK, _RESIZE2FS = e2fs_tools()

# 源镜像：优先 out/dist/rom 下 build-vendor / build-vendor_dlkm 的修补产物；
# 尚未构建时回退 lineage-23 底包的 vendor/vendor_dlkm（= 未加机型 HAL/patch 的
# lineage virtio vendor，功能等价于"lineage vendor 直接作 /vendor"），保证 patch.img
# 可在 vendor 阶段落地前先跑通整条引导链。
VENDOR_SRC = VENDOR_DIST if os.path.isfile(VENDOR_DIST) \
    else os.path.join(LINEAGE_SUPER_DIR, "vendor_a.img")
VENDOR_DLKM_SRC = VENDOR_DLKM_DIST if os.path.isfile(VENDOR_DLKM_DIST) \
    else os.path.join(LINEAGE_SUPER_DIR, "vendor_dlkm_a.img")

# patch.img 内布局。vdc 挂在 /mnt/vendor，所以 **vendor 树的内容直接落在镜像根**
# （运行态即 /mnt/vendor/etc、/mnt/vendor/lib64 …），vendor_dlkm 树落在 vendor_dlkm/
# 子目录（重定向 /vendor_dlkm/lib -> /mnt/vendor/vendor_dlkm/lib）。
# (patch 内子目录，"" = 镜像根；源镜像)
PATCH_TREES = (
    ("", VENDOR_SRC),
    ("vendor_dlkm", VENDOR_DLKM_SRC),
)

# 镜像根（= /mnt/vendor）下不许被 vendor 树自带内容占掉的名字：vendor_dlkm 是另一棵
# 源树的落点，其余四个是 VENDOR_SKELETON_DIRS 自供的目录。
ROOT_FORBIDDEN = ("vendor_dlkm", "EFI", "persist", "shared")

# "指向不存在以屏蔽"的两条重定向，其落点必须真的不存在，否则屏蔽会反过来变命中：
#   /odm/etc/selinux/odm_sepolicy.cil -> /mnt/vendor/odm/etc/selinux/odm_sepolicy.cil
#       （官方 odm 策略引用 MTK 专属类型，secilc 解析失败会让 init 直接重启）
#   /system/bin/update_verifier       -> /mnt/vendor/system/bin/update_verifier
#       （缺 A/B bootctrl HAL 时会主动 reboot，形成引导死循环）
# vendor 树自带一个空的 odm/ 目录，无妨；里面长出 sepolicy 才致命。
MUST_ABSENT = (
    "odm/etc/selinux/odm_sepolicy.cil",
    "system/bin/update_verifier",
)

# 官方 odm 的 64 位 ABI 覆盖件（build_odm.py 产物 out/dist/odm/etc/build.prop）。
# 运行时内核重定向 /odm/etc/build.prop -> /mnt/vendor/odm/etc/build.prop，init 加载该
# build.prop 时 ro.product.cpu.abilist* 被 lock 为纯 64（framework 不再连 zygote_secondary）。
# 该文件无对应源镜像 inode，meta 固定：目录 ROOT_META / 文件 FILE_META。
ODM_PROP_SRC = os.path.join(DIST_DIR, "odm", "etc", "build.prop")
FILE_META = (0o100644, 0, 0, "u:object_r:vendor_file:s0")

WORK_DIR = os.path.join(TMP_DIR, "patch")
DEFAULT_SIZE_MIB = 384

# 目录/文件默认标签（源镜像缺 xattr 时兜底；正常应全部命中）
FALLBACK_LABEL = "u:object_r:vendor_file:s0"

# 自供条目（无源镜像 inode）的固定 meta：目录用 ROOT_META、文件用 FILE_META，
# 命中 SKELETON_META 的按该表。
ROOT_META = (0o040755, 0, 0, "u:object_r:vendor_file:s0")


def _ctx(type_):
    return f"u:object_r:{type_}:s0"


# —— /mnt/vendor 下必须自带的目录 ——
# vdc 以 first_stage_mount 挂在 /mnt/vendor，会盖掉 first_stage_init 在 /mnt tmpfs 上建
# 的那个空 /mnt/vendor。两件事因此必须烘进镜像：
#   1. fstab 里 /mnt/vendor/{EFI,persist,shared} 由二阶段 mount_all 挂载，挂载点得先
#      存在 —— 只读分区上 fs_mgr 的 mkdir 会 EROFS，挂载直接失败（persist 里是
#      grubenv，GRUB 的槽位与 android_theme 都靠它）。
#   2. /mnt/vendor/mi_ext 是真 mi_ext 分区（super 内 mi_ext_a，erofs）的挂载点：boot
#      ramdisk 一阶段 fstab 在 vdc 之后挂 mi_ext 到这里（见 build-boot.py FIRSTSTAGE_FSTAB），
#      init 随即原生加载其 /etc/build.prop 并解析 /etc/init（ro.mi.os.* / ro.ai.os.* 等
#      属性与 init.miui.mi_ext.rc 全部来自真分区内容）。
# 标签取 file_contexts 的最具体匹配：/mnt/vendor(/.*)? -> mnt_vendor_file、
# /mnt/vendor/persist(/.*)? -> persist_file（vendor_file_contexts，更具体故胜出）；
# mi_ext 对齐真机实测（ls -Z /mi_ext 全树 system_file），与挂载源根标签一致以过 mounton。
# EFI/persist 挂上后的可见标签由 vfat 的 context= 决定，这里的底层标签只参与 init 的
# mounton 检查，与现状一致。
#
# /mnt 本身仍是 first_stage_init 挂的可写 tmpfs：init.rc `on init` 的 mkdir、zygote 的
# fs_prepare_dir("/mnt/user/0")、vold 的 pass_through/runtime/installer 视图、netmgr 的
# /mnt/run/adb_net 全部照旧可写，不需要任何骨架复刻。
VENDOR_SKELETON_DIRS = (
    # (相对镜像根的路径, 含类型位的 mode, uid, gid, SELinux 类型)
    ("EFI",        0o040755, 0,    0,    "mnt_vendor_file"),
    ("persist",    0o040755, 0,    0,    "persist_file"),
    ("shared",     0o040770, 1000, 1000, "mnt_vendor_file"),
)


def _skeleton_meta():
    """骨架表 -> {patch 内绝对路径: (mode, uid, gid, label, is_dir)}。"""
    meta = {}
    for rel, mode, uid, gid, type_ in VENDOR_SKELETON_DIRS:
        meta["/" + rel] = (mode, uid, gid, _ctx(type_), True)
    return meta


SKELETON_META = _skeleton_meta()


def _run(cmd, **kw):
    print("  + " + " ".join(cmd))
    return subprocess.run(cmd, **kw)


def _stat_meta(img, path):
    """debugfs stat 取 (mode, uid, gid)；失败返回 (0o100644, 0, 0)。

    mode 为**含文件类型位的完整 mode**（如 regular+0755 = 0o100755）：
    debugfs stat 的 "Mode:" 只含权限位，"Type:" 给类型；sif mode 字段上限 65535
    且按十进制解析，故须拼完整 mode 后以十进制写入（0o100755 = 33261）。
    """
    res = _run([DEBUGFS, "-R", f"stat {path}", img],
               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    perms = uid = gid = None
    ftype = ""
    for raw in res.stdout.decode("utf8", "replace").splitlines():
        line = raw.strip()
        # Mode/User/Group 均可能位于行中（如 "Inode: 106 ... Mode: 0644 ..."、
        # "User: 0   Group: 0   Project: 0"），一律用 "xxx:" in line 独立匹配
        if "Type:" in line:
            m = re.search(r"Type:\s*(\w+)", line)
            if m:
                ftype = m.group(1)
        if "Mode:" in line:
            m = re.search(r"Mode:\s+(\d+)", line)
            if m:
                perms = int(m.group(1), 8)
        if "User:" in line:
            m = re.search(r"User:\s+(\d+)", line)
            if m:
                uid = int(m.group(1))
        if "Group:" in line:
            m = re.search(r"Group:\s+(\d+)", line)
            if m:
                gid = int(m.group(1))
    if perms is None or uid is None or gid is None:
        print(f"[warn] stat 解析失败: {img} {path}，按 0644/0/0 兜底")
        return 0o100644, 0, 0
    type_bits = {"regular": 0o100000, "directory": 0o040000,
                 "symlink": 0o120000, "block": 0o060000, "char": 0o020000,
                 "fifo": 0o010000, "socket": 0o140000}.get(ftype, 0o100000)
    return perms | type_bits, uid, gid


def _ea_label(img, path):
    """debugfs ea_get 取 security.selinux 标签；缺失返回 FALLBACK_LABEL。"""
    res = _run([DEBUGFS, "-R", f"ea_get {path} security.selinux", img],
               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    text = res.stdout.decode("utf8", "replace")
    m = re.search(r'= "([^"]*)"', text)
    if not m:
        print(f"[warn] 缺 security.selinux: {img} {path}，兜底 {FALLBACK_LABEL}")
        return FALLBACK_LABEL
    val = m.group(1)
    # 反转义 \ooo（如 \000 -> NUL）
    val = re.sub(r"\\([0-7]{3})", lambda mm: chr(int(mm.group(1), 8)), val)
    val = val.replace("\\n", "\n").replace("\\t", "\t").replace("\\\\", "\\")
    return val


def _rdump(img, dest):
    """debugfs rdump 整树解出（内容/mtime；不保留属主/权限/xattr）。"""
    os.makedirs(dest, exist_ok=True)
    res = _run([DEBUGFS, "-R", f"rdump / {dest}", img],
               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    # rdump 尾部 "Operation not permitted while changing ownership" 是 macOS 非 root 提示，忽略
    err = res.stderr.decode("utf8", "replace")
    if "File not found" in err or "Error" in err:
        print(err)
        sys.exit(1)


def _collect(stage_root):
    """遍历宿主 staging 树，返回 [(img 内路径, 宿主路径, 是否目录)]。"""
    entries = []
    for base, dirs, files in os.walk(stage_root):
        for d in dirs:
            hp = os.path.join(base, d)
            entries.append((os.path.relpath(hp, stage_root), hp, True))
        for f in files:
            hp = os.path.join(base, f)
            entries.append((os.path.relpath(hp, stage_root), hp, False))
    return sorted(entries)


def build_patch(dry_run=False, size_mib=DEFAULT_SIZE_MIB):
    for name, src in PATCH_TREES:
        if not os.path.isfile(src):
            print(f"[err] 源镜像缺失: {src}")
            sys.exit(1)
    os.makedirs(WORK_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(PATCH_DIST), exist_ok=True)
    work_img = os.path.join(WORK_DIR, "patch.work.img")
    stage = os.path.join(WORK_DIR, "stage")

    if dry_run:
        print(f"[..] (dry) patch.img -> {PATCH_DIST}（{size_mib} MiB，"
              f"含 {[n or '<镜像根>=vendor' for n, _ in PATCH_TREES]} 子树）")
        return 0

    # 1. rdump 两棵源树到 staging
    raw = {}
    for name, src in PATCH_TREES:
        key = name or "root"
        dest = os.path.join(stage, "raw_" + key)
        if os.path.exists(dest):
            shutil.rmtree(dest)
        print(f"[..] rdump {src} -> {dest}")
        _rdump(src, dest)
        raw[key] = dest

    # 2. 组装 patch root：vendor 树内容摊到镜像根（= /mnt/vendor），vendor_dlkm 树落到
    #    root/vendor_dlkm（= /mnt/vendor/vendor_dlkm）。
    root = os.path.join(stage, "root")
    if os.path.exists(root):
        shutil.rmtree(root)
    os.makedirs(root)
    for name, _src in PATCH_TREES:
        key = name or "root"
        dst = os.path.join(root, name) if name else root
        os.makedirs(dst, exist_ok=True)
        for entry in os.listdir(raw[key]):
            shutil.move(os.path.join(raw[key], entry), os.path.join(dst, entry))
    # 镜像根摊平后，我们自己要放上去的目录名不能被 vendor 树自带内容占掉。
    _tree_dirs = {n for n, _ in PATCH_TREES if n}
    for bad in ROOT_FORBIDDEN:
        if bad in _tree_dirs:            # vendor_dlkm 是我们自己放上去的，不算冲突
            continue
        if os.path.lexists(os.path.join(root, bad)):
            print(f"[err] vendor 树自带 /{bad}，与镜像根布局冲突（需人工复核）")
            sys.exit(1)

    # 2.45 vendor 树自带的 odm 是指向 /odm 的**绝对**符号链接（lineage 约定
    #      /vendor/odm -> /odm）。摊平到镜像根后，它会让屏蔽落点
    #      /mnt/vendor/odm/etc/selinux/odm_sepolicy.cil 在 path_walk 内解析回官方
    #      /odm（符号链接目标不经过 getname_flags 重定向），"指向不存在以屏蔽"
    #      反过来命中官方 MTK 策略 -> secilc "Failed to resolve allow statement"
    #      -> InitFatalReboot 引导死循环。换成真实空目录即恢复 ENOENT 语义（与
    #      挂 /mi_ext 时等价）；build_odm.py 的 64 位 ABI 覆盖件也才有落点
    #      （否则 os.makedirs 会顺着符号链接写到宿主的 /odm 上）。
    odm_link = os.path.join(root, "odm")
    if os.path.islink(odm_link):
        tgt = os.readlink(odm_link)
        os.unlink(odm_link)
        os.makedirs(odm_link)
        print(f"[..] odm 符号链接（-> {tgt}）替换为真实空目录")

    # 2.5 把 /vendor/lib/modules 由软链接改为真实目录（直接放模块副本）。
    #     基座/注入树的该路径是 -> /vendor_dlkm/lib/modules 的绝对软链接；
    #     内核 getname_flags 只改写用户态初始路径，软链接目标在 path_walk 内
    #     解析不经过重定向，会落到官方 vendor_dlkm 分区读到 MTK ko（Exec format
    #     error）。改为真实目录后，通用 /vendor/lib -> /mnt/vendor/lib 重定向
    #     直接命中本目录，不依赖软链接/内核特例。
    v_mods = os.path.join(root, "lib", "modules")
    if os.path.islink(v_mods):
        d_mods = os.path.join(root, "vendor_dlkm", "lib", "modules")
        print(f"[..] 替换软链接 {v_mods} -> 真实目录（源: {d_mods}）")
        os.unlink(v_mods)
        if os.path.isdir(d_mods):
            shutil.copytree(d_mods, v_mods)
        else:
            os.makedirs(v_mods)

    # 2.4 官方 odm 的 64 位 ABI 覆盖件（build_odm.py 产物）收编进 /odm 子树
    has_odm_prop = os.path.isfile(ODM_PROP_SRC)
    if has_odm_prop:
        odt = os.path.join(root, "odm", "etc")
        os.makedirs(odt, exist_ok=True)
        shutil.copy2(ODM_PROP_SRC, os.path.join(odt, "build.prop"))
        print(f"[..] 收编 {ODM_PROP_SRC} -> {os.path.join(odt, 'build.prop')}")

    # 2.6 /mnt/vendor 下必须自带的目录（三个 mount_all 挂载点 + mi_ext 分区挂载点）
    for rel, *_rest in VENDOR_SKELETON_DIRS:
        if os.path.lexists(os.path.join(root, rel)):
            print(f"[err] 骨架与 vendor 树内容冲突: /{rel}（基座变了？需人工复核）")
            sys.exit(1)
    for rel, *_rest in VENDOR_SKELETON_DIRS:
        os.makedirs(os.path.join(root, rel), exist_ok=True)
    print(f"[..] /mnt/vendor 骨架 {len(VENDOR_SKELETON_DIRS)} 目录")

    # 2.8 屏蔽落点必须真的不存在（见 MUST_ABSENT 说明）：odm_sepolicy.cil 命中会让
    #     secilc 解析失败、init 直接重启；update_verifier 命中会形成引导死循环。
    #     用 exists（跟随符号链接）而不是 lexists，避免绝对符号链接把检查骗过去。
    for rel in MUST_ABSENT:
        if os.path.exists(os.path.join(root, rel)):
            print(f"[err] 屏蔽落点竟存在: /mnt/vendor/{rel}（会反噬，需人工复核）")
            sys.exit(1)
    print(f"[..] 屏蔽落点校验通过（{len(MUST_ABSENT)} 项均不存在）")

    # 3. 逐路径从源镜像取元数据（mode/uid/gid/label）
    plan = []  # (patch 内路径, 源镜像, 源镜像内路径, 是否目录)
    # vendor 树摊在镜像根上，os.walk(root) 会连带走到后面几步放进去的自供子树，
    # 这些顶层名字一律跳过（各自有独立 plan 条目）。
    _skip_top = _tree_dirs | {"odm"} | {k.lstrip("/").split("/", 1)[0]
                                        for k in SKELETON_META}
    for name, src in PATCH_TREES:
        prefix = "/" + name if name else ""
        # os.walk 不含树根本身：vendor 树的根就是镜像根 "/"，vendor_dlkm 是 "/vendor_dlkm"
        plan.append((prefix + "/" if name else "/", src, "/", True))
        for rel, _hp, is_dir in _collect(os.path.join(root, name) if name else root):
            if not name and rel.split("/", 1)[0] in _skip_top:
                continue
            patch_path = f"{prefix}/{rel}"
            if patch_path in SKELETON_META:
                continue
            if not name and rel in ("lib/modules", "odm"):
                # 步骤 2.45/2.5 已把这两个路径从符号链接替换为真实目录；源镜像里它们
                # 仍是符号链接，回填若取源 inode 类型位会把实目录改坏（sif mode 覆盖
                # inode 类型）。固定套用目录 ROOT_META（0o040755 / 0:0 / vendor_file）。
                plan.append((patch_path, None, None, True))
                continue
            plan.append((patch_path, src, f"/{rel}", is_dir))
    if has_odm_prop:
        plan.append(("/odm", None, None, True))
        plan.append(("/odm/etc", None, None, True))
        plan.append(("/odm/etc/build.prop", None, None, False))
    # /mnt/vendor 骨架（三个 mount_all 挂载点 + mi_ext 分区挂载点）：一律固定 meta
    for patch_path, (_mode, _uid, _gid, _label, is_dir) in sorted(SKELETON_META.items()):
        plan.append((patch_path, None, None, is_dir))

    # 4. mke2fs -d 导入内容与 mode（uid/gid 由 sif 回填）
    if os.path.exists(work_img):
        os.remove(work_img)
    size_bytes = size_mib * 1024 * 1024
    # mkfs.ext4 末尾参数是块数（非字节）；显式 -b 4096 使大小与 size_mib 一致
    _run([os.path.join(os.path.dirname(DEBUGFS), "mkfs.ext4"),
          "-q", "-F", "-b", "4096", "-d", root, work_img, str(size_bytes // 4096)])
    print(f"[ok] mke2fs -d 导入 {len(plan)} 项 -> {work_img}（{size_mib} MiB）")

    # 5. debugfs -w 单会话回填 uid/gid + security.selinux（含 NUL 结尾）
    cmds = []
    labels = {}
    for patch_path, src, img_path, is_dir in plan:
        if src is None:                     # 骨架/自供文件：固定 meta
            if patch_path in SKELETON_META:
                mode, uid, gid, label = SKELETON_META[patch_path][:4]
            elif is_dir:
                mode, uid, gid, label = ROOT_META
            else:
                mode, uid, gid, label = FILE_META
        else:
            mode, uid, gid = _stat_meta(src, img_path)
            label = _ea_label(src, img_path)
        labels[patch_path] = label
        cmds += [
            f"sif {patch_path} mode {mode}",   # mode 已是含类型位的十进制 int
            f"sif {patch_path} uid {uid}",
            f"sif {patch_path} gid {gid}",
        ]
    # 标签统一用 -f 值文件（label + NUL 结尾，与源字节一致）
    val_files = []
    cmd_file = os.path.join(WORK_DIR, "patch-debugfs.cmd")
    with open(cmd_file, "w") as f:
        # 先写 sif（mode/uid/gid），再写 ea_set（标签）
        for c in cmds:
            f.write(c + "\n")
        for patch_path in [p for p, _s, _i, _d in plan]:
            vf = os.path.join(WORK_DIR, "selinux" + patch_path.replace("/", "_") + ".val")
            if patch_path not in val_files:
                with open(vf, "wb") as fv:
                    fv.write(labels[patch_path].encode("utf8") + b"\x00")
                val_files.append(patch_path)
            f.write(f"ea_set -f {vf} {patch_path} security.selinux\n")
    res = _run([DEBUGFS, "-w", "-f", cmd_file, work_img],
               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    err = res.stderr.decode("utf8", "replace")
    if res.returncode != 0 or re.search(r"Could not|Couldn't|File not found|exceeds|error",
                                        err, re.I):
        print(err)
        print("[err] debugfs 回填标签/属主失败")
        sys.exit(1)
    print(f"[ok] 回填 {len(plan)} 项 uid/gid/标签")

    # 6. e2fsck 校验
    res = _run([E2FSCK, "-fy", work_img], capture_output=True)
    if res.returncode not in (0, 1):
        print(res.stderr.decode("utf8", "replace"))
        print(f"[err] e2fsck 失败: {res.returncode}")
        sys.exit(1)
    print("[ok] e2fsck 通过")

    # 7. 输出
    shutil.copy2(work_img, PATCH_DIST)
    print(f"[ok] patch.img -> {PATCH_DIST}（{os.path.getsize(PATCH_DIST) // 2**20} MiB）")
    return 0


def main():
    ap = argparse.ArgumentParser(description="note13-5G-15 patch.img 构建（vdc 挂载到 /mnt）")
    ap.add_argument("--dry-run", action="store_true", help="只打印不执行")
    ap.add_argument("--size", type=int, default=DEFAULT_SIZE_MIB,
                    help="patch.img 大小（MiB，默认 %(default)s）")
    args = ap.parse_args()
    sys.exit(build_patch(dry_run=args.dry_run, size_mib=args.size))


if __name__ == "__main__":
    main()
