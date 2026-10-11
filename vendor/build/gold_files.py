"""官方 vendor EROFS 对齐件提取缓存（gold_props / gold_selinux 共用入口）。

popsicle 的官方固件为 images 包：官方 vendor_a.img 是 EROFS（只读压缩镜像），
宿主侧不具备直接按普通目录读取的能力；本模块把 gold 对齐所需的 /etc/selinux
子树用 `fsck.erofs --extract` 提取到 out/tmp/gold-vendor/etc/selinux 缓存，
gold_props / gold_selinux 再以普通文件方式读取（与 note13 的 ROM_ROOT_DIR/
vendor_a/etc/selinux 平铺产物等价）。

缓存以标记文件（记录源镜像路径/大小/mtime/子树）保证幂等：同 ROM 重复构建零成本，
换 ROM 或重新 unpack 后自动失效重提取。

另提供官方 /vendor/etc/permissions 的补件（`permissions_missing_cmds`）：内核 CDH
白名单把 /vendor/etc 整目录重定向到 patch.img，lineage 口径下真机的 feature /
privapp 声明会整体消失（实测 instance 24：缺
vendor.samsung.hardware.telephony.gsm.xml → SubscriptionManagerService 抛
'getActiveSubIdList is unsupported without android.hardware.telephony.subscription'
→ com.android.phone 崩溃循环 → RescueParty 重启）。故把官方件里 lineage 没有的
xml 全部补回 vendor.img（lineage 同名件优先，不覆盖）。

另提供官方 /vendor/etc/{passwd,group} 的补入（`creds_cmds`）：lineage 基座这两个
文件是 0 字节，而真机 vendor 分区带 37 条厂商 uid 定义（vendor_samsungcloud 等）。
bionic getpwuid 按 passwd_files 列表逐个查（/system_ext /vendor /odm /product /etc），
都查不到时合成 oem_<uid> 名；zygote 的 selinux_android_setcontext 以解析出的用户名
匹配 *_seapp_contexts 的 user= 字段（官方 Samsung 规则是 user=vendor_samsungcloud），
名字对不上即 "No match" → JNI FatalError SIGABRT 崩溃循环（实测 instance 25：
com.samsung.android.scpm / uid 5009，并连带拖垮 com.sec.android.sdhms）。故把官方
passwd/group 的缺失条目并入 vendor.img（镜像已有条目优先，不覆盖）。
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

from buildenv import SUPER_OUT, TMP_DIR, baselines_file, erofs_tool
from debugfs import cat

GOLD_CACHE_DIR = os.path.join(TMP_DIR, "gold-vendor")
SELINUX_SUBPATH = ("etc", "selinux")
PERMISSIONS_SUBPATH = ("etc", "permissions")
# 提取成功的最低要求（缺失说明提取失败/镜像不符）
_REQUIRED = {
    "/".join(SELINUX_SUBPATH): ("vendor_sepolicy.cil", "vendor_property_contexts"),
    "/".join(PERMISSIONS_SUBPATH): ("handheld_core_hardware.xml",),
}
# 单文件（非子树）对齐件：镜内路径 -> gold 侧相对路径（fsck.erofs 单文件模式）
CREDS_FILES = (("/etc/passwd", "etc/passwd"), ("/etc/group", "etc/group"))
LABEL_PERM = "u:object_r:vendor_configs_file:s0"
MODE_FILE = 0o100644  # 0x81a4 常规文件（含 S_IFREG，与 inject/gold_selinux 一致）


def vendor_img():
    """官方 super 拆解出的 vendor_a.img（金色 vendor 分区）。缺失即报错退出。"""
    img = os.path.join(SUPER_OUT, "vendor_a.img")
    if not os.path.isfile(img):
        print(f"[err] 官方 vendor_a.img 缺失: {img}（先跑 unpack 阶段）")
        sys.exit(1)
    return img


def _extract(subpath, required):
    """把官方 vendor_a.img 的 subpath 子树提取到缓存，返回缓存内绝对路径（幂等）。"""
    img = vendor_img()
    key = "/".join(subpath)
    dst = os.path.join(GOLD_CACHE_DIR, *subpath)
    stamp = os.path.join(GOLD_CACHE_DIR, ".source-stamp-" + subpath[-1])
    want = (f"{os.path.realpath(img)} {os.path.getsize(img)} "
            f"{int(os.path.getmtime(img))} {key}")
    if os.path.isdir(dst) and os.path.isfile(stamp):
        with open(stamp, encoding="utf-8") as f:
            if f.read() == want:
                return dst

    print(f"[..] EROFS 提取官方 /{key} -> 缓存 {dst}")
    tmp = dst + ".tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp, exist_ok=True)
    res = subprocess.run(
        [erofs_tool("fsck.erofs"), f"--extract={tmp}", f"--path=/{key}", img],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    missing = [n for n in required if not os.path.isfile(os.path.join(tmp, n))]
    if res.returncode != 0 or missing:
        print(res.stdout.decode("utf8", "replace"))
        print(f"[err] 官方 /{key} 提取失败（rc={res.returncode}，"
              f"缺: {', '.join(missing) or '无'}）")
        shutil.rmtree(tmp, ignore_errors=True)
        sys.exit(1)
    shutil.rmtree(dst, ignore_errors=True)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    os.rename(tmp, dst)
    with open(stamp, "w", encoding="utf-8") as f:
        f.write(want)
    return dst


def _extract_file(relpath):
    """提取官方 vendor_a.img 的单个文件到缓存，返回缓存内绝对路径（幂等）。

    fsck.erofs 单文件模式：--extract 的目标即文件本身（非目录），且目标须预先
    不存在，否则会被当作目录而写入其中。故先清干净 tmp（文件/目录两种形态都可能
    残留），提取后校验非空。
    """
    img = vendor_img()
    dst = os.path.join(GOLD_CACHE_DIR, relpath)
    stamp = os.path.join(GOLD_CACHE_DIR,
                         ".source-stamp-" + relpath.replace("/", "-"))
    want = (f"{os.path.realpath(img)} {os.path.getsize(img)} "
            f"{int(os.path.getmtime(img))} {relpath}")
    if os.path.isfile(dst) and os.path.isfile(stamp):
        with open(stamp, encoding="utf-8") as f:
            if f.read() == want:
                return dst

    print(f"[..] EROFS 提取官方 /{relpath} -> 缓存 {dst}")
    tmp = dst + ".tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    if os.path.exists(tmp):
        os.unlink(tmp)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    res = subprocess.run(
        [erofs_tool("fsck.erofs"), f"--extract={tmp}", f"--path=/{relpath}", img],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if res.returncode != 0 or not os.path.isfile(tmp) or os.path.getsize(tmp) == 0:
        print(res.stdout.decode("utf8", "replace"))
        print(f"[err] 官方 /{relpath} 提取失败（rc={res.returncode}）")
        shutil.rmtree(tmp, ignore_errors=True)
        if os.path.exists(tmp):
            os.unlink(tmp)
        sys.exit(1)
    os.replace(tmp, dst)
    with open(stamp, "w", encoding="utf-8") as f:
        f.write(want)
    return dst


def selinux_dir():
    """确保官方 /etc/selinux 已提取到缓存，返回缓存内该目录的绝对路径。"""
    return _extract(SELINUX_SUBPATH, _REQUIRED["/".join(SELINUX_SUBPATH)])


def permissions_dir():
    """确保官方 /etc/permissions 已提取到缓存，返回缓存内该目录的绝对路径。"""
    return _extract(PERMISSIONS_SUBPATH, _REQUIRED["/".join(PERMISSIONS_SUBPATH)])


def creds_cmds(work_img, work_dir, dry_run=False):
    """把官方 /etc/passwd、/etc/group 的缺失条目并入 vendor 工作镜像。

    返回 (cmds, added_paths)；added_paths（镜内路径）同时登记进 baselines
    vendor.selinux-labels（标签 vendor_configs_file），便于审计。
    """
    added, cmds = [], []
    host_dir = os.path.join(work_dir, "gold-creds")
    os.makedirs(host_dir, exist_ok=True)
    for img_path, relpath in CREDS_FILES:
        gold_path = _extract_file(relpath)
        with open(gold_path, encoding="utf-8") as f:
            gold_lines = [ln for ln in f.read().splitlines() if ln.strip()]
        cur = (cat(work_img, img_path) or b"").decode("utf-8", "replace")
        have = {ln.split(":", 1)[0] for ln in cur.splitlines() if ln.strip()}
        new = [ln for ln in gold_lines if ln.split(":", 1)[0] not in have]
        if not new:
            print(f"[..] {img_path} 无缺失官方条目，跳过")
            continue
        merged = cur if (not cur or cur.endswith("\n")) else cur + "\n"
        merged += "".join(ln + "\n" for ln in new)
        host = os.path.join(host_dir, os.path.basename(img_path))
        with open(host, "w", encoding="utf-8") as f:
            f.write(merged)
        cmds += [
            f"rm {img_path}",
            f"write {host} {img_path}",
            f"sif {img_path} mode {MODE_FILE:#x}",
            f"sif {img_path} uid 0",
            f"sif {img_path} gid 0",
            f"ea_set {img_path} security.selinux {LABEL_PERM}",
        ]
        added.append(img_path)
        print(f"[..] {img_path} 补入官方条目 {len(new)} 条"
              f"（镜像原有 {len(have)} 条不动）")
    if added:
        _register_labels({p: LABEL_PERM for p in added},
                         f"/etc/{{passwd,group}} 标签", dry_run=dry_run)
    return cmds, added


def _existing_names(patch_permissions_dir):
    if not os.path.isdir(patch_permissions_dir):
        return set()
    return {n for n in os.listdir(patch_permissions_dir)
            if os.path.isfile(os.path.join(patch_permissions_dir, n))}


def permissions_missing_cmds(work_dir, patch_permissions_dir, dry_run=False):
    """官方 /etc/permissions 里 lineage 缺失的 xml -> debugfs 注入命令清单。

    返回 (cmds, added_names)；added_names 同时登记进 baselines
    vendor.selinux-labels（标签 vendor_configs_file），便于审计。
    """
    gold = permissions_dir()
    skip = _existing_names(patch_permissions_dir)
    added = []
    cmds = []
    host_dir = os.path.join(work_dir, "gold-permissions")
    os.makedirs(host_dir, exist_ok=True)
    for name in sorted(os.listdir(gold)):
        if name in skip or not name.endswith(".xml"):
            continue
        src = os.path.join(gold, name)
        if not os.path.isfile(src):
            continue
        dst = os.path.join(host_dir, name)
        shutil.copy2(src, dst)
        img_path = f"/etc/permissions/{name}"
        cmds.append(f"write {dst} {img_path}")
        cmds.append(f"sif {img_path} mode 0x81a4")
        cmds.append(f"sif {img_path} uid 0")
        cmds.append(f"sif {img_path} gid 0")
        cmds.append(f"ea_set {img_path} security.selinux {LABEL_PERM}")
        added.append(name)
    if added:
        print(f"[..] 补回官方 /etc/permissions 缺失件 {len(added)} 个"
              f"（lineage 已有 {len(skip)} 个不动）")
        _register_labels({f"etc/permissions/{n}": LABEL_PERM for n in added},
                         "/etc/permissions 标签", dry_run=dry_run)
    else:
        print("[..] 官方 /etc/permissions 无缺失件，跳过")
    return cmds, added


def _register_labels(pairs, what, dry_run=False):
    """把 {键: 标签} 幂等登记进 baselines vendor.selinux-labels。

    键 = 注入树内相对路径（去前导 /），与 inject.py 的查找口径一致。
    """
    path = baselines_file()
    if not path or not os.path.isfile(path):
        print(f"[err] 基线清单缺失: {path or 'None'}", file=sys.stderr)
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    labels = doc.setdefault("vendor", {}).setdefault("selinux-labels", {})
    missing = {k.lstrip("/"): v for k, v in pairs.items()
               if labels.get(k.lstrip("/")) != v}
    if not missing:
        return
    labels.update(missing)
    if dry_run:
        print(f"[..] (dry) baselines 将登记 {what} {len(missing)} 条")
        return
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path),
                               prefix=".baselines.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise
    print(f"[ok] baselines 登记 {what} {len(missing)} 条")