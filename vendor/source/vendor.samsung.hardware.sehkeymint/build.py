#!/usr/bin/env python3
"""sm-s9380-16：构建 software-only vendor.samsung.hardware.keymint.ISehKeyMintExtension 服务。

三星 keystore2 启动期无条件按裸名 find SEH KeyMint 扩展，取不到就 panic
（`SehKeyMintExtension must be present`）→ IKeystoreService 起不来 → vold/zygote 连锁、
boot 卡死（实测 instance 28 qemu.log 里 `find ... ISehKeyMintExtension` 刷 133 次、
`KeyStorage: getRotStr There is no rot value`）。gold keymint 会挂这个 extension，但它
同时把 IKeyMintDevice 换成安全后端、在 virtio 客机上建不出 FBE key（M02R → /data 重格式），
故不能收编 gold。本模块用 NDK 裸 binder C API 自研一个 descriptor/version/hash 与 gold
一致、getLastFailedRot 返回良性字节的独立服务补上裸名，puresoft keymint 原样保留给 vold。

工具链：本机 NDK r29 clang（仅 C，无 C++ AIDL 运行时）+ 从官方 system 分区取真实
libbinder_ndk.so 参与链接（NDK 桩库不含 AServiceManager_* / ABinderProcess_*）。

产物（相对路径即镜像内 /vendor 路径）：
  bin/hw/vendor.samsung.hardware.sehkeymint-service   (0755, pioneer_exec)
  etc/init/vendor.samsung.hardware.sehkeymint-service.rc
  etc/vintf/manifest/vendor.samsung.hardware.sehkeymint.xml

SELinux 标签经 baselines 登记；裸名→hal_keymint_service 的 vendor_service_contexts 映射
在 build/vendor/build/sepolicy.py（SEH_KEYMINT_VSC_LINES）。

用法：
  python3 build/vendor/source/vendor.samsung.hardware.sehkeymint/build.py
  python3 build/vendor/source/vendor.samsung.hardware.sehkeymint/build.py --dry-run
"""

import argparse
import glob
import json
import os
import subprocess
import sys
import tempfile

# 本文件位于 build/vendor/source/vendor.samsung.hardware.sehkeymint/ 下，向上 5 级为设备根
_DEVICE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
sys.path.insert(0, os.path.join(_DEVICE_ROOT, "build", "scripts"))

from buildenv import (  # noqa: E402
    SUPER_OUT, TMP_DIR, VENDOR_STAGE_DIR, baselines_file, erofs_tool,
)

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
COMMON_DIR = os.path.join(os.path.dirname(MODULE_DIR), "common")
SRC_DIR = os.path.join(MODULE_DIR, "src")
WORK_DIR = os.path.join(TMP_DIR, "vendor", "sehkeymint")
LINK_DIR = os.path.join(WORK_DIR, "link")          # 放真实 libbinder_ndk.so 供链接
SYSTEM_IMG = os.path.join(SUPER_OUT, "system_a.img")

BINARY = "vendor.samsung.hardware.sehkeymint-service"
RC_NAME = BINARY + ".rc"
VINTF_NAME = "vendor.samsung.hardware.sehkeymint.xml"

TARGET = "aarch64-linux-android33"

# 二进制落 CDH 值守域（rc 内 seclabel u:r:pioneer:s0），rc/vintf 沿用基座配置口径。
LABEL_BIN = "u:object_r:pioneer_exec:s0"
LABEL_CONFIG = "u:object_r:vendor_configs_file:s0"


def env(name, default):
    return os.environ.get(name) or default


def toolchain():
    ndk = env("CDH_NDK", os.path.expanduser(
        "~/Library/Android/sdk/ndk/29.0.14206865"))
    prebuilt = os.path.join(ndk, "toolchains", "llvm", "prebuilt",
                            "darwin-x86_64")
    return {
        "clang": env("CDH_CLANG", os.path.join(prebuilt, "bin", "clang")),
        "sysroot": os.path.join(prebuilt, "sysroot"),
    }


def run(argv, dry_run=False):
    if dry_run:
        print("[..] (dry)", " ".join(argv))
        return
    res = subprocess.run(argv, capture_output=True, text=True)
    if res.returncode != 0:
        print(res.stdout, file=sys.stderr)
        print(res.stderr, file=sys.stderr)
        sys.exit(1)


def erofs_extract(src_inner, dst, mode=0o644, dry_run=False):
    """从官方镜像提取单文件到 dst（幂等；fsck.erofs 拒绝已存在目标文件）。"""
    if os.path.isfile(dst) and os.path.getsize(dst) > 0:
        return
    if dry_run:
        print(f"[..] (dry) EROFS 提取 {src_inner} -> {dst}")
        return
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    tmp = dst + ".tmp"
    if os.path.exists(tmp):
        os.unlink(tmp)
    res = subprocess.run(
        [erofs_tool("fsck.erofs"), f"--extract={tmp}", f"--path={src_inner}",
         SYSTEM_IMG], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if not os.path.isfile(tmp) or os.path.getsize(tmp) == 0:
        print(res.stdout.decode("utf8", "replace"))
        print(f"[err] EROFS 提取失败: {src_inner}", file=sys.stderr)
        sys.exit(1)
    os.chmod(tmp, mode)
    os.replace(tmp, dst)


def ensure_link_lib(dry_run=False):
    """取出真实 libbinder_ndk.so（NDK 桩库缺 AServiceManager_*/ABinderProcess_*）。"""
    lib = os.path.join(LINK_DIR, "libbinder_ndk.so")
    erofs_extract("/system/lib64/libbinder_ndk.so", lib, dry_run=dry_run)
    return lib


def clang_rt_dir(prebuilt):
    base = os.path.join(prebuilt, "lib", "clang")
    cands = sorted(d for d in glob.glob(os.path.join(base, "*")) if os.path.isdir(d))
    return cands[-1] if cands else None


def compile_service(tc, ndk_real_lib, out_bin, dry_run=False):
    src = os.path.join(SRC_DIR, "sehkeymint_ext.c")
    argv = [
        tc["clang"], "--target=" + TARGET, "--sysroot=" + tc["sysroot"],
        "-std=c11", "-O2", "-fPIE", "-pie",
        "-Wall", "-Wextra", "-Wno-unused-parameter",
        "-I" + os.path.join(COMMON_DIR, "ndk-binder-platform"),
        src,
        # 真实 binder_ndk 库提供全部 binder 符号（含 AServiceManager_*/ABinderProcess_*）
        ndk_real_lib,
        "-llog",
        "-o", out_bin,
    ]
    run(argv, dry_run=dry_run)


def write_asset(src_rel, dst, dry_run=False):
    src = os.path.join(MODULE_DIR, src_rel)
    if dry_run:
        print(f"[..] (dry) 写 {os.path.relpath(dst, VENDOR_STAGE_DIR)}")
        return
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(src, encoding="utf-8") as f:
        content = f.read()
    with open(dst, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"    写 {os.path.relpath(dst, VENDOR_STAGE_DIR)}")


def register_labels(dry_run=False):
    path = baselines_file()
    if not path or not os.path.isfile(path):
        print(f"[err] 基线清单缺失: {path or 'None'}", file=sys.stderr)
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    labels = doc.setdefault("vendor", {}).setdefault("selinux-labels", {})
    entries = {
        f"bin/hw/{BINARY}": LABEL_BIN,
        f"etc/init/{RC_NAME}": LABEL_CONFIG,
        f"etc/vintf/manifest/{VINTF_NAME}": LABEL_CONFIG,
    }
    missing = {k: v for k, v in entries.items() if labels.get(k) != v}
    if not missing:
        print("[..] baselines 标签已齐，跳过")
        return
    labels.update(missing)
    if dry_run:
        print(f"[..] (dry) baselines 将登记标签 {len(missing)} 条")
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
    print(f"[ok] baselines 登记标签 {len(missing)} 条")


def build(dry_run=False):
    if not dry_run and not os.path.isfile(SYSTEM_IMG):
        print(f"[err] 缺官方 system 镜像: {SYSTEM_IMG}（先 unpack）", file=sys.stderr)
        sys.exit(1)

    tc = toolchain()
    os.makedirs(WORK_DIR, exist_ok=True)

    print("==> 取出真实 libbinder_ndk.so（供链接 AServiceManager_*）")
    ndk_real_lib = ensure_link_lib(dry_run=dry_run)

    print("==> 编译 SEH KeyMint 扩展服务")
    out_bin = os.path.join(VENDOR_STAGE_DIR, "bin", "hw", BINARY)
    os.makedirs(os.path.dirname(out_bin), exist_ok=True)
    compile_service(tc, ndk_real_lib, out_bin, dry_run=dry_run)
    if not dry_run:
        os.chmod(out_bin, 0o755)
        print(f"    写 {os.path.relpath(out_bin, VENDOR_STAGE_DIR)} "
              f"（{os.path.getsize(out_bin)} B）")

    print("==> rc / vintf")
    write_asset(os.path.join("vendor", "etc", "init", RC_NAME),
                os.path.join(VENDOR_STAGE_DIR, "etc", "init", RC_NAME),
                dry_run=dry_run)
    write_asset(os.path.join("vendor", "etc", "vintf", "manifest", VINTF_NAME),
                os.path.join(VENDOR_STAGE_DIR, "etc", "vintf", "manifest",
                             VINTF_NAME),
                dry_run=dry_run)

    print("==> SELinux 标签登记")
    register_labels(dry_run=dry_run)

    print("[ok] SEH KeyMint 扩展服务构建完成")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="sm-s9380-16 software-only SEH KeyMint 扩展服务构建")
    ap.add_argument("--dry-run", action="store_true", help="只打印不执行")
    args = ap.parse_args()
    sys.exit(build(dry_run=args.dry_run))


if __name__ == "__main__":
    main()
