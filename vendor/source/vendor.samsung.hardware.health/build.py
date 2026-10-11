#!/usr/bin/env python3
"""sm-s9380-16 health HAL 收编：官方 vendor.samsung.hardware.health-service 整件搬运。

背景（实测 2026-10-10，instance 14）：lineage 底包用 APEX
（/vendor/apex/com.google.cf.health.apex）提供 AOSP 口径的
android.hardware.health-service.cuttlefish，它只注册 android.hardware.health.IHealth/
default。三星框架的 HealthRegCallbackAidl 要的是 **SEH 扩展**：

    E Zygote: java.lang.RuntimeException: Failed to start service
        com.android.server.BatteryService: onStart threw an exception
    Caused by: java.lang.NullPointerException: Attempt to invoke virtual method
        'void vendor.samsung.hardware.health.ISehHealth$Stub$Proxy.registerCallback(
         com.android.server.health.HealthRegCallbackAidl$HalInfoCallback)'
        on a null object reference
      at com.android.server.health.HealthRegCallbackAidl.onRegistration(:75)

→ system_server FATAL、zygote 反复重启、boot_completed 永不置位。

官方二进制把 ISehHealth 以 **binder extension** 挂在同一个 IHealth binder 上
（strings 可见 `AIBinder_setExtension(healthBinder.get(), sehHealth->asBinder().get())`
与 `AIBinder_getExtension(tBinder.get(), sehtBinder.getR()) fail`），框架侧即从
extension 取 ISehHealth；cuttlefish 没有 extension → asInterface(null) → null。
故必须收编官方服务，且必须移除 cf.health APEX（两者都声明 IHealth/default，
同时存在会撞实例，见 prune.PRUNE_FILES）。

产物（相对路径即镜像内 /vendor 路径，与真机同名同路径）：
  bin/hw/vendor.samsung.hardware.health-service   (0755, pioneer_exec)
  lib64/android.hardware.health-V3-ndk.so         (vendor_file；底包无此库)
  lib64/vendor.samsung.hardware.health-V1-ndk.so  (vendor_file)
  lib64/vendor.samsung.hardware.thermal-V1-ndk.so (vendor_file)
  etc/init/vendor.samsung.hardware.health-service.rc
  etc/vintf/manifest/vendor.samsung.hardware.health-service.xml

三个 .so 即 readelf -d 的全部缺失依赖：其余 NEEDED（libbase/libcutils/libutils/
libhidlbase/libc++、android.hardware.thermal-V2-ndk）底包或系统分区已有
（instance 14 guest 侧逐个 stat 实测）。真机 rc 里的 charger 模式服务不启用。

用法：
  python3 build/vendor/source/vendor.samsung.hardware.health/build.py [--dry-run]
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile

# 本文件位于 build/vendor/source/vendor.samsung.hardware.health/ 下，向上 5 级为设备根
_DEVICE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
sys.path.insert(0, os.path.join(_DEVICE_ROOT, "build", "scripts"))

from buildenv import (  # noqa: E402
    SUPER_OUT, VENDOR_STAGE_DIR, baselines_file, erofs_tool,
)

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
VENDOR_IMG = os.path.join(SUPER_OUT, "vendor_a.img")

BINARY = "vendor.samsung.hardware.health-service"
# gold 二进制 readelf -d 里底包/系统分区没有的三个 ndk 库
LIBS = (
    "android.hardware.health-V3-ndk.so",
    "vendor.samsung.hardware.health-V1-ndk.so",
    "vendor.samsung.hardware.thermal-V1-ndk.so",
)
RC_NAME = BINARY + ".rc"
VINTF_NAME = BINARY + ".xml"

# 二进制用 CDH 值守域（rc 内 seclabel u:r:pioneer:s0；lineage 基座没有
# init → hal_health_default 的转换规则），配置/库沿用基座口径。
LABEL_BIN = "u:object_r:pioneer_exec:s0"
LABEL_LIB = "u:object_r:vendor_file:s0"
LABEL_CONFIG = "u:object_r:vendor_configs_file:s0"


def erofs_extract(src_inner, dst, mode=0o644, dry_run=False):
    """从官方 vendor_a.img 提取 src_inner 到 dst（幂等；fsck.erofs 拒绝已存在目标）。"""
    rel = os.path.relpath(dst, VENDOR_STAGE_DIR)
    if dry_run:
        print(f"[..] (dry) EROFS 提取 {src_inner} -> {rel}")
        return
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    tmp = dst + ".tmp"
    if os.path.exists(tmp):
        os.unlink(tmp)
    res = subprocess.run(
        [erofs_tool("fsck.erofs"), f"--extract={tmp}", f"--path={src_inner}",
         VENDOR_IMG],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if res.returncode != 0 or not os.path.isfile(tmp) or os.path.getsize(tmp) == 0:
        print(res.stdout.decode("utf8", "replace"))
        print(f"[err] EROFS 提取失败: {src_inner}（rc={res.returncode}）",
              file=sys.stderr)
        if os.path.exists(tmp):
            os.unlink(tmp)
        sys.exit(1)
    os.chmod(tmp, mode)
    os.replace(tmp, dst)
    print(f"    取 {src_inner} -> {rel}（{os.path.getsize(dst)} B）")


def write_asset(src_rel, dst, dry_run=False):
    """把模块内 vendor/ 下的源文件拷到 staging。"""
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
    """bin/lib64/rc/vintf 的 SELinux 标签登记进 baselines（inject.py 据此 ea_set）。"""
    path = baselines_file()
    if not path or not os.path.isfile(path):
        print(f"[err] 基线清单缺失: {path or 'None'}", file=sys.stderr)
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    labels = doc.setdefault("vendor", {}).setdefault("selinux-labels", {})
    entries = {f"bin/hw/{BINARY}": LABEL_BIN}
    entries.update({f"lib64/{lib}": LABEL_LIB for lib in LIBS})
    entries.update({
        f"etc/init/{RC_NAME}": LABEL_CONFIG,
        f"etc/vintf/manifest/{VINTF_NAME}": LABEL_CONFIG,
    })
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
    if not dry_run and not os.path.isfile(VENDOR_IMG):
        print(f"[err] 缺官方 vendor 镜像: {VENDOR_IMG}（先 unpack）", file=sys.stderr)
        sys.exit(1)

    print("==> 收编官方 health HAL 二进制与 ndk 库")
    erofs_extract(f"/bin/hw/{BINARY}",
                  os.path.join(VENDOR_STAGE_DIR, "bin", "hw", BINARY),
                  mode=0o755, dry_run=dry_run)
    for lib in LIBS:
        erofs_extract(f"/lib64/{lib}",
                      os.path.join(VENDOR_STAGE_DIR, "lib64", lib),
                      dry_run=dry_run)

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

    print("[ok] health HAL 收编完成")
    return 0


def main():
    ap = argparse.ArgumentParser(description="sm-s9380-16 health HAL 收编")
    ap.add_argument("--dry-run", action="store_true", help="只打印不执行")
    args = ap.parse_args()
    sys.exit(build(dry_run=args.dry_run))


if __name__ == "__main__":
    sys.exit(main())
