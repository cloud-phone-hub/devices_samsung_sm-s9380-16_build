#!/usr/bin/env python3
"""SM-S9380-16（Samsung Galaxy S25 Ultra / SM8750 / Android 16）构建全流程编排（main）。

按顺序串联 build/scripts/ 下的脚本（与 buildenv.STAGES 保持一致）：

  unpack       -> unpack-roms.py        解 Samsung FUS 服务包（enc4 -> zip -> tar.md5 -> 各 *.img）
  kernel       -> build-kernel.py       编译内核/模块（GKI android15-6.6 + virtio + CDH 重定向）
  boot         -> build-boot.py         打包 boot.img（lineage-23 基座 + 自编译内核 + fstab 注入）
  vendor_boot  -> build-vendor-boot.py  删 vendor_boot fragment 内 fstab 副本 + 对齐 androidboot.hardware
  vendor       -> build-vendor.py       lineage vendor 基座 + patch 注入 -> vendor.img
  vendor_dlkm  -> build-vendor_dlkm.py  lineage vendor_dlkm 基座 + 内核模块注入
  patch        -> build-patch.py        vendor/vendor_dlkm -> ext4 镜像（vdc 挂 /mnt/vendor）
  super        -> pack_super.py         官方 super.img 直拷（零改动）
  pack         -> pack-roms.py          组装 vda.img + data.qcow2

依赖：unpack 最先；kernel 先于 boot/vendor/vendor_dlkm；patch 需 vendor/vendor_dlkm
产物（缺省回退 lineage 基座）；super 前置于 pack；pack 最后。

用法（可在任何目录）：
  python3 build/main.py                    # 全流程
  python3 build/main.py --skip-unpack      # 跳过 unpack（已解好时）
  python3 build/main.py --only kernel      # 只跑指定阶段
  python3 build/main.py --from vendor      # 从指定阶段起跑
  python3 build/main.py --dry-run          # 只打印将执行的命令
  python3 build/main.py --force-pack       # pack 阶段加 --force
"""

import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

BUILD_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(BUILD_DIR, "scripts")

_manifest_path = os.path.join(BUILD_DIR, "manifest.json")


def _load_manifest():
    """读取 manifest.json（声明 roms/ 下支持的固件与关键镜像），返回 dict。

    仅用于打印设备名与可编译 build-id；文件缺失或解析失败时返回 None 优雅降级。
    """
    try:
        with open(_manifest_path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _print_device_info(manifest):
    if not manifest:
        print("[warn] 缺少或无法解析 manifest.json，跳过设备信息")
        return
    dev = manifest.get("device", {})
    builds = manifest.get("build", [])
    print(f"  设备: {dev.get('name') or dev.get('codename') or '未知'}")
    ids = [b.get("build-id") for b in builds if b.get("build-id")]
    if ids:
        print(f"  可编译 build-id: {', '.join(ids)}")


def _device_info_lines(manifest):
    """机型 TSV 行（供 just device list 收集），每个 build-id 一行机型：
    <vendor>/<device>\\t<显示名>\\t<build-id>
    无 build 条目时输出一行空 build-id，保证设备仍可被列出。"""
    dev = manifest.get("device", {}) if manifest else {}
    builds = manifest.get("build", []) if manifest else []
    name = dev.get("name") or dev.get("codename") or "unknown"
    vendor = os.path.basename(os.path.dirname(os.path.dirname(BUILD_DIR)))  # xiaomi
    device = os.path.basename(os.path.dirname(BUILD_DIR))                   # note13-5G-15
    ids = [b.get("build-id") for b in builds if b.get("build-id")]
    if not ids:
        ids = [""]
    return [f"{vendor}/{device}\t{name}\t{i}" for i in ids]


# 阶段：短名 -> 脚本文件名（沿用既有固定命名，非各阶段同名），扩展参数
# 注：super 阶段暂不传参——note13 pack_super.py 还是骨架，待实现时从单一数据源取
# SUPER_SIZE/分区映射（对齐 pixel6-15 main.py 的做法）。
STAGE_SCRIPTS = [
    ("unpack", "unpack-roms.py", []),
    ("kernel", "build-kernel.py", []),
    ("boot", "build-boot.py", []),
    ("vendor_boot", "build-vendor-boot.py", []),
    ("vendor", "build-vendor.py", []),
    ("vendor_dlkm", "build-vendor_dlkm.py", []),
    ("patch", "build-patch.py", []),
    ("super", "pack_super.py", []),
    ("pack", "pack-roms.py", []),
]
STAGE_NAMES = [s[0] for s in STAGE_SCRIPTS]


def _stage_index(name):
    try:
        return STAGE_NAMES.index(name)
    except ValueError:
        print(f"[err] 未知阶段: {name}（可选: {', '.join(STAGE_NAMES)}）")
        sys.exit(2)


def _run_script(script, extra, dry_run):
    path = os.path.join(SCRIPTS_DIR, script)
    cmd = [sys.executable, path] + extra
    print("  + " + " ".join(cmd))
    if dry_run:
        return 0
    rc = subprocess.run(cmd)
    if rc.returncode != 0:
        print(f"[err] {script} 执行失败 (rc={rc.returncode})")
        sys.exit(rc.returncode)
    return 0


def main():
    ap = argparse.ArgumentParser(description="SM-S9380-16 构建全流程编排")
    ap.add_argument("--skip-unpack", action="store_true", help="跳过 unpack")
    ap.add_argument("--only", metavar="STAGE", help=f"只跑指定阶段（{', '.join(STAGE_NAMES)}）")
    ap.add_argument("--from", dest="from_stage", metavar="STAGE", help="从指定阶段起跑")
    ap.add_argument("--dry-run", action="store_true", help="只打印将执行的命令")
    ap.add_argument("--force-pack", action="store_true", help="pack 阶段加 --force")
    ap.add_argument("--device-info", action="store_true",
                    help="只打印机型 TSV 行（vendor/device、显示名、build-id，每机型一行）后退出，"
                         "供 just device list 收集")
    ap.add_argument("--build-id", metavar="ID",
                    help="选择 manifest.json 中的固件条目（校验存在性；各阶段按其选择固件）")
    args = ap.parse_args()

    if args.device_info:
        for line in _device_info_lines(_load_manifest()):
            print(line)
        return 0

    manifest = _load_manifest()
    if args.build_id:
        ids = [b.get("build-id") for b in (manifest or {}).get("build", [])]
        if args.build_id not in ids:
            print(f"[err] 未知 build-id: {args.build_id}（可选: {', '.join(ids)}）")
            sys.exit(2)
        print(f"==> 选择固件 build-id: {args.build_id}")

    _print_device_info(manifest)

    stages = list(STAGE_SCRIPTS)
    if args.skip_unpack:
        stages = [s for s in stages if s[0] != "unpack"]
    if args.only:
        _stage_index(args.only)
        stages = [s for s in stages if s[0] == args.only]
        if not stages:
            print(f"[err] 阶段 {args.only} 已被 --skip-unpack 移除")
            sys.exit(2)
    elif args.from_stage:
        # --skip-unpack 已删掉 unpack，stages 与 STAGE_NAMES 索引错位；
        # 必须按名字在过滤后的 stages 里定位，否则会把 vendor 等阶段跳掉。
        _stage_index(args.from_stage)  # 校验阶段名合法
        names = [s[0] for s in stages]
        if args.from_stage not in names:
            print(f"[err] 阶段 {args.from_stage} 已被 --skip-unpack 移除")
            sys.exit(2)
        stages = stages[names.index(args.from_stage):]

    if args.force_pack:
        stages = [(n, s, a + ["--force"]) if n == "pack" else (n, s, a)
                  for n, s, a in stages]

    if not stages:
        print("[err] 没有要执行的阶段")
        sys.exit(2)

    print(f"==> 执行 {len(stages)} 个阶段: {', '.join(n for n, _, _ in stages)}")
    for name, script, extra in stages:
        print(f"==> [{name}] {script}")
        _run_script(script, extra, args.dry_run)
    print("[ok] 全流程完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())