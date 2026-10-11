#!/usr/bin/env python3
"""官方 super.img 直拷（零改动）到 out/dist/rom/super.img。

Samsung 的 `super.img` 以 **sparse** 形式下发，unpack 阶段已就地展开为 raw
（sparse→raw 是无损的官方表示，等价于设备刷写时的展开结果）。本脚本把展开后的官方
super **字节级复制**到 SUPER_DIST，作为「官方 super 零改动」路线的 super 产物；
pack-roms 将其原样写入 vda 的 super 分区。lineage vendor/vendor_dlkm 内容由
patch.img（vdc 挂 /mnt/vendor）承担，内核 getname_flags 白名单重定向到 /mnt。

用法（可在任何目录）：
  python3 build/scripts/pack_super.py
  python3 build/scripts/pack_super.py --dry-run    # 只打印不执行
"""

import argparse
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from buildenv import SUPER_DIST, SUPER_IMG  # noqa: E402


def pack_super(dry_run=False):
    if not os.path.isfile(SUPER_IMG):
        print(f"[err] 官方 super.img 缺失: {SUPER_IMG}（先 unpack）")
        sys.exit(1)
    os.makedirs(os.path.dirname(SUPER_DIST), exist_ok=True)
    if dry_run:
        print(f"[..] (dry) 官方 super.img 直拷 -> {SUPER_DIST}"
              f"（{os.path.getsize(SUPER_IMG)} B，零改动）")
        return 0
    shutil.copy2(SUPER_IMG, SUPER_DIST)
    print(f"[ok] 官方 super.img 直拷 -> {SUPER_DIST}"
          f"（{os.path.getsize(SUPER_DIST)} B，零改动）")
    return 0


def main():
    ap = argparse.ArgumentParser(description="note13-5G-15 官方 super.img 直拷（零改动）")
    ap.add_argument("--dry-run", action="store_true", help="只打印不执行")
    args = ap.parse_args()
    sys.exit(pack_super(dry_run=args.dry_run))


if __name__ == "__main__":
    main()
