"""vendor_dlkm.img 构建（Samsung，分层对齐 popsicle-16 / note13）。

  1. 基座：lineage 底包 vendor_dlkm_a.img（ext4，与本项目 virtio 内核同 6.12 分支）；
     真机厂商 vendor_dlkm 是 Samsung 内核的模块，不能用于 virtio 云主机；
  2. modules.py：注入 `out/dist/kernel/modules/` 自编译 .ko 并**重建**
     modules.load/dep/alias/options 索引，注入前回收基座 kunit/测试件腾出 inode/块
     （基座仅剩 16 inode / 12 块，不回收会有 .ko 静默写失败）；
  3. e2fsck -fy 重打包 -> out/dist/rom/vendor_dlkm.img。

编排只做一次 debugfs 会话 + 回读校验（dump+cmp 逐件严格比对），任何写入失败即退出，
不再出现「日志说注入 11 个、镜像里 7 个是基座陈件」的情况。
"""

import os
import shutil
import sys

from buildenv import (
    LINEAGE_SUPER_DIR, TMP_DIR, VENDOR_DLKM_DIST,
)
from debugfs import E2FSCK, run, run_command_file
import modules

BASE = os.path.join(LINEAGE_SUPER_DIR, "vendor_dlkm_a.img")
WORK_DIR = os.path.join(TMP_DIR, "vendor_dlkm")


def build_vendor_dlkm(dry_run=False):
    if not os.path.isfile(BASE):
        print(f"[err] 基座 vendor_dlkm_a.img 缺失: {BASE}（先 unpack lineage）")
        sys.exit(1)

    os.makedirs(WORK_DIR, exist_ok=True)
    work_img = os.path.join(WORK_DIR, "vendor_dlkm.work.img")
    if not dry_run:
        shutil.copy2(BASE, work_img)
    print(f"[ok] 基座副本: {BASE} -> {work_img}")

    kois = modules.discover_modules()
    if not kois:
        print(f"[warn] 无内核模块产物（{modules.KERNEL_MODULES_DIR}），vendor_dlkm 基座直通")
        if dry_run:
            print("[..] (dry) 将直拷基座")
        else:
            os.makedirs(os.path.dirname(VENDOR_DLKM_DIST), exist_ok=True)
            shutil.copy2(BASE, VENDOR_DLKM_DIST)
            print(f"[ok] vendor_dlkm.img -> {VENDOR_DLKM_DIST}")
        return 0

    if dry_run:
        print(f"[..] (dry) 将注入 {len(kois)} 个模块并重建 modules.load/dep/alias/options")
        return 0

    cmds = modules.inject_cmds(work_img, kois, WORK_DIR)
    if not run_command_file(work_img, cmds, WORK_DIR):
        print("[err] debugfs 注入内核模块/索引失败（基座空间不足或路径不符）")
        sys.exit(1)
    print(f"[ok] 注入 {len(kois)} 个内核模块 + 重建 4 类索引")
    modules.verify(work_img, kois, WORK_DIR)

    res = run([E2FSCK, "-fy", work_img], capture_output=True, text=True)
    if res.returncode not in (0, 1):
        print(res.stderr)
        print(f"[err] e2fsck 失败: {res.returncode}")
        sys.exit(1)
    print("[ok] e2fsck 通过")

    os.makedirs(os.path.dirname(VENDOR_DLKM_DIST), exist_ok=True)
    shutil.copy2(work_img, VENDOR_DLKM_DIST)
    print(f"[ok] vendor_dlkm.img -> {VENDOR_DLKM_DIST}"
          f"（{os.path.getsize(VENDOR_DLKM_DIST) // 2**20} MiB）")
    return 0
