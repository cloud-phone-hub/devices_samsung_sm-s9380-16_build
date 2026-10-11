#!/usr/bin/env python3
"""note13-5G-15 boot.img 打包脚本（移植自 pixel6-15 build-boot.py）。

以 lineage-22.0 解包 boot_a.img 为基底（保留其 v4 header 结构与内嵌 initrd），
kernel 段替换为编译的 Image，ramdisk 注入 first_stage virtio fstab 后重新对齐，
os_version 保留基底值（当前能正常引导的值即 EDK II 直启接受值），
原子写回 out/dist/rom/boot.img。

vendor_boot.img 由 build-vendor-boot.py 处理（删其 ramdisk fragment 内的 fstab 副本，
让本脚本注入的 fstab 成为唯一来源）。

关键点：
  - lineage virtio boot_a.img 有内嵌 ramdisk，配合自编译 virtio 内核可让
    EDK II EFI-stub 直启；官方 gold images 仅保留 super.img（无 boot.img），
    preloader->lk 引导链的官方 boot 不适用于 QEMU/EDK II 云机。
  - fstab 注入布局对齐 cloud-droid-hub cmd/gsifix boot_firststage_fstab.go：
    各 fstab 名同时落到根/system/etc/first_stage_ramdisk/first_stage_ramdisk/system/etc 四处。
  - fstab 名 = fstab.qcom（云机 ro.hardware 已对齐真机 qcom），内容取自 vendor
    patch 树那份（/vendor/etc/fstab.qcom 同源）。

用法（可在任何目录）：
  python3 build/scripts/build-boot.py --kernel-image <Image>  # 打包 boot.img（默认 out/kernel/Image）
"""

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from buildenv import (  # noqa: E402
    KERNEL_OUT, LINEAGE_OUT_DIR, ROM_DIST,
)
from buildenv import env  # noqa: E402

# 设备根（本文件位于 build/scripts/ 下，向上 3 级即设备根）
_DEVICE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# boot 源与输出
# boot.img 以 lineage-22.0 解包 boot_a.img 为基底：它有内嵌 ramdisk（@12 非零），
# 配合自编译内核可让 edk2 EFI-stub 直启；官方 gold images 无可用 boot.img。
# lineage 解压目录由 CDH_LINEAGE_DIR 环境变量优先（main.py --build-id 导出）。
LINEAGE_DIR = env("CDH_LINEAGE_DIR", LINEAGE_OUT_DIR)
LINEAGE_BOOT_IMG = os.path.join(
    LINEAGE_DIR,
    "boot_a.img" if os.path.isfile(os.path.join(LINEAGE_DIR, "boot_a.img")) else "boot.img",
)
BOOT_IMG_OUT = os.path.join(ROM_DIST, "boot.img")


# Android boot image v4 header 关键字段偏移（大端 magic，其余小端 u32）。
BOOT_MAGIC = b"ANDROID!"
BOOT_KERNEL_SIZE_OFF = 8
BOOT_RAMDISK_SIZE_OFF = 12
BOOT_OS_VERSION_OFF = 16
BOOT_HEADER_SIZE_OFF = 20
BOOT_PAGE_SIZE = 4096

MAX_BOOT_PARTITION_BYTES = 256 * 1024 * 1024

# —— first_stage fstab 注入（对齐基线，让 EDK II 直启后的 init 首阶段能挂载
#   /system(logical/super)/data(vdb)/metadata/mi_ext 等）。名字 = fstab.qcom，
#   与 init 按 ro.hardware(=qcom，见 build-vendor-boot.py) 拼出的路径一致；内容取自
#   vendor patch 树那份 /vendor/etc/fstab.qcom（单一来源）。
#   注入布局与 cloud-droid-hub cmd/gsifix boot_firststage_fstab.go 完全一致：
#   各 fstab 名同时落到根/system/etc/first_stage_ramdisk/first_stage_ramdisk/system/etc 四处。
_FSTAB_NAMES = (
    "fstab.qcom",
)
_FSTAB_DUMP_PATHS = (
    "{name}",
    "system/etc/{name}",
    "first_stage_ramdisk/{name}",
    "first_stage_ramdisk/system/etc/{name}",
)
_FSTAB_DIR_PATHS = (
    "first_stage_ramdisk",
    "first_stage_ramdisk/system",
    "first_stage_ramdisk/system/etc",
    "system",
    "system/etc",
)

# first stage fstab 内容来源：与 /vendor/etc/fstab.qcom 同一份文件（vendor patch 树，
# 同时由 inject.py 注入 vendor 分区供二阶段 mount_all 读取），单一来源避免两处漂移。
# 真机同此——其 boot ramdisk 里的 fstab.qcom 就是 /vendor 分区那份的完整副本。
_FSTAB_SRC = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "vendor", "patch", "etc", "fstab.qcom")


def firststage_fstab():
    with open(_FSTAB_SRC, "rb") as f:
        return f.read()


def _file_ok(p):
    return os.path.isfile(p) and os.path.getsize(p) > 0


def _align_up(value, align):
    return (value + align - 1) // align * align


def _parse_boot_header(data):
    """解析 Android boot header，返回 kernel/ramdisk/header 字段。"""
    if len(data) < 64 or data[:8] != BOOT_MAGIC:
        raise ValueError("非 Android boot 镜像 (magic 不匹配)")
    kernel_size = struct.unpack_from("<I", data, BOOT_KERNEL_SIZE_OFF)[0]
    ramdisk_size = struct.unpack_from("<I", data, BOOT_RAMDISK_SIZE_OFF)[0]
    header_size = struct.unpack_from("<I", data, BOOT_HEADER_SIZE_OFF)[0]
    if kernel_size <= 0 or header_size <= 0:
        raise ValueError("boot header 参数异常")
    kernel_offset = _align_up(header_size, BOOT_PAGE_SIZE)
    ramdisk_offset = _align_up(kernel_offset + kernel_size, BOOT_PAGE_SIZE)
    ramdisk_end = ramdisk_offset + ramdisk_size
    if ramdisk_end > len(data):
        raise ValueError(f"boot ramdisk 越界: {ramdisk_end} > {len(data)}")
    return {
        "kernel_size": kernel_size,
        "ramdisk_size": ramdisk_size,
        "header_size": header_size,
        "kernel_offset": kernel_offset,
        "ramdisk_offset": ramdisk_offset,
        "ramdisk_end": ramdisk_end,
    }


def _rebuild_boot_with_kernel(boot_data, kernel, ramdisk=None):
    """对齐 cloud-droid-hub rebuildAndroidBootImageWithKernel：替换 kernel，可注入外部 ramdisk。

    - ramdisk 缺省时保留 boot_data 自身的内嵌 ramdisk（基底 lineage boot 自带 initrd）。
    - 传入 ramdisk 时用其替换，使 boot 分区带内嵌 initrd，
      从而让 EDK II 走 EFI-stub 直启内核（绕开 GRUB）。
    """
    if not kernel:
        raise ValueError("boot kernel 为空")
    if len(kernel) > 0xFFFFFFFF:
        raise ValueError(f"boot kernel 过大: {len(kernel)}")
    header = _parse_boot_header(boot_data)
    if ramdisk is None:
        ramdisk = boot_data[header["ramdisk_offset"]:header["ramdisk_end"]]
    new_ramdisk_offset = _align_up(header["kernel_offset"] + len(kernel), BOOT_PAGE_SIZE)
    if new_ramdisk_offset > len(boot_data) or len(ramdisk) > len(boot_data) - new_ramdisk_offset:
        raise ValueError(f"boot kernel+ramdisk 超过分区大小: "
                         f"{new_ramdisk_offset + len(ramdisk)} > {len(boot_data)}")
    rebuilt = bytearray(boot_data)
    struct.pack_into("<I", rebuilt, BOOT_KERNEL_SIZE_OFF, len(kernel))
    struct.pack_into("<I", rebuilt, BOOT_RAMDISK_SIZE_OFF, len(ramdisk))
    rebuilt[header["kernel_offset"]:header["kernel_offset"] + len(kernel)] = kernel
    # 清掉新旧位置中间的数据，再放新 ramdisk（与 cloud-droid-hub 的 make()+copy 语义一致）
    rebuilt[header["kernel_offset"] + len(kernel):] = b"\x00" * (
        len(rebuilt) - header["kernel_offset"] - len(kernel)
    )
    rebuilt[new_ramdisk_offset:new_ramdisk_offset + len(ramdisk)] = ramdisk
    return bytes(rebuilt)


def _atomic_write(path, data):
    """临时文件写入后原子替换。"""
    tmp = path + ".new.{pid}.{rand}".format(pid=os.getpid(), rand=os.urandom(4).hex())
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def _extract_ramdisk(boot_path):
    """从 Android boot 镜像解出内嵌 ramdisk 段。无内嵌 ramdisk 时返回 b''。"""
    if not os.path.isfile(boot_path):
        raise RuntimeError(f"缺少 ramdisk 源 boot 镜像: {boot_path}")
    data = open(boot_path, "rb").read()
    h = _parse_boot_header(data)
    return data[h["ramdisk_offset"]:h["ramdisk_end"]]


# —— first_stage fstab 注入（镜像 cmd/gsifix boot_firststage_fstab.go） --------

# ramdisk 内属性文件（GKI 12+ 布局），注入 ro.zygote=zygote64。
# 背景：MIUI /system 是双 zygote 布局（ro.zygote=zygote32_64/64_32），AMS
# bootCompleted 会连 /dev/socket/zygote_secondary；而底座 lineage virtio 只有
# primary zygote -> LocalSocket ENOENT -> system_server FATAL -> 68s 自杀循环
# （qemu.log: FATAL EXCEPTION IN SYSTEM PROCESS: android.display /
#  ZygoteStartFailedEx: Error connecting to zygote / attemptConnectionToSecondaryZygote）。
# 在 ramdisk 属性文件（first-stage 最先加载、ro.* 一旦设置即锁定）置 zygote64，
# 让 init 只定义 primary 64 位 zygote，AMS 不再尝试 secondary。
_RAMDISK_BUILD_PROP = "system/etc/ramdisk/build.prop"
_ZYGOTE64_LINE = b"ro.zygote=zygote64"


def _patch_zygote64_cpio_payload(name, payload):
    """命中 ramdisk build.prop 时追加/更新 ro.zygote=zygote64（文件尾追加，幂等）。"""
    if name != _RAMDISK_BUILD_PROP:
        return payload
    if b"ro.zygote=" in payload:
        return payload
    return payload.rstrip(b"\n") + b"\n" + _ZYGOTE64_LINE + b"\n"


def _rewrite_hdr_filesize(hdr, new_size):
    """重建 newc 头部：只有 filesize 字段（54:62）按新长度更新，其余原样。"""
    return hdr[:54] + _newc_hex(new_size) + hdr[62:]

def _align4(v):
    return (v + 3) & ~3


def _newc_hex(value):
    return b"%08x" % value


def _read_newc_entries(data):
    """解析 newc cpio，返回 [(name, header, name_raw, payload)] 与流。"""
    entries = []
    off = 0
    n = len(data)
    while off + 110 <= n:
        hdr = data[off:off + 110]
        if hdr[:6] not in (b"070701", b"070702"):
            raise ValueError("cpio magic 错误: %r" % hdr[:6])
        size = int(hdr[54:62], 16)
        namesize = int(hdr[94:102], 16)
        if namesize == 0:
            raise ValueError("cpio namesize 为 0")
        name_start = off + 110
        name_end = name_start + namesize
        if name_end > n:
            raise ValueError("cpio name 越界")
        name_raw = data[name_start:name_end]
        name = name_raw.rstrip(b"\x00").decode("utf-8", errors="replace")
        data_start = _align4(name_end)
        data_end = data_start + size
        payload = data[data_start:data_end]
        entries.append([name, hdr, name_raw, payload])
        off = _align4(data_end)
        if name == "TRAILER!!!":
            break
    return entries


def _patch_firststage_fstab_cpio(archive):
    """把 fstab.qcom 注入 newc ramdisk，替换缺失/已有项，返回新 cpio。

    内容取自 _FSTAB_SRC（vendor patch 树那份），与二阶段 /vendor/etc/fstab.qcom 同源。
    """
    source_for = lambda name: firststage_fstab()

    targets = {}
    for name in _FSTAB_NAMES:
        data = source_for(name)
        for path in _FSTAB_DUMP_PATHS:
            targets[path.format(name=name)] = data
    for d in _FSTAB_DIR_PATHS:
        targets.setdefault(d, None)

    entries = _read_newc_entries(archive)
    trailer = None
    body = []
    for name, hdr, name_raw, payload in entries:
        if name == "TRAILER!!!":
            trailer = (name, hdr, name_raw, payload)
            continue
        if name in targets:
            continue
        body.append((name, hdr, name_raw, payload))
    if trailer is None:
        raise ValueError("cpio 缺少 TRAILER!!!")

    existing = {e[0] for e in body}
    inode = {"v": 100000}
    added = []
    raw_out = bytearray()

    # newc 对齐是"绝对偏移 mod 4"（110 非 4 倍数），须按 raw_out 累计长度对齐，
    # 而非对 name/payload 各自独立 4 对齐（否则非/根条目错位）。
    def pad4():
        nonlocal raw_out
        n = (4 - len(raw_out) % 4) % 4
        raw_out += b"\x00" * n

    for fname, hdr, name_raw, payload in body:
        if fname == _RAMDISK_BUILD_PROP:
            payload = _patch_zygote64_cpio_payload(fname, payload)
            hdr = _rewrite_hdr_filesize(hdr, len(payload))
        raw_out += hdr + name_raw
        pad4()
        raw_out += payload
        pad4()

    def append_entry(name, mode, payload):
        nonlocal raw_out
        inode["v"] += 1
        meta = (
            b"070701"          # magic(6)
            + _newc_hex(inode["v"])   # ino
            + _newc_hex(mode)         # mode
            + _newc_hex(0)            # uid
            + _newc_hex(0)            # gid
            + _newc_hex(1)            # nlink
            + _newc_hex(0)            # mtime
            + _newc_hex(len(payload)) # filesize
            + _newc_hex(0)            # devmajor
            + _newc_hex(0)            # devminor
            + _newc_hex(0)            # rdevmajor
            + _newc_hex(0)            # rdevminor
            + _newc_hex(len(name) + 1)  # namesize
            + _newc_hex(0)            # check
        )
        raw_out += meta
        raw_out += name.encode("latin1") + b"\x00"
        pad4()
        raw_out += payload
        pad4()

    for d in _FSTAB_DIR_PATHS:
        if d in existing:
            continue
        append_entry(d, 0o040755, b"")
        added.append(d)
    for fname in _FSTAB_NAMES:
        data = source_for(fname)
        for path in _FSTAB_DUMP_PATHS:
            p = path.format(name=fname)
            append_entry(p, 0o100644, data)
            added.append(p)
    # trailer
    _, thdr, tname_raw, tpayload = trailer
    raw_out += thdr + tname_raw
    pad4()
    raw_out += tpayload
    pad4()
    return bytes(raw_out), added


def _inject_firststage_fstab_lz4(ramdisk_lz4):
    """legacy-LZ4(newc cpio) ramdisk 解压->注入 fstab->重打包 legacy-LZ4。"""
    if not shutil.which("lz4"):
        raise RuntimeError("缺少命令: lz4")
    work = tempfile.mkdtemp(prefix="cdh-boot-fstab.")
    try:
        in_lz4 = os.path.join(work, "rd.in.lz4")
        cpio = os.path.join(work, "rd.cpio")
        lz4c = os.path.join(work, "rd.out.lz4")
        with open(in_lz4, "wb") as f:
            f.write(ramdisk_lz4)
        subprocess.run(["lz4", "-d", "-f", in_lz4, cpio],
                       check=True, capture_output=True)
        archive = open(cpio, "rb").read()
        patched, added = _patch_firststage_fstab_cpio(archive)
        subprocess.run(["lz4", "-12", "-l", "-f", "-", lz4c],
                       input=patched, check=True, capture_output=True)
        return open(lz4c, "rb").read(), added
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _os_version_of(boot_path):
    """读取 Android boot 镜像（v1+）的 os_version 字段，供 EDK II 直启判定。"""
    data = open(boot_path, "rb").read()
    if len(data) < BOOT_HEADER_SIZE_OFF + 4 or data[:8] != BOOT_MAGIC:
        return 0
    return struct.unpack_from("<I", data, BOOT_OS_VERSION_OFF)[0]


def build_boot(kernel_path):
    """把 kernel Image 打包进 boot.img，输出到 out/dist/rom/boot.img。

    以 lineage-22.0 解包 boot_a.img 为基底（保留其 v4 头部/内嵌 initrd），
    kernel 替换为编译的 Image，ramdisk 注入 first_stage virtio fstab，
    os_version 保留基底值（当前能正常引导，即 EDK II 直启接受值）。
    """
    if not _file_ok(kernel_path):
        print(f"[err] 内核 Image 不存在: {kernel_path}")
        sys.exit(1)
    if not os.path.isfile(LINEAGE_BOOT_IMG):
        print(f"[err] 缺少 lineage boot.img: {LINEAGE_BOOT_IMG}")
        sys.exit(1)
    boot_data = open(LINEAGE_BOOT_IMG, "rb").read()
    if len(boot_data) > MAX_BOOT_PARTITION_BYTES:
        print(f"[err] boot.img 超过分区上限: {len(boot_data)} B")
        sys.exit(1)
    kernel = open(kernel_path, "rb").read()
    # 关键：取基底自身的内嵌 ramdisk（lineage 自带 initrd）
    ramdisk = _extract_ramdisk(LINEAGE_BOOT_IMG)
    if not ramdisk:
        print(f"[err] lineage boot.img 无内嵌 ramdisk（无法直启）：{LINEAGE_BOOT_IMG}")
        sys.exit(1)
    # —— 关键：注入 first_stage virtio fstab（挂载 super/system、vdb/data、metadata），
    # 否则 init 首阶段读不到 default fstab 直接 panic。fstab 为内联基线单盘常量。
    ramdisk, _fstab_added = _inject_firststage_fstab_lz4(ramdisk)
    print(f"[ok] first_stage fstab 已注入 ramdisk（{len(_fstab_added)} 项）")
    # —— os_version 保留基底值（当前能正常引导 = EDK II 直启接受值）
    src_os_version = _os_version_of(LINEAGE_BOOT_IMG)
    print(f"==> 基底 {LINEAGE_BOOT_IMG} (os_version=0x{src_os_version:x}, 保留)")
    header = _parse_boot_header(boot_data)
    rebuilt = _rebuild_boot_with_kernel(boot_data, kernel, ramdisk=ramdisk)
    os.makedirs(BOOT_IMG_OUT and os.path.dirname(BOOT_IMG_OUT), exist_ok=True)
    _atomic_write(BOOT_IMG_OUT, rebuilt)
    print(f"[ok] boot.img 打包完成: {BOOT_IMG_OUT}")
    print(f"    kernel_size={len(kernel)} (原 {header['kernel_size']}), "
          f"ramdisk={len(ramdisk)} B (原 {header['ramdisk_size']} B), "
          f"os_version=0x{src_os_version:x}")
    return BOOT_IMG_OUT


def main():
    parser = argparse.ArgumentParser(description="note13-5G-15 boot.img 打包")
    parser.add_argument("--kernel-image", default=None,
                        help="打包用的 Image 路径（默认 out/kernel/Image）")
    args = parser.parse_args()
    kernel = args.kernel_image or os.path.join(KERNEL_OUT, "Image")
    build_boot(kernel)
    return 0


if __name__ == "__main__":
    sys.exit(main())
