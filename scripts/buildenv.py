"""SM-S9380-16（Samsung Galaxy S25 Ultra / 高通 SM8750 / Android 16）构建环境。

各阶段脚本统一从这里读取构建选择与路径：env（CDH_*）优先，其次 build/manifest.json
推导；脚本不硬编码绝对路径。架构参考 note13-5G-15（官方 super 零改动 + patch.img(vdc)
+ 内核路径重定向），工具定位与 lineage 基座路径沿用其约定。

设备事实（与兄弟机型的差异）：
  - 官方固件是 Samsung FUS 加密服务包 `.zip.enc4`，解密 → zip → BL/AP/CP/CSC 的
    `.tar.md5` → 各 `*.img.lz4`；`super.img` 是 **sparse**（须展开 raw 才能定位 liblp）；
  - super 逻辑分区全为 **erofs**（system/vendor/product/odm/vendor_dlkm/system_ext/
    system_dlkm），slot B 全空；
  - 真机 ro.hardware=`qcom`（官方 vendor/etc/fstab.qcom + boot cmdline
    androidboot.hardware=qcom）；
  - lineage 底包取 **lineage-23.2**（Android 16 virtio_arm64only，super 逻辑分区为 ext4，
    其 vendor 提供 fstab.virtio / ueventd.rc / init / vintf）。

宿主工具解析优先级：env 直指 > brew e2fsprogs sbin / Android SDK > PATH。
"""

import glob
import json
import os
import shutil

# 宿主工具常用安装位置（macOS brew e2fsprogs / erofs-utils / Android SDK emulator）
_E2FSPROGS_SBIN = "/opt/homebrew/opt/e2fsprogs/sbin"
_EROFS_UTILS_BIN = "/opt/homebrew/opt/erofs-utils/bin"
_QEMU_CANDIDATES = (
    os.path.expanduser("~/Library/Android/sdk/emulator/qemu-img"),
    "/opt/homebrew/bin/qemu-img",
    "/usr/local/bin/qemu-img",
)


def env(name, default=""):
    """读取环境变量，未设置或为空时回退 default。"""
    return os.environ.get(name) or default


def _tool(name):
    """定位 e2fsprogs 工具；env 覆盖 > brew sbin > PATH，缺失时抛异常。"""
    cand = os.environ.get("E2FSPROGS_" + name.upper())
    if cand and os.path.isfile(cand):
        return cand
    brew = os.path.join(_E2FSPROGS_SBIN, name)
    if os.path.isfile(brew):
        return brew
    found = shutil.which(name)
    if found:
        return found
    raise FileNotFoundError(
        f"缺少 e2fsprogs 工具: {name}（brew install e2fsprogs）")


def e2fs_tools():
    """返回 (debugfs, e2fsck, resize2fs) 绝对路径元组。"""
    return _tool("debugfs"), _tool("e2fsck"), _tool("resize2fs")


def erofs_tool(name):
    """定位 erofs-utils 工具（fsck.erofs / dump.erofs / mkfs.erofs）。"""
    brew = os.path.join(_EROFS_UTILS_BIN, name)
    if os.path.isfile(brew):
        return brew
    found = shutil.which(name)
    if found:
        return found
    raise FileNotFoundError(
        f"缺少 erofs-utils 工具: {name}（brew install erofs-utils）")


def lz4_tool():
    """定位 lz4 命令（vendor_boot fragment 编解码）。"""
    found = shutil.which("lz4")
    if found:
        return found
    raise FileNotFoundError("缺少 lz4（brew install lz4）")


def _qemu_img():
    """定位 qemu-img（QEMU_IMG 环境变量优先，其次常见安装位置，最后 PATH）。"""
    cand = os.environ.get("QEMU_IMG")
    if cand and os.path.isfile(cand):
        return cand
    for p in _QEMU_CANDIDATES:
        if os.path.isfile(p):
            return p
    found = shutil.which("qemu-img")
    if found:
        return found
    raise FileNotFoundError("缺少 qemu-img（可用 QEMU_IMG 环境变量指定）")


# =====================================================================
# 设备事实与路径（单一数据源，env 优先，其次 manifest.json 推导）
# =====================================================================

# 本文件位于 <设备>/build/scripts/ 下：向上 3 级为设备根，再向上 3 级为项目根
_DEV_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(_DEV_ROOT)))

BUILD_DIR = os.path.join(_DEV_ROOT, "build")
ROMS_DIR = os.path.join(_DEV_ROOT, "roms")          # 官方固件输入（非源码）
OUT_DIR = os.path.join(_DEV_ROOT, "out")            # 设备编译产物
BASELINES_DIR = os.path.join(BUILD_DIR, "baselines")


def _manifest():
    """读取 build/manifest.json（固件/构建声明），缺失或解析失败返回 {}。"""
    try:
        with open(os.path.join(BUILD_DIR, "manifest.json"), encoding="utf-8") as f:
            return json.load(f) or {}
    except (OSError, ValueError):
        return {}


def _manifest_build():
    builds = (_manifest().get("build") or [])
    return builds[0] if builds else {}


_MB = _manifest_build()

# ---- 构建选择：CDH_BUILD_ID 优先，其次 manifest.json 首个 build ----
BUILD_ID = env("CDH_BUILD_ID", _MB.get("build-id") or "")

# Android 版本（主/主.次，取自 manifest build 的 android-version，如 16.0.0）
_ANDROID_VERSION = _MB.get("android-version") or ""
OS = _ANDROID_VERSION.split(".")[0] if _ANDROID_VERSION else "16"
_ANDROID_MINOR = ".".join(_ANDROID_VERSION.split(".")[:2]) if _ANDROID_VERSION else "16.0"

# 固件版本号（s9380zcsdczh1，取自 manifest build 的 version；CDH_VERSION 可覆盖）
VERSION = env("CDH_VERSION", _MB.get("version") or "")

# 版本目录：out/device/sm-s9380-16/16/<版本小写>（daemon 运行盘集）
VERSION_DIR = os.path.join(PROJECT_ROOT, "out", "device",
                           os.path.basename(_DEV_ROOT), OS, VERSION.lower())


def baselines_file():
    """定位 build/baselines/<build-id>.json；无法确定时返回 None（不虚构）。"""
    p = os.environ.get("CDH_BASELINES_JSON")
    if p:
        return p if os.path.isfile(p) else None
    build_id = os.environ.get("CDH_BUILD_ID")
    if build_id:
        p = os.path.join(BASELINES_DIR, f"{build_id}.json")
        return p if os.path.isfile(p) else None
    entries = sorted(glob.glob(os.path.join(BASELINES_DIR, "*.json")))
    return entries[0] if len(entries) == 1 else None


def load_baselines():
    """读取基线清单 JSON；文件缺失或解析失败时返回 None。"""
    p = baselines_file()
    if not p:
        return None
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


# ---- 官方固件输入 ----
ENC4 = env("CDH_FACTORY_ENC4",
           os.path.join(ROMS_DIR, _MB.get("factory-enc4") or ""))
FACTORY_ZIP = env("CDH_FACTORY_ZIP",
                  os.path.join(ROMS_DIR, _MB.get("factory-zip") or ""))
# 平铺镜像目录（unpack 产物：官方各分区 *.img，含 super.img 展开后的 raw）
ROM_ROOT_DIR = env("CDH_FACTORY_DIR",
                   os.path.join(ROMS_DIR, _MB.get("factory-dir") or ""))
SUPER_IMG = os.path.join(ROM_ROOT_DIR, "super.img")     # 已展开为 raw 的官方 super
# 官方 super 逻辑分区拆解结果（本流水线 unpack 平铺于 factory-dir 根，故 = ROM_ROOT_DIR）
SUPER_OUT = ROM_ROOT_DIR

# ---- lineage 底包（UTM 虚机，vda -> GPT 分区；Android 16 = lineage-23.2）----
LINEAGE_ZIP = env("CDH_LINEAGE_ZIP", "")
if not LINEAGE_ZIP and _MB.get("lineage-zip"):
    _cand = os.path.join(PROJECT_ROOT, "lineage-rom", _MB["lineage-zip"])
    if os.path.isfile(_cand):
        LINEAGE_ZIP = _cand
LINEAGE_VDA_MEMBER = "LineageOS_on_arm64.utm/Data/vda.img"  # lineage-23.2 起为 raw
LINEAGE_OUT_DIR = env("CDH_LINEAGE_DIR",
                      os.path.join(PROJECT_ROOT, "lineage-rom",
                                   _MB.get("lineage-dir") or "lineage-23"))
# lineage 底包 super 逻辑分区（ext4；vendor/vendor_dlkm/odm 基座）
LINEAGE_SUPER_DIR = os.path.join(LINEAGE_OUT_DIR, "super")

# ---- 输出布局 ----
DIST_DIR = os.path.join(OUT_DIR, "dist")
ROM_DIST = os.path.join(DIST_DIR, "rom")        # 分发镜像（boot/vendor/super/...）
TMP_DIR = os.path.join(OUT_DIR, "tmp")          # 调试临时（不用 /tmp）
KERNEL_OUT = os.path.join(OUT_DIR, "kernel")    # 内核编译产物（Image/modules/config）
KERNEL_MODULES_DIR = os.path.join(DIST_DIR, "kernel", "modules")  # 模块归集
KERNEL_SRC = os.path.join(_DEV_ROOT, "kernel", "source")          # 内核源码

# ---- vendor patch 注入树（note13 式：debugfs 注入的第二棵树）----
VENDOR_PATCH_DIR = os.path.join(BUILD_DIR, "vendor", "patch")
VENDOR_STAGE_DIR = os.path.join(DIST_DIR, "vendor")

# ---- 分发/最终产物 ----
VENDOR_DIST = os.path.join(ROM_DIST, "vendor.img")
VENDOR_DLKM_DIST = os.path.join(ROM_DIST, "vendor_dlkm.img")
SUPER_DIST = os.path.join(ROM_DIST, "super.img")
BOOT_DIST = os.path.join(ROM_DIST, "boot.img")
VENDOR_BOOT_DIST = os.path.join(ROM_DIST, "vendor_boot.img")
PATCH_DIST = os.path.join(ROM_DIST, "patch.img")     # vdc 载入的 lineage vendor 打包镜像
VERSION_VDA = os.path.join(VERSION_DIR, "vda.img")
VERSION_DATA = os.path.join(VERSION_DIR, "data.qcow2")

# ---- 构建阶段（与 build/main.py 的阶段名保持一致）----
STAGES = ["unpack", "kernel", "boot", "vendor_boot",
          "vendor", "vendor_dlkm", "patch", "super", "pack"]