"""popsicle-16 vendor sepolicy：向 /etc/selinux/vendor_sepolicy.cil 追加最小 CDH 声明。

内容（本盘精简版，机制对齐 note13-5G-15）：
  1. pioneer 段：guest 值守域（daemon 及其自研 adbd 的 shell/sync 子进程以
     seclabel u:r:pioneer:s0 运行，user/group root 且不降权）。该域需要完全 root
     语义：凡是它作为主体的判定都要放行，逐条 allow 枚举既写不全也易碎（vendor
     CIL 追加段还存在互相覆盖丢失的历史事故）。
  2. coredomain 属性区直读段（引导修复，承自 note13 实测）。
  3. 官方 gold vendor 属性类型段（gold_props.prop_types_cil，/dev/__properties__
     类型命名空间对齐真机）。
  4. 官方 gold vendor「plat 域 → plat 类型」授权重放段（gold_grant_cil）：三星把
     system_server 等平台域对平台属性/文件/服务的授权写在 vendor 策略里，lineage
     基座没有这段，实测会让 SystemProperties.set 被拒并拖死 system_server。

HAL 专属段（audio/radio/sensors/camera/.../chipinfo）不在本盘：各 HAL 在 bring-up
时经 hal_cil_chain 的同一机制追加（保持扩展点）。

pioneer 的 permissive 由**内核**承担（本盘 init 内嵌 secilc 不支持 CIL `permissive`
语句，Unknown keyword → init fatal）：
  * 内核补丁：kernel/source/security/selinux/ss/services.c (cdh_mark_pioneer_permissive)
  * 内核配置：kernel/build/lineage-kernel.config
    CONFIG_CDH_PIONEER_PERMISSIVE 在 security_load_policy() 解析完策略、发布前把
    pioneer 写进 policydb->permissive_map，等价于策略文件里的 "permissive pioneer"，
    且免疫策略追加段覆盖。

因此 pioneer 段只需保留 permissive **覆盖不到** 的两类规则，加上结构性类型声明：
  1. 启动链：源域是 init（换域 execve 的前置 process transition / file execute），
     permissive 只看源上下文 type，init 不是 pioneer，覆盖不到；
  2. 反向授权：源域是对端域、目标才是 pioneer（netd fwmark / system_server 管道 /
     媒体域 binder 回程），这些判定同样不因 pioneer 是 permissive 而放行；
  3. 类型/属性声明本身：init 的 `seclabel u:r:pioneer:s0` 若解析不到该类型会直接
     Invalid argument，故 (type pioneer)/(type pioneer_exec) 及其
     domain/exec_type/file_type/vendor_file_type 归属必须始终存在。

两条 vendor cil 约束（均实测自基座 vendor_sepolicy.cil）：
  * plat 类型在 vendor cil 中必须以「版本化影子名」引用（如 init_{vers} /
    shell_exec_{vers}），版本号运行时读 /etc/selinux/plat_sepolicy_vers.txt，不得
    硬编码。vendor 自有类型（如 mediacodec）未版本化，直接引用原名；
  * 属性（domain/exec_type/file_type/vendor_file_type）以原名关联，追加单成员
    typeattributeset 与基座的大集合语句按 union 语义合并。

entrypoint 永远只落 exec_type（plat 约束 neverallow domain ~exec_type:file entrypoint），
故 pioneer_exec / shell_exec_{vers} 仅授 entrypoint。

平台策略源 = **官方（Xiaomi）plat_sepolicy.cil**（CDH 架构 guest 平台 = 官方 super
零改动直拷，运行时 init 内嵌 secilc 以官方 plat 声明 class/权限；与 note13 的 AOSP 15
基线不同，AOSP 16 各家内核 classmap 已分叉，「各家一致」假设不成立）。构建期据此
做两件事：
  1. sanitize_vendor_cil：清理 lineage vendor 策略里官方类表没有的权限语句（实测
     netlink_route_socket 裸 nlmsg ×1 + nlmsg allowx ×2、system firmware_load ×1 ——
     目标内核 6.12.23 classmap 同样没有这些权限，内核永远不会对其判定，剔除/裁剪
     语义等价），否则开机 secilc "Failed to resolve permission" → InitFatalReboot；
  2. validate_cil 的 class/权限/名字全集改用官方 plat（名集 = 官方 plat +
     plat_pub_versioned.cil + vendor 基座 cil 声明全集，精确名匹配），片段内自声明
     的类型（pioneer/pioneer_exec 及 gold 属性类型）跳过；引用错名不再等到开机
     secilc 失败才发现。
"""

import os
import re
import shutil
import subprocess
import sys

from buildenv import SUPER_OUT, TMP_DIR, erofs_tool
from debugfs import cat
import gold_files
import gold_props

SELINUX_DIR = "/etc/selinux"
VERS_FILE = SELINUX_DIR + "/plat_sepolicy_vers.txt"
POLICY_FILE = SELINUX_DIR + "/vendor_sepolicy.cil"
PUB_VER_FILE = SELINUX_DIR + "/plat_pub_versioned.cil"
# 基座内该文件的原始标签（rm+write 新 inode 后须回填，debugfs write 不带 xattr）
POLICY_LABEL = "u:object_r:vendor_configs_file:s0"
MARKER = ";; cdh popsicle-16: pioneer"
# ---- coredomain 直读 vendor_default_prop（引导修复段，见 coredomain_vendor_prop_read_cil）----
VENDOR_PROP_READ_MARKER = ";; cdh popsicle-16: coredomain-vendor-prop-read"

# ---- HAL 段（自研虚拟 HAL；扩展点见 hal_cil_chain）----
# vibrator：lineage 基座无 vibrator HAL —— 官方 odm 声明 android.hardware.vibrator@2
# （IVibrator/default），而 lineage vendor 既无该服务进程、vendor_service_contexts
# 也无表项 → SystemServer 构造 VibratorManagerService 时 nativeGetVibratorIds() 阻塞
# （等不到 HAL 服务），主线程卡 65s 被 Watchdog 杀，boot_completed 永不置位
# （实测栈：VibratorManagerService.<init> → nativeGetVibratorIds）。
# 自研虚拟 HAL（build/vendor/source/android.hardware.vibrator）接管
# IVibrator/default 与 IVibratorManager/default。
VIBRATOR_MARKER = ";; cdh popsicle-16: vibrator-hal"
VSC = "/etc/selinux/vendor_service_contexts"
VSC_LABEL = "u:object_r:vendor_service_contexts_file:s0"
VIBRATOR_VSC_LINES = [
    "android.hardware.vibrator.IVibrator         u:object_r:hal_vibrator_service:s0",
    "android.hardware.vibrator.IVibratorManager  u:object_r:hal_vibrator_service:s0",
]

# IR（红外）：官方 /odm 声明 FEATURE_CONSUMER_IR，而 lineage vendor 无 IR 服务 →
# SystemServer 的 ConsumerIrService 抛
# "RuntimeException: FEATURE_CONSUMER_IR present, but no IR HAL loaded!" 启动即死。
# 已收编官方 vendor 的 android.hardware.ir-service.example
# （build/vendor/source/android.hardware.ir），故补服务名映射与 add/find 授权。
IR_MARKER = ";; cdh popsicle-16: ir-hal"
IR_VSC_LINES = [
    "android.hardware.ir.IConsumerIr             u:object_r:hal_ir_service:s0",
]

# FRP 承载块设备：MIUI 16 pdb 按 ro.frp.pst 打开 FRP 分区，本盘把它软链到未使用的
# misc(vda3)（见 build/vendor/patch/etc/init/cph_frp_symlink.rc）。平台策略只给
# system_server 授了 frp_block_device，而该节点的类型是 misc_block_device：
# DAC 已由 ueventd 规则放开（0660 root:system），SELinux 侧此处补 allow（策略里带
# dontaudit，故日志无 AVC，表现为 open EACCES）。
FRP_MARKER = ";; cdh popsicle-16: frp-block-device"
FRP_BLK_PERMS = ["open", "read", "write", "ioctl", "getattr", "map", "lock",
                 "append"]

# QTI perf2 HAL：官方 system 的 compatibility_matrix.device.xml 将其列为必需 HAL，
# 而 lineage 基座既无该服务、也无任何 perf 策略类型 → 已收编官方 HAL
# （build/vendor/source/vendor.qti.hardware.perf2），其策略段（vendor_hal_perf* 类型/域/
# allow）从官方 vendor_sepolicy.cil 逐行移植（同为 plat 版本后缀 _202504，可直接对齐）。
PERF_MARKER = ";; cdh popsicle-16: perf2-hal"
PERF_VSC_LINES = [
    "vendor.qti.hardware.perf2.IPerf/default      u:object_r:vendor_hal_perf2_service:s0",
]

# SEH KeyMint 扩展：三星 system 侧 keystore2（get_rot_value，globals.rs:633）在启动时
# 强制 find 服务名 vendor.samsung.hardware.keymint.ISehKeyMintExtension（**裸名，无
# /default**，servicemanager 日志实测）；拿不到即 panic
#   "SehKeyMintExtension must be present" → keystore2 SIGABRT 反复重启 →
#   IKeystoreService/default 缺席 → vold FBE/keyguard 卡死 → 重启循环（实测 instance 28）。
# 自研纯软件 ISehKeyMintExtension（build/vendor/source/vendor.samsung.hardware.
# sehkeymint，pioneer 域）注册该裸名；官方 gold vendor_service_contexts 把裸名与
# /default 都映射为 hal_keymint_service，故照此登记。find 授权无需新增 CIL：官方 plat
# 已有 allow hal_keymint_client hal_keymint_service (service_manager (find))，且
# keystore ∈ hal_keymint_client；add 由 pioneer permissive 覆盖。
SEH_KEYMINT_VSC_LINES = [
    "vendor.samsung.hardware.keymint.ISehKeyMintExtension         u:object_r:hal_keymint_service:s0",
    "vendor.samsung.hardware.keymint.ISehKeyMintExtension/default u:object_r:hal_keymint_service:s0",
]

# 运行态平台策略源：官方（Xiaomi）system 分区（unpack 自官方 super 拆出；与 guest
# 运行时一致——super 零改动直拷）。宿主 dump.erofs 读官方 system 报
# "invalid de[0].nameoff"（实测 2026-10-09），改用 fsck.erofs --extract --path
# 提取（与 build-patch 读官方 odm 的 erofs 工具链同一来源）。
OFFICIAL_PLAT_IMG = os.path.join(SUPER_OUT, "system_a.img")
OFFICIAL_PLAT_XDIR = os.path.join(TMP_DIR, "vendor", "official_plat")

# ---- 服务 execv 前置检查权限集（init_{vers} -> pioneer_exec:file）----
_INIT_EXEC_P = "ioctl read open execute getattr map".split()


def _allow(target, ttype, cls, perms):
    """渲染一条 allow；权限 set 化去重排序（输出稳定、天然无重复权限）。"""
    body = " ".join(sorted(set(perms)))
    return f"(allow {target} {ttype} ({cls} ({body})))\n"


def pioneer_cil(vers: str) -> str:
    """生成 pioneer 追加段（vers = plat 策略版本后缀，如 202504）。

    内核已把 pioneer 类型置入 permissive_map（内核开关 CONFIG_CDH_PIONEER_PERMISSIVE），
    凡以 pioneer 为主体的 AVC 判定一律放行，故本段只保留 permissive **覆盖不到** 的
    两类规则：
      1. 启动链：源域是 init（换域 exec 的前置 process transition / file execute）；
      2. 反向授权：源域是对端域、目标才是 pioneer（netd / system_server / 媒体域），
         这些判定不因 pioneer 是 permissive 而放行。
    另有两条 pioneer -> {pioneer_exec,shell_exec}:file entrypoint 属结构性声明，内核侧
    已覆盖，保留以保证「内核开关关掉时仍能起服务」。
    """
    stmts = [
        "(type pioneer)\n",
        "(type pioneer_exec)\n",
        "(typeattributeset domain (pioneer))\n",
        "(typeattributeset exec_type (pioneer_exec))\n",
        "(typeattributeset file_type (pioneer_exec))\n",
        "(typeattributeset vendor_file_type (pioneer_exec))\n",
        # ---- 启动链：源域 init，permissive 覆盖不到 ----
        # init 换域拉起 pioneer 服务（noatsecure/siginh/rlimitinh 消 transition 噪音）
        _allow(f"init_{vers}", "pioneer", "process",
               "transition noatsecure siginh rlimitinh".split()),
        _allow(f"init_{vers}", "pioneer_exec", "file", _INIT_EXEC_P),
        # ---- 结构性 entrypoint（内核侧已覆盖，保留兜底）----
        _allow("pioneer", "pioneer_exec", "file", ["entrypoint"]),
        _allow("pioneer", f"shell_exec_{vers}", "file", ["entrypoint"]),
        # ---- 反向授权：源域为对端域，permissive 覆盖不到 ----
        # fwmarkd（netd 域）经 SCM_RIGHTS 持有 pioneer 的 socket fd 写 fwmark：
        # 缺 use 时 connect 在 fwmark 客户端路径被拒（avc denied { use }
        # scontext=netd tcontext=pioneer tclass=fd，note13 实测）。
        _allow(f"netd_{vers}", "pioneer", "fd", ["use"]),
        # netd InetDiag（destroySockets）要读写 pioneer 的 socket 才能完成销毁，
        # 否则每 0.5s 刷 avc denied（note13 实测）；udp 同理预留。
        # setopt：fwmarkd（binder 线程）给 connect 路径上 pioneer 的 socket 打
        # SO_MARK，缺它 connect 直接 EACCES（note13 实测，2117 次 avc 全是它）
        _allow(f"netd_{vers}", "pioneer", "tcp_socket",
               ["getattr", "getopt", "setattr", "setopt", "read", "write"]),
        _allow(f"netd_{vers}", "pioneer", "udp_socket", ["getattr", "getopt", "setattr", "read", "write"]),
        # 投屏媒体链路反向授权（note13 实测）: binder 回程（reply 携带 binder
        # 对象 / 服务回调）由对端域发起 transfer/call。缺 mediaswcodec_{vers} →
        # pioneer:binder transfer 时 Codec2 AIDL "software" 取 IConfigurable 的
        # transaction 直接 FAILED_TRANSACTION，CHECK abort（且被 vendor dontaudit
        # 吞掉 avc，logcat 无痕迹）。
        # mediacodec 是 vendor 自有类型（lineage vendor cil 未版本化声明）；
        # mediaswcodec 是 plat 公共类型（版本化影子），swcodec 软编解码进程二选一
        # 实跑，两个域都授。
        *(_allow(src, "pioneer", cls, perms)
          for src in ("mediacodec", f"mediaswcodec_{vers}",
                      f"mediaextractor_{vers}", f"mediaserver_{vers}",
                      f"audioserver_{vers}", f"cameraserver_{vers}",
                      f"surfaceflinger_{vers}", f"system_server_{vers}",
                      f"servicemanager_{vers}", f"hwservicemanager_{vers}")
          for cls, perms in (("binder", ["transfer", "call"]),
                             ("fd", ["use"]))),
        # 三星 keystore2（plat coredomain `keystore` 域）取 SEH KeyMint 扩展：
        # connect_skeymint_extension 先用 servicemanager find 拿到我们 pioneer 域裸名
        # 服务的 binder 句柄（VSC 把该名列成 hal_keymint_service，keystore∈hal_keymint_client
        # → find 放行，实测 `service check` found），再 AIBinder_associateClass → BpBinder
        # 对目标发 INTERFACE_TRANSACTION 取接口描述符（frameworks/native/libs/binder/
        # BpBinder.cpp:162）。缺 keystore→pioneer:binder call 时该事务被内核拒
        # （BR_FAILED_REPLY / -1 EPERM，同上面媒体回程，被 vendor dontaudit 吞掉 avc、
        # logcat 无痕迹），mDescriptorCache 留空 → descriptor 回 '' → associateClass
        # "descriptor is actually ''" → get_keymint_extension 返回 None → keystore2
        # panic「SehKeyMintExtension must be present」(globals.rs:633) → 崩溃循环、
        # keyguard/Bouncer 卡死（黑屏）。pioneer 非 hal 属性域，只能按源域反向授权；
        # 实测旁证：shell 域能取到本服务描述符（`service list` 正确显示），证明服务本身
        # 正常应答 INTERFACE_TRANSACTION，缺的正是 keystore 这条 binder 授权。
        _allow(f"keystore_{vers}", "pioneer", "binder", ["transfer", "call"]),
        # 自研 adbd 的 shell/sync 服务子进程继承 pioneer 域（daemon 是 root 常驻服务，
        # 子进程不降权）。system_server 需把命令输出写回子进程的 stdio 管道
        # （fifo_file）、并读写它的 socketpair（unix_stream_socket），缺任一条时
        # `dumpsys`/`settings`/`pm` 一律 FAILED_TRANSACTION（note13 实测 avc：
        # comm="dumpsys" tclass=fifo_file denied { write }；
        # comm="cmd" tclass=unix_stream_socket denied { read write }）。
        _allow(f"system_server_{vers}", "pioneer", "fifo_file",
               ["read", "write", "getattr", "ioctl"]),
        _allow(f"system_server_{vers}", "pioneer", "unix_stream_socket",
               ["read", "write", "getattr", "ioctl", "getopt", "setopt", "shutdown"]),
    ]
    return f"{MARKER}: pioneer minimal declaration (kernel permissive).\n" + "".join(stmts)


_RE_CLASS = re.compile(r"\(class\s+(\S+)\s+\(([^)]*)\)\)")
_RE_COMMON = re.compile(r"\(common\s+(\S+)\s+\(([^)]*)\)\)")
_RE_CLASSCOMMON = re.compile(r"\(classcommon\s+(\S+)\s+(\S+)\)")
_RE_ALLOW = re.compile(r"\(allow\s+(\S+)\s+(\S+)\s+\((\S+)\s+\(([^)]*)\)\)\)")
_RE_TYPE = re.compile(r"\(type\s+(\S+)\)")
_RE_TYPEATTR = re.compile(r"\(typeattribute\s+(\S+)\)")
# allow 家族（同一权限语法）：用于平台兼容清理整行解析
_RE_ALLOW_FAMILY = re.compile(
    r"\((allow|dontaudit|auditallow|neverallow)\s+(\S+)\s+(\S+)\s+\((\S+)\s+\(([^)]*)\)\)\)")
# allowx：权限值可含嵌套括号（(range 0x… 0x…)），贪婪匹配到行尾
_RE_ALLOWX_FULL = re.compile(
    r"\(allowx\s+(\S+)\s+(\S+)\s+\((\S+)\s+(\S+)\s+\((.+)\)\)\)\s*$")
# 内核支持的 xperm 家族（CIL allowx 的 op 名）：6.12.23 avtab.h 仅
# AVTAB_XPERMS_IOCTLFUNCTION/IOCTLDRIVER；nlmsg（netlink 消息类型过滤）是更新
# 内核线特性，本盘内核没有。
KERNEL_XPERM_OPS = {"ioctl"}

_decl_cache = None
_name_cache = None


def _official_plat_text() -> str:
    """提取官方 plat_sepolicy.cil 文本（EROFS system 分区的 /etc/selinux）。

    fsck.erofs --extract --path 每次全量重提（~5MB，亚秒级），避免缓存陈旧；
    提取失败即报错退出（校验数据不允许静默降级）。两个实测坑（2026-10-09）：
      * 目标目录必须不存在（fsck.erofs 自建该目录，预先存在会静默不产出）；
      * path 必须用 system-as-root 的真实路径 /system/etc/selinux —— 镜像内
        /etc 是符号链接，fsck.erofs 沿链接查找会报 "invalid de[0].nameoff /
        failed to lookup"，提取不到。
    """
    if not os.path.isfile(OFFICIAL_PLAT_IMG):
        print(f"[err] 官方 system_a.img 缺失: {OFFICIAL_PLAT_IMG}（先 unpack）")
        sys.exit(1)
    shutil.rmtree(OFFICIAL_PLAT_XDIR, ignore_errors=True)
    parent = os.path.dirname(OFFICIAL_PLAT_XDIR)
    os.makedirs(parent, exist_ok=True)
    res = subprocess.run(
        [erofs_tool("fsck.erofs"), f"--extract={OFFICIAL_PLAT_XDIR}",
         "--path=/system/etc/selinux", OFFICIAL_PLAT_IMG],
        capture_output=True, text=True)
    cil = os.path.join(OFFICIAL_PLAT_XDIR, "plat_sepolicy.cil")
    if res.returncode != 0 or not os.path.isfile(cil):
        print(f"[err] 官方 plat 提取失败: {res.stdout.strip()} {res.stderr.strip()}")
        sys.exit(1)
    with open(cil, encoding="utf-8", errors="replace") as f:
        return f.read()


def plat_class_perms() -> dict:
    """解析官方 plat_sepolicy.cil 的 (class)/(common)/(classcommon) 声明，
    返回 {class: 合法权限集}；读不到即报错退出（校验数据不允许静默降级）。"""
    global _decl_cache
    if _decl_cache is not None:
        return _decl_cache
    blob = _official_plat_text()
    classes, commons, links = {}, {}, {}
    for raw in blob.splitlines():
        s = raw.strip()
        m = _RE_CLASS.match(s)
        if m:
            classes[m[1]] = set(m[2].split())
            continue
        m = _RE_COMMON.match(s)
        if m:
            commons[m[1]] = set(m[2].split())
            continue
        m = _RE_CLASSCOMMON.match(s)
        if m:
            links[m[1]] = m[2]
    _decl_cache = {c: own | commons.get(links.get(c), set())
                   for c, own in classes.items()}
    return _decl_cache


def _read_cil(img, path) -> str:
    blob = cat(img, path)
    if not blob:
        print(f"[err] 读不到策略声明: {path} @ {img}")
        sys.exit(1)
    return blob.decode("utf-8", "replace")


def _cil_names(text: str) -> set:
    """(type X) / (typeattribute X) 声明名集合。
    正则不误伤: (typetransition/typeattributeset 无 type 后空白，不匹配)。"""
    return {m[1] for m in _RE_TYPE.finditer(text)} | \
           {m[1] for m in _RE_TYPEATTR.finditer(text)}


def plat_name_set() -> set:
    """官方 plat cil 的 type/typeattribute 名全集。版本化影子的 typeattribute 声明
    在 plat_pub_versioned.cil（vendor 侧文件），由调用方经 _cil_names 解析后并入。"""
    global _name_cache
    if _name_cache is None:
        _name_cache = _cil_names(_official_plat_text())
    return _name_cache


# 类型名可含连字符（gold 属性类型，如 vendor_ctl_port-bridge_prop）：字符集漏掉
# '-' 会把片段内自声明的连字符类型当未知名字误报。
_TYPE_DECL_RE = re.compile(r"^\(type\s+([a-z0-9_\- ]+?)\s*\)\s*$", re.M)


def _declared_types(cil: str) -> set:
    """收集 CIL 片段里 (type X) 自声明的类型名。

    这些类型随本片段一起写进 vendor_sepolicy.cil，编译期必定存在，故 validate_cil
    对它们跳过「名字全集」存在性检查（此前用硬编码白名单，新增类型会误报）。
    """
    names = set()
    for group in _TYPE_DECL_RE.findall(cil):
        names.update(group.split())
    return names


def sanitize_vendor_cil(text: str, table: dict) -> str:
    """按官方 plat 类表清理 vendor CIL（运行态平台兼容，构建期一次完成）。

    背景：运行态 init 内嵌 secilc 以**官方 plat 策略**声明 class/权限，而 lineage
    vendor 策略是随更新内核线（6.12.81-line）生成的，含官方类表没有的权限；任何一条
    解析失败即 secilc 报 "Failed to resolve permission" → InitFatalReboot。本盘内核
    6.12.23 classmap 同样没有这些权限（nlmsg 于 netlink_route_socket、firmware_load
    于 system），内核永远不会对其判定，剔除/裁剪语义等价。

    规则：
      * allow 家族（allow/dontaudit/auditallow/neverallow）：class 不在官方类表 →
        整条删除；部分权限不在（`-perm` 否定式不参与判定）→ 仅剔除缺失权限，全缺则
        整条删除；
      * allowx：op 不在内核 xperm 家族（KERNEL_XPERM_OPS，nlmsg 即此类）或 class
        未知 → 整条删除；
      * 无法整行解析的语句原样保留（不做过删）。

    输出与输入行序一致，未改动行逐字节保留。
    """
    out, dropped, pruned = [], [], []
    for ln in text.splitlines(keepends=True):
        s = ln.strip()
        if s.startswith(("(allow ", "(dontaudit ", "(auditallow ", "(neverallow ")):
            m = _RE_ALLOW_FAMILY.fullmatch(s)
            if m is None:
                out.append(ln)
                continue
            kind, src, tgt, cls, perm_s = m.groups()
            perms = perm_s.split()
            if cls not in table:
                dropped.append(f"{kind} {src} {tgt} (class {cls} 未知)")
                continue
            miss = [p for p in perms if not p.startswith("-") and p not in table[cls]]
            if not miss:
                out.append(ln)
                continue
            keep = [p for p in perms if p.startswith("-") or p in table[cls]]
            if not keep:
                dropped.append(f"{kind} {src} {tgt} ({cls}: {' '.join(miss)})")
                continue
            pruned.append(f"{kind} {src} {tgt} ({cls}: {' '.join(miss)})")
            eol = ln[len(ln.rstrip("\r\n")):]
            out.append(f"({kind} {src} {tgt} ({cls} ({' '.join(keep)})))" + eol)
            continue
        if s.startswith("(allowx "):
            m = _RE_ALLOWX_FULL.fullmatch(s)
            if m is None:
                out.append(ln)
                continue
            src, tgt, op, cls, _vals = m.groups()
            if op not in KERNEL_XPERM_OPS or cls not in table:
                dropped.append(f"allowx {src} {tgt} (op {op} class {cls})")
                continue
            out.append(ln)
            continue
        out.append(ln)
    for d in dropped:
        print(f"[..] 平台兼容剔除: {d}")
    for p in pruned:
        print(f"[..] 平台兼容裁剪: {p}")
    if dropped or pruned:
        print(f"[ok] vendor CIL 平台兼容清理：剔除 {len(dropped)} 条、"
              f"裁剪 {len(pruned)} 条（官方 plat 类表）")
    else:
        print("[ok] vendor CIL 平台兼容检查通过（无语句需清理）")
    return "".join(out)


def validate_cil(cil: str, name_universe: set) -> None:
    """逐条 allow 校验: class/perm 合法性（按平台声明）、源/目标名存在性
    （name_universe = plat cil + plat_pub_versioned.cil + vendor 基座 cil 的
    声明全集，精确名匹配）与冗余（完全重复语句、同一 (src,tgt,class) 拆分授权）。
    违规即报错退出。"""
    valid = plat_class_perms()
    names = plat_name_set() | set(name_universe)
    # 本段自有类型/标签（片段内 (type X) 声明，如 pioneer/gold 属性类型）
    # + CIL 关键字目标，不做存在性检查
    skip = {"self"} | _declared_types(cil)
    seen_stmt, seen_pair, errs, n = set(), set(), [], 0
    for ln in cil.splitlines():
        s = ln.strip()
        if not s.startswith("(allow "):
            continue
        n += 1
        m = _RE_ALLOW.fullmatch(s)
        if not m:
            errs.append(f"语句格式不可解析: {s}")
            continue
        src, tgt, cls, perms = m[1], m[2], m[3], m[4].split()
        if s in seen_stmt:
            errs.append(f"重复语句: {s}")
            continue
        seen_stmt.add(s)
        if cls not in valid:
            errs.append(f"未知 class {cls}: {s}")
            continue
        bad = sorted(set(perms) - valid[cls])
        if bad:
            errs.append(f"非法权限 {cls}:{bad} -> {tgt}")
        for name in (src, tgt):
            if name in skip or name in names:
                continue
            errs.append(f"未知 type/attribute {name}: {s}")
        key = (src, tgt, cls)
        if key in seen_pair:
            errs.append(f"拆分冗余授权 ({src} {tgt} {cls}): {s}")
        seen_pair.add(key)
    if errs:
        for e in errs:
            print(f"[err] sepolicy 校验: {e}")
        sys.exit(1)
    print(f"[ok] CIL 校验通过（{n} 条 allow，平台 {len(valid)} class、"
          f"{len(names)} type/attr 声明）")


# ---- vold netlink（Samsung 引导修复段）----
VOLO_NETLINK_MARKER = ";; cdh sm-s9380-16: vold-netlink-socket"


def vold_netlink_cil(vers: str) -> str:
    """vold 自建 netlink socket 授权（Samsung 实测引导修复段）。

    实测 qemu.log：`avc: denied { create } ... scontext=u:r:vold:s0 tcontext=u:r:vold:s0
    tclass=netlink_socket permissive=0` 持续刷屏 → vold `Socket created with fd:-1` →
    `Exiting(13)` 循环 → zygote 拿不到 vold，被 SIGKILL，boot 永不完成。
    授权 vold 自建 netlink socket。
    """
    return (
        f"{VOLO_NETLINK_MARKER}\n"
        + _allow(f"vold_{vers}", "self", "netlink_socket", ["create"])
    )


# ---- init 创建 /dev/socket 套接字文件（Samsung 引导修复段，见 init_socket_device_cil）----
INIT_SOCKET_DEVICE_MARKER = ";; cdh sm-s9380-16: init-socket-device-create"


def init_socket_device_cil(vers: str) -> str:
    """init 在 socket_device 目录里创建/维护 sock_file（Samsung 实测引导修复段）。

    实测（instance 4 vs instance 8，同硬件同 QEMU 配置）：netd 起来即 exit(1)，
    zygote 反复被重启；qemu.log 里 `avc: denied { create } for name=<socket>
    scontext=u:r:init tcontext=u:object_r:socket_device tclass=sock_file`
    共 **313 条**（占总 avc 964 条的主体）。

    根因：本项目的 /vendor/etc 被内核整目录重定向到 patch.img（CDH 白名单），
    于是 `/dev/socket/*` 的上下文来自 lineage 基座的 vendor_file_contexts，
    官方 Samsung vendor_file_contexts 里那些 socket 标签（perfmond 等）根本不存在；
    init 按官方 init.rc 的 `socket` 段落 /dev/socket/<name> 时，落到基座口径的
    socket_device，而基座策略没有授权 init 创建它。

    选型（对齐 note13，只加通用授权，不搬 gold 类型）：
      * 曾评估把官方 vendor_file_contexts 的 socket 类型移进本策略 —— 实测官方
        Samsung plat_sepolicy.cil 对这 65 个 /dev/socket/* 类型引用数为 **0**，
        且 gold 自身也没有授权 init 创建它们，搬运既无必要也无配套授权；
      * netd 是 plat/coredomain 域，vendor 策略无法点名授权它（版本化影子只覆盖
        public 类型），故只能在 init 侧解决。
    因此只补一条通用授权：init 对 socket_device 的 sock_file 全生命周期权限
    （create/setattr/unlink 是 init 建/清 socket 的必经路径，getattr/read/write 为
    connect 侧检查）。实测该段把 init 的 socket 拒绝 313 → 0，总 avc 964 → 38，
    netd 常驻、`android.system.net.netd.INetd/default` 可解析、system_server 起来、
    BOOT_COMPLETED 在 00:01:26 送达。
    """
    return (
        f"{INIT_SOCKET_DEVICE_MARKER}\n"
        + _allow(f"init_{vers}", f"socket_device_{vers}", "sock_file",
                 ["create", "setattr", "unlink", "getattr", "read", "write"])
    )


# ---- 官方 gold vendor 策略「plat 域 → plat 类型」授权重放段 ----
GOLD_GRANT_MARKER = ";; cdh sm-s9380-16: gold-plat-grant-replay"

# gold vendor_sepolicy.cil 里两端都带版本化后缀的 allow：这类语句的主体与客体都是
# 平台公共类型（版本化影子），即「三星在 vendor 策略里给平台域补的授权」。
_RE_GOLD_ALLOW = re.compile(
    r"^\(allow\s+([A-Za-z0-9_\-]+?)_(\d{6})\s+([A-Za-z0-9_\-]+?)_(\d{6})\s+"
    r"\((\S+)\s+\(([^)]*)\)\)\)\s*$", re.M)


def gold_grant_cil(vers: str, names: set, existing: str = "") -> str:
    """重放官方 gold vendor 策略里「plat 域 → plat 类型」的 allow 授权。

    实测（instance 17，2026-10-10）：BatteryService 通过后 system_server 在
    WifiService 里 `SystemProperties.set("vendor.wifi.dualconcurrent.interface",
    "swlan0")` 抛
      java.lang.RuntimeException: failed to set system property ... (check logcat
      for reason) → FATAL EXCEPTION IN SYSTEM PROCESS → zygote 反复 SIGKILL。
    init 侧同一时刻打印
      Unable to set property 'vendor.wifi.dualconcurrent.interface' from uid:1000
      gid:1000 pid:938: SELinux permission check failed
    该属性由官方 system_ext_property_contexts 标为 wifi_log_prop（第 762 行），而放行
    它的规则 `(allow system_server_202404 wifi_log_prop_202404 (property_service
    (set)))` 位于**官方 vendor_sepolicy.cil**（第 9353 行）——本盘 vendor 策略是
    lineage 基座，没有三星的这段，故拒绝。

    因此不做单点补丁，而是把 gold vendor 策略里两端均为版本化平台名的 allow 全量
    重放到运行期版本号（gold 202404 -> 运行期读 plat_sepolicy_vers.txt）。过滤条件：
      * 两端影子名都必须在运行期名字全集里（lineage 的 plat_pub_versioned.cil +
        基座 vendor cil 声明）——三星自有域（at_distributor / bootchecker / sem ...）
        在 lineage 侧无影子，整条丢弃（实测 4569 条中 1656 条可重放）；
      * class/权限按官方 plat 类表校验（与 sanitize_vendor_cil 同口径）；
      * 与前序 CDH 段/本段内重复的语句丢弃，同一 (src,tgt,class) 的权限合并，
        以免 validate_cil 判「重复语句 / 拆分冗余授权」。
    """
    gold_dir = gold_files.selinux_dir()
    gold_cil = os.path.join(gold_dir, "vendor_sepolicy.cil")
    if not os.path.isfile(gold_cil):
        print(f"[err] 官方 gold vendor_sepolicy.cil 缺失: {gold_cil}")
        sys.exit(1)
    with open(gold_cil, encoding="utf-8", errors="replace") as f:
        text = f.read()
    valid = plat_class_perms()
    existing_lines = set(existing.splitlines())
    # 前序 CDH 段已授过的 (src,tgt,class)：整条跳过，否则 validate_cil 判
    # 「拆分冗余授权」（同键不同权限集的两条语句）。
    existing_keys = {(_m[1], _m[2], _m[3])
                     for _m in (_RE_ALLOW.fullmatch(ln.strip())
                                for ln in existing.splitlines())
                     if _m}
    merged, order, skipped = {}, [], 0
    for m in _RE_GOLD_ALLOW.finditer(text):
        src, gv_src, tgt, gv_tgt, cls, perm_s = m.groups()
        if gv_src != gv_tgt:
            skipped += 1
            continue
        s, t = f"{src}_{vers}", f"{tgt}_{vers}"
        if s not in names or t not in names:
            skipped += 1
            continue
        if cls not in valid:
            skipped += 1
            continue
        perms = [p for p in perm_s.split() if p.startswith("-") or p in valid[cls]]
        if not perms:
            skipped += 1
            continue
        key = (s, t, cls)
        if key in existing_keys:
            skipped += 1
            continue
        if key not in merged:
            merged[key] = []
            order.append(key)
        for p in perms:
            if p not in merged[key]:
                merged[key].append(p)
    rules = []
    for key in order:
        s, t, cls = key
        line = f"(allow {s} {t} ({cls} ({' '.join(merged[key])})))"
        if line in existing_lines:
            continue
        rules.append(line)
    print(f"[ok] gold plat 授权重放：{len(rules)} 条（丢弃 {skipped} 条不可解析/"
          f"名字缺失，plat vers {vers}）")
    return (
        f"{GOLD_GRANT_MARKER}: replay of gold vendor grants between plat types.\n"
        + "".join(r + "\n" for r in rules)
    )


def coredomain_vendor_prop_read_cil(vers: str) -> str:
    """coredomain 服务直读 vendor_default_prop 属性区（引导修复段）。

    note13 实测：lmkd/keystore2 读取 /dev/__properties__/u:object_r:vendor_default_prop:s0
    被拒（avc denied { read } tclass=file）后 20ms 内 SIGABRT —— keystore2 起不来导致
    vold 等 IKeystoreService 卡死、boot 永不完成。授权直读该属性区文件即可让服务正常
    启动。风险：若 plat 对 coredomain→vendor_default_prop 有 neverallow，本段会导致
    init 编译策略失败（引导极早失败，可立即发现回退）。
    """
    return (
        f"{VENDOR_PROP_READ_MARKER}\n"
        + _allow(f"lmkd_{vers}", f"vendor_default_prop_{vers}", "file",
                 ["read", "getattr", "map", "open"])
        + _allow(f"keystore_{vers}", f"vendor_default_prop_{vers}", "file",
                 ["read", "getattr", "map", "open"])
        # 诊断：crash_dump 默认被拒 ptrace/dac_override（note13 实测 avc denied），
        # tombstone 永远写不出来，崩溃根因不可见。授权后 abort 栈可落盘定位。
        + _allow(f"crash_dump_{vers}", "domain", "process", ["ptrace"])
        + _allow(f"crash_dump_{vers}", "self", "capability", ["dac_override"])
    )


def vibrator_hal_cil(vers: str) -> str:
    """vibrator HAL 段：hal_vibrator_default 注册 IVibrator/IVibratorManager default。

    lineage 基座无 vibrator HAL，自研服务以 hal_vibrator_default 域注册
    android.hardware.vibrator.IVibrator/default 与 IVibratorManager/default，
    需 service_manager add/find（plat 公共类型用版本化影子 hal_vibrator_service_{vers}）。
    vibrator HAL 不使用 FMQ，故无 ashmem 授权。
    """
    return (
        f"{VIBRATOR_MARKER}\n"
        + _allow("hal_vibrator_default", f"hal_vibrator_service_{vers}",
                 "service_manager", ["add", "find"])
        + _allow(f"system_server_{vers}", f"hal_vibrator_service_{vers}",
                 "service_manager", ["find"])
    )


def ir_hal_cil(vers: str) -> str:
    """IR HAL 段：hal_ir_default 注册 android.hardware.ir.IConsumerIr/default。"""
    return (
        f"{IR_MARKER}\n"
        + _allow("hal_ir_default", f"hal_ir_service_{vers}",
                 "service_manager", ["add", "find"])
        + _allow(f"system_server_{vers}", f"hal_ir_service_{vers}",
                 "service_manager", ["find"])
    )


def frp_pdb_cil(vers: str) -> str:
    """FRP 承载块设备段：system_server（pdb）读写 misc_block_device。

    本盘没有 frp 分区，pdb 经 ro.frp.pst 打开的是软链到 misc(vda3) 的节点
    （类型 misc_block_device），平台策略只允许 system_server 访问 frp_block_device。
    """
    return (
        f"{FRP_MARKER}\n"
        + _allow(f"system_server_{vers}", "misc_block_device", "blk_file",
                 list(FRP_BLK_PERMS))
    )


def perf_policy_cil(vers: str) -> str:
    """perf2 HAL 段（手写最小面，按平台 neverallow 精确构造）。

    官方整段搬运不可行：lineage 侧缺兄弟域、且平台 neverallow 规定
    `(and (domain) (not (vendor_hal_perf_client vendor_hal_perf_server)))` 不得
    add/find vendor_hal_perf2_service —— 即 system_server 必须先被并入
    vendor_hal_perf_client、本 HAL 域并入 vendor_hal_perf_server，才允许注册与查找。
    这里只声明服务启动/注册/查找所需的最小集合。
    """
    return (
        f"{PERF_MARKER}\n"
        # 类型与域
        "(type vendor_hal_perf_default)\n"
        "(type vendor_hal_perf_default_exec)\n"
        "(type vendor_hal_perf2_service)\n"
        "(typeattribute vendor_hal_perf_server)\n"
        "(typeattribute vendor_hal_perf_client)\n"
        "(roletype object_r vendor_hal_perf_default)\n"
        "(roletype object_r vendor_hal_perf_default_exec)\n"
        "(roletype object_r vendor_hal_perf2_service)\n"
        # neverallow 豁免集：本 HAL 域=server，system_server=client
        "(typeattributeset domain (vendor_hal_perf_default))\n"
        "(typeattributeset vendor_hal_perf_server (vendor_hal_perf_default))\n"
        f"(typeattributeset vendor_hal_perf_client (system_server_{vers}))\n"
        # init 启动该服务
        f"(typetransition init_{vers} vendor_hal_perf_default_exec process"
        " vendor_hal_perf_default)\n"
        + _allow(f"init_{vers}", "vendor_hal_perf_default", "process",
                 ["transition", "siginh", "rlimitinh", "noatsecure"])
        + _allow(f"init_{vers}", "vendor_hal_perf_default_exec", "file",
                 ["read", "getattr", "map", "execute", "open"])
        + _allow("vendor_hal_perf_default", "vendor_hal_perf_default_exec",
                 "file", ["read", "getattr", "map", "execute", "open",
                          "entrypoint"])
        # 注册 / 查找（neverallow 豁免已就位）
        + _allow("vendor_hal_perf_default", "vendor_hal_perf2_service",
                 "service_manager", ["add", "find"])
        + _allow(f"system_server_{vers}", "vendor_hal_perf2_service",
                 "service_manager", ["find"])
        # 与 servicemanager 通 binder（注册路径）
        + _allow("vendor_hal_perf_default", f"servicemanager_{vers}", "binder",
                 ["call", "transfer"])
        + _allow(f"servicemanager_{vers}", "vendor_hal_perf_default", "binder",
                 ["transfer"])
        + _allow("vendor_hal_perf_default", f"servicemanager_{vers}", "fd",
                 ["use"])
    )


def hal_vsc_lines() -> list:
    """全部自研/收编 HAL 需要追加的 vendor_service_contexts 映射行。"""
    return (list(VIBRATOR_VSC_LINES) + list(IR_VSC_LINES) + list(PERF_VSC_LINES)
            + list(SEH_KEYMINT_VSC_LINES))


def hal_vsc_missing(vsc: bytes) -> list:
    """工作镜像 vendor_service_contexts 里尚缺的 HAL 映射行。"""
    text = vsc.decode("utf-8", "replace")
    return [line for line in hal_vsc_lines() if line.split()[0] not in text]


def hal_cil_chain(merged: str, vers: str, names=None) -> str:
    """按固定顺序补齐缺失的 CDH CIL 段
    （pioneer + coredomain 属性区直读 + 官方 gold vendor 属性类型段）。

    各 *_patch_commands 都基于工作镜像里的「原始」vendor_sepolicy.cil 拼接（debugfs
    命令此刻尚未执行），而命令序列里只有最后一次 write 生效 —— 所以最后调用的那个
    函数必须把所有前序段一并写出，否则会把它们覆盖丢失。新增 HAL 段时只需在这里加
    一行，再由该 HAL 的 *_patch_commands 调用本函数即可（note13 机制）。
    names = 本策略已声明的类型/属性名全集（供 gold prop types 段过滤源域不存在的授权）。
    """
    cil = ""
    if MARKER not in merged:
        cil += pioneer_cil(vers)
    if VENDOR_PROP_READ_MARKER not in merged:
        cil += coredomain_vendor_prop_read_cil(vers)
    if VOLO_NETLINK_MARKER not in merged:
        cil += vold_netlink_cil(vers)
    if INIT_SOCKET_DEVICE_MARKER not in merged:
        cil += init_socket_device_cil(vers)
    if gold_props.MARKER not in merged:
        cil += gold_props.prop_types_cil(vers, names or set())
    if VIBRATOR_MARKER not in merged:
        cil += vibrator_hal_cil(vers)
    if IR_MARKER not in merged:
        cil += ir_hal_cil(vers)
    if FRP_MARKER not in merged:
        cil += frp_pdb_cil(vers)
    if PERF_MARKER not in merged:
        cil += perf_policy_cil(vers)
    # gold 重放段必须最后生成：它要以前序各段为 existing 去重（同键不同权限集会
    # 被 validate_cil 判为拆分冗余授权）。
    if GOLD_GRANT_MARKER not in merged:
        cil += gold_grant_cil(vers, names or set(), existing=cil)
    return cil


def patch_commands(work_img, tmp_dir=None) -> list:
    """补齐 vendor_sepolicy.cil 的各 CDH 段，返回 debugfs 命令清单。

    幂等：基座副本每次从 lineage vendor_a.img 重新拷贝，正常不会已含标记；
    若已含（重复构建同一 work.img）则跳过不重复追加。
    """
    vers = cat(work_img, VERS_FILE)
    if not vers:
        print(f"[err] 读不到 {VERS_FILE}")
        sys.exit(1)
    vers = vers.decode("ascii", "ignore").strip()

    orig = cat(work_img, POLICY_FILE)
    if orig is None:
        print(f"[err] 读不到 {POLICY_FILE}")
        sys.exit(1)
    orig_text = orig.decode("utf-8", "replace")
    # 运行态平台兼容清理（官方 plat 类表）：secilc 以官方 plat 解析权限，
    # lineage 策略里官方类表没有的权限语句必须先剔除，否则开机 InitFatalReboot。
    merged = sanitize_vendor_cil(orig_text, plat_class_perms())
    # 名字全集: vendor 基座自有类型（mediacodec 等，未版本化）
    #          + plat_pub_versioned.cil（plat 公共类型的版本化 typeattribute 影子）
    #          + 官方 plat（plat_name_set 内部缓存）
    name_universe = _cil_names(merged) | \
        _cil_names(_read_cil(work_img, PUB_VER_FILE))
    cil = hal_cil_chain(merged, vers, name_universe)
    tmp_dir = tmp_dir or os.path.join(TMP_DIR, "vendor")
    os.makedirs(tmp_dir, exist_ok=True)
    cmds = []
    if cil or merged != orig_text:
        validate_cil(cil, name_universe)
        tmp = os.path.join(tmp_dir, "vendor_sepolicy.cil")
        with open(tmp, "wb") as f:
            f.write(merged.encode("utf-8") + cil.encode("utf-8"))
        print(f"[ok] vendor_sepolicy.cil 追加 CDH 段（plat vers {vers}，"
              f"+{len(cil)} B）")
        cmds += [
            f"rm {POLICY_FILE}",
            f"write {tmp} {POLICY_FILE}",
            f"ea_set {POLICY_FILE} security.selinux {POLICY_LABEL}",
        ]
    else:
        print("[ok] vendor_sepolicy.cil 各段齐全，跳过")

    # 自研 HAL 的 vendor_service_contexts 映射：缺了服务名会落到 default 类型，
    # 服务 add/find 被拒、框架找不到 HAL（vibrator 即因此卡死 SystemServer 主线程）。
    # 与 CIL 段同为追加工件，命令序列里保持在后。
    vsc = cat(work_img, VSC)
    if vsc is None:
        print(f"[err] 读不到 {VSC}")
        sys.exit(1)
    missing = hal_vsc_missing(vsc)
    if not missing:
        print("[ok] vendor_service_contexts 已含自研 HAL 映射，跳过")
    else:
        blob = ("\n# cdh popsicle-16: AIDL HAL services\n"
                + "\n".join(missing) + "\n").encode("utf-8")
        tmp = os.path.join(tmp_dir, "vendor_service_contexts")
        with open(tmp, "wb") as f:
            f.write(vsc + blob)
        print(f"[ok] vendor_service_contexts 追加 {len(missing)} 条 HAL 映射")
        cmds += [
            f"rm {VSC}",
            f"write {tmp} {VSC}",
            f"ea_set {VSC} security.selinux {VSC_LABEL}",
        ]
    return cmds
