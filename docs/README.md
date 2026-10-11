# SM-S9380-16（Samsung Galaxy S25 Ultra / Android 16）构建流水线

架构参考 **note13-5G-15**：官方 super 零改动 + 独立 `patch.img`(vdc 挂 `/mnt/vendor`) +
自编译内核 `getname_flags` 路径重定向。本目录当前已把该链路的代码框架移植到本机型，
unpack/vendor/super/patch 可实跑，kernel/boot 待内核源树就位。

## 设备事实

| 项 | 值 |
|----|----|
| 销售型号 | SM-S9380（Galaxy S25 Ultra，国行 CHC） |
| SoC / board | Qualcomm Snapdragon 8 Elite（SM8750）/ `sun` |
| Android | 16 |
| 内核 | `6.6.98-android15-8-p5a696e2-abogkiS9380ZCSDCZH1-4k`（GKI，clang 18） |
| 固件版本 | `S9380ZCSDCZH1/S9380CHCDCZH1/S9380ZCSDCZH1/S9380ZCSDCZH1` |
| 真机 ro.hardware | `qcom`（官方 `vendor/etc/fstab.qcom`；boot cmdline `androidboot.hardware=qcom`） |
| lineage 底包 | `lineage-23.2`（Android 16 virtio_arm64only；分区为 ext4） |

## 官方固件形态（Samsung 特有）

```
.zip.enc4                 FUS 加密服务包（AES-128-ECB-PKCS7）
  └─(解密)→ .zip
       ├── BL/AP/CP/CSC/HOME_CSC_*.tar.md5   各分区为 *.img.lz4
       └── AP 内 super.img 是 **sparse**（须展开 raw 才能定位 liblp）
```

- super 逻辑分区全为 **erofs**：system(9.25G)/vendor(3.34G)/product(470M)/system_ext(153M)/
  vendor_dlkm(28M)/system_dlkm(7.3M)/odm(1.1M)，slot B 全空。
- CSC 与 HOME_CSC 内容重叠，流水线只取 CSC。

## 架构（note13 范式）

```
┌── 官方 super.img（Samsung，零改动，QEMU vda）──────────────┐
│  /system   One UI（官方）    /product /system_ext …        │
└──────────────────────────────────────────────────────────┘
┌── patch.img（lineage-23.2 virtio vendor，独立 vdc）────────┐
│  镜像根 = /mnt/vendor（= lineage vendor 树，ext4）         │
│  镜像根/vendor_dlkm = lineage vendor_dlkm                  │
└──────────────────────────────────────────────────────────┘
┌── 自编译内核（GKI 6.12.23 / android16-6.12 + virtio + CDH 重定向）┐
│  /vendor/{etc,bin,lib,lib64} → /mnt/vendor/...             │
│  /vendor_dlkm/lib → /mnt/vendor/vendor_dlkm/lib            │
└──────────────────────────────────────────────────────────┘
```

- 系统进程访问 `/vendor/...` 被内核重定向到 `/mnt/vendor/...` → 拿到 lineage virtio
  HAL/库/rc；`/proc/mounts` 只见官方 `/vendor`（erofs ro）+ `/mnt/vendor` 一条 ext4。
- 官方 super 全程不写入；lineage 内容全在独立 vdc。

## 阶段与产物

`main.py` 阶段：`unpack → kernel → boot → vendor_boot → vendor → vendor_dlkm → patch → super → pack`

| 阶段 | 脚本 | 产物 | 状态 |
|------|------|------|------|
| unpack | `scripts/unpack-roms.py` | `roms/<factory-dir>/` 各 `*.img` | ✅ 实跑 |
| kernel | `scripts/build-kernel.py` → `kernel/build/build-kernel.sh` | `out/kernel/{Image,modules}` | ✅ 实跑（6.12.23-4k-cdh，11 模块） |
| boot | `scripts/build-boot.py` | `out/dist/rom/boot.img` | ✅ 实跑（ramdisk 注入 fstab.qcom×4） |
| vendor_boot | `scripts/build-vendor-boot.py` | `out/dist/rom/vendor_boot.img` | ✅ 实跑 |
| vendor | `scripts/build-vendor.py` | `out/dist/rom/vendor.img` | ✅（基座+patch 注入） |
| vendor_dlkm | `scripts/build-vendor_dlkm.py` | `out/dist/rom/vendor_dlkm.img` | ✅（基座+模块注入） |
| patch | `scripts/build-patch.py` | `out/dist/rom/patch.img` | ✅ 实跑 |
| super | `scripts/pack_super.py` | `out/dist/rom/super.img` | ✅ 实跑 |
| pack | `scripts/pack-roms.py` | `out/device/sm-s9380-16/16/<ver>/{vda.img,data.qcow2,patch.img}` | ✅ 实跑（vda 21 GiB） |

## 关键设备适配（相对 note13）

- **fstab**：真机 ro.hardware=`qcom` → 用 `build/vendor/patch/etc/fstab.qcom`
  （由 lineage 的 `fstab.virtio` 派生 + 加 `vdc /mnt/vendor ext4 ro first_stage_mount`），
  `build-boot.py` 注入 boot ramdisk 的 first_stage fstab，`build-patch.py` 带入
  patch.img 的 `/etc/fstab.qcom`，单一来源。
- **vendor_boot**：lineage 基底 cmdline `androidboot.hardware=virtio` → 原位替换为
  `qcom`（补 2 空格凑等长）；并删 fragment 内 lineage `fstab.virtio*` 副本，
  让 boot.img 注入的 fstab 成为唯一来源；verifiedbootstate orange→green。
- **enc4 解密**：`key = md5(logic_check(BINARY_SW_VERSION, LOGIC_VALUE_FACTORY))`
  （FUS），key 存 manifest `enc4-key-hex`；算法同下载器 `samsung.rs`。
- **super**：sparse → raw 后字节级直拷（零改动）。**但底盘放不下**：lineage-23 底盘整盘
  仅 13.00 GiB、`super` 分区 12288 MiB，而 Samsung 官方 super 声明 **18500 MiB**（extents
  实测最远到 13.24 GiB，所以既装不下也不能截断）。`pack-roms.py` 的 `_grow_super()` 把 super
  分区放大到 **20480 MiB**（盘 13.00 → 21.00 GiB），并后移其后的 9 个分区；**GRUB 硬编码
  GPT 索引**（lineage-23 grub.cfg: `boot_a=gpt9`/`vendor_boot_a=gpt7`/`misc=gpt3`/`EFI=gpt1`），
  故条目顺序、名字、type/unique GUID 一律不变，只改 LBA 并重算主/备 GPT CRC。

## 实例引导实测（2026-10-09，第一轮）

已起实例实测（daemon 规格见 `core/host/daemon/device/device.go` 的 `SmS938016`）。

**已生效**（qemu.log 实证）：
- 自编译内核 `6.12.23-4k-cdh` 起来；`BOOT_IMAGE=(hd0,gpt9)/kernel`、`androidboot.slot_suffix=_a`
- 官方 super 的 7 个逻辑分区全部挂上：`/system /odm /product /system_dlkm /system_ext /vendor
  /vendor_dlkm`（dm-0..dm-6，erofs）
- **vdc 挂载成功**：`__mount(source=/dev/block/vdc,target=/mnt/vendor,type=ext4)=0`
- **内核重定向生效**：`cdh_redirect: /mnt/vendor/lib64/...` 大量命中
- `/metadata` 挂载成功（见下）

**本轮修掉**：lineage 底盘的 `metadata` 分区是**空白镜像**（非 ext4）→ first-stage 报
`Invalid ext4 superblock` → `/metadata` 挂成 Read-only → keystore2/vold/zygote 连锁失败。
`pack-roms.py` 增 `ensure_metadata_ext4()`：非 ext4 时用 `mkfs.ext4` 重生成并写回 vda
（同 oriole-16 已验证做法）。修复后 `e2fsck clean` + `__mount(... /metadata,type=ext4)=0`。

**当前卡点**（未到 `Zygote`/`system_server`/`boot_completed`）：
- `/data` 未正常挂载/FBE 失败：`FsCrypt: Failed to prepare /data/data`，`post-fs-data`
  里 `/data` 与 `/metadata` 相关命令报 Read-only
- `vold` 被 SELinux 持续拒绝：`avc denied { create } ... scontext=vold tcontext=vold
  tclass=netlink_socket permissive=0`（Samsung plat policy + lineage vendor policy 混搭）
- 早期服务崩溃循环：`vendor.boot-default` SIGABRT、`tombstoned`/`odsign` exit 1、
  `vendor.dlkm_loader_mainline` SIGABRT、`scs` exit 255
- `init.qcom.rc` 缺失（ro.hardware=qcom 但 lineage vendor 只有 `init.virt.rc`）——
  note13 是在 patch 树里自备 `init.mt6833.rc` 解决的，本机型需补 `init.qcom.rc`
  或改走 virtio 命名

**第二轮（接上 popsicle 的 guest 内容 + 两处引导修复）**：把 popsicle 的 `build/vendor`
（patch 树：`init.qcom.rc`/`cph_*.rc`/`netmgr.rc`/idc/permissions；guest Rust daemon；HAL
源码）整树移植过来，机型耦合的 ir/vibrator/qti-perf2 移到 `source/_pending/`；生成
`build/baselines/<build-id>.json`（334 条从三星官方 `vendor_a.img` 提取的身份属性 + 注入
文件 SELinux 标签 + odm/vendor_dlkm build.prop 基线）。

新增进展（qemu.log 实证）：
- **`/data` 已可用**：vold 对其做 FBE 格式化并挂载（dm-61），`post-fs-data` 里
  `/data/bootchart` 等命令由「Read-only」变为 **succeeded**；`/metadata`、`EFI`、`persist` 均挂上
- **zygote64 已启动并预加载**（194 个 boot class 校验通过）
- 移植内容在跑：`init.qcom.rc`、`cph_*`、`netmgr`、`pioneer` 均有日志
- 修复①：底盘 `metadata` 分区空白 → `ensure_metadata_ext4()`（见上）
- 修复②：**vold 自建 netlink socket 被 SELinux 拒**（`vold:self:netlink_socket create`）导致
  `vold: Exiting(13)` 循环、zygote 拿不到 vold 被 SIGKILL → `sepolicy.vold_netlink_cil()` 追加
  授权段后 `Exiting(13)`/`netlink_socket` 归零

**第三轮（netd 卡点已解，全链跑到 BOOT_COMPLETED）**：早前判断的
`NapProxyListener`/`napproxyd` 只是**症状**，真因是 SELinux 让 init 建不出
`/dev/socket/*`，netd 因此 `exit(1)`：

```
01-01 00:00:34 E SocketListener: Obtaining file descriptor socket 'napproxyd' failed: Success
avc:  denied { create } for name="perfmond" scontext=u:r:init tcontext=u:object_r:socket_device
      tclass=sock_file permissive=0        （qemu.log 里共 313 条）
```

根因：内核 CDH 白名单把 `/vendor/etc` **整目录**重定向到 patch.img，于是
`/dev/socket/*` 的上下文口径来自 **lineage 基座** 的 `vendor_file_contexts`，三星官方
`vendor_file_contexts` 里的 socket 标签在运行时根本不存在；init 按官方 init.rc 的
`socket` 段落这些文件时落到基座口径的 `socket_device`，而基座策略没授权 init 创建它。

曾评估「搬官方 gold 策略」这条路，实测否决（详见 `gold_selinux.py` 模块说明）：
`CDH_GOLD_SELINUX=1` 构建成功但 boot 不完成 —— gold vendor cil 的 1388 条 genfscon 让
guest 侧 secilc 报 `Problems processing genfscon rules`（54 条以 '/' 结尾、7 条挂在平台
不认识的 `sdfat/udfs/ntfs/ntfs3/udf/iso9660/ecryptfs` 上；删掉全部 genfscon 即可编译，实证）；
再往下 `op=setxattr invalid_context=u:object_r:vendor_graphics_prop:s0` → `Failed to
initialize property area` → `Kernel panic - Attempted to kill init`，因为 gold 策略里没有
lineage 侧的 `vendor_graphics_prop`/`vendor_virtgpu_detect`/`setup_sound_card`/`pioneer`
等类型。gold 自身的 65 个 `/dev/socket/*` 类型在其官方 `plat_sepolicy.cil` 里引用数为 **0**，
且 gold 也没授权 init 建它们；netd 是 plat/coredomain 域，vendor 策略无法点名 —— 所以只能在
init 侧补一条通用授权：`sepolicy.init_socket_device_cil()`（叠 `init_{vers}` →
`socket_device_{vers}:sock_file` 的 create/setattr/unlink/getattr/read/write）。

实测前后对比（同硬件、同 QEMU 配置，instance 4 → instance 8）：

| 指标 | 修复前 | 修复后 |
| --- | --- | --- |
| avc denied 总数 | 964 | 38 |
| `init → socket_device:sock_file {create}` | 313 | **0** |
| Kernel panic | 0 | 0 |
| netd | 启动 ~1s 后 `exit(1)`，zygote 循环被杀 | 常驻，`android.system.net.netd.INetd/default` 可解析 |
| system_server | 起不来 | pid 1216/1444 正常起来 |
| 显示 | — | `内置屏幕 1440 x 3120` 已 add |
| boot | 永不完成 | `BOOT_COMPLETED` 于 00:01:26 送达，日志 86,161 行 |

随后把该段编进构建（`sepolicy.hal_cil_chain()` 扩展点），`main.py --from vendor` 全链重出
vendor/vendor_dlkm/patch/super/pack（instance 10/11 纯用产物复现：`init→socket_device`
拒绝 0 条、无 panic、`init: Created socket '/dev/socket/perfmond'`、`BOOT_COMPLETED`
于 00:01:50 送达）。

**次要缺口**：`start recover_radio`（Samsung `init.rilcommon.rc`，`onrestart netd` 触发）仍报
`/vendor/bin/sh` 标签 `vendor_shell_exec`、无 init→域迁移；netd 在 ~120s 被 SIGKILL 一次
（init 随即重启，`INetd/default` 恢复）；残留 avc 主要是 `audioserver→vendor_dolby_prop:file read`、
`zygote→product_ship_prop:file read`、`ss_conn_daemon→sysfs_android_usb:dir search`、
`sem→property_socket:sock_file write`、`pioneer→kmsg_device` 等；`vendor.dlkm_loader_mainline`
对 `/system/lib/modules/rfkill.ko` 报 Exec format；`/mnt/vendor/shared` virtiofs 挂载 -1；
`fscrypt: Timed out waiting for loading global de`；`zygote_secondary` 服务未定义。

**第四轮（adb offline → vendor_dlkm 分层对齐 popsicle）**：宿主 `adb connect` 后一直
`offline`，链路逐层实证到底：

```
adb 127.0.0.1:5911 offline
  ← guest daemon: adbkey: 握手失败 open /dev/hvc2: No such file or directory
  ← hvc-event:    open /dev/hvc7: No such file or directory   （/dev/hvc* 一个都没有）
  ← qemu:         virtio-serial-bus: Guest failure in adding port 8/9/10
  ← virtio_console.ko 从未被加载
```

两个三星侧 `vendor_dlkm` 简化实现的缺陷（popsicle 都有、三星移植时丢了）：

1. **基座写满、write 静默失败**：`lineage-rom/lineage-23/super/vendor_dlkm_a.img` 只有
   16 个空闲 inode / 12 个空闲块（`dumpe2fs -h`）。旧编排只做 `rm + write`，不回收空间，
   且忽略 debugfs 的 stderr（单命令失败仍返回 0）—— 11 个模块里 **7 个报
   `Could not allocate block`**（`cdh_device_info / cdh_goodix_fingerprint / cdh_media /
   cdh_virt_wifi / mac80211 / mac80211_hwsim / virtio_console`），日志却照样打印
   「[ok] 注入 11 个内核模块」。逐件 `dump` + `cmp` 与 `out/dist/kernel/modules/*.ko`
   比对才能看出那 7 个其实是**基座陈件**（尺寸相同、内容不同）。
2. **从不重建索引**：基座 `modules.load` 是 `btusb / cfg80211 / virt_wifi`（lineage 自留
   清单），与本盘模块集不符。libmodprobe 于是在 `/system/lib/modules`（三星官方内核编译的
   同名件）解析 → `Failed to insmod '/system/lib/modules/rfkill.ko': Exec format error`，
   而 `virtio_console` 根本不在清单里 → 永不加载。

**对齐 popsicle 的修法**（移植其分层，规则模块只出命令清单、编排层一次会话）：
新增 `build/vendor_dlkm/build/debugfs.py`（`run_command_file` 扫 stderr 错误标记，
分配失败即返回 false）与 `modules.py`（先 `rm` 基座 kunit/测试件回收 inode/块 → 写 .ko →
**全量重建** `modules.load/dep/alias/options`（清单按产物目录实际 .ko，依赖取 modinfo
`depends=`，`options cdh_media allow_userptr=1` 随加载下发）→ 逐件 `dump`+`cmp` 回读校验，
不一致即退出）。`vendor_dlkm_builder.py` 改为编排上述两步 + `e2fsck -fy`。
实测：`[ok] 注入 11 个内核模块 + 重建 4 类索引`、`[ok] 回读校验通过`、无
`Could not allocate`；产物 `patch.img` 内 `/vendor_dlkm/lib/modules/modules.load` =
11 个自编译件（含 virtio_console），`virtio_console.ko` 与内核产物逐字节一致。



## 待办

- [ ] **内核源树**：`kernel/{source,build,modules}` 已从 **popsicle-16**（同为高通 Android 16）
  整树复制：GKI **6.12.23**（builder 目标 `android16-6.12`，localversion `-4k-cdh`），
  `lineage-kernel.config` 已含 A16 必需项（`CONFIG_CDH_PATH_REDIRECT`、`CONFIG_CDH_PIONEER_PERMISSIVE`、
  `CONFIG_ASHMEM=y` C 实现、`CONFIG_RTC_DRV_TEST=y`、mac80211_hwsim）。与 lineage-23 虚机
  vendor_dlkm 模块（同 6.12 分支）匹配。待编并测。
- [ ] **机型身份模块**：`kernel/modules/{cpu_probe,device_info,goodix_fingerprint}` 目前沿用
  popsicle-16 实现，需按 Samsung SM9380 校验/调整。
- [ ] **vendor HAL**：note13 的 `build/vendor/source/`（audio 等 HAL）、依赖提取、
  gold props/sepolicy 尚未移植；当前 vendor 阶段为「lineage 基座 + patch 注入」。
- [ ] **baselines**：`build/baselines/<build-id>.json` 未建立（不虚构）。
- [ ] **pack 实跑**：需 boot/vendor_boot/patch 与 lineage-23 底包 vda 提取。
- [ ] **daemon 设备规格**：`core/host/daemon/run/devices.go` 的 `inferSpecID` 与
  `core/host/daemon/device/device.go` 的 `specs` 注册表目前都没有三星条目（未匹配会回退
  `pixel6-15`）。起实例前需新增 `sm-s9380-16` DeviceSpec（盘布局/GPU/secure-env/cmdline），
  可按 note13/popsicle 范式移植。
- [ ] **实例引导实测**：起实例验证重定向命中（`dmesg | grep cdh_redirect`）、vdc 挂载与
  `/proc/mounts` 形态。