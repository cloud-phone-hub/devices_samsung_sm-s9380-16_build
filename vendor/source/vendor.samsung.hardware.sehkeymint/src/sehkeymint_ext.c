/* sm-s9380-16 CDH：software-only vendor.samsung.hardware.keymint.ISehKeyMintExtension
 * 值守 binder 服务。
 *
 * 为什么需要它（实测 2026-10-11，instance 28 qemu.log）：
 *   三星 keystore2（编译自 system 分区的 Samsung fork）在启动早期无条件
 *   `connect_skeymint_extension` → `get_keymint_extension`（globals.rs:633）取
 *   SEH KeyMint 扩展，取不到就 panic：
 *       samsung_keystore_wrapper.rs: get_rot_value::SehKeyMintExtension must be present
 *   → keystore2 反复 SIGABRT → servicemanager 里 `android.system.keystore2.
 *   IKeystoreService/default` 起不来 → vold 拿不到 keymint → zygote 被重启 →
 *   boot 卡死 / 重启循环。
 *
 *   本盘 vendor 侧是 lineage 基座的 puresoft keymint（只注册标准
 *   android.hardware.security.keymint.IKeyMintDevice/default，供 vold FBE 用，
 *   不能动：换成 gold keymint 会因安全后端建不出 FBE key 而拖死 /data 重格式）。
 *   puresoft 既不在 IKeyMintDevice binder 上挂 SEH extension，也没把
 *   ISehKeyMintExtension 注册成独立服务，故三星 keystore2 的兜底路径——按**裸名**
 *   `servicemanager.find("vendor.samsung.hardware.keymint.ISehKeyMintExtension")`
 *   ——查不到（qemu.log 里这条 find 刷了 133 次，且因该名未进 vendor_service_contexts
 *   落到 default_android_service、keystore 无 find 权限 → selinux_check_access -1）。
 *
 *   本服务补上这个裸名服务：注册一个 descriptor / version / hash 与 gold 完全一致的
 *   最小 binder，让 find 命中、get_keymint_extension 不再 panic。运行期真正的取 RoT
 *   调用（get_rot_value → getLastFailedRot）返回一段良性固定字节即可让 FBE/keyguard
 *   流程继续（puresoft 口径本就是「no rot value」，并不依赖真实硬件 RoT）。
 *
 * ABI（逐条实测自 out/tmp/gkm/vendor.samsung.hardware.keymint-V3-ndk.so 的 Bp/Bn 反汇编）：
 *   descriptor            "vendor.samsung.hardware.keymint.ISehKeyMintExtension"
 *   接口方法事务码：attestKey=1 / encryptWithPasswordHwKey=2 / getLastFailedRot=3
 *   特殊码：getInterfaceVersion=0xffffff（回 int32 3）、getInterfaceHash=0xfffffe
 *   接口 version=3（Bn 里 `mov w8,#0x3`）、interfaceHash=SHA-1
 *   "74a538630d5d90f732f361a2313cbb69b09eb047"（.rodata 取；若 keystore2 校验不过则换
 *   另一候选 "d73e689d2be3b4a7fc5e5e5e3bf2c6d1d199ff7f"）。
 *   getLastFailedRot 出参 = `out byte[]`：AIDL 回包 = 先 int32 异常码(0) 再字节数组。
 *
 * 只用 NDK 裸 binder C API（AIBinder_Class_define/AIBinder_new + 自写 onTransact），
 * 不引入 C++ AIDL 运行时、不需要重建 gold 的 parcelable 依赖图。boot 关键路径上
 * keystore2 只会调用 getLastFailedRot / getInterfaceVersion / getInterfaceHash；
 * attestKey、encryptWithPasswordHwKey 属密钥业务、启动期不触达，回 EX_UNSUPPORTED_OPERATION。
 *
 * SELinux：本服务以 CDH 值守域 pioneer（rc 内 seclabel u:r:pioneer:s0，内核
 * CONFIG_CDH_PIONEER_PERMISSIVE 放行其作为主体的判定，含 addService）运行；消费侧
 * 三星 keystore2 跑在 plat 的 keystore 域，`keystore` 是 plat 属性 hal_keymint_client
 * 成员、plat 已授 `hal_keymint_client → hal_keymint_service:service_manager find`，
 * 故只要在 vendor_service_contexts 把本服务名映射成 hal_keymint_service，find 即放行
 * （见 build/vendor/build/sepolicy.py SEH_KEYMINT_VSC_LINES）。
 */

#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>
#include <android/binder_process.h>
#include <android/binder_status.h>
#include <android/log.h>

#include <stdint.h>
#include <string.h>

/* 本文件按 C 编译（build.py 用 -std=c11）。common/ndk-binder-platform/android/
 * binder_manager.h 是 C++ 快照（`enum X : uint32_t`、无 tag 引用前向声明的 struct），
 * 在 C 下报 "must use 'enum'/'struct' tag"；且 NDK sysroot 不含 binder_manager.h。
 * 本服务只用 AServiceManager_addService 这一个稳定 NDK C 符号（签名常年不变），故
 * 直接声明、不引入那份 C++ 专用头，避免改动被 vibrator/thermal/sensors 共用的头。
 * 返回类型 binder_exception_t 与 AIBinder 已由上面 binder_status.h /
 * binder_ibinder.h 提供。 */
__attribute__((warn_unused_result)) binder_exception_t
AServiceManager_addService(AIBinder* binder, const char* instance);

#define LOG_TAG "cdh-sehkeymint"

/* ---- 接口身份（与 gold 对齐）---- */
#define DESCRIPTOR "vendor.samsung.hardware.keymint.ISehKeyMintExtension"
#define IFACE_VERSION 3
#define IFACE_HASH "74a538630d5d90f732f361a2313cbb69b09eb047"

/* ---- 事务码（实测自 gold BpSehKeyMintExtension 反汇编）---- */
#define TX_ATTEST_KEY 1u
#define TX_ENCRYPT_WITH_PASSWORD_HW_KEY 2u
#define TX_GET_LAST_FAILED_ROT 3u
#define TX_GET_INTERFACE_VERSION 0xffffffu
#define TX_GET_INTERFACE_HASH 0xfffffeu

/* ---- AIDL 异常码（frameworks Parcel.cpp exception_code）---- */
#define EX_NONE 0
#define EX_UNSUPPORTED_OPERATION 4

/* getLastFailedRot 返回的良性 RoT：32 字节固定串（非空，避免下游按“无 rot”再走
 * 其它分支；真机语义是“最近一次失败的 RoT”，正常设备本就为空/固定值）。 */
static const int8_t kLastFailedRot[32] = {0};

static void* onCreate(void* args) {
    (void)args;
    static char instance;
    return &instance;
}

static void onDestroy(void* user) {
    (void)user;
}

/* AIDL 回包头：先写 int32 异常码；异常非 0 时紧跟一条字符串 message。 */
static binder_status_t write_ok_header(AParcel* out) {
    return AParcel_writeInt32(out, EX_NONE);
}

static binder_status_t write_exception(AParcel* out, int32_t code, const char* msg) {
    binder_status_t s = AParcel_writeInt32(out, code);
    if (s != STATUS_OK) {
        return s;
    }
    return AParcel_writeString(out, msg, (int32_t)strlen(msg));
}

static binder_status_t onTransact(AIBinder* binder, transaction_code_t code,
                                  const AParcel* in, AParcel* out) {
    (void)binder;
    (void)in;
    switch (code) {
    case TX_GET_LAST_FAILED_ROT: {
        binder_status_t s = write_ok_header(out);
        if (s != STATUS_OK) {
            return s;
        }
        return AParcel_writeByteArray(out, kLastFailedRot,
                                      (int32_t)sizeof(kLastFailedRot));
    }
    case TX_GET_INTERFACE_VERSION: {
        binder_status_t s = write_ok_header(out);
        if (s != STATUS_OK) {
            return s;
        }
        return AParcel_writeInt32(out, IFACE_VERSION);
    }
    case TX_GET_INTERFACE_HASH: {
        binder_status_t s = write_ok_header(out);
        if (s != STATUS_OK) {
            return s;
        }
        return AParcel_writeString(out, IFACE_HASH,
                                   (int32_t)sizeof(IFACE_HASH) - 1);
    }
    case TX_ATTEST_KEY:
    case TX_ENCRYPT_WITH_PASSWORD_HW_KEY:
        /* 密钥业务，启动关键路径不触达；返回结构良好的 AIDL 异常而非 binder 硬失败。 */
        return write_exception(out, EX_UNSUPPORTED_OPERATION,
                               "cdh-sehkeymint: software extension does not implement this call");
    default:
        return write_exception(out, EX_UNSUPPORTED_OPERATION,
                               "cdh-sehkeymint: unknown transaction");
    }
}

int main(void) {
    AIBinder_Class* clazz =
        AIBinder_Class_define(DESCRIPTOR, onCreate, onDestroy, onTransact);
    if (clazz == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "class define failed");
        return 1;
    }
    AIBinder* binder = AIBinder_new(clazz, NULL);
    if (binder == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "binder create failed");
        return 2;
    }

    ABinderProcess_setThreadPoolMaxThreadCount(2);
    ABinderProcess_startThreadPool();

    /* keystore2 兜底路径按裸名 find；同时按 AIDL 约定注册 <iface>/default，
     * 覆盖两种取法（裸名是实测主路径）。 */
    binder_exception_t e_bare = AServiceManager_addService(binder, DESCRIPTOR);
    binder_exception_t e_def =
        AServiceManager_addService(binder, DESCRIPTOR "/default");
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                        "addService bare=%d default=%d (descriptor %s v%d)",
                        (int)e_bare, (int)e_def, DESCRIPTOR, IFACE_VERSION);

    ABinderProcess_joinThreadPool();
    return 3; /* 不可达 */
}
