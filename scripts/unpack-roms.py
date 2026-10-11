#!/usr/bin/env python3
"""解包 SM-S9380-16（Samsung Galaxy S25 Ultra）构建输入。

Samsung 官方固件是 FUS 加密服务包 `.zip.enc4`（AES-128-ECB-PKCS7），解密后为普通
zip，内含 BL/AP/CP/CSC/HOME_CSC 五个 `.tar.md5`；各分区镜像在 tar 内为 `*.img.lz4`。
本脚本把全流程拆成三个幂等任务：

  decrypt   .zip.enc4 -> .zip（AES-128-ECB，key 取自 manifest 的 enc4-key-hex）
  factory   .zip -> 解出各 *.tar.md5 -> 抽出 *.img.lz4 -> lz4 解压为 *.img，
            **平铺**落 roms/<factory-dir>/（输入分区源，不落 out/）
  super     roms/<factory-dir>/super.img -> lpunpack 拆出 system/vendor/... 逻辑分区，
            同样平铺落 roms/<factory-dir>/

用法（可在任何目录）：
  python3 build/unpack-roms.py                 # decrypt + factory + super
  python3 build/unpack-roms.py decrypt         # 只解密
  python3 build/unpack-roms.py factory         # 只解 tar/lz4
  python3 build/unpack-roms.py super           # 只拆 super
  python3 build/unpack-roms.py super --list     # 只打印 super 逻辑分区清单

enc4 解密 key 的由来（FUS，可复现）：对 SM-S9380/CHC 走 FUS 会话拿到本次固件的
BINARY_SW_VERSION 与 LOGIC_VALUE_FACTORY，令
  logic_check(s, nonce) = "".join(s[b & 0x0f] for b in nonce)
  key = md5(logic_check(BINARY_SW_VERSION, LOGIC_VALUE_FACTORY))
本例 build=S9380ZCSDCZH1/S9380CHCDCZH1/S9380ZCSDCZH1/S9380ZCSDCZH1、
LOGIC_VALUE_FACTORY=vc7nx8wz20hotegd，key 见 manifest。
"""

import glob
import os
import shutil
import struct
import subprocess
import sys
import zipfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import buildenv  # noqa: E402

# Samsung 全量刷机包层；HOME_CSC 与 CSC 内容重叠（home 变体），只取 CSC。
TAR_PREFIXES = ["BL", "AP", "CP", "CSC"]

# 工厂空数据分区，约 8.4G 且内容为空，云机盘集另行生成 data.qcow2，无下游用途。
SKIP_IMAGES = {"userdata.img"}

SECTOR = 512
CHUNK = 16 * 1024 * 1024
TMP_DIR = os.path.join(buildenv.OUT_DIR, "tmp", "unpack-roms")

# AOSP liblp / sparse 常量（来源 liblp/metadata_format.h、libsparse/sparse_format.h）
LP_METADATA_HEADER_MAGIC = 0x414C5030    # "0PLA"
LP_METADATA_GEOMETRY_SIZE = 4096
LP_PARTITION_RESERVED_BYTES = 4096
LP_SECTOR_SIZE = 512
LP_PARTITION_ATTR_SLOT_SUFFIXED = 1 << 1
LP_PARTITION_ATTR_DISABLED = 1 << 3
METADATA_OFFSET = LP_PARTITION_RESERVED_BYTES + LP_METADATA_GEOMETRY_SIZE * 2

SPARSE_MAGIC = 0xED26FF3A
SPARSE_RAW = 0xCAC1
SPARSE_FILL = 0xCAC2
SPARSE_DONT_CARE = 0xCAC3


def _run(cmd, **kw):
    print("  $ " + " ".join(str(c) for c in cmd))
    subprocess.run(cmd, check=True, **kw)


def _copy(src, dst, length):
    remaining = length
    while remaining > 0:
        buf = src.read(min(CHUNK, remaining))
        if not buf:
            raise SystemExit("[err] 镜像读取越界")
        dst.write(buf)
        remaining -= len(buf)


# ---------------- decrypt ----------------

def _enc4_key():
    entry = (buildenv.manifest().get("build") or [{}])[0]
    for b in buildenv.manifest().get("build") or []:
        if b.get("build-id") == buildenv.BUILD_ID:
            entry = b
            break
    key = (entry.get("enc4-key-hex") or "").strip()
    if len(key) != 32:
        raise SystemExit("[err] manifest 缺少有效 enc4-key-hex（32 位 hex）")
    return key


def decrypt_enc4():
    """.zip.enc4 -> .zip（AES-128-ECB-PKCS7）。幂等：zip 已存在且为合法 zip 则跳过。"""
    if buildenv.FACTORY_ZIP and os.path.isfile(buildenv.FACTORY_ZIP):
        with open(buildenv.FACTORY_ZIP, "rb") as f:
            if f.read(4) == b"PK\x03\x04":
                print(f"[skip] 已解密: {buildenv.FACTORY_ZIP}")
                return 0
    if not buildenv.ENC4 or not os.path.isfile(buildenv.ENC4):
        raise SystemExit(f"[err] 找不到加密包: {buildenv.ENC4 or '(未配置)'}")
    key = _enc4_key()
    tmp = buildenv.FACTORY_ZIP + ".part"
    print(f"  解密 {os.path.basename(buildenv.ENC4)}（{os.path.getsize(buildenv.ENC4)} 字节, aes-128-ecb）")
    _run(["openssl", "enc", "-d", "-aes-128-ecb", "-K", key, "-nosalt",
          "-in", buildenv.ENC4, "-out", tmp])
    with open(tmp, "rb") as f:
        if f.read(4) != b"PK\x03\x04":
            os.remove(tmp)
            raise SystemExit("[err] 解密结果不是 zip（key 或包不匹配）")
    os.replace(tmp, buildenv.FACTORY_ZIP)
    print(f"[ok] {os.path.basename(buildenv.FACTORY_ZIP)} ({os.path.getsize(buildenv.FACTORY_ZIP)} 字节)")
    return 0


# ---------------- factory ----------------

def _find_tars():
    """定位 factory-dir 内各层 *.tar.md5（优先已解出的目录，否则从 zip 解）。"""
    found = {}
    for prefix in TAR_PREFIXES:
        hits = sorted(glob.glob(os.path.join(buildenv.ROM_ROOT_DIR, f"{prefix}_*.tar.md5")))
        if hits:
            found[prefix] = hits[0]
    if len(found) == len(TAR_PREFIXES):
        return found
    if not os.path.isfile(buildenv.FACTORY_ZIP):
        raise SystemExit(f"[err] 找不到固件 zip: {buildenv.FACTORY_ZIP}")
    os.makedirs(buildenv.ROM_ROOT_DIR, exist_ok=True)
    with zipfile.ZipFile(buildenv.FACTORY_ZIP) as zf:
        for prefix in TAR_PREFIXES:
            if prefix in found:
                continue
            member = next((n for n in zf.namelist()
                           if os.path.basename(n).startswith(prefix + "_")
                           and n.endswith(".tar.md5")), None)
            if not member:
                raise SystemExit(f"[err] zip 内找不到 {prefix}_*.tar.md5")
            print(f"  解出 {os.path.basename(member)}")
            with zf.open(member) as src, open(os.path.join(buildenv.ROM_ROOT_DIR,
                                                           os.path.basename(member)), "wb") as dst:
                shutil.copyfileobj(src, dst, CHUNK)
            found[prefix] = os.path.join(buildenv.ROM_ROOT_DIR, os.path.basename(member))
    return found


def _lz4_decompress():
    exe = shutil.which("lz4")
    if not exe:
        raise SystemExit("[err] 本机无 lz4（brew install lz4）")
    return exe


def unpack_factory():
    """各 tar.md5 -> 抽出 *.img.lz4 -> lz4 解压为 *.img，平铺落 factory-dir。"""
    lz4 = _lz4_decompress()
    tars = _find_tars()
    for prefix in TAR_PREFIXES:
        tar_path = tars[prefix]
        members = subprocess.run(["tar", "-tf", tar_path], capture_output=True, text=True,
                                 check=True).stdout.splitlines()
        members = [m for m in members
                   if m.endswith(".lz4") and m[:-len(".lz4")] not in SKIP_IMAGES]
        todo = [m for m in members
                if not os.path.isfile(os.path.join(buildenv.ROM_ROOT_DIR,
                                                   m[:-len(".lz4")]))]
        if not todo:
            print(f"[skip] {prefix} 已解压（{len(members)} 个镜像）")
            continue
        print(f"==> [{prefix}] {len(todo)}/{len(members)} 个镜像待解压（{os.path.basename(tar_path)}）")
        work = os.path.join(TMP_DIR, prefix)
        shutil.rmtree(work, ignore_errors=True)
        os.makedirs(work, exist_ok=True)
        # 只抽需要的成员，避免整包展开（AP 含 8.4G userdata 等大件）
        _run(["tar", "-xf", tar_path, "-C", work] + todo)
        for m in todo:
            src = os.path.join(work, m)
            dst = os.path.join(buildenv.ROM_ROOT_DIR, m[:-len(".lz4")])
            if not os.path.isfile(src):
                # tar 内的 meta-data/ 子目录成员等
                continue
            _run([lz4, "-d", "-q", "-f", src, dst])
            os.remove(src)
        shutil.rmtree(work, ignore_errors=True)
    print(f"[ok] 平铺镜像 -> {buildenv.ROM_ROOT_DIR}")
    return 0


# ---------------- super (lpunpack) ----------------

def _read_table(f, hdr, desc):
    off, num, entry_size = desc
    header_size = struct.unpack_from("<I", hdr, 8)[0]
    f.seek(METADATA_OFFSET + header_size + off)
    return f.read(num * entry_size), num, entry_size


def _lunpack_plan(super_path):
    """解析 super 元数据，返回 [(name, [(offset, len), ...]), ...]（不含 disabled）。"""
    with open(super_path, "rb") as f:
        f.seek(METADATA_OFFSET)
        hdr = f.read(256)
        if struct.unpack_from("<I", hdr, 0)[0] != LP_METADATA_HEADER_MAGIC:
            raise SystemExit(f"[err] {super_path} 不是合法 super 镜像")
        pdata, pnum, pesz = _read_table(f, hdr, struct.unpack_from("<III", hdr, 80))
        edata, _en, eesz = _read_table(f, hdr, struct.unpack_from("<III", hdr, 92))
    out = []
    for i in range(pnum):
        e = pdata[i * pesz:(i + 1) * pesz]
        name = e[0:36].split(b"\x00", 1)[0].decode("ascii", "ignore")
        attrs = struct.unpack_from("<I", e, 36)[0]
        first_ext, num_ext = struct.unpack_from("<II", e, 40)
        if not name or (attrs & LP_PARTITION_ATTR_DISABLED):
            continue
        if (attrs & LP_PARTITION_ATTR_SLOT_SUFFIXED) and not name.endswith(("_a", "_b")):
            name += "_a"
        segs = []
        for k in range(num_ext):
            et = edata[(first_ext + k) * eesz:(first_ext + k + 1) * eesz]
            nsectors, ttype, tdata, _tsrc = struct.unpack_from("<QIQI", et, 0)
            if ttype != 0:  # LP_TARGET_TYPE_LINEAR
                continue
            segs.append((tdata * LP_SECTOR_SIZE, nsectors * LP_SECTOR_SIZE))
        out.append((name, segs))
    return out


def _unsparse(path):
    """sparse -> raw 就地替换（Samsung 的 super.img 与个别分区以 sparse 形式下发）。"""
    with open(path, "rb") as f:
        head = f.read(28)
        if len(head) < 28:
            return False
        magic, _maj, _min, fhsz, chsz, blk, total_blks, total_chunks, _csum = struct.unpack(
            "<IHHHHIIII", head)
        if magic != SPARSE_MAGIC:
            return False
        tmp = path + ".raw"
        with open(tmp, "wb") as out:
            f.seek(fhsz)
            for _ in range(total_chunks):
                ctype, _res, csz, tsz = struct.unpack("<HHII", f.read(chsz)[:12])
                if ctype == SPARSE_RAW:
                    remaining = csz * blk
                    while remaining:
                        buf = f.read(min(CHUNK, remaining))
                        if not buf:
                            raise SystemExit("[err] sparse 数据截断")
                        out.write(buf)
                        remaining -= len(buf)
                elif ctype in (SPARSE_FILL, SPARSE_DONT_CARE):
                    block = (f.read(4) * (blk // 4)) if ctype == SPARSE_FILL else b"\x00" * blk
                    pattern = block * (CHUNK // blk + 1)
                    remaining = csz * blk
                    while remaining:
                        n = min(CHUNK, remaining)
                        out.write(pattern[:n])
                        remaining -= n
                else:  # CRC32 块：跳过载荷
                    f.seek(tsz - chsz, os.SEEK_CUR)
        size = os.path.getsize(tmp)
        if size != total_blks * blk:
            os.remove(tmp)
            raise SystemExit(f"[err] sparse 展开大小异常: {size} != {total_blks * blk}")
    os.replace(tmp, path)
    return True


def unpack_super(only_list=False):
    super_img = os.path.join(buildenv.ROM_ROOT_DIR, "super.img")
    if not os.path.isfile(super_img):
        print(f"[skip] 不存在: {super_img}")
        return 0
    if _unsparse(super_img):
        print(f"  super.img 为 sparse，已展开为 raw（{os.path.getsize(super_img)} 字节）")
    plan = _lunpack_plan(super_img)
    if only_list:
        print("super 逻辑分区:")
        for name, segs in plan:
            print(f"  {name:<16} {sum(l for _, l in segs) / 2**30:8.2f} GiB  {len(segs)} 段")
        return 0
    exported = 0
    with open(super_img, "rb") as src:
        for name, segs in plan:
            total = sum(length for _, length in segs)
            if total == 0:
                print(f"[skip] {name} 为空（未使用槽位）")
                continue
            dst_path = os.path.join(buildenv.ROM_ROOT_DIR, f"{name}.img")
            if os.path.isfile(dst_path) and os.path.getsize(dst_path) == total:
                print(f"[skip] {name}.img 已存在")
                continue
            print(f"  逻辑分区 {name} ({total / 2**30:.2f} GiB, {len(segs)} 段)")
            with open(dst_path, "wb") as dst:
                for off, length in segs:
                    src.seek(off)
                    _copy(src, dst, length)
            if _unsparse(dst_path):
                print(f"    (sparse -> raw) {name}.img")
            exported += 1
    print(f"[ok] super 拆出 {exported} 个逻辑分区 -> {buildenv.ROM_ROOT_DIR}")
    return 0


def main():
    argv = [a.lower() for a in sys.argv[1:]]
    only_list = "--list" in argv
    keys = [a for a in argv if not a.startswith("-")]
    if not keys:
        keys = ["decrypt", "factory", "super"]
    for key in keys:
        if key == "decrypt":
            print("=== decrypt (.enc4 -> .zip) ===")
            decrypt_enc4()
        elif key == "factory":
            print("=== factory (tar.md5 -> .img) ===")
            unpack_factory()
        elif key == "super":
            print("=== super (lpunpack) ===")
            unpack_super(only_list=only_list)
        else:
            print(f"[err] 未知任务: {key}（可选: decrypt / factory / super）")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())