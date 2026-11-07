import sys
import os
import re
import math
import struct
import zlib
import threading
import queue

import numpy as np

try:
    import lightgbm
except ImportError:
    lightgbm = None

# 维度布局（940 维 = 旧 1086 - 哈希桶 224 + 语义特征 78）:
#   0-255    字节直方图
#   256-383  128 分块熵
#   384-511  128 分块均值
#   512-639  128 分块字节多样性
#   640-735  节区 16x6
#   736-759  全局头 24
#   760-775  导入统计 16
#   776-799  节区属性 24（逐节可执行位 + 聚合位）
#   800-815  全局扩展 16（签名/.NET/TLS/EP位置/overlay熵/校验和等）
#   816-823  Rich Header 统计 8（纯统计量，无编译器哈希桶）
#   824-831  导出表 8
#   832-843  资源 12
#   844-853  敏感 API 词表 10（强信号低误报核心）
#   854-861  字符串计数 8（URL/IP/注册表/命令解释器/自启动/加密勒索词/总量/均长）
#   862-877  版本信息 RT_VERSION 16（白证据核心）
#   878-891  链接器版本/DOS stub/EP prologue 14
#   892-899  节区名 MSVC Jaccard 8
#   900-911  导入白名单覆盖 12
#   912-919  字符串白名单 8
#   920-927  PDB CodeView 8
#   928-931  时间戳交叉验证 4
#   932-939  文件结构合理性 8
FEATURE_DIM = 940
MALWARE_THRESHOLD = 99
SCAN_WORKERS = 10
BYTE_STAT_CAP = 2 * 1024 * 1024
N_CHUNKS = 128
N_SECTIONS = 16

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(ROOT_DIR, "Model", "SevenML.onnx")

# 节区名分类集合
_MSVC_SECTIONS = {".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc", ".tls", ".didat"}
_DLL_WHITELIST = {
    "kernel32", "user32", "advapi32", "ole32", "oleaut32", "shell32", "comctl32",
    "gdi32", "ws2_32", "msvcrt", "vcruntime140", "ucrtbase", "ntdll", "comdlg32",
    "winmm", "version", "shlwapi", "crypt32", "userenv", "wintrust", "secur32",
    "gdiplus", "d3d9", "dxgi", "opengl32", "msvcp140", "concrt140", "wininet",
    "setupapi", "dbghelp", "psapi", "imm32", "usp10", "dwmapi", "riched20",
    "msimg32", "winhttp", "netapi32", "powrprof", "cabinet", "shcore", "xmllite",
    "dwrite", "msvfw32", "uxtheme", "win32u", "kernelbase",
}
_CRT_INIT_FUNCS = {
    "__scrt_common_main_seh", "_initterm", "_initterm_e",
    "_configure_narrow_argv", "_pei386_runtime_relocator", "__report_gsfailure",
}
_PROLOGUES = [
    b"\x55\x8b\xec", b"\x48\x89\x5c\x24", b"\x55\x48\x8b\xec", b"\x40\x53",
    b"\x48\x83\xec", b"\x48\x89\xe5",
]
_COMPANY_WHITELIST = [
    "microsoft", "google", "adobe", "apple", "tencent", "nvidia", "intel",
    "vmware", "oracle", "mozilla", "valve", "discord", "7-zip", "igor pavlov",
    "python software", "jetbrains", "the qt company", "bilibili", "netease",
    "alibaba", "bytedance", "vim", "gcc", "gnu", "lwip", "openssl",
]
_STRING_WHITE_KEYS = [
    b"copyright", b"all rights reserved", b"version", b"company",
    b"microsoft", b".com", b"windows", b"license",
]
_COMMON_SECTIONS = {
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".tls", ".rsrc",
    ".reloc", ".pdata", ".debug", ".crt", ".gfx", ".didata", ".xdata", ".edata",
    "idata", "edata", "bss", "tls", "rsrc", "reloc", "pdata", "text", "data", "rdata",
}
_PACKER_SECTIONS = {
    "upx0", "upx1", "upx2", "upx!", "aspack", "adata", "aspack1", "aspack2",
    "enigma1", "enigma2", "themida", "winlicen", "vmp0", "vmp1", "vmp2",
    "mpress1", "mpress2", "petite", "pec1", "pec2", "pebundle", "mew", "nsp0", "nsp1", "nsp2",
}
# 敏感 API 词表（函数名去 A/W 后缀小写匹配），仅保留 10 个最强低误报核心：
# 正规软件极少直接导入，命中即高价值信号
_SENSITIVE_APIS = [
    "createremotethread",      # 远程线程注入
    "writeprocessmemory",      # 跨进程写内存
    "ntunmapviewofsection",    # 进程镂空（hollowing）
    "queueuserapc",            # APC 注入
    "setthreadcontext",        # 线程上下文劫持
    "setwindowshookex",        # 全局钩子/键盘记录
    "urldownloadtofile",       # 下载执行
    "cryptencrypt",            # 加密（勒索核心）
    "systemfunction032",       # 流加密混淆（勒索常用）
    "ldrgetprocedureaddress",  # 隐蔽动态解析
]
_API_INDEX = {name: i for i, name in enumerate(_SENSITIVE_APIS)}
assert len(_SENSITIVE_APIS) == 10, len(_SENSITIVE_APIS)

_STR_RE = re.compile(rb"[\x20-\x7E]{5,}")
_IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def is_pe(data):
    return isinstance(data, (bytes, bytearray)) and len(data) >= 64 and data[0:2] == b"MZ"


def _chunk_stats(arr):
    pad = (-arr.size) % N_CHUNKS
    if pad:
        arr = np.concatenate([arr, np.zeros(pad, dtype=np.uint8)])
    blocks = arr.reshape(N_CHUNKS, -1)
    ents = np.zeros(N_CHUNKS, dtype=np.float64)
    means = np.zeros(N_CHUNKS, dtype=np.float64)
    divs = np.zeros(N_CHUNKS, dtype=np.float64)
    arange = np.arange(256, dtype=np.float64)
    for i in range(N_CHUNKS):
        b = blocks[i]
        n = b.size
        c = np.bincount(b, minlength=256).astype(np.float64)
        p = c[c > 0] / n
        ents[i] = float(-(p * np.log2(p)).sum()) if p.size else 0.0
        means[i] = float(c @ arange) / n
        divs[i] = float(np.count_nonzero(c)) / 256.0
    return ents, means, divs


def _read_cstr(data, off, limit=256):
    if off is None or off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off, off + limit)
    if end < 0:
        end = min(off + limit, len(data))
    return data[off:end].decode("latin-1", "ignore")


def _rva_to_off(rva, sections):
    for s in sections:
        span = max(s["vsize"], s["rawsize"], 1)
        if s["vaddr"] <= rva < s["vaddr"] + span:
            delta = rva - s["vaddr"]
            if delta < s["rawsize"]:
                return s["rawptr"] + delta
            return None
    return None


def _parse_pe(data):
    info = {
        "sections": [],
        "dlls": [],
        "funcs": [],
        "pe32plus": False,
        "global": None,
        "dd": [],
        "e_lfanew": 0,
        "imagebase": 0,
        "checksum": 0,
        "tstamp": 0,
        "ep": 0,
        "ordinal_count": 0,
    }
    if len(data) < 0x40:
        return info
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return info
    machine, nsec, tstamp, symptr, symnum, optsize, chars = struct.unpack_from(
        "<HHIIIHH", data, e_lfanew + 4
    )
    off = e_lfanew + 24
    if off + optsize > len(data) or optsize < 70:
        return info
    magic = struct.unpack_from("<H", data, off)[0]
    if magic == 0x20B:
        pe32plus = True
        dd_base = off + 112
    elif magic == 0x10B:
        pe32plus = False
        dd_base = off + 96
    else:
        return info
    if dd_base + 128 > len(data):
        dd_base = -1

    sizecode, sizeinit, sizeuninit = struct.unpack_from("<III", data, off + 4)
    ep, basecode = struct.unpack_from("<II", data, off + 16)
    sizeimage, sizeheaders, checksum = struct.unpack_from("<III", data, off + 56)
    subsystem, dllchar = struct.unpack_from("<HH", data, off + 68)
    rva_and_sizes = struct.unpack_from("<I", data, off + (108 if pe32plus else 92))[0]

    data_dirs = []
    if dd_base > 0:
        for i in range(16):
            rva, sz = struct.unpack_from("<II", data, dd_base + i * 8)
            data_dirs.append((rva, sz))
    info["dd"] = data_dirs

    sec_off = off + optsize
    sections = []
    for i in range(min(nsec, N_SECTIONS)):
        so = sec_off + i * 40
        if so + 40 > len(data):
            break
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, so + 8)
        schar = struct.unpack_from("<I", data, so + 36)[0]
        sname = data[so:so + 8].decode("latin-1", "ignore").rstrip("\x00 \t")
        raw = data[rawptr:rawptr + min(rawsize, BYTE_STAT_CAP)] if rawptr + rawsize <= len(data) else data[rawptr:rawptr + max(rawsize, 0)]
        if len(raw) > 1:
            n = len(raw)
            arr = np.frombuffer(raw, dtype=np.uint8)
            c = np.bincount(arr, minlength=256).astype(np.float64)
            p = c[c > 0] / n
            sent = float(-(p * np.log2(p)).sum()) if p.size else 0.0
        else:
            sent = 0.0
        sections.append({
            "vsize": vsize, "vaddr": vaddr, "rawsize": rawsize,
            "rawptr": rawptr, "char": schar, "entropy": sent, "name": sname,
        })
        info["sections"] = sections

    info["e_lfanew"] = e_lfanew
    info["tstamp"] = tstamp
    info["ep"] = ep
    info["checksum"] = checksum
    info["sizecode"] = sizecode
    info["sizeinit"] = sizeinit
    info["sizeimage"] = sizeimage
    info["sizeheaders"] = sizeheaders
    info["linker"] = struct.unpack_from("<BB", data, off + 2) if off + 4 <= len(data) else (0, 0)
    info["filealign"] = struct.unpack_from("<I", data, off + 36)[0] if off + 40 <= len(data) else 0
    info["secalign"] = struct.unpack_from("<I", data, off + 32)[0] if off + 36 <= len(data) else 0
    dos = data[0x40:min(e_lfanew, 0x40 + 256)] if e_lfanew > 0x40 else b""
    info["dos_msg"] = b"This program cannot be run in DOS mode" in dos
    if pe32plus:
        info["imagebase"] = struct.unpack_from("<Q", data, off + 24)[0] if off + 32 <= len(data) else 0
    else:
        info["imagebase"] = struct.unpack_from("<I", data, off + 28)[0] if off + 32 <= len(data) else 0

    max_end = max((s["rawptr"] + s["rawsize"]) for s in sections) if sections else 0
    overlay = max(0, len(data) - max_end)

    ep_off = _rva_to_off(ep, sections) if ep else None
    info["ep_off"] = ep_off
    ep_bytes = data[ep_off:ep_off + 256] if ep_off is not None else b""
    if len(ep_bytes) > 1:
        n = len(ep_bytes)
        arr = np.frombuffer(ep_bytes, dtype=np.uint8)
        c = np.bincount(arr, minlength=256).astype(np.float64)
        p = c[c > 0] / n
        ep_entropy = float(-(p * np.log2(p)).sum()) if p.size else 0.0
    else:
        ep_entropy = 0.0

    head = data[:1024]
    n = len(head)
    arr = np.frombuffer(head, dtype=np.uint8)
    c = np.bincount(arr, minlength=256).astype(np.float64)
    p = c[c > 0] / n
    head_entropy = float(-(p * np.log2(p)).sum()) if p.size else 0.0

    imp_rva, imp_size = data_dirs[1] if len(data_dirs) > 1 else (0, 0)
    res_size = data_dirs[2][1] if len(data_dirs) > 2 else 0
    tls_size = data_dirs[9][1] if len(data_dirs) > 9 else 0
    bound_size = data_dirs[11][1] if len(data_dirs) > 11 else 0
    iat_size = data_dirs[12][1] if len(data_dirs) > 12 else 0
    delay_size = data_dirs[13][1] if len(data_dirs) > 13 else 0

    info["global"] = [
        machine / 65535.0,
        min(nsec, 16) / 16.0,
        (tstamp % 1000000) / 1000000.0,
        min(optsize, 480) / 480.0,
        chars / 65535.0,
        magic / 547.0,
        sizecode / 4194304.0,
        sizeinit / 4194304.0,
        sizeuninit / 4194304.0,
        ep / 4194304.0,
        basecode / 4194304.0,
        sizeimage / 33554432.0,
        sizeheaders / 65536.0,
        checksum / 4294967295.0,
        subsystem / 20.0,
        dllchar / 65535.0,
        rva_and_sizes / 16.0,
        imp_size / 65536.0,
        res_size / 4194304.0,
        tls_size / 1024.0,
        ep_entropy,
        head_entropy,
        overlay / max(len(data), 1),
        1.0 if any(s["vaddr"] <= ep < s["vaddr"] + max(s["vsize"], 1) for s in sections) else 0.0,
        bound_size / 65536.0,
        iat_size / 65536.0,
        delay_size / 65536.0,
        symptr / 4194304.0,
        min(symnum, 65535) / 65535.0,
        min(len(data), 16777216) / 16777216.0,
    ]
    if len(info["global"]) < 24:
        info["global"] = (info["global"] + [0.0] * 24)[:24]
    else:
        info["global"] = info["global"][:24]

    if imp_rva and imp_size:
        imp_off = _rva_to_off(imp_rva, sections)
        if imp_off is not None:
            step_thunk = 8 if pe32plus else 4
            ordinal_flag = 1 << (63 if pe32plus else 31)
            cur = imp_off
            func_total = 0
            ordinal_total = 0
            for _ in range(4096):
                if cur + 20 > len(data):
                    break
                oft, _ts, _fc, name_rva, ft = struct.unpack_from("<IIIII", data, cur)
                if oft == 0 and name_rva == 0 and ft == 0:
                    break
                dll = _read_cstr(data, _rva_to_off(name_rva, sections))
                if dll:
                    info["dlls"].append(dll)
                thunk_rva = oft if oft else ft
                toff = _rva_to_off(thunk_rva, sections) if thunk_rva else None
                cnt = 0
                if toff is not None:
                    t = toff
                    while cnt < 8192 and func_total < 16384:
                        if t + step_thunk > len(data):
                            break
                        val = struct.unpack_from("<Q" if pe32plus else "<I", data, t)[0]
                        if val == 0:
                            break
                        if not (val & ordinal_flag):
                            hoff = _rva_to_off(val & 0x7FFFFFFF, sections)
                            fname = _read_cstr(data, hoff + 2 if hoff is not None else None)
                            if fname:
                                info["funcs"].append(fname)
                        else:
                            ordinal_total += 1
                        cnt += 1
                        func_total += 1
                        t += step_thunk
                cur += 20
            info["ordinal_count"] = ordinal_total
    return info


def _entropy(raw):
    if len(raw) < 2:
        return 0.0
    arr = np.frombuffer(raw, dtype=np.uint8)
    c = np.bincount(arr, minlength=256).astype(np.float64)
    p = c[c > 0] / arr.size
    return float(-(p * np.log2(p)).sum())


def _checksum_valid(data, info):
    """PE 校验和验证（DWORD 累加算法，与 pefile.generate_checksum 一致，numpy 加速）。返回 0/1。"""
    cval = info.get("checksum", 0)
    if not cval:
        return 0.0
    e_lfanew = info.get("e_lfanew", 0)
    cf = e_lfanew + 24 + 64  # OptionalHeader.CheckSum 字段偏移
    arr = np.frombuffer(data, dtype=np.uint8)
    orig_len = arr.size
    pad = (-arr.size) % 4
    if pad:
        arr = np.concatenate([arr, np.zeros(pad, dtype=np.uint8)])
    d = arr.view("<u4").astype(np.uint64)
    if cf % 4 == 0 and cf + 4 <= arr.size:
        d[cf // 4] = 0
    s = int(d.sum())
    while s >= 4294967296:
        s = (s & 0xFFFFFFFF) + (s >> 32)
    s = (s & 0xFFFF) + (s >> 16)
    s = s + (s >> 16)
    s = (s & 0xFFFF) + orig_len
    return 1.0 if s == cval else 0.0


def _tls_callback_count(data, info):
    dd = info.get("dd") or []
    if len(dd) <= 9:
        return 0.0
    rva, size = dd[9]
    if not rva or size < 16:
        return 0.0
    off = _rva_to_off(rva, info["sections"])
    if off is None:
        return 0.0
    plus = info.get("pe32plus", False)
    cb_field = off + (24 if plus else 12)  # AddressOfCallBacks
    field_size = 8 if plus else 4
    if cb_field + field_size > len(data):
        return 0.0
    va = struct.unpack_from("<Q" if plus else "<I", data, cb_field)[0]
    if not va:
        return 0.0
    coff = _rva_to_off(va - info.get("imagebase", 0), info["sections"])
    if coff is None:
        return 0.0
    cnt = 0
    while cnt < 64 and coff + field_size <= len(data):
        v = struct.unpack_from("<Q" if plus else "<I", data, coff)[0]
        if v == 0:
            break
        cnt += 1
        coff += field_size
    return float(cnt)


def _rich_info(data, e_lfanew):
    """解析 Rich Header，返回 (编译器id列表, 计数列表, rich偏移) 或 None。"""
    limit = min(e_lfanew, len(data))
    if limit < 16:
        return None
    idx = data.find(b"Rich", 0, limit)
    if idx < 8 or idx + 8 > len(data):
        return None
    key = struct.unpack_from("<I", data, idx + 4)[0]
    dans = struct.pack("<I", 0x536E6144 ^ key)
    start = data.find(dans, 0, idx)
    if start < 0:
        return None
    ids, counts = [], []
    p = start + 16
    while p + 8 <= idx and len(ids) < 512:
        a, b = struct.unpack_from("<II", data, p)
        a ^= key
        b ^= key
        if a == 0 and b == 0:
            break
        ids.append(a)
        counts.append(b)
        p += 8
    return ids, counts, idx


def _export_feats(data, info):
    feats = np.zeros(8, dtype=np.float64)
    dd = info.get("dd") or []
    if not dd:
        return feats
    rva, size = dd[0]
    if not rva or not size:
        return feats
    off = _rva_to_off(rva, info["sections"])
    if off is None or off + 40 > len(data):
        return feats
    _c, _tds, _maj, _min, _nm, _base, nfuncs, nnames, afuncs, anames, _ao = \
        struct.unpack_from("<IIHHIIIIIII", data, off)
    nfuncs = min(nfuncs, 65536)
    nnames = min(nnames, 65536)
    feats[0] = 1.0 if nfuncs else 0.0
    feats[1] = nfuncs / 8192.0
    feats[2] = nnames / max(nfuncs, 1)
    feats[6] = min(size, 65536) / 65536.0
    feats[7] = 1.0 if (nfuncs and not nnames) else 0.0
    # 转发占比
    foff = _rva_to_off(afuncs, info["sections"])
    fwd = 0
    if foff is not None:
        checked = min(nfuncs, 1024)
        for i in range(checked):
            if foff + i * 4 + 4 > len(data):
                break
            frva = struct.unpack_from("<I", data, foff + i * 4)[0]
            if rva <= frva < rva + size:
                fwd += 1
        feats[3] = fwd / max(checked, 1)
    # 导出名熵与平均长度
    noff = _rva_to_off(anames, info["sections"])
    if noff is not None and nnames:
        total_len = 0
        ent_blob = bytearray()
        cnt = min(nnames, 2048)
        for i in range(cnt):
            if noff + i * 4 + 4 > len(data):
                break
            nrva = struct.unpack_from("<I", data, noff + i * 4)[0]
            nm = _read_cstr(data, _rva_to_off(nrva, info["sections"]), limit=128)
            total_len += len(nm)
            ent_blob.extend(nm.encode("latin-1", "ignore"))
        if total_len:
            feats[4] = (total_len / cnt) / 64.0
            feats[5] = min(_entropy(bytes(ent_blob[:65536])), 8.0) / 8.0
    return feats


def _walk_res(data, dir_off, base, sections, depth, tid, out):
    if depth > 3 or len(out) >= 512:
        return
    if dir_off + 16 > len(data):
        return
    _c, _tds, _maj, _min, nnamed, nid = struct.unpack_from("<IIHHHH", data, dir_off)
    n = min(nnamed + nid, 4096)
    for i in range(n):
        if len(out) >= 512:
            return
        eo = dir_off + 16 + i * 8
        if eo + 8 > len(data):
            return
        _nm, nxt = struct.unpack_from("<II", data, eo)
        cur_tid = (i if i < nid else -1) if depth == 1 else tid
        if nxt & 0x80000000:
            _walk_res(data, base + (nxt & 0x7FFFFFFF), base, sections, depth + 1, cur_tid, out)
        else:
            lo = base + nxt
            if lo + 16 <= len(data):
                drva, dsize = struct.unpack_from("<II", data, lo)
                out.append((cur_tid, drva, dsize))


def _resource_feats(data, info):
    feats = np.zeros(12, dtype=np.float64)
    dd = info.get("dd") or []
    if not dd or len(dd) <= 2:
        return feats
    rva, size = dd[2]
    if not rva or not size:
        return feats
    base = _rva_to_off(rva, info["sections"])
    if base is None:
        return feats
    leaves = []
    _walk_res(data, base, base, info["sections"], 1, -1, leaves)
    if not leaves:
        return feats
    total = sum(min(s, 16777216) for _, _r, s in leaves)
    maxs = max(min(s, 16777216) for _, _r, s in leaves)
    ents = []
    types = set()
    for tid, drva, dsize in leaves:
        types.add(tid)
        off = _rva_to_off(drva, info["sections"])
        if off is None:
            continue
        raw = data[off:off + min(dsize, 262144)]
        ents.append(_entropy(raw))
    feats[0] = len(leaves) / 64.0
    feats[1] = total / max(len(data), 1)
    feats[2] = maxs / max(len(data), 1)
    if ents:
        feats[3] = sum(ents) / len(ents) / 8.0
        feats[4] = max(ents) / 8.0
    flags = {
        5: 5, 16: 6, 24: 7, 3: 8, 6: 9, 2: 10,
    }
    known = set(flags) | {1, 4}
    feats[11] = 1.0 if any(t not in known for t in types) else 0.0
    for t, pos in flags.items():
        if t in types:
            feats[pos] = 1.0
    return feats


def _string_feats(data):
    """字符串计数特征 8 维（无哈希桶，仅精确关键词计数，避免误报噪声）。"""
    counters = np.zeros(8, dtype=np.float64)
    region = data[:BYTE_STAT_CAP]
    strs = _STR_RE.findall(region)
    total = len(strs)
    if not total:
        return counters
    sample = strs if total <= 20000 else strs[::max(1, total // 20000)][:20000]
    lensum = 0
    for s in sample:
        lensum += len(s)
        low = s.lower()
        if b"http://" in low or b"https://" in low or b"ftp://" in low:
            counters[0] += 1.0
        if _IP_RE.search(s):
            counters[1] += 1.0
        if b"hkey_" in low or b"software\\" in low or b"currentversion" in low:
            counters[2] += 1.0
        if (b"cmd.exe" in low or b"powershell" in low or b"wscript" in low
                or b"rundll32" in low or b"regsvr32" in low or b"mshta" in low):
            counters[3] += 1.0
        if b"currentversion\\run" in low or b"schtasks" in low or b"\\startup" in low:
            counters[4] += 1.0
        if b"crypt" in low or b".locked" in low or b"decrypt" in low or b"readme" in low:
            counters[5] += 1.0
    ns = len(sample)
    for i in range(6):
        counters[i] = min(counters[i], 100) / 100.0
    counters[6] = min(total, 20000) / 20000.0
    counters[7] = (lensum / max(ns, 1)) / 128.0
    return counters


def _api_feats(info):
    feats = np.zeros(len(_SENSITIVE_APIS), dtype=np.float64)
    if not info["funcs"]:
        return feats
    counts = {}
    for f in info["funcs"]:
        base = f.lower()
        if len(base) > 2 and base[-1] in ("a", "w") and not base[-2].isdigit():
            base = base[:-1]
        if base in _API_INDEX:
            counts[base] = counts.get(base, 0) + 1
    for name, c in counts.items():
        feats[_API_INDEX[name]] = min(c, 8) / 8.0
    return feats


def _version_feats(data, info):
    """RT_VERSION 解析 16 维：正常软件几乎必有，恶意常缺。"""
    feats = np.zeros(16, dtype=np.float64)
    dd = info.get("dd") or []
    if not dd or len(dd) <= 2:
        return feats
    rva, size = dd[2]
    if not rva or not size:
        return feats
    base = _rva_to_off(rva, info["sections"])
    if base is None:
        return feats
    leaves = []
    _walk_res(data, base, base, info["sections"], 1, -1, leaves)
    blobs = []
    for tid, drva, dsize in leaves:
        if tid == 16:
            off = _rva_to_off(drva, info["sections"])
            if off is not None:
                blobs.append(data[off:off + min(dsize, 262144)])
    if not blobs:
        return feats
    feats[0] = 1.0
    blob = b"\x00".join(blobs[:8])[:1048576]
    text = blob.decode("utf-16-le", "ignore").lower()
    feats[1] = 1.0 if "companyname" in text else 0.0
    feats[2] = 1.0 if any(w in text for w in _COMPANY_WHITELIST) else 0.0
    feats[3] = 1.0 if "productname" in text else 0.0
    feats[4] = 1.0 if "fileversion" in text else 0.0
    feats[5] = 1.0 if re.search(r"fileversion[\x00-\x1f ]+(\d+(?:\.\d+){1,3})", text) else 0.0
    feats[6] = 1.0 if "legalcopyright" in text else 0.0
    feats[7] = 1.0 if "originalfilename" in text else 0.0
    feats[8] = 1.0 if "filedescription" in text else 0.0
    feats[9] = 1.0 if "productversion" in text else 0.0
    feats[10] = 1.0 if "varfileinfo" in text else 0.0
    feats[11] = 1.0 if "internalname" in text else 0.0
    feats[12] = min(_entropy(blob[:262144]), 8.0) / 8.0
    feats[13] = len(blobs) / 8.0
    feats[14] = min(len(blob), 262144) / 262144.0
    feats[15] = 1.0 if "stringfileinfo" in text else 0.0
    return feats


def _linker_dos_ep_feats(data, info):
    """链接器版本 / DOS stub / EP prologue 14 维。"""
    feats = np.zeros(14, dtype=np.float64)
    maj, mn = info.get("linker", (0, 0))
    feats[0] = maj / 20.0
    feats[1] = mn / 20.0
    feats[2] = 1.0 if info.get("dos_msg") else 0.0
    e_lfanew = info.get("e_lfanew", 0)
    stub = data[0x40:min(e_lfanew, 0x40 + 128)] if e_lfanew > 0x40 else b""
    std_head = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
    feats[3] = 1.0 if (len(stub) >= 64 and stub[:14] == std_head) else 0.0
    ep_off = info.get("ep_off")
    epb = data[ep_off:ep_off + 16] if ep_off is not None else b""
    if epb:
        for i, pat in enumerate(_PROLOGUES):
            if epb.startswith(pat):
                feats[4 + i] = 1.0
        ep = info.get("ep", 0)
        ep_sec = next((s for s in info["sections"]
                       if s["vaddr"] <= ep < s["vaddr"] + max(s["vsize"], 1)), None)
        feats[10] = 1.0 if (ep_sec is not None and ep_sec["name"].lower().lstrip(".") == "text") else 0.0
        feats[11] = 1.0 if len(set(epb)) <= 3 else 0.0
        feats[12] = 1.0 if any(feats[4 + i] for i in range(len(_PROLOGUES))) else 0.0
        feats[13] = min(_entropy(data[ep_off:ep_off + 64]), 8.0) / 8.0
    return feats


def _sec_jaccard_feats(info):
    """节区名 MSVC 白名单 Jaccard 8 维。"""
    feats = np.zeros(8, dtype=np.float64)
    names = {s["name"].lower() for s in info["sections"]}
    if not names:
        return feats
    feats[0] = len(names & _MSVC_SECTIONS) / max(len(names | _MSVC_SECTIONS), 1)
    feats[1] = 1.0 if ".pdata" in names else 0.0
    feats[2] = 1.0 if 3 <= len(info["sections"]) <= 8 else 0.0
    blob = "".join(sorted(names)).encode("latin-1", "ignore")
    feats[3] = min(_entropy(blob[:4096]), 5.0) / 5.0
    ordered = [s["name"].lower().lstrip(".") for s in info["sections"]]
    feats[4] = 1.0 if (ordered and ordered[0] == "text") else 0.0
    feats[5] = 1.0 if all(c in "abcdefghijklmnopqrstuvwxyz0123456789_.$-" for nm in names for c in nm) else 0.0
    feats[6] = 1.0 if ".rdata" in names else 0.0
    feats[7] = 1.0 if (".reloc" in names or ".rsrc" in names) else 0.0
    return feats


def _import_cov_feats(info):
    """导入白名单覆盖 12 维：导入表像不像正常软件。"""
    feats = np.zeros(12, dtype=np.float64)
    dlls = []
    for d in info["dlls"]:
        dl = d.lower()
        if dl.endswith(".dll"):
            dl = dl[:-4]
        dlls.append(dl)
    funcs = info["funcs"]
    nd = len(dlls)
    nf = len(funcs)
    if not nd:
        return feats
    hits = sum(1 for d in dlls if d in _DLL_WHITELIST or d.startswith("api-ms-win"))
    feats[0] = hits / nd
    feats[1] = 1.0 if "kernel32" in dlls else 0.0
    feats[2] = 1.0 if "user32" in dlls else 0.0
    feats[3] = 1.0 if "advapi32" in dlls else 0.0
    feats[4] = 1.0 if any(f.lower() in _CRT_INIT_FUNCS for f in funcs) else 0.0
    feats[5] = 1.0 if 20 <= nf <= 2000 else 0.0
    feats[6] = (sum(len(f) for f in funcs) / max(nf, 1)) / 32.0
    blob = "".join(funcs[:8192]).encode("latin-1", "ignore")
    feats[7] = min(_entropy(blob[:65536]), 8.0) / 8.0
    feats[8] = (sum(len(d) for d in dlls) / nd) / 32.0
    feats[9] = sum(1 for d in dlls if d.startswith("api-ms-win")) / nd
    feats[10] = 1.0 if any(d in ("msvcrt", "vcruntime140", "ucrtbase", "msvcp140") for d in dlls) else 0.0
    feats[11] = 1.0 if 2 <= nd <= 40 else 0.0
    return feats


def _string_white_feats(data):
    """字符串白名单 8 维：正常软件高频关键词。"""
    feats = np.zeros(8, dtype=np.float64)
    region = data[:BYTE_STAT_CAP]
    strs = _STR_RE.findall(region)
    total = len(strs)
    if not total:
        return feats
    sample = strs if total <= 20000 else strs[::max(1, total // 20000)][:20000]
    for s in sample:
        low = s.lower()
        for i, k in enumerate(_STRING_WHITE_KEYS):
            if k in low:
                feats[i] += 1.0
    for i in range(8):
        feats[i] = min(feats[i], 100) / 100.0
    return feats


def _pdb_feats(data, info):
    """Debug 目录 / CodeView PDB 8 维。"""
    feats = np.zeros(8, dtype=np.float64)
    dd = info.get("dd") or []
    if not dd or len(dd) <= 6:
        return feats
    rva, size = dd[6]
    if not rva or not size:
        return feats
    off = _rva_to_off(rva, info["sections"])
    if off is None:
        return feats
    feats[0] = 1.0
    types = set()
    rsds = False
    pdb_path = b""
    repro = False
    n = min(size // 28, 64)
    for i in range(n):
        eo = off + i * 28
        if eo + 28 > len(data):
            break
        _c, _tds, _maj, _min, typ, _sz, _arva, prva = struct.unpack_from("<IIIIIIII", data, eo)
        types.add(typ)
        if typ == 2:
            rd = _rva_to_off(prva, info["sections"])
            if rd is not None and rd + 24 <= len(data) and data[rd:rd + 4] == b"RSDS":
                rsds = True
                pend = data.find(b"\x00", rd + 24, rd + 24 + 512)
                pdb_path = data[rd + 24:pend if pend > 0 else rd + 24 + 512]
        elif typ == 16:
            repro = True
    feats[1] = 1.0 if 2 in types else 0.0
    feats[2] = 1.0 if rsds else 0.0
    feats[3] = 1.0 if b"\\" in pdb_path else 0.0
    feats[4] = min(_entropy(pdb_path[:512]), 8.0) / 8.0 if pdb_path else 0.0
    feats[5] = 1.0 if repro else 0.0
    feats[6] = 1.0 if pdb_path.lower().endswith(b".pdb") else 0.0
    feats[7] = len(types) / 8.0
    return feats


def _ts_cross_feats(data, info):
    """时间戳交叉验证 4 维。"""
    feats = np.zeros(4, dtype=np.float64)
    ts = int(info.get("tstamp", 0))
    year = 1970 + ts // 31536000
    feats[0] = 1.0 if 1998 <= year <= 2028 else 0.0
    dd = info.get("dd") or []
    if dd and len(dd) > 6 and dd[6][0]:
        off = _rva_to_off(dd[6][0], info["sections"])
        if off is not None and off + 28 <= len(data):
            tsdbg = struct.unpack_from("<I", data, off + 4)[0]
            if tsdbg:
                feats[1] = 1.0 if abs(tsdbg - ts) <= 7 * 86400 else 0.0
                feats[2] = 1.0 if tsdbg == ts else 0.0
    feats[3] = 1.0 if (0 < ts < 2147483647 and year >= 2015) else 0.0
    return feats


def _struct_sane_feats(data, info):
    """文件结构合理性 8 维。"""
    feats = np.zeros(8, dtype=np.float64)
    fa = info.get("filealign", 0)
    sa = info.get("secalign", 0)
    feats[0] = 1.0 if fa in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536) else 0.0
    feats[1] = 1.0 if sa >= fa else 0.0
    feats[2] = 1.0 if (sa in (4096, 8192, 16384, 65536) or sa == fa) else 0.0
    sections = info["sections"]
    sumv = sum(s["vsize"] for s in sections)
    sizeimage = info.get("sizeimage", 0)
    feats[3] = 1.0 if (sumv and 1.0 <= sizeimage / max(sumv, 1) <= 2.5) else 0.0
    n = max(len(data), 1)
    feats[4] = min(info.get("sizecode", 0) / n, 1.0)
    feats[5] = min(info.get("sizeinit", 0) / n, 1.0)
    dd = info.get("dd") or []
    feats[6] = min((dd[2][1] if len(dd) > 2 else 0) / n, 1.0)
    feats[7] = 1.0 if (sizeimage and info.get("sizeheaders", 0) / sizeimage < 0.1) else 0.0
    return feats


def _extra_feats(data, info):
    """追加的 164 维：节区属性 24 + 全局扩展 16 + Rich 统计 8 + 导出 8 + 资源 12 + API 10 + 字符串 8
    + 版本信息 16 + 链接器/DOS/EP 14 + 节区 Jaccard 8 + 导入覆盖 12 + 字符串白名单 8 + PDB 8 + 时间戳交叉 4 + 结构合理性 8"""
    sections = info["sections"]
    ep = info.get("ep", 0)

    # ---- A. 节区属性 24 ----
    sec_char = np.zeros(24, dtype=np.float64)
    nsec = len(sections)
    if nsec:
        exec_flags = [(s["char"] & 0x20000000) != 0 for s in sections]
        for i in range(min(nsec, 16)):
            sec_char[i] = 1.0 if exec_flags[i] else 0.0
        wx = [(s["char"] & 0x20000000) and (s["char"] & 0x80000000) for s in sections]
        sec_char[16] = sum(wx) / nsec
        sec_char[17] = 1.0 if any(wx) else 0.0
        ep_sec = next((i for i, s in enumerate(sections)
                       if s["vaddr"] <= ep < s["vaddr"] + max(s["vsize"], 1)), None)
        sec_char[18] = 1.0 if (ep_sec is not None and ep_sec < len(wx) and wx[ep_sec]) else 0.0
        sec_char[19] = sum(1 for s in sections if s["char"] & 0x20) / nsec
        sec_char[20] = sum(1 for s in sections if s["rawsize"] == 0 and s["vsize"] > 0) / nsec
        names = [s["name"].lower().lstrip(".") for s in sections]
        sec_char[21] = 1.0 - sum(1 for nm in names if nm in _COMMON_SECTIONS) / nsec
        sec_char[22] = 1.0 if any(nm in _PACKER_SECTIONS for nm in names) else 0.0
        sec_char[23] = sum(1 for s in sections if s["vsize"] > s["rawsize"] * 2) / nsec

    # ---- B. 全局扩展 16 ----
    dd = info.get("dd") or []
    glob = np.zeros(16, dtype=np.float64)
    if dd:
        cert_rva, cert_size = dd[4] if len(dd) > 4 else (0, 0)
        glob[0] = 1.0 if cert_size else 0.0
        glob[1] = min(cert_size, 65536) / 65536.0
        glob[2] = 1.0 if (len(dd) > 14 and dd[14][1]) else 0.0  # .NET COM dir
        glob[3] = 1.0 if (len(dd) > 9 and dd[9][1]) else 0.0
        glob[4] = _tls_callback_count(data, info) / 64.0
        ep_sec = next((i for i, s in enumerate(sections)
                       if s["vaddr"] <= ep < s["vaddr"] + max(s["vsize"], 1)), None)
        if ep_sec is not None:
            glob[5] = 1.0 if ep_sec == len(sections) - 1 else 0.0
            s = sections[ep_sec]
            glob[6] = (ep - s["vaddr"]) / max(s["vsize"], 1)
            glob[12] = 1.0 if s["char"] & 0x80000000 else 0.0
        max_end = max((s["rawptr"] + s["rawsize"]) for s in sections) if sections else 0
        overlay_raw = data[max_end:max_end + 1048576]
        glob[7] = _entropy(overlay_raw) / 8.0
        glob[9] = 1.0 if (len(dd) > 6 and dd[6][1]) else 0.0
        glob[10] = sum(1 for r, s2 in dd if r and s2) / 16.0
        glob[13] = 1.0 if any(
            sections[i]["rawptr"] < sections[j]["rawptr"] + sections[j]["rawsize"]
            and sections[j]["rawptr"] < sections[i]["rawptr"] + sections[i]["rawsize"]
            for i in range(nsec) for j in range(i + 1, nsec)
            if sections[i]["rawsize"] and sections[j]["rawsize"]
        ) else 0.0
        glob[14] = 1.0 if (len(dd) > 10 and dd[10][1]) else 0.0
        glob[15] = 1.0 if (len(dd) > 5 and dd[5][1]) else 0.0
    ts = info.get("tstamp", 0)
    glob[11] = 1.0 if (ts == 0 or ts > 2147483647) else 0.0
    glob[8] = _checksum_valid(data, info)

    # ---- C. Rich Header 统计 8 ----
    rich = np.zeros(8, dtype=np.float64)
    ri = _rich_info(data, info.get("e_lfanew", 0))
    if ri:
        ids, counts, ridx = ri
        if ids:
            prods = {a >> 16 for a in ids}
            builds = {a & 0xFFFF for a in ids}
            rich[0] = 1.0
            rich[1] = len(ids) / 512.0
            rich[2] = len(prods) / 256.0
            rich[3] = len(builds) / 1024.0
            rich[4] = sum(counts) / 4096.0
            rich[5] = max(counts) / 1024.0
            rich[6] = ridx / max(info.get("e_lfanew", 1), 1)
            rich[7] = 1.0 if all(c > 0 for c in counts) else 0.0

    # ---- D. 导出 8 / E. 资源 12 ----
    exp = _export_feats(data, info)
    res = _resource_feats(data, info)

    # ---- F. 敏感 API 128 ----
    apis = _api_feats(info)

    # ---- G. 字符串计数 8 ----
    strs = _string_feats(data)

    # ---- H. 语义白证据 78 ----
    ver = _version_feats(data, info)
    lde = _linker_dos_ep_feats(data, info)
    jac = _sec_jaccard_feats(info)
    imp = _import_cov_feats(info)
    swh = _string_white_feats(data)
    pdb = _pdb_feats(data, info)
    tsc = _ts_cross_feats(data, info)
    stc = _struct_sane_feats(data, info)

    return np.concatenate([sec_char, glob, rich, exp, res, apis, strs,
                           ver, lde, jac, imp, swh, pdb, tsc, stc])


def extract_features(data):
    if not is_pe(data):
        return None
    buf = bytes(data[:BYTE_STAT_CAP])
    n = len(buf)
    arr = np.frombuffer(buf, dtype=np.uint8)
    hist = np.bincount(arr, minlength=256).astype(np.float64) / max(n, 1)
    ents, means, divs = _chunk_stats(arr)

    info = _parse_pe(data)
    sec_feats = np.zeros(N_SECTIONS * 6, dtype=np.float64)
    for i, s in enumerate(info["sections"][:N_SECTIONS]):
        base = i * 6
        sec_feats[base + 0] = s["vsize"] / 16777216.0
        sec_feats[base + 1] = s["vaddr"] / 16777216.0
        sec_feats[base + 2] = s["rawsize"] / 16777216.0
        sec_feats[base + 3] = s["rawptr"] / 16777216.0
        sec_feats[base + 4] = s["entropy"]
        sec_feats[base + 5] = s["rawsize"] / max(s["vsize"], 1) if s["vsize"] else 0.0

    if info["global"] is None:
        glob = np.zeros(24, dtype=np.float64)
    else:
        glob = np.asarray(info["global"], dtype=np.float64)

    per_dll = []
    if info["dlls"]:
        seen = {}
        for d in info["dlls"]:
            seen[d] = seen.get(d, 0) + 1
        per_dll = list(seen.values())
    counts = np.asarray(per_dll, dtype=np.float64)
    nd = max(len(info["dlls"]), 1)
    nf = max(len(info["funcs"]), 1)
    stats = np.zeros(16, dtype=np.float64)
    stats[0] = len(info["dlls"]) / 64.0
    stats[1] = len(info["funcs"]) / 8192.0
    stats[2] = counts.max() / 2048.0 if counts.size else 0.0
    stats[3] = counts.mean() / 128.0 if counts.size else 0.0
    stats[4] = counts.std() / 64.0 if counts.size else 0.0
    stats[5] = len(set(info["funcs"])) / nf
    stats[6] = min(len(info["funcs"]) / max(len(buf) / 1024.0, 1), 10.0) / 10.0
    stats[7] = (sum(len(d) for d in info["dlls"]) / nd) / 64.0
    stats[8] = (sum(len(f) for f in info["funcs"]) / nf) / 128.0
    stats[9] = counts.min() / 64.0 if counts.size else 0.0
    stats[10] = info.get("ordinal_count", 0) / max(len(info["funcs"]) + info.get("ordinal_count", 0), 1)
    stats[11] = len(set(info["dlls"])) / nd
    stats[12] = 1.0 if any(d.endswith(".dll") for d in info["dlls"]) else 0.0
    stats[13] = 1.0 if any(not d for d in info["dlls"]) else 0.0
    stats[14] = min(nf, 16384) / 16384.0
    stats[15] = 1.0 if not info["dlls"] else 0.0

    extra = _extra_feats(data, info)
    feats = np.concatenate([hist, ents, means, divs, sec_feats, glob, stats, extra])
    feats = np.nan_to_num(feats, nan=0.0, posinf=0.0, neginf=0.0)
    return feats[:FEATURE_DIM].astype(np.float32)


def load_model(path=None):
    if lightgbm is None:
        raise RuntimeError("lightgbm not installed")
    return lightgbm.Booster(model_file=path or MODEL_PATH)


def scan_bytes(data, model):
    if not is_pe(data):
        return "error", None
    feats = extract_features(data)
    if feats is None:
        return "error", None
    prob = float(model.predict(feats.reshape(1, -1))[0])
    score = int(round(prob * 100))
    if score >= MALWARE_THRESHOLD:
        return "malware", score
    return "clean", score


def scan_file(path, model):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return "error", None
    return scan_bytes(data, model)


def _walk_into_queue(root, q):
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            q.put(os.path.join(dirpath, name))


def scan_folder(root, model):
    q = queue.Queue()
    results = []
    lock = threading.Lock()

    def worker():
        while True:
            item = q.get()
            if item is None:
                q.task_done()
                break
            try:
                status, score = scan_file(item, model)
            except Exception:
                status, score = "error", None
            with lock:
                results.append((item, status, score))
                try:
                    rel = os.path.relpath(item, root)
                except ValueError:
                    rel = item
                if status == "malware":
                    print(f"[Malware] {rel} | Score:{score}")
                elif status == "clean":
                    print(f"[Clean] {rel} | Score:{score}")
                else:
                    print(f"[Error] {rel} | Score:None")
            q.task_done()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(SCAN_WORKERS)]
    for t in threads:
        t.start()
    _walk_into_queue(root, q)
    q.join()
    for _ in threads:
        q.put(None)
    for t in threads:
        t.join()

    malware = [(p, s) for p, st, s in results if st == "malware"]
    n_clean = sum(1 for _, st, _ in results if st == "clean")
    n_error = sum(1 for _, st, _ in results if st == "error")
    print("------[Return]------")
    for p, s in malware:
        try:
            rel = os.path.relpath(p, root)
        except ValueError:
            rel = p
        print(f"Malware | {rel} | Score:{s}")
    print(f"Malware:{len(malware)} | Clean:{n_clean} |Error:{n_error}")


def resolve_target(args):
    if not args:
        return None
    first = args[0]
    if os.path.exists(first):
        return first
    joined = " ".join(args)
    if os.path.exists(joined):
        return joined
    cur = first
    for arg in args[1:]:
        cand = cur + " " + arg
        if os.path.exists(cand):
            return cand
        cur = cand
    return first


def main():
    target = resolve_target(sys.argv[1:])
    if target is None:
        print("Usage: SevenEngine.py <file / folder path>")
        return 1
    try:
        model = load_model()
    except Exception as e:
        print(f"Return:Error")
        print("Score:None")
        print(f"Model load failed: {e}", file=sys.stderr)
        return 1

    if os.path.isfile(target):
        status, score = scan_file(target, model)
        if status == "malware":
            print("Return:ML:Gen.Malware")
            print(f"Score:{score}")
        elif status == "clean":
            print("Return:ML:Clean")
            print(f"Score:{score}")
        else:
            print("Return:Error")
            print("Score:None")
        return 0

    if os.path.isdir(target):
        scan_folder(target, model)
        return 0

    print("Return:Error")
    print("Score:None")
    return 1


if __name__ == "__main__":
    sys.exit(main())
