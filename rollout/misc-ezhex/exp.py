#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ezhex —— 三个空文件的文件名是 flag 三段的 CRC32

附件里三个 0 字节文件，名字形如 `<8 位 hex>_4.txt`。把名字里的 hex 当作数值，
它们正好是 CRC32：0x94900dad / 0x1185397d / 0xed3e85c8。
CRC32 只有 32 bit，短串（≤4 字节）可以爆破原像：

    crc32(b"nex{")  = 0x94900dad
    crc32(b"ezCr")  = 0x1185397d
    crc32(b"c32}")  = 0xed3e85c8
    => flag = nex{ezCrc32}

用法：python exp.py   （爆破 4 字节以内的候选，约几千万次 CRC32）
"""
import binascii
import itertools
import re
import string
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
EV = HERE / "evidence"
EV.mkdir(exist_ok=True)
FLAG_RE = re.compile(r"(?:nex|flag|NEX|FLAG)\{[^}]+\}")
CHARSET = (string.ascii_letters + string.digits + "_{}").encode()


def targets():
    out = {}
    for p in sorted((HERE / "attachments").iterdir()):
        if p.is_file():
            out[int(p.name.split("_")[0], 16)] = p.name
    return out


def crack(wanted):
    """返回 {crc32: 原像(bytes)}，在长度 1..4 的 CHARSET 串中搜索。"""
    found = {}
    t0 = time.time()
    for L in range(1, 5):
        for tup in itertools.product(CHARSET, repeat=L):
            data = bytes(tup)
            c = binascii.crc32(data) & 0xFFFFFFFF
            if c in wanted and c not in found:
                found[c] = data
        print("[*] 长度 %d 搜索完成 (%.1fs)" % (L, time.time() - t0), flush=True)
        if len(found) == len(wanted):
            break
    return found


def main():
    tg = targets()
    print("[*] 文件名里的 hex:", {f"{k:08x}": v for k, v in tg.items()})
    pre = crack(set(tg))
    for c, name in tg.items():
        assert c in pre, "0x%08x 没爆出原像" % c
        print("    0x%08x = crc32(%r)   <- %s" % (c, pre[c], name))

    pieces = [pre[c] for c in tg]
    flag = None
    for order in itertools.permutations(pieces):
        s = b"".join(order).decode("latin-1")
        if s.startswith("nex{") and s.endswith("}") and FLAG_RE.fullmatch(s):
            flag = s
            break
    assert flag, "三段顺序组合失败"

    # 复核：flag 按三段切分后，每段的 CRC32 必须等于对应文件名
    checks = {}
    pos = 0
    for i, c in enumerate(tg):
        piece = pieces[i]
        checks["crc32(%r)" % piece] = "%08x == %08x %s" % (
            binascii.crc32(piece) & 0xFFFFFFFF, c,
            "OK" if (binascii.crc32(piece) & 0xFFFFFFFF) == c else "FAIL")
    checks["flag regex"] = str(bool(FLAG_RE.fullmatch(flag)))
    out = "\n".join([f"{k:<16}: {v}" for k, v in checks.items()] + [f"FLAG            : {flag}"])
    print(out)
    (EV / "step1_solve.txt").write_text(out + "\n", encoding="utf-8")
    assert all("FAIL" not in v for v in checks.values())


if __name__ == "__main__":
    sys.exit(main() or 0)
