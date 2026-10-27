#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""压缩包（伪加密）—— zip 的 general purpose bit 0（加密标志）被置位，但数据是明文 deflate

伪加密：本地头 + 中央目录的 flag 都写了 0x0001（bit0 = encrypted），
但压缩数据本身没有加密（csz/crc 正常，直接 inflate 就能出原文）。
修复：把两处 flag 的 bit0 清掉，再正常解压。

用法：python exp.py
"""
import re
import struct
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
EV = HERE / "evidence"
EV.mkdir(exist_ok=True)
FLAG_RE = re.compile(r"(?:nex|flag|NEX|FLAG)\{[^}]+\}")
FLAG_ENC = 0x0001


def patch_zip(src: Path, dst: Path):
    raw = bytearray(src.read_bytes())
    fixed = []
    for sig, hdr in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):  # flags 相对头部的偏移
        off = 0
        while True:
            off = raw.find(sig, off)
            if off < 0:
                break
            flags = struct.unpack_from("<H", raw, off + hdr)[0]
            if flags & FLAG_ENC:
                struct.pack_into("<H", raw, off + hdr, flags & ~FLAG_ENC)
                fixed.append((sig.decode("latin-1"), off, hex(flags)))
            off += 4
    dst.write_bytes(raw)
    return fixed


def main():
    src = HERE / "attachments" / "challenge.zip"
    dst = EV / "challenge_patched.zip"
    fixed = patch_zip(src, dst)
    print("[*] 清了 %d 处加密标志: %s" % (len(fixed), fixed))

    outdir = EV / "extracted"
    outdir.mkdir(exist_ok=True)
    with zipfile.ZipFile(dst) as z:
        bad = z.testzip()
        assert bad is None, "CRC 校验失败: %s" % bad
        z.extractall(outdir)
        print("[*] 解压:", [i.filename for i in z.infolist()])

    text = {}
    for p in sorted(outdir.iterdir()):
        data = p.read_bytes()
        text[p.name] = data
        print("--- %s (%d bytes) ---" % (p.name, len(data)))
        print(data.decode("utf-8", "replace"))

    joined = b"\n".join(text.values()).decode("utf-8", "replace")
    m = FLAG_RE.search(joined)
    assert m, "没找到 flag"
    flag = m.group(0)
    (EV / "step1_solve.txt").write_text(
        "patched headers: %s\nfiles: %s\nFLAG: %s\n" % (fixed, list(text), flag), encoding="utf-8")
    print("[+] FLAG:", flag)


if __name__ == "__main__":
    sys.exit(main() or 0)
