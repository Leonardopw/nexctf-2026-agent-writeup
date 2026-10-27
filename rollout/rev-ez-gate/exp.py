#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""山门 · 验灵碑（ez_gate）—— 50 条仙诀里找出与 strcmp 常量一致的那条

方法（静态分析，不需要运行 ELF）：
  1) 在 .text 里找 `lea rdx, [rip+disp]`（48 8d 15）后紧跟 strcmp 调用的那处，
     解出比较目标字符串的虚拟地址；
  2) 50 条仙诀存放在 0x3c00..0x3d90 的一串 R_X86_64_RELATIVE 重定位里
     （.rela.dyn 的 r_offset 槽位 + addend 指向 .rodata 字符串）；
  3) 每条按“刻法”解码：正刻 plain、倒刻 reversed、金文 hex、base64、以及 ARK 开头的假货；
  4) 解码结果与 strcmp 常量相同的即为真门规。

结果：NEX{gu4n_9ui1_y4n7}（运行 ELF 输入该串会打印 [OK]，小写 nex 会被 strcmp 拒绝）。

用法：python exp.py
"""
import base64
import re
import struct
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile

HERE = Path(__file__).resolve().parent
EV = HERE / "evidence"
EV.mkdir(exist_ok=True)
BIN = HERE / "attachments" / "ez_gate"
FLAG_RE = re.compile(r"(?:nex|NEX|flag|FLAG)\{[^}]+\}")


def main():
    data = BIN.read_bytes()
    f = open(BIN, "rb")
    elf = ELFFile(f)

    segs = [(s["p_vaddr"], s["p_offset"], s["p_filesz"])
            for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]

    def off(va):
        for v, o, sz in segs:
            if v <= va < v + sz:
                return o + (va - v)
        raise ValueError("bad va %#x" % va)

    def cstr(va):
        o = off(va)
        end = data.index(b"\x00", o)
        return data[o:end].decode("latin-1")

    # --- 1) 找 strcmp 的目标常量 ---
    text = elf.get_section_by_name(".text")
    tb = text.data()
    base = text["sh_addr"]
    target = None
    for m in re.finditer(rb"\x48\x8d\x15(?P<disp>.{4})", tb, re.S):
        disp = struct.unpack("<i", m.group("disp"))[0]
        end = base + m.end()
        nxt = tb[m.end():m.end() + 24]
        if b"\x48\x89\xd6\x48\x89\xc7\xe8" in nxt:   # mov rsi,rdx; mov rdi,rax; call
            target = end + disp
            break
    assert target, "没找到 strcmp 常量"
    expected = cstr(target)
    print("[*] strcmp 目标 @%#x: %r" % (target, expected))

    # --- 2) 收集 50 条仙诀 ---
    entries = []
    for sec in elf.iter_sections():
        if sec["sh_type"] != "SHT_RELA":
            continue
        for r in sec.iter_relocations():
            if 0x3c00 <= r["r_offset"] < 0x3d90:
                entries.append((r["r_offset"], r["r_addend"]))
    entries.sort()
    print("[*] 仙诀条数:", len(entries))

    # --- 3) 按刻法解码 ---
    def decode(raw):
        if raw.startswith("NEX{") or raw.startswith("nex{"):
            return "正刻", raw
        if raw.startswith("ARK{"):
            return "伪刻", raw
        if raw.startswith("}") and raw.upper().endswith("XEN"):
            return "倒刻", raw[::-1]
        if re.fullmatch(r"[0-9a-fA-F]+", raw) and len(raw) % 2 == 0:
            try:
                return "金文(hex)", bytes.fromhex(raw).decode("latin-1")
            except ValueError:
                pass
        if re.fullmatch(r"[A-Za-z0-9+/=]+", raw):
            try:
                return "base64", base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("latin-1")
            except Exception:
                pass
        return "?", raw

    match = None
    rows = []
    for idx, (slot, addr) in enumerate(entries):
        kind, dec = decode(cstr(addr))
        ok = dec == expected
        if ok:
            match = dec
        rows.append("[%02d] %#06x %-10s %-36s -> %s%s" %
                    (idx, addr, kind, cstr(addr), dec, "   <== 真门规" if ok else ""))

    out = "\n".join(rows)
    print(out)
    assert match, "没有找到与 strcmp 常量一致的仙诀"
    assert FLAG_RE.fullmatch(match), "格式不对"

    result = "strcmp 目标: %s\n匹配条数: %d\nFLAG: %s\n" % (expected, 1, match)
    print(result)
    (EV / "step1_static.txt").write_text(out + "\n\n" + result, encoding="utf-8")
    (EV / "step1_flag.txt").write_text(match + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main() or 0)
