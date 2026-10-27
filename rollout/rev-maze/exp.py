#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""桃花瘴迷踪阵（maze.exe）—— 逆出 441 个砖块函数的有向图，BFS 找 (1,1)→(19,19) 的走位

PE 结构：
  - .pdata 里每个函数对应一个"砖块"（441 个），函数体对 eax（走位字符 'w'/'a'/'s'/'d'）
    做 cmp + je：命中跳转块里 lea rax,[rip+…] 给出下一块地址（生路），或 call 禁制函数（死路）。
  - 入口函数（img+0x17aa）为起点，出口（img+0x8644）为终点。
做法：逐函数解析转移表 → 建图 → BFS → 走位串 → 喂原 exe 复核，输出里的 NEX{...} 即 flag。

用法：python exp.py
"""
import re
import struct
import subprocess
import sys
from collections import deque
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

HERE = Path(__file__).resolve().parent
EV = HERE / "evidence"
EV.mkdir(exist_ok=True)
EXE = HERE / "attachments" / "maze.exe"
FLAG_RE = re.compile(r"NEX\{[^}]+\}")
DIRS = {0x77: "w", 0x73: "s", 0x61: "a", 0x64: "d"}


def build_graph():
    pe = pefile.PE(str(EXE))
    img = pe.OPTIONAL_HEADER.ImageBase
    d = EXE.read_bytes()
    secs = [(s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData,
             s.Name.decode(errors="replace").rstrip("\x00")) for s in pe.sections]
    text = next(s for s in secs if s[4] == ".text")
    code = d[text[2]:text[2] + text[3]]
    pdata = next(s for s in secs if s[4] == ".pdata")

    funcs = []
    for i in range(pdata[1] // 12):
        b, e, _u = struct.unpack_from("<III", d, pdata[2] + i * 12)
        funcs.append((img + b, img + e))
    funcs.sort()

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    def insns(va, end):
        off = (va - img) - text[0]
        return list(md.disasm(code[off:off + (end - va)], va))

    cells, traps = {}, set()
    for b, e in funcs:
        ins = insns(b, e)
        if not ins:
            continue
        if not any(i.mnemonic == "cmp" and i.op_str.startswith("eax, 0x7") for i in ins):
            continue
        by_addr = {i.address: k for k, i in enumerate(ins)}
        trans = {}
        for k, i in enumerate(ins):
            if i.mnemonic != "cmp" or not i.op_str.startswith("eax, 0x"):
                continue
            try:
                imm = int(i.op_str.split(", ")[1], 16)
            except ValueError:
                continue
            if imm not in DIRS:
                continue
            if k + 1 >= len(ins) or ins[k + 1].mnemonic != "je":
                continue
            tgt = int(ins[k + 1].op_str, 16)
            blk = ins[by_addr[tgt]:by_addr[tgt] + 8] if tgt in by_addr else (
                insns(tgt, min(tgt + 0x30, e)) if tgt < e else [])
            nxt = None
            for q in blk:
                if q.mnemonic == "lea" and q.op_str.startswith("rax, [rip"):
                    nxt = q.address + q.size + q.operands[1].mem.disp
                    break
                if q.mnemonic == "call":
                    traps.add(int(q.op_str, 16))
                    break
                if q.mnemonic == "mov" and q.op_str.startswith("eax, 0x0"):
                    break
            trans[DIRS[imm]] = nxt
        if trans:
            cells[b] = trans
    return img, cells, traps


def bfs(cells, start, win):
    q = deque([(start, "")])
    seen = {start}
    while q:
        cur, path = q.popleft()
        if cur == win:
            return path
        for ch, nxt in cells.get(cur, {}).items():
            if nxt and nxt in cells and nxt not in seen:
                seen.add(nxt)
                q.append((nxt, path + ch))
    return None


def main():
    img, cells, traps = build_graph()
    start, win = img + 0x17AA, img + 0x8644
    print("[*] 砖块函数 %d 个，禁制函数 %d 个；起点/终点都在图中: %s/%s"
          % (len(cells), len(traps), start in cells, win in cells))
    path = bfs(cells, start, win)
    assert path, "找不到通路"
    print("[*] BFS 走位:", path, "(%d 步)" % len(path))

    p = subprocess.run([str(EXE)], input=(path + "\n").encode(), cwd=str(EXE.parent),
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
    out = p.stdout.decode("gbk", "replace")
    (EV / "step2_run.txt").write_text(out + "\nexit=%d\n" % p.returncode, encoding="utf-8")
    print(out)
    m = FLAG_RE.search(out)
    checks = {
        "有通路": bool(path),
        "起点=终点?": start != win,
        "exe 退出码 0": p.returncode == 0,
        "成功文案": "迷踪阵，破！" in out,
        "flag 提取": bool(m),
    }
    assert all(checks.values()), checks
    flag = m.group(0)
    res = "\n".join([f"{k:<14}: {v}" for k, v in checks.items()] +
                    [f"PATH          : {path}", f"FLAG          : {flag}"])
    print(res)
    (EV / "step1_solve.txt").write_text(res + "\n", encoding="utf-8")
    (EV / "flag.txt").write_text(flag + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main() or 0)
