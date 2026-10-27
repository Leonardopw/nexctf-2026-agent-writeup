# ret2libc · 笔记

## 关键点
- 附件：`attachments/pwn`（24,272 B）+ `libc.so.6` + `ld-linux-x86-64.so.2`；ELF64 amd64，**非 PIE（0x3fe000）**、Partial RELRO、NX、无 canary、未 strip。
- 符号：`vuln@0x40116f`（`push rbp; mov rbp,rsp; sub rsp,0x40` → 0x40+8 = **偏移 72**）、`main@0x401190`。
- gadget：`pop rdi; ret @0x40116a`（`5f c3`）、`ret @0x40101a`（`c3`）。
- `puts@plt = 0x401030`：本机 pwntools 缺 unicorn，`e.plt` 填不出来，按 `.plt` 第 2 个桩（reloc 0x404000）手算；`puts@got = 0x404000`。
- libc（附件版本）：`puts=0x8e860`、`system=0x5c2e0`、`/bin/sh=0x1db799`。
- 交互：banner `=== libc roulette ===\nshow me what you got\n> `，vuln 每次读一行；**第二次进入 vuln 不会再打印 `> `**。
- 结果：`nex{Re7zI1GC_wzjwsxbi}`（flag 在 `/home/ctf/flag`，权限 `-r--r--r--`）。

## 失败分支（排除理由）
- 第一版 exp 在 leak 之后 `recvuntil(b"> ")` 等提示：第二次进 vuln 没有提示，白等 3 秒且脚本时序错乱 → shell 无回显；改成「leak 完直接发 stage2」后稳定。
- 不加 `ret` 对齐（`72 + pop_rdi + binsh + system`）：`system` 里 `movaps` 要求 16 字节对齐，直接崩、无回显 → 必须插一条 `ret`。
- 直接硬编码 libc 地址：两次跑 leaks 不同（`0x14fce2ee8860` vs `0x14b66de59860`），ASLR 生效，排除。
- `p.recvn(8)` 读泄露会卡住：puts 打印的是 GOT 里的指针字节，遇到 `0x00` 就停，实际只有 6 字节 + 换行；用 `recvline` 拿 6 字节再 `ljust(8,b"\0")`。
- 无本地执行环境（Windows，沙箱禁 WSL、无 Docker/qemu），本地复现改为「静态标定 + 远程两次 ASLR 复现」；与手搓 `p2.py` 的偏移/链完全一致，仅端口不同（p2 写 37481，本次 35194）。

## 时间线
- T0 14:33:13 收到题目 + 附件 + 手搓 `p2.py`。
- T1 14:33:40 静态：非 PIE、vuln@0x40116f、偏移 72、gadget 与 libc 偏移逐一核对；手算 puts@plt=0x401030。
- T2 14:34:30 首版 exp：leak 正常但 shell 无回显（recvuntil 时序 + 对齐）。
- T3 14:35:02 改成「leak 后直接发 stage2 + ret 对齐」。
- T4 14:35:10 打通：`id` 回 `uid=1001(ctf)`，`cat ./flag` → `nex{Re7zI1GC_wzjwsxbi}`。
- T5 14:35:26 第二次连接（不同 ASLR）复现同 flag，落 evidence。

## 可复用 TTP
- 非 PIE + Partial RELRO 的 ret2libc 标准两段式：`pop rdi; got; plt; vuln` 泄露 → 算 base → `pop rdi; binsh; ret; system`。
- `system` 前一律加一条 `ret` 修 16 字节栈对齐，失败先怀疑对齐。
- puts 泄露是「指针字节串」：遇 `0x00` 截断，通常 6 字节；用 `recvline` + `ljust(8,b"\0")`，别 `recvn(8)`。
- 反复执行的函数（vuln）适合做两阶段；注意第二次进入有没有提示符，不要盲 `recvuntil`。
- pwntools 缺 unicorn 时 `e.plt` 为空：解析 `.plt` 里的 `ff 25` 桩 + `.rela.plt` 顺序即可手算。
