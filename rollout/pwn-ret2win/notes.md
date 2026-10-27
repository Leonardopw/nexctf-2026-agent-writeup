# ret2win · 笔记

## 关键点
- 附件：`attachments/pwn`（20,681 B）+ `libc.so.6` + `ld-linux-x86-64.so.2`；ELF64 amd64，**PIE + NX + Full RELRO，无 canary，未 strip**。
- 符号：`win@0x1169`、`main@0x117f`；启动打印 `gift: %p`（就是 win 的运行时地址）。
- `win` 反汇编（字节手解）：
  ```
  0x1169 push rbp; mov rbp,rsp
  0x116d lea rax,[rip+0xe90]   ; 0x1174+0xe90 = 0x2004 -> "cat ./flag"
  0x1174 mov rdi,rax
  0x1177 call 0x1030           ; system@plt
  0x117c nop; pop rbp; ret
  ```
  strings 里 `0x2004 = "cat ./flag"`，`0x200b = "gift: %p\n"`。
- 溢出偏移 72（用户手搓 `p1.py` 已标定，复现一致）；payload = `b"A"*72 + p64(base+0x101A) + p64(win)`。
- `base+0x101A` 是一条 `ret`，用于修 `system()` 里 `movaps` 的 16 字节栈对齐。
- 结果：`nex{Re72win_ko3ko111}`，两次连接（ASLR 不同）均复现。

## 失败分支（排除理由）
- 无远程时只能静态分析：本机 Windows，沙箱禁 WSL（`Wsl/E_ACCESSDENIED`）、无 Docker、无 qemu，ELF 无法本地执行 → 本地复现不可行，改用「静态确认 + 远程两次独立跑」作为验证，已记录。
- 不泄露地址直接硬编码 win：PIE 每次基址不同（`0x5592a235d169` vs `0x55a7d2e98169`），排除。
- 不加 ret 对齐：`system` 内 `movaps` 需要 16 字节对齐，直接 `72+win` 会崩；加 `ret` 后稳定，与手搓脚本一致。
- 不用 `p.recvline()` 直接读整行：banner 固定单行 `gift: 0x...`，直接正则提取 hex 更稳（避免端口/提示变化）。

## 时间线
- T0 14:28:48 收到题目 + 附件 + 手搓 `p1.py`（remote 219.216.64.241:37260）。
- T1 14:29:10 解压附件、`pwntools` 静态：PIE/NX/Full RELRO、win@0x1169、strings `cat ./flag`。
- T2 14:29:30 用户给出新端口 39546；banner 实测 `gift: 0x...`。
- T3 14:29:44 写 `exp.py`（base=gift-0x1169，ret=base+0x101A，72 填充）。
- T4 14:29:59 打通，得 `nex{Re72win_ko3ko111}`；随后第二次连接换 ASLR 复现同 flag（evidence/step2）。

## 可复用 TTP
- PIE 题先找泄露：本题直接 `gift: %p` 打印 win 地址，`base = win - 符号偏移`。
- ret2win 最小链：`填充 + (可选) ret 对齐 + win`；`system` 类调用前务必确认 16 字节对齐。
- 偏移标定用手搓脚本 + 二进制符号交叉验证；两边一致再上远程。
- 无 Linux 环境时：pwntools 静态（ELF/symbols/strings/字节手解）＋远程多次 ASLR 复现，能覆盖「偏移对、对齐对、flag 真」三点。
