# fmtstack · 笔记

## 关键点
- 附件：`attachments/pwn`（20,705 B）+ `libc.so.6` + `ld-linux`；ELF64 amd64，**PIE + canary + NX + Full RELRO**，未 strip。
- 符号：`vuln@0x1179`、`main@0x120b`；提示 `name: `（0x2004）与 `msg: `（0x200b）。
- 漏洞 1：name 被直接传给 printf，格式串可控；一次发 `%23$p.%25$p.%29$p` 拿到三样：
  - `%23$p` → **canary**
  - `%25$p` → 返回地址（PIE）→ `pie_base = leak - 0x1281`
  - `%29$p` → 返回地址（libc）→ `libc_base = leak - 0x2a601`
- 漏洞 2：msg 为 read 栈缓冲区，偏移 72；canary 后 8 字节，然后 ROP：
  `pop rdi(0x11b9fa) + /bin/sh(0x1db799) + ret(0x289fe) + system(0x5c2e0)`（libc 相对偏移）。
- gadget 已核对字节：0x11b9fa=`5f c3`（pop rdi; ret）、0x289fe=`c3`（ret）。
- 结果：`nex{lMt5TaCk_w2rheic4}`，flag 在 `/home/ctf/flag`。

## 失败分支（排除理由）
- **pwntools 在本机卡死**：`remote()` + `recvrepeat()` 两次各挂 120s（进程不退出，被移到后台），改用**纯 socket + select** 实现 `read_until/read_for`，稳定且无依赖；这也是 exp.py 用标准库的原因。
- 裸 socket 连接测试正常（banner `name: \n`），排除端口/网络问题，确认是本地 tube 行为。
- name 只发 `%23$p.%25$p.%29$p`（不带 `\n\x00`）：格式串会继续吃掉后面的字节/换行，泄露行不干净；按 p3.py 的 `\n\x00` 结尾，printf 在 NUL 处停，输出正好一行。
- 不加 ret 对齐（`pop_rdi + binsh + system`）：`system` 的 `movaps` 需要 16 字节对齐，直接崩；加 `ret` 后稳定。
- 无本地执行环境（Windows，沙箱禁 WSL、无 Docker/qemu）：本地复现改为「静态标定 + 远程两次 ASLR 复现」；与手搓 `p3.py` 的常量完全一致，仅端口不同（p3 写 38821，本次 35053）。

## 时间线
- T0 14:40:14 收到题目 + 附件 + 手搓 p3.py。
- T1 14:40:40 静态：PIE/canary/RELRO、vuln@0x1179、校验 libc gadget 字节。
- T2 14:42:00 pwntools 两次挂死（120s×2），改用裸 socket。
- T3 14:43:50 裸 socket 探针拿到 `canary.pie.libc` 泄露行，确认三个 `%p` 位置。
- T4 14:45:06 写 exp.py（socket 版），发送 120 字节 ROP 载荷。
- T5 14:45:10 打通：`id`=ctf，`cat ./flag` → `nex{lMt5TaCk_w2rheic4}`；随后第二次连接（ASLR 不同）复现。

## 可复用 TTP
- 拿到格式串先试「一次性泄露三件套」：canary/返回地址×2；按栈帧顺序找 `%p` 位置，再固化成偏移。
- canary 泄露后溢出布局：`填充 + canary + saved rbp(8) + ROP`。
- `system` 前一律补 `ret` 修 16 字节对齐。
- 本机 pwntools tube 偶发挂死时，用 socket+select 写小 Tube（read_until/read_for）更稳，也便于把证据落盘。
- 校验泄露质量：`leak - 偏移` 必须页对齐（0x1000 倍数），不然偏移/位置就错了。
