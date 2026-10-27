# heapnote · 笔记

## 关键点
- 附件：`attachments/pwn`（24,688 B）+ libc + ld；ELF64 amd64，**非 PIE（0x3fe000）+ canary + NX + Full RELRO**，未 strip。
- 菜单：`1. add` / `2. delete` / `3. edit` / `4. show` / `5. call` / `6. exit`；字符串：`idx:`、`size:`、`data:`、`done`、`invalid idx`。
- 关键符号：`backdoor@0x4011fe`（内部引用 `cat ./flag`），`menu@0x40136a`，`main@0x4016f7`。
- `call` 调的是 BSS 函数指针 **0x404040**（初始为默认 handler，字符串 “this is the default handler. nothing here.”）。
- 漏洞：`delete` 只 free 不置空 → 之后 `show`/`edit` 仍能操作 freed chunk（UAF）。
- 泄露：free 后 tcache fd 字段 = `next ^ (chunk>>12)`，本题 next=NULL，所以 `fd = chunk>>12`；`show` 读 8 字节即得 heap key。
- 利用：`edit` 把 fd 改成 `0x404040 ^ key`（safe-linking 编码后的目标），下一次 add 消费原 chunk，再下一次 add 返回 0x404040 并在那里写入 `0x4011fe`；`call` 即跳 backdoor。
- 结果：`nex{HeApn07e_t50p6zr4}`。

## 失败分支（排除理由）
- 直接改 chunk size / 打 __free_hook：Full RELRO + 无 libc 泄露，成本高；本题只要 BSS 函数指针，不需要 libc，排除。
- 用 double-free 直接构造 tcache 链：`delete` 未阻止重复 free 但本题单次 UAF 已够，未走 double-free（避免触发 tcache double free 检测）。
- 硬编码 fd/地址：两次 heap key 不同（`0x25e3e` / `0x377ad`），必须用 show 的泄露，排除硬编码。
- 0x404040 处的“chunk”不是合法 malloc 块：glibc 只做对齐检查（0x404040 16 字节对齐），能通过；若目标未对齐会报 `unaligned tcache chunk`，本题不存在。
- pwntools tube（上次 fmtstack 挂死）风险：本题一律用纯 socket + select 实现（exp.py 零依赖），两次运行均稳定。

## 时间线
- T0 14:48:35 收到题目 + 附件 + 手搓 p4.py。
- T1 14:48:50 静态：非 PIE/canary/Full RELRO、backdoor@0x4011fe、菜单与 0x404040 函数指针、strings `cat ./flag`。
- T2 14:49:09 写 exp.py（socket 版）：add→delete→show 泄露→edit 编码指针→两次 add→call。
- T3 14:49:25 打通：`> nex{HeApn07e_t50p6zr4}`。
- T4 14:49:46 第二次连接（heap key 不同）复现同 flag，落 evidence。

## 可复用 TTP
- 堆题先看 delete 是否置空、show/edit 是否校验已释放 → UAF 三连。
- glibc ≥2.32 tcache 有 safe-linking：free 后 fd = `next ^ (chunk>>12)`；单块 free 时 `fd = chunk>>12`，能直接当 heap key 用。
- 想写任意地址：`edit(freed, p64(target ^ key))`，再 malloc 两次即可返回 target 并写入数据。
- 目标优先选 **非 PIE 的 BSS 函数指针 / GOT（Partial RELRO 时）**，可以完全不碰 libc。
- 菜单型程序用「发送菜单号 → recvuntil(提示) → 发参数」的节奏最稳；用纯 socket 自己实现 read_until 可绕开本机 pwntools tube 偶发挂死。
