# Pwn playbooks

## Stack / ret2win

1. `checksec`（triage 已给）：PIE、NX、Canary、RELRO。
2. `offset`：cyclic + GDB，确认 saved RIP/EIP 偏移；64 位注意 `ret` 对齐。
3. `symbols`：找 `win`/`get_shell`；非 PIE 直接跳，PIE 先找泄露。
4. `run_exploit`：最小 payload；成功标准是 flag/UID，不是“没崩”。

## ret2libc

1. `offset`。
2. 泄露：`puts@GOT` / `printf@GOT` / `write@GOT`；64 位用 `pop rdi; ret`。
3. `libc_match(leak, symbol, libc)`：base 必须页对齐；拿 `system`、`/bin/sh`。
4. `rop_plan(goal=system, base=...)`：生成 stage2；64 位先 `ret` 对齐。
5. 本地跑通再远程；远程记得 `remote(host, port)` 和 prompt 同步。

## Format string

1. 确认 `printf(buf)` / `fprintf` 用户可控。
2. `%p` 扫描确定输入在栈上的下标（32/64 位不同）。
3. `fmtstr_plan(mode=leak)` 泄露 libc/栈；`libc_match` 解析。
4. `fmtstr_plan(mode=write)` 写 GOT/返回地址/hook；写 2 字节通常更稳。
5. 若 `%N$` 被过滤，用顺序 `%p`/`%n`；注意 payload 对齐。

## Heap: UAF / tcache

1. 审计 `malloc/free` 的 ownership、大小、编辑长度。
2. `heap_plan(release, chunk_size)`：看 tcache 容量、`next/key` 偏移、safe-linking 公式。
3. 先做 leak（unsorted bin / stdout / GOT），再写 hook 或 tcache next。
4. glibc ≥ 2.34 很多构建没有 `__free_hook`/`__malloc_hook`；用 FSOP/exit_funcs。
5. 每次只改一个 metadata 字段；崩了看 `heap_integrity` 分类。

## FSOP

1. `libc_info` 确认 `_IO_list_all`、`_IO_wfile_jumps`、`setcontext` 偏移。
2. `heap_plan(goal=fsop)` 拿 wide FILE 字段表。
3. 伪造 `_IO_write_base=0`、`_IO_write_ptr=1`、`_chain=0`、`_mode=0`。
4. 触发 `exit`/`fflush`；`setcontext+61` 做栈迁移时，ROP 链与 FILE 字段分开放。
5. 需要 seccomp 时先用 `seccomp`，再决定 ORW。

## ORW / seccomp

1. `seccomp`：确认 `execve` 是否被过滤。
2. `rop_plan(goal=orw)`：`open(path,O_RDONLY)` → `read(3,buf,n)` → `write(1,buf,n)`。
3. 把 `path` 写到可写段（`.bss`），避免空字节；`open` 返回 fd 通常是 3。
4. 若没有 `pop rax/rsi/rdx`，用 libc gadgets 或 ret2csu。

## SROP / ret2dlresolve

- **SROP**：需要 `syscall; ret`；`rop_plan(goal=srop)` 生成 `SigreturnFrame`（rax=59, rdi=binsh, rip=syscall）。
- **ret2dlresolve**：没有 libc 泄露且需要 `system` 时；`rop_plan(goal=ret2dlresolve)` 生成 pwntools `Ret2dlresolvePayload` 模板，先 `read` 再发 `dlresolve.payload`。

## 通用排错

- **crash**：先 `offset` 复核偏移；64 位加 `ret`；确认 gadget 地址来自正确的 ELF base。
- **EOF / broken pipe**：检查是否 `sendline` 多了换行、是否在错误 prompt 发送。
- **no_proof**：flag 可能没有换行；`recvall` 后全文搜索，不要只取一行。
- **heap_integrity**：检查 tcache count、safe-linking、prev_size/PREV_INUSE。
