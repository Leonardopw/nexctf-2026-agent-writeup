# fmtstack · 渗透记录

> **脚本来源**：本题 exploit 脚本由参赛者本人手搓提供，Agent 负责在目标环境复现、验证、排错与题解/记录整理。


## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | fmtstack |
| 类型 | Pwn / 格式化字符串泄露（canary/PIE/libc）+ 栈溢出 ret2libc |
| 入口 | 219.216.64.241:35053（附件：attachments/pwn + libc.so.6 + ld-linux） |
| 耗时 | 0 日 0 时 5 分 0 秒 |
| LLM | deepseek-flash |
| flag | `nex{lMt5TaCk_w2rheic4}` |

## 2.2 目标与授权
- 授权范围：仅用户给定的 219.216.64.241:35053；只读 flag，未在靶机留文件
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
ELF64 amd64，PIE + canary + NX + Full RELRO，未 strip；vuln@0x1179、main@0x120b；提示 `name: ` / `msg: `；name 直接进 printf（格式串可控），msg 为 read 栈缓冲区（偏移 72）

## 2.4 攻击面
1) name 字段的 printf 格式串（%23$p/%25$p/%29$p 泄露 canary、PIE ret、libc ret）2) msg 字段栈溢出（canary 后 8 字节 -> ROP）

## 2.5 漏洞判定
- 类型：Pwn / 格式化字符串泄露（canary/PIE/libc）+ 栈溢出 ret2libc
- 位置：name 的 printf 与 msg 的 read（vuln@0x1179）
- 证据：evidence/step1_*、step2_*（两次连接 canary/PIE/libc 全不同，payload 120 字节，shell 回显同一 flag）；leak 行如 `0x71c68f8b346aa500.0x56462755c281.0x14787eef5601`
- 误报排除：两次独立连接 ASLR 全变（canary 0x77a19a25e8a97f00 vs 0x570014155cdd2c00）仍成功，排除固定地址；pie_leak-0x1281=0x562bb7248000、libc_leak-0x2a601=0x148f6b0e8000 均页对齐，偏移正确；不加 ret 对齐会崩（system 的 movaps），payload 里保留 ret(libc+0x289fe)

## 2.6 利用链
```
connect -> `name: `
send `%23$p.%25$p.%29$p\n\x00\n`
recv -> `0x<canary>.0x<pie_ret>.0x<libc_ret>`
pie_base  = pie_ret  - 0x1281
libc_base = libc_ret - 0x2a601
`msg: ` -> payload = 72*A + p64(canary) + 8*A + p64(pop_rdi+libc_base) + p64(binsh+libc_base) + p64(ret+libc_base) + p64(system+libc_base)
system('/bin/sh') -> cat ./flag -> nex{lMt5TaCk_w2rheic4}
```

## 2.7 影响
远程代码执行（uid=ctf），读取 /home/ctf/flag；格式串同时泄露 canary 与两个基址，canary 保护形同虚设

## 2.8 修复建议
printf("%s", name) 固定格式串，禁止用户输入进格式串；read 限长、校验返回值；保留 canary/PIE/Full RELRO；不要把栈上的 canary/返回地址通过 %p 暴露

## 2.9 复盘
名字直接进 printf，一次泄露 canary/PIE/libc；canary 后 8 字节再 ROP，system 前补 ret。
