# pivot_orw · 渗透记录

> **脚本来源**：本题 exploit 脚本由参赛者本人手搓提供，Agent 负责在目标环境复现、验证、排错与题解/记录整理。


## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | pivot_orw |
| 类型 | Pwn / 栈迁移（leave;ret）+ ORW（open/read/write） |
| 入口 | 219.216.64.241:35302（附件：attachments/pwn，静态链接单文件） |
| 耗时 | 0 日 0 时 0 分 45 秒 |
| LLM | deepseek-flash |
| flag | `nex{PIV0t_oRW_8j5s9eki}` |

## 2.2 目标与授权
- 授权范围：仅用户给定的 219.216.64.241:35302；只读 flag，未在靶机落文件/未横向
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
ELF64 amd64 **静态链接**（无 libc 依赖）、非 PIE（0x400000）、Canary、NX、Partial RELRO、带调试符号；vuln@0x401964、main@0x40198f；提示 `stage: ` 与 `overflow: `；.bss = 0x4b3a60..0x4b9588

## 2.4 攻击面
1) `stage: ` 把 0x300 字节读进 .bss（0x4b3ac0 可写）2) `overflow: ` 栈溢出（0x40 到 saved RIP）3) 二进制内自带 pop rdi/pop rsi/pop rax/xchg rax,rdx/syscall gadget

## 2.5 漏洞判定
- 类型：Pwn / 栈迁移（leave;ret）+ ORW（open/read/write）
- 位置：overflow 栈溢出 + 可控 .bss 缓冲（两段式）
- 证据：evidence/step1_*、step2_*（两次运行 stage1 768 字节、sha256 一致，stage2=0x40*A+p64(0x4b3ac0)+p64(0x40198d)，输出同一 flag）；stepN_output.txt 为 write(1,buf,0x100) 原始回显
- 误报排除：二进制静态链接、无 libc，所以不是 ret2libc 误用；两次独立连接同一 stage1 均成功，排除随机偏移；gadget 字节逐一核对：leave;ret c9c3@0x40198d、pop rdi 5fc3@0x47de22、pop rsi 5ec3@0x48264f、pop rax 58c3@0x423603、xchg rax,rdx 4892c3@0x41875a、syscall 0f05c3@0x40c8b6；bss_stage 0x4b3ac0 落在 .bss 范围内（0x4b3a60+0x5b28）

## 2.6 利用链
```
connect -> `stage: `
send stage1(0x300)：[0x000]=bss(占位 rbp)，之后 open("flag"@bss+0x180,0)、read(3,bss+0x200,0x100)、write(1,bss+0x200,0x100) 的 ORW 链，[0x180]="flag\0"
`overflow: ` -> stage2 = 0x40*A + p64(0x4b3ac0) + p64(0x40198d)
leave;ret 把 rsp 迁到 .bss 并开始执行 ORW 链
write 输出 -> nex{PIV0t_oRW_8j5s9eki}
```

## 2.7 影响
栈溢出 + 可写 .bss 组合出任意 syscall 链（本题 ORW 读 flag）；静态链接下无 libc 也能完整利用

## 2.8 修复建议
read/gets 限制长度并校验；开启 PIE；不要把用户输入读进固定可写 .bss；用 seccomp 白名单只放行必要 syscall（如 write/exit），禁止 open/read 任意文件

## 2.9 复盘
p4.py 其实是上一题 heapnote；正确脚本是同目录 p5.py。stage 写 bss 布 ORW，overflow 里 leave;ret 迁移，一次打通。
