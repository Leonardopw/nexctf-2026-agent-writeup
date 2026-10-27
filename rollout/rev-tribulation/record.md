# 心魔劫 · 渗透记录

## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | 心魔劫 |
| 类型 | Reverse / UD2 当 hypercall（SIGILL handler 做校验）+ TEA 风格幻台分支 |
| 入口 | 本地附件 tribulation (1).zip → ELF64 PIE tribulation（14,472 B，无远程） |
| 耗时 | 0 日 0 时 3 分 7 秒（17:55:40 收附件 → 17:58:47 出 flag） |
| LLM | deepseek-flash |
| flag | `NEX{ud2_1s_n0t_a_cr4sh}` |

## 2.2 目标与授权
- 授权范围：纯本地离线分析（WSL 运行），无网络目标
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
ELF64 LSB PIE, x86-64, stripped, BuildID 4a8413686d2cb7af00bb803cf38cf671031a4240；导入 strcspn/fgets/puts/__printf_chk；main 内含 ud2 循环与 SIGILL handler

## 2.4 攻击面
用 UD2 触发 SIGILL 传参（[0x401a]=index, [0x401b]=char），handler 做 XOR/rot/add 变换后与 23 字节 CMP 表比较，不符则置 [0x4019]；另有一条 0x16a0 的 TEA 风格分支可跳过循环直接打印同样的 ACCESS_GRANTED（幻台）

## 2.5 漏洞判定
- 类型：Reverse / UD2 当 hypercall（SIGILL handler 做校验）+ TEA 风格幻台分支
- 位置：.rodata 表：CMP@0x22d0、XOR1@0x22f0、ADD@0x2310、XOR2@0x2330（各 23B）；main 循环 0x12a0..0x12ba；幻台分支 0x1289 call 0x16a0 → 0x131c
- 证据：evidence/step1_solve.txt（静态 4 项 + 动态 4 项校验）；evidence/step2_run.txt（good/bad 的 rc、SIGILL 计数、verdict）；evidence/verify.sh；evidence/flag.txt
- 误报排除：两条独立证据：①静态逆变换后逐字节正向重算 23/23 等于 CMP 表；②原 ELF 跑正确输入 rc=0 且 SIGILL=24（证明真走了 ud2 循环，而非幻台跳转），错误输入 rc=1、SIGILL=24 但 verdict=DENIED；长度错误只有 1 次 SIGILL，说明计数能区分路径

## 2.6 利用链
```
反汇编定位 ud2 循环与 4 张 23 字节表 → 逆变换：rotl8(CMP,2) ^ XOR1 - ADD rotl 后 rotr8 ^ XOR2 → NEX{ud2_1s_n0t_a_cr4sh} → 正向重算等于 CMP → WSL 跑原 ELF：good ACCESS_GRANTED rc=0 SIGILL=24，bad ACCESS_DENIED rc=1
```

## 2.7 影响
校验逻辑可被静态还原并通过；更关键的是存在“幻台”分支可伪造成功提示，说明“程序打印 ACCESS_GRANTED”不能作为通过依据

## 2.8 修复建议
不要用 UD2/信号处理器传递校验参数（易被静态还原）；本地校验不要同时保留可伪造的成功分支；判定结果应由不可逆校验（签名/服务端）给出，且不要把成功文案与真实结果解耦

## 2.9 复盘
UD2+SIGILL 传参是本题核心，静态读 4 张表即可逆出；额外发现 0x16a0 幻台分支会跳过循环打印同样的成功，因此用 strace 数 SIGILL（24 vs ~1）来确认走的是真路径。
