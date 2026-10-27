# 飞升台 · 最终禁制 · 渗透记录

## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | 飞升台 · 最终禁制 |
| 类型 | Reverse / 构造函数（.init_array）里 ptrace 反调试 + RC4 派生密钥 + 自定义 base64 + XXTEA |
| 入口 | 本地附件 final_protocol (1).zip → ELF64 PIE final_protocol（14,488 B，无远程） |
| 耗时 | 0 日 0 时 1 分 9 秒（18:01:44 收附件 → 18:02:53 出 flag） |
| LLM | deepseek-flash |
| flag | `NEX{c0nstruct0r_rc4_t34_m4st3r}` |

## 2.2 目标与授权
- 授权范围：纯本地离线分析（WSL 裸跑复核），无网络目标
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
ELF64 LSB PIE, x86-64, stripped, BuildID 6e7a83f6d74b8e9c369a1d88bb8fd00b63631559；含 ptrace 导入；.init_array 构造函数 0x1180 在 main 前运行

## 2.4 攻击面
构造函数 ptrace(PTRACE_TRACEME) 反调试（被跟踪则 SIGSEGV），并用 RC4(key="NEX2025") 异或常量派生 XXTEA 密钥；main 用自定义字母表 base64 解码 BLOB，再 XXTEA 解密与 31 字节输入比较

## 2.5 漏洞判定
- 类型：Reverse / 构造函数（.init_array）里 ptrace 反调试 + RC4 派生密钥 + 自定义 base64 + XXTEA
- 位置：.rodata：KEYSTR "NEX2025"@0x2004、自定义字母表@0x22c0、BLOB(44 字符)@0x2320、常量@0x23b0；构造函数 0x1180 调 0x1160(ptrace)；XXTEA 12 轮
- 证据：evidence/step1_solve.txt（静态 4 项 + 动态 3 项）；evidence/step2_run.txt（good/bad 回显与 rc、strace 下 rc=139）；evidence/verify.sh；evidence/flag.txt
- 误报排除：两条独立证据：①XXTEA 把解出的明文重新加密，结果与 .rodata 的 32 字节密文完全一致；②原 ELF 裸跑：flag → ACCESS_GRANTED rc=0，31 字节错误输入 → ACCESS_DENIED rc=1；另 strace 下 SIGSEGV 印证 ptrace 反调试

## 2.6 利用链
```
读 .rodata → RC4("NEX2025") keystream ^ 0x23b0 常量 → key16="NEX-XXTEA-REAL-K" → 小写优先自定义 base64 解 0x2320 BLOB → 32B 密文 → XXTEA(n=8,12 轮) 解密 → NEX{c0nstruct0r_rc4_t34_m4st3r}\0 → 重加密回代 + 原 ELF 裸跑复核
```

## 2.7 影响
构造函数虽加了 ptrace 反调试，但密钥派生与密文都可静态提取，PTRACE_TRACEME 只挡动态调试不挡静态分析；flag 可完全还原

## 2.8 修复建议
不要把密钥派生放在客户端构造函数据此；反调试只能提高成本，不能作为保密手段；本地校验应改为服务端签发/非对称签名；密钥必须来自安全存储而非 .rodata 常量异或

## 2.9 复盘
先看 .init_array：ptrace 反调试 + RC4 派生 key16（"NEX-XXTEA-REAL-K"）；自定义字母表是小写在前；XXTEA 轮数 6+52/8=12。重加密回代密文 + 裸跑 good/bad 双向复核，strace 会触发反调试。
