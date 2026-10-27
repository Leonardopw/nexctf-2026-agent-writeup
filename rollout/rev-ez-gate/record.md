# 山门 · 验灵碑 · 渗透记录

## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | 山门 · 验灵碑 |
| 类型 | Reverse / 字符串藏于重定位表 + 多种编码（正刻/倒刻/hex/base64）的候选筛选 |
| 入口 | 本地附件 ez_gate (1).zip → ELF64 PIE（16,424 B，无远程） |
| 耗时 | 0 日 0 时 1 分 27 秒（17:31:52 收附件 → 17:33:19 出 flag） |
| LLM | deepseek-flash |
| flag | `NEX{gu4n_9ui1_y4n7}` |

## 2.2 目标与授权
- 授权范围：纯本地离线分析，无网络目标
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
ELF 64-bit LSB PIE, x86-64, dynamically linked, BuildID 09361000e672c82f925dacb41879e42660b342e9, not stripped；导入 puts/printf/fgets/strlen/strcmp；main @0x1209

## 2.4 攻击面
main 用 strcmp 把 fgets 输入与 0x21dd 处常量比较；50 条候选串存放在 0x3c00..0x3d90 的 R_X86_64_RELATIVE 重定位槽，r_addend 指向 .rodata

## 2.5 漏洞判定
- 类型：Reverse / 字符串藏于重定位表 + 多种编码（正刻/倒刻/hex/base64）的候选筛选
- 位置：main @0x1350 `lea rdx,[rip+0xe86]` → 常量 @0x21dd；.rela.dyn 中 50 个 r_offset ∈ [0x3c00,0x3d90) 的槽位
- 证据：evidence/step1_static.txt（50 条解码 + strcmp 目标 + 唯一匹配）；evidence/step1_flag.txt；evidence/step2_run.txt（WSL 运行 [OK]）
- 误报排除：静态侧只有第 23 条解码结果与 strcmp 常量逐字节相等（其余 44 条 NEX 串互不相同、5 条 ARK 伪前缀）；动态侧输入该串实际打印 [OK]，输入小写 nex 打印 [FAIL]，双向印证

## 2.6 利用链
```
file 确认 ELF → 反汇编 main 找 strcmp 常量 @0x21dd = NEX{gu4n_9ui1_y4n7} → 解析 .rela.dyn 50 个 RELATIVE 槽的 addend → 按 plain/reversed/hex/base64/ARK 解码 → 第 23 条与常量一致 → 运行 ELF 输入该串得 [OK]
```

## 2.7 影响
程序把“正确口诀”以明文常量放在 .rodata，且把 50 条候选放在重定位表里；逆向即可直接读出，不需要猜/爆破

## 2.8 修复建议
不要把口令/flag 以明文常量放在二进制里；需要校验就用哈希/口令派生（如 SHA-256 + 加盐）而不是 strcmp 明文；候选表也别放在可静态解析的重定位里

## 2.9 复盘
关键两步：strcmp 常量在 .rodata 明文、50 条候选在 .rela.dyn 的 addend 里；解码 plain/reversed/hex/base64 后与常量比对即可唯一确定，小写版本会被 strcmp 拒绝。
