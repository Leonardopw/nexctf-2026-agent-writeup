# 心魔劫（tribulation）· 笔记（已解）

## 关键点
- 附件 `tribulation`：ELF64 PIE（14,472 B，stripped）。读 23 字节「渡劫真言」，判定 ACCESS_GRANTED / ACCESS_DENIED。
- 题眼「崩毁亦是运行，非法亦是指令」= **用 UD2 当 hypercall**：
  ```
  12a0  movzx edx, byte ptr [rbx+rax]     ; 当前字符
  12a4  mov   [0x401a], al                ; 传参：下标 i
  12aa  mov   [0x401b], dl                ; 传参：字符 c
  12b0  ud2                               ; 故意触发 SIGILL
  12b2  add rax, 1 ... 循环 23 次
  ```
  程序自己装了 SIGILL handler，读 0x401a/0x401b，执行：
  ```
  x = c ^ XOR2[i]; rotl8(x,3); x += ADD[i]; x ^= XOR1[i]; rotr8(x,2)
  与 CMP[i] 比较；不符则把 [0x4019] 置 1
  ```
  循环后 `[0x4019]==0` → ACCESS_GRANTED，否则 ACCESS_DENIED。
  表就在 .rodata：CMP@0x22d0、XOR1@0x22f0、ADD@0x2310、XOR2@0x2330（各 23 字节，形式像
  `cmp/xor imm8/add imm8` 的“指令字节”——这就是“非法亦是指令”）。
- **幻台（decoy）**：main 在循环前先 `call 0x16a0`（一个 TEA 风格的分组变换 + 三组常量比较）；
  一旦它返回 1，就跳到 0x131c，**不跑 ud2 循环**，直接打印同样的
  「心魔幻象寸寸碎裂，道心澄明。ACCESS_GRANTED / 心魔劫，渡！」。
  所以“程序点头”不可信——要确认它是否真的执行了 23 次 UD2。
- 验证手段：`strace -f -o trace ./tribulation`，数 SIGILL：
  - 真路径（正确/错误的 23 字节输入）都是 **24 次**（1 次固定 + 23 次循环）；
  - 幻台路径会只有约 1 次（跳过循环）。
- 静态逆出真言：`NEX{ud2_1s_n0t_a_cr4sh}`（“UD2 不是崩溃”），正向重算 23 字节全等于 CMP。

## 判定
- 静态：逆变换后逐字节正向重算 == CMP（23/23）；
- 动态：正确输入 `ACCESS_GRANTED`、rc=0、SIGILL=24（真路径）；
  23 字节错误输入 `ACCESS_DENIED`、rc=1、SIGILL=24（同路径但 handler 置位）；
  长度不对（20 字节）→ 只 1 次 SIGILL（长度检查提前退出）。

## 失败分支（排除理由）
- 只信 stdout：幻台路径会打印同样的 ACCESS_GRANTED（“它点头，未必是你渡了劫”），
  必须用 SIGILL 计数/静态重算确认走的是 ud2 真路径。
- 不动态单步：SIGILL handler 里逻辑较长且用了 XMM/TEA 风格常量；直接按 .rodata 字节表逆推最快。
- 输入带换行：程序会 strip 掉 \n（23/24 字节都行），但长度不对直接拒。

## 时间线
- 17:55:5x 解包，file/反汇编定位 ud2 循环与 4 张 23 字节表；
- 17:56:5x 逆变换得候选并正向重算；
- 17:57:5x 发现 0x16a0 幻台与 SIGILL 计数验证法；
- 17:58:47 exp.py 复核 good/bad 的 rc、SIGILL、verdict 全通过。

## 可复用 TTP
- UD2/INT3 被当 hypercall：非法指令 + 自装信号处理器，参数经固定内存槽传递；
  静态找 `mov [addr], reg` + `ud2`，再找处理器读同一地址即可还原语义。
- “程序打印成功”不等于通过：对比执行路径（strace 数 SIGILL / 断点数）或直接静态重算校验式。
- 这类题的 flag 常直接点题（ud2_1s_n0t_a_cr4sh）。
