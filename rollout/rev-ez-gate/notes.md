# 山门 · 验灵碑（ez_gate）· 笔记（已解）

## 关键点
- 附件 `ez_gate`：ELF 64-bit PIE、not stripped、动态链接（只用 puts/printf/fgets/strlen/strcmp）。
- 运行流程：打印碑文 → `fgets` 读口诀 → 去尾部 `\n\r` → `strcmp(输入, 常量)` → 相等打印
  `[OK] 碑上灵光一闪，验证通过！`，否则 `[FAIL]`。
- `main` 里 `lea rdx, [rip+0xe86]`（0x1350）指向 **strcmp 的常量 @0x21dd = `NEX{gu4n_9ui1_y4n7}`**。
- 50 条仙诀存放在 `0x3c00..0x3d90` 的 **R_X86_64_RELATIVE 重定位槽**：每个 `r_offset` 是槽位、
  `r_addend` 指向 .rodata 字符串。按“刻法”分类解码：
  - 正刻 plain：直接是 `NEX{...}`（17 条）
  - 倒刻 reversed：`}...{XEN`，反转后得 `NEX{...}`（13 条）
  - 金文 hex：8 位 hex 串（如 `4e45587b...`），`bytes.fromhex` 后是 `NEX{...}`（3 条）
  - base64：`TkVY...`，解码得 `NEX{...}`（12 条）
  - 伪刻：`ARK{...}` 假前缀（5 条），直接排除
- 50 条解码后互不相同，只有 **第 [23] 条（0x21dd，正刻）** 与 strcmp 常量一致 → 真门规。

## 判定
- 静态：50 条里与 `strcmp` 目标相等的只有 1 条（`NEX{gu4n_9ui1_y4n7}`），地址/字节都对得上；
- 动态：WSL 里运行 ELF，输入该串 → `[OK] ...`；输入小写 `nex{...}` → `[FAIL]`（strcmp 区分大小写）。
- 结论：flag 为 **`NEX{gu4n_9ui1_y4n7}`**（大写 NEX 前缀）。

## 失败分支（排除理由）
- 先按“50 条全是候选、需要全解码后挑一条”做：解码完发现 45 条都是 NEX{...}（互不相同），
  5 条 ARK{...} 是干扰项；靠“哪条等于 strcmp 常量”唯一确定。
- 试过小写 `nex{gu4n_9ui1_y4n7}`：strcmp 拒绝，说明本题 flag 就是大写 NEX。
- 不需要动态调试/爆破：常量直接以明文在 .rodata，关键是把“50 条表 + 解码规则”对上。

## 时间线
- 17:31:5x 解包，确认 ELF，看 strings/符号。
- 17:32:2x 反汇编 main，定位 strcmp 常量 @0x21dd。
- 17:32:5x 解析 .rela.dyn 的 50 个槽位，按 plain/reversed/hex/base64/ARK 解码。
- 17:33:19 静态 exp.py 输出唯一匹配，WSL 运行 ELF 复核 [OK]。

## 可复用 TTP
- 字符串藏在重定位表（R_X86_64_RELATIVE）里的题：读 `.rela.*` 的 `r_addend` 取字符串，
  `r_offset` 只是数据槽，不是内容。
- 竞赛题常见的“正刻/倒刻/金文” = plain / reversed / hex / base64；`ARK{` 是伪前缀干扰。
- 最终以程序里的 strcmp 常量（或运行回显）为准，别被 50 条候选绕晕。
