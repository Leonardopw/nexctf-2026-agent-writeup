# 坊市 · 千层符（qiancengfu）· 笔记（已解）

## 关键点
- 附件 `千层符.html`（78,203 B），页面里只有一段 `<script>`，内容是 aaencode/JSFuck 风格乱码
  （`锞熛夛緹…` 那种），外面套 `Function` 构造。
- **layer0 剥壳**：把 `Function.prototype.constructor` 换掉，捕获它要 `new Function(...)` 的源码，
  得到 **layer1**（1100 B 明文 JS，含 `RUNES`、`SPIRIT_KEY`、`wrapTicket()`、`check()`）。
- **灵钥**：`SPIRIT_KEY = "QiXuanMen"`（七玄门），就缝在 layer1 的 `wrapTicket()` 里——题面说的
  “钥匙缝在符纸的画法里”。
- **三层封装**（`wrapTicket` 正向）：
  1. `plain` 逐字节 XOR `SPIRIT_KEY`（循环）→ `mixed`
  2. `mixed` → `btoa` → `layer1_b64`
  3. `layer1_b64` 整体反转 → `layer2`
  4. `layer2` → `btoa` → `RUNES`
- **逆向**：`RUNES` → b64 解码 → 反转 → b64 解码 → 逐字节 XOR 灵钥 → `plain`。
  实测：`layer2 = "=gxPdhRQ0YDKMozPdhRQ0YjNAQVKeJgDAwyH"`、
  `layer1 = "HywADgJeKVQANjY0QRhdPzoMKDY0QRhdPxg="`、
  `mixed = 1f2c000e025e29540036363441185d3f3a0c28363441185d3f18`、
  `plain = NEX{c0d1ng_l4y3r_by_l4y3r}`。
- **验证**：用页面自己的 `wrapTicket(plain)` 重封装，结果与 `RUNES` 完全相等；
  再在 VM 里跑页面 `check()`，输入 `plain` → `out.className = "ok"`（「对上了！…符胆归你了。」），
  输入 `NEX{wrong}` → `bad`。

## 判定
- `wrapTicket(plain) === RUNES` 为 true（等价于原页面校验通过）；
- 页面 `check()` 实际返回 `ok` 且文案正确；
- flag 命中 `NEX{...}` 格式。

## 失败分支（排除理由）
- 直接读 HTML 的 `<script>` 是 obfuscated 字符串，不能静态搜 flag；
- 尝试把脚本当普通 JS 执行会因 `Function` 构造 + 乱码标识符报错，必须替换构造器捕获源码；
- 不需要爆破 RUNES：`wrapTicket` 是可逆的（XOR + base64 + 反转），直接逆推。

## 时间线
- 17:44:50 收附件，确认是 HTML + 单段脚本；
- 17:45:2x 写 exp.js：捕获 layer1 → 提取 RUNES/KEY → 逆三层封装；
- 17:46:0x 得到 plain，重封装校验 true，VM 跑 check() 得 ok；
- 17:46:15 落盘证据。

## 可复用 TTP
- aaencode/JSFuck 的通用解：替换 `Function.prototype.constructor` 捕获 `new Function` 的源码（见 exp.js）。
- 自定义封装函数一律先读实现再逆；本题三层是 XOR→base64→反转→base64，反着做即可。
- 验证要用**原程序的校验函数**（这里是页面 `wrapTicket` + `check`），别只靠肉眼。
