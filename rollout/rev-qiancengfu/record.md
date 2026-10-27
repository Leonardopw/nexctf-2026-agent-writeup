# 坊市 · 千层符 · 渗透记录

## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | 坊市 · 千层符 |
| 类型 | Reverse / aaencode 壳 + 自定义三层封装（XOR→base64→反转→base64） |
| 入口 | 本地附件 千层符 (2).zip → 千层符.html（78,203 B，无远程） |
| 耗时 | 0 日 0 时 1 分 25 秒（17:44:50 收附件 → 17:46:15 出 flag） |
| LLM | deepseek-flash |
| flag | `NEX{c0d1ng_l4y3r_by_l4y3r}` |

## 2.2 目标与授权
- 授权范围：纯本地离线分析，无网络目标
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
HTML 单页，内嵌一段 aaencode/JSFuck 风格脚本（经 Function 构造执行）；layer1 为 1100 B 明文 JS，含 RUNES/SPIRIT_KEY/wrapTicket()/check()

## 2.4 攻击面
渲染逻辑把口令封装成 RUNES 后与输入重封装结果比较；封装可逆（XOR 灵钥 + base64 + 整体反转 + base64），灵钥明文写在 wrapTicket 里

## 2.5 漏洞判定
- 类型：Reverse / aaencode 壳 + 自定义三层封装（XOR→base64→反转→base64）
- 位置：千层符.html 的 <script>（offset 约 33）中的 obfuscated 源码；layer1 的 RUNES="PWd4UGRoUlEw…"、SPIRIT_KEY="QiXuanMen"、wrapTicket()
- 证据：evidence/run.log（剥壳、RUNES/KEY、三层中间值、plain、页面 check 判定 ok）；evidence/layer1_code.js（剥壳后源码）；evidence/step1_solve.txt（中间值与 flag）
- 误报排除：用页面自身 wrapTicket(plain) 重封装结果与 RUNES 逐字节相等；VM 中实际执行页面 check()，输入 plain 返回 out.className='ok' 且文案「对上了！…符胆归你了」，输入 NEX{wrong} 返回 'bad'；flag 命中 NEX{...} 格式

## 2.6 利用链
```
读 千层符.html → 替换 Function.prototype.constructor 捕获 aaencode 要执行的源码 → 得 layer1（1100 B JS）→ 取 RUNES/SPIRIT_KEY → RUNES→b64→反转→b64→XOR(QiXuanMen) → plain=NEX{c0d1ng_l4y3r_by_l4y3r} → 页面 wrapTicket 重封装相等、check() 返回 ok
```

## 2.7 影响
页面口令可被完全逆出，封印只是编码层而非密码学保护；任何拿到 HTML 的人都能还原符胆

## 2.8 修复建议
不要把校验逻辑和密钥放在客户端；口令校验应放到服务端，客户端只做展示；若必须本地校验，用带盐 KDF/哈希而不是可逆的 XOR+base64

## 2.9 复盘
两层：aaencode 壳用 Function 捕获法秒破；三层封装可逆（XOR/base64/反转），关键是先读 wrapTicket 再反着做。用页面自身 check() 复核 ok 才算数。
