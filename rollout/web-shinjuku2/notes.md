# 新宿决战2 · 笔记

## 关键点
- 目标：`http://0ea5rmoupjmy5teu.neu-nex.fun`（Web，中等）。与「新宿决战1」同一套回合制玩法，但改成了 **JWT 授权**：
  - 前端 `attack()` 先 `GET /get_token?skill=<ao|he|ci|void>`，拿 `{"token": "..."}`；
  - 再 `POST /attack`，只带 `Authorization=<REDACTED> <token>`，**body 里不再有 power**。
- 指纹：`Server: nginx` + Flask（`session` 为 itsdangerous 签名，payload 只有 `{"battle_id":"<32 hex>"}`）；无 Shiro/Spring。
- `get_token` 是严格白名单：`ao→60`、`he→90`、`ci→140`、`void→180`；未知 skill 返回 400「未知技能」。
- token 是标准 HS256 JWT：header `{"alg":"HS256","typ":"JWT"}`，payload `{"skill":"void","power":180}`。
- 服务端校验签名：改 payload 不重签 → `401 {"error":"token 签名无效"}`；`alg:none` → `401 {"error":"token 无效"}`
  （说明算法被固定为 HS256，alg 混淆不走）。

## 判定
- **JWT 弱密钥**：签名密钥是主题弱口令 `gojo`。
- 用 1875 个候选（常见弱口令 + 题目主题词 gojo/sukuna/shinjuku/jujutsu/... + 大小写/数字/leet 变体）
  离线 HMAC-SHA256 比对，命中 `gojo`。
- 用 `gojo` 重签 `{"skill":"void","power":200000}`，`POST /attack` 一回合清空宿傩 HP → `result:victory` + flag。

## 失败分支（排除理由）
- 直接改 `/attack` body 的 power：`/attack` 只认 `Authorization` 里的 token，body 被忽略。
- 改 JWT payload 但沿用原签名：401「token 签名无效」。
- `alg:none` / 删签名：401「token 无效」，算法固定。
- 目录/源码泄露（`/app.py`、`/source`、`/.git/HEAD`、`/.env`、`/requirements.txt`、`/debug`、`/flag`、`/admin`…）：全 404。
- 复放原 token：只能打出 180 伤害；正常玩法 200000/180≈1112 回合，而五条悟 1000 HP、宿傩每回合反击 220~350，必败。

## 时间线
- T0 16:24:38 建题骨架（newcase）。
- T1 16:24:39 抓首页，读内联 JS：改为 `/get_token` + Bearer JWT。
- T2 16:24:5x 枚举 skill 拿 4 个 token；确认 HS256、payload 含 skill/power。
- T3 16:25:0x 验证：改 payload 重签失败（401 签名无效）、alg:none 失败（401 token 无效）、源码路径全 404。
- T4 16:25:3x 字典爆破命中密钥 `gojo`。
- T5 16:25:50 伪造 power=200000 打一发 victory；换 skill=ao / power=999999 独立复核同 flag。

## 可复用 TTP
- JWT 题先看三处：header 的 alg/kid/jku、payload 里的权限字段、服务端错误文案。
  错误文案区分「签名无效」与「token 无效」说明解析层和验签层是分开的，算法被钉死。
- HS256 弱密钥优先用**题目主题词**（角色名、作品名、标题拼音）+ 常见后缀；
  1875 个候选离线 HMAC 比对秒级完成，比上 hashcat 更快。
- 拿到密钥后按业务语义伪造字段（这里是 power），一次打满。
