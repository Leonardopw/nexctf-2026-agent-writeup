# shiro-web · 笔记

## 关键点
- 指纹：`rememberMe=AAAA` → `Set-Cookie=<REDACTED> → `302 /login;jsessionid=...`，而 `/login` 返回 404（无登录页）。
- 典型的「只能伪造 rememberMe 或走路径归一化」局面；留言板是幌子。
- 路径矩阵（`pentestctl bypass`）一发命中：
  - `/x/..;/admin/flag` → 200
  - `/x/..;/admin/flag/` → 200
  - `/;/admin/flag` → 200
  - `/.;/admin/flag` → 200
  - 直连 `/admin/flag`、`/x/../admin/flag`、`/x/%2e%2e/admin/flag`、`/admin/flag;` → 302
- flag：`nex{teAm_5pIrIt_sH1r0_nn0dvbkr}`（三个变体回显一致）。

## 失败分支（排除理由）
- **留言板存储型 XSS**：`/submit?msg=` 原样存储，`innerHTML` 渲染，`<img onerror>` 能执行；但 admin bot 只带回 `document.cookie=<REDACTED> 是 HttpOnly），
  bot 自己 `fetch('/admin/flag')` 最终 404（`/login;jsessionid=...`），说明 bot 没有管理员会话 → XSS 路线拿不到 flag，排除。
- `Cookie=<REDACTED> 直连 `/admin/flag` 仍 302，排除「简单 cookie 伪造」。
- `rememberMe` 伪造（Shiro-550）：需要 key 与 Java gadget 链（本地有 `shiro/` 下的 Forge 代码与 `shiro_keys.txt`），但路径绕过已出 flag，未展开爆破，记为备选路线。
- `/admin/flag;`、`/admin/flag/..;/` → 302，说明不是所有分号变体都有效，必须走能触发容器归一化的形态。

## 时间线
- T0 14:23:47 收到题目，建骨架 + recon：确认 Shiro 指纹与 302 链路。
- T1 14:24:05 留言板接口探测：`/api/messages` 空数组、`/submit` ok、`/report` 触发 bot。
- T2 14:24:30 XSS 探测：`<img onerror>` 成功回调 `admin=1`；bot 调 `/admin/flag` 仍是 404 → 排除 XSS。
- T3 14:25:00 跑 `pentestctl bypass`：`/x/..;/admin/flag` 等 4 个变体 200。
- T4 14:25:21 取 flag `nex{teAm_5pIrIt_sH1r0_nn0dvbkr}`，再用 `/;/`、`/.;/` 两种变体复核一致。

## 可复用 TTP
- Shiro 场景先看两条线：rememberMe 指纹 + `/admin` 302 到 `/login;jsessionid` → 优先路径归一化，成本最低。
- 归一化变体要一次打全矩阵：`/x/..;/`、`/;/`、`/.;/`、`;` 后缀、`%2e%2e`；命中判据是 200 + body 变化，不是 302 消失。
- 留言板/举报类功能默认怀疑「admin bot + XSS」，但先验证 bot 是否真带管理员会话（让 bot 自己 fetch 一次受保护接口即可判定），避免在红鲱鱼上耗时间。
- 对靶机的清理：本题没有删除接口，探测用 XSS payload 会留在 board（`step4_messages.json` 留档），后续不再追加。
