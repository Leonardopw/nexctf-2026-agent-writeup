# 新宿决战1 · 笔记

## 关键点
- 目标：`http://u8q0hcswmbnhwz70.neu-nex.fun`（Web，简单）。首页「五条悟 vs 宿傩」回合制小游戏。
- 指纹：`Server: nginx`；`Set-Cookie=<REDACTED> 为 `{"battle_id":"<32 hex>"}`，
  说明战斗状态按服务端 session 存；无 Shiro/Spring 痕迹，`/admin`、`/login`、`/robots.txt`、`/.git/` 全 404。
- 前端内联 JS 全部逻辑：
  - `GOJO_MAX=1000`，`SUKUNA_MAX=200000`；
  - 按钮 `<button data-skill="ao|he|ci|void" data-power="60|90|140|180">`；
  - `attack()` 把 `btn.dataset.skill / btn.dataset.power` 原样 `JSON.stringify({skill, power})` POST 到 `/attack`。
- 服务端直接采信 body 里的 `power` 扣 Sukuna 血：正常 60 伤害时回 `sukuna_hp: 199940`、`gojo_hp: 650`（宿傩反击 350）。

## 判定
- **参数篡改**：`power` 是客户端可控且无签名/无白名单，改成 200000 即一回合让宿傩 HP 归零。
- 正常玩法需要 200000/180 ≈ 1112 回合，而五条悟只有 1000 HP（宿傩每回合 220~350 反击），根本打不过，
  所以题目设计就是让选手改 `power`。

## 失败分支（排除理由）
- 目录/端点爆破（`/admin`、`/admin/flag`、`/login`、`/robots.txt`、`/.git/HEAD`、`/actuator`）：全 404，无隐藏入口。
- Shiro 指纹（`rememberMe=deleteMe`）：无，排除反序列化路线。
- Cookie 伪造：session 为 itsdangerous 签名，不知道 SECRET_KEY；但本题不需要——服务端状态不影响漏洞，直接改请求体即可。

## 时间线
- T0 16:21:57 建题骨架（newcase）。
- T1 16:22:02 recon：nginx + Flask session，静态目录全 404。
- T2 16:22:08 抓首页，读内联 JS 发现 `power` 由前端提交。
- T3 16:22:2x 正常请求确认服务端按 body 数值扣血。
- T4 16:22:35 `power=200000` 一次 victory，JSON 顶层 `flag` + 日志末尾 `flag: nex{...}`；换 `skill=he`、`power="1000000"`（字符串）复核同 flag。

## 可复用 TTP
- 回合制/小游戏类 Web 题：先读内联 JS 找**客户端计算/客户端提交的数值**（伤害、价格、数量、坐标、seed），
  改 JSON 里的数值往往比找注入快。
- 服务端返回结构里同时看 `result`、数值字段和 `log` 原文；flag 常在“胜利分支”被写进日志。
- 复核时换一个技能/类型（数值 vs 字符串）再打一次，排除“某条 payload 触发特定分支”的假象。
