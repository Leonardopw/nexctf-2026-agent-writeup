# 牢九门（APEX 待加强名单）· 笔记

## 关键点
- /search?name= 直接拼进 SQL，回显只有 found / not found → 布尔盲注
- sqlmap 一条命令确认：`sqlmap -u ".../search?name=Bloodhound" --batch --dbs --technique=B`
- SQLite 不能 --dbs，改 --tables；拿到 legends / flag，`-T flag --dump` 出 flag
- 手工等价手法：`x' OR (条件)--`，用 `unicode(substr(...,pos,1))>mid` 二分，35 字符约 280 请求

## 失败分支
- `' OR 1=1#` 无效（SQLite 注释是 `--` 不是 `#`）
- sqlmap 首次 `--dbs` 报「SQLite 不支持枚举库」，改 `--tables` 即通

## 时间线
- T0 13:14:26 首条消息
- T1 13:16 定位 /search?name=
- T2 13:18 sqlmap 确认 SQLite boolean-based blind
- T3 13:23 --tables 得 flag 表
- T4 13:23:44 dump 出 flag；13:26 手工二分复核一致

## 可复用 TTP
- 只有两态回显时先跑 sqlmap --technique=B 定性，再决定手工还是 dump
- SQLite 枚举顺序：sqlite_master 表名 → pragma_table_info 列名 → 目标表 dump
- 二分用 `>`，每字符 7 次请求；先 length() 定长，避免越界空转
