# 超大杯flask · 渗透记录

## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | 超大杯flask |
| 类型 | Web / Flask（静态备份泄露 + 类污染改 IS_ADMIN；另有 SSTI/pickle 可利用链） |
| 入口 | http://zpsrdd9p7lls0tp5.neu-nex.fun |
| 耗时 | 0 日 0 时 11 分 43 秒（约；19:50:07 收题 → 20:01:50 出 flag） |
| LLM | deepseek-flash |
| flag | `nex{Sup3R_B1G_cUP_lg3nfbio}` |

## 2.2 目标与授权
- 授权范围：题目给定目标，未触达非靶标地址
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
nginx 反代 + Flask(Python 3.11, Werkzeug)；单入口 / 登录，/shop、/item/<id>、/buy(POST JSON)、/restock(POST JSON)、/admin；/static/<path> 由 Flask send_from_directory 提供

## 2.4 攻击面
/static/backup.sql 泄露数据库（zc 密码、goods 中的 flag 条目）；/restock 的 merge(Goods(), cfg) 可沿 __class__→__init__→__globals__ 污染模块全局 IS_ADMIN；/restock 的 f-string + render_template_string 还有 SSTI（\u007b 绕 WAF）；/buy 的 pickle.loads 可用 OBJ 绕 REDUCE/INST 禁用

## 2.5 漏洞判定
- 类型：Web / Flask（静态备份泄露 + 类污染改 IS_ADMIN；另有 SSTI/pickle 可利用链）
- 位置：GET /static/backup.sql；POST /restock（config 参数）；GET /admin
- 证据：evidence/step1_solve.txt（exp.py 全链路输出：备份→登录→污染→/admin 拿 flag）、evidence/backup.sql（泄露的数据库备份）、evidence/app.py（RCE 读回的完整源码）、evidence/home.html
- 误报排除：两条独立证据：①exp.py 从 /static/backup.sql 取密码登录，污染后 GET /admin 返回 {"flag":"nex{Sup3R_B1G_cUP_lg3nfbio}"}；②app.py 源码确认 /admin 仅在 IS_ADMIN 为真时返回 get_flag()，而 merge() 的 getattr 下钻可写 __globals__['IS_ADMIN']

## 2.6 利用链
```
hint→/static/backup.sql 拿到 zc/325X1@n5hUbeI! → POST /login 得 session → POST /restock {__class__:{__init__:{__globals__:{IS_ADMIN:true}}}} 类污染 → GET /admin 返回 flag
```

## 2.7 影响
普通用户可把自己提权为管理员，读取内存中的 flag；同时 /restock 存在 SSTI 可 RCE（root），/buy 存在 pickle 反序列化

## 2.8 修复建议
不要用 merge/getattr 递归合并用户可控 JSON；禁止外部输入触碰 __class__/__globals__ 等 dunder 键；/static 下不要放数据库备份与源码；SSTI 处避免把用户输入拼进 render_template_string；pickle 一律不接收外部数据

## 2.9 复盘
关键是 hint 直接指向 static 备份，猜 backup.sql（而不是 app.py.bak）一次命中；随后读源码发现 IS_ADMIN 类污染点，一条 JSON 就结束。SSTI 与 pickle 是冗余链。
