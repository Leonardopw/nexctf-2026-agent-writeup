# 新宿决战2 · 渗透记录

## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | 新宿决战2 |
| 类型 | Web / JWT 弱密钥（HS256 密钥为 gojo）+ 越权改 power |
| 入口 | http://0ea5rmoupjmy5teu.neu-nex.fun |
| 耗时 | 0 日 0 时 1 分 12 秒（16:24:38 建题 → 16:25:50 得 flag） |
| LLM | deepseek-flash |
| flag | `nex{sH1_5t5_Y1ng_L3_zjdh8q6g}` |

## 2.2 目标与授权
- 授权范围：题目给定目标，未触达非靶标地址
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
Server: nginx + Flask（session 为 itsdangerous 签名，payload 仅 {battle_id:<32 hex>}）；无 Shiro/Spring；/app.py、/source、/.git/HEAD、/.env、/requirements.txt、/debug、/flag、/admin 等全 404

## 2.4 攻击面
GET /get_token?skill=ao|he|ci|void 返回 HS256 JWT（header {alg:HS256,typ:JWT}，payload {skill,power}）；POST /attack 仅凭 Authorization=<REDACTED> <JWT> 扣血，body 被忽略；token 无 exp、无 nonce，也未与 battle_id 绑定

## 2.5 漏洞判定
- 类型：Web / JWT 弱密钥（HS256 密钥为 gojo）+ 越权改 power
- 位置：get_token 用弱口令 'gojo' 做 HS256 签名；服务端只验签、不校验 skill→power 的业务约束，power 直接取自 token payload 用于扣 Sukuna HP
- 证据：evidence/step1_resp.txt（首页 + Set-Cookie）；evidence/step2_req.txt / step2_resp.txt（自签 payload {skill:void,power:200000}：sukuna_hp 0、result victory、flag 字段 + 日志 'flag: nex{...}'）；evidence/step3_req.txt / step3_resp.txt（换 skill=ao、power=999999，同一 flag）
- 误报排除：两次独立会话、不同 skill 与不同 power 的自签 token 均 victory 且 flag 相同；改 payload 不重签返回 401「token 签名无效」，alg:none 返回 401「token 无效」，证明签名确实被校验、伪造 token 才是有效路径；正常 /get_token 的 void token 只打 180 伤害

## 2.6 利用链
```
GET / 建 session → GET /get_token?skill=void 取样本 JWT → 字典爆破 HS256 密钥得 'gojo' → 用 gojo 重签 {"skill":"void","power":200000} → POST /attack（Bearer 伪造 token）→ 宿傩 200000 HP 一回合归零 → result=victory + flag nex{sH1_5t5_Y1ng_L3_zjdh8q6g}
```

## 2.7 影响
可伪造任意 skill/power 的授权 token，一次请求通关并拿 flag；若 token 还承载用户/权限字段，可越权成管理员；弱密钥使整套 JWT 授权形同虚设

## 2.8 修复建议
使用高熵随机密钥（≥32 字节）并从环境变量注入；固定算法为 HS256 并显式校验（拒绝 none/算法混淆）；token 增加 exp/nonce 并与 battle_id 绑定；服务端按 skill 白名单取伤害，绝不信任 token 里的 power

## 2.9 复盘
改 body 的 power 被忽略后转向 JWT；用 1875 个主题词+常见弱口令离线爆破，命中密钥 gojo；重签 power=200000 一发通关，换技能复核同 flag。
