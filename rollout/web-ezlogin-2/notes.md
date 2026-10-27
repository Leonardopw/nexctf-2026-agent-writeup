# ezlogin · 笔记

## 关键点
- 首页只有一个 `<input type="password" name="password">`，`action="/verify" method="get"`，没有用户名 → 只考口令。
- `/verify` 回 `application/json`：
  - 错：`400 {"error":"Password incorrect. Matched N chars.","success":false}`
  - 对：`200 {"flag":"nex{...}","message":"验证通过！","success":true}`
- `N` 是**按位置对齐**的逐位命中数，不是前缀长度：
  - `S` → 1（第 0 位对）
  - `xSxxxxxxxx` → 0（S 在第 1 位，secret[1] 是 `3`）
  - `xxcr3t` → 4（c/r/3/t 四个位置对）
  - `S3cr3tXXXXXXX` → 6（长度不参与，超出部分忽略）
- 恢复算法：`count(prefix) == len(prefix)` 时前缀全对；追加 c 后 `count == len(prefix)+1` 即下一位命中；`success=true` 即整串正确。
- 结果：`S3cr3tP@ssw0rd123`（16 位）→ flag `nex{oNE_0f_A_k1nD_3y3iye1p}`。

## 失败分支（排除理由）
- 前缀判定：先用 `S3cr3t` 命中 6 以为是前缀长度，再试 `xSxxxxxxxx` 得 0 → 否定"前缀长度"模型，确认为位置对齐比较（否则不会出现中间位命中）。
- 字典/爆破：题目明说"不是上来就爆破"，且 oracle 已能逐位还原，不需要字典；爆破反而慢且触发限速风险，排除。
- 用户名注入 / 改参数：表单无用户名，`/admin`、`/flag` 等路径一律 500，排除越权读取。
- 长度侧信道：`S3cr3tXXXXXXX` 与 `S3cr3t` 同为 6，长度不可直接读出；只能靠 `success` 判定终点。

## 时间线
- T0 14:01:10 收到题目，建骨架 + recon（nginx；首页 Login 表单）。
- T1 14:01:40 `/verify?password=…` 探测：发现 `Matched N chars.`，`S3cr3t` 命中 6。
- T2 14:02:10 三组对照否定前缀模型（`xSxxxxxxxx`=0、`xxcr3t`=4、`S3cr3tXXXXXXX`=6）。
- T3 14:02:40 写 `exp.py` 逐位扩展，16 轮 × ~70 字符。
- T4 14:03:39 得到 `S3cr3tP@ssw0rd123` → 200 + flag `nex{oNE_0f_A_k1nD_3y3iye1p}`。

## 可复用 TTP
- 登录错误信息里出现"匹配位数/相似度/长度"就是侧信道：先做三组对照（中间位命中、错位、超长），确定是前缀、位置对齐还是编辑距离。
- 位置对齐的恢复代价是 O(L×|charset|)，16 位 × 70 ≈ 1.1k 请求，远小于字典。
- 端点用 400/200 区分错误与成功时，状态码本身就是可靠信号，别只看 body。
- flag 仍是四格式正则兜底；本题命中 `nex{...}`。
