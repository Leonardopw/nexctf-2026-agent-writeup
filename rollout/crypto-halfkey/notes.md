# halfkey · 笔记（已解：partial key exposure，flag 已出）

## 结果
- **flag：`nex{p3m_DEr_aNd_paCkEdsXjaLsdJ4sD}`**（`exp.py` 一条命令复核：7 项校验全 True）。
- 因子：Coppersmith (m,t)=(4,5)、dim 9 格，纯 Python LLL 约 1046 s；p,q 各 1024-bit，q-p>2^1016。
- 旧 `exploit.py` 失败根因（已定位）：`s0 = A//k ≥ s` ⇒ `q0 ≥ q`，应求 `f(x)=x-q0` 的正根 `q0-q`；
  旧代码用 `q0+x` 方向反了，真实数据上永远 miss。误差界实测 `|q0-q| < 2^452 < n^(1/4)=2^512`，dim4 的 (2,1) 理论上也够。


## 题目与泄露
- 附件：`chall.py`（2048-bit RSA，e=65537，p,q 各 1024-bit，要求 d ≥ 2047 bit、q-p > 2^1016）+ `output.txt`。
- `output.txt` 第 1 行是 `key.export_key()[:677]` 的 bytes repr → 解码后：
  - PEM 头 31 字符 + 9 行 base64 + 半行 → 636 base64 字符 → **477 字节 DER 前缀**；
  - DER 字段：version(1B)、**n(完整 257B)**、**e=65537**、**d 只活下 200B**（缺低 56B = 448 bit）。
- 结论：n、e 完整；d 的高 1600 位已知、低 448 位丢失 → 经典 partial key exposure。

## 攻击链（已确认推导正确）
1. `k = (e·d − 1)/φ`，φ=N−(p+q)+1；用 d0 估：`k0=(e·d0)//N`，实测 **k = k0+1 = 25487**（唯一使 S=p+q ≥ 2√n 的）。
2. `A = k(N+1) − e·d0 + 1`；`s0 = A//k`；真 `s = (A − e·x)/k`，x = d 的低 448 位（0 ≤ x < 2^448）。
3. `q0 = (s0 + isqrt(s0²−4N))//2`，误差来自 Δs=e·x/k（≈2^449）经 `dq/ds = p/(q−p)` 放大 ≤2^8 → q 误差 < 2^457；题目强制的 q−p > 2^1016 正是保证 |dp/ds| ≤ 2^8。
4. 用 f(x)=q0+x mod q 做 Howgrave-Graham 单变量 Coppersmith（X≈2^453~2^459 < N^0.25=2^512）。
5. 得到 p,q 后：d 反算应与 PEM 高位逐位一致；(e·d−1)/φ == 25487；pow(m,e,n)==c → 强一致性校验（题解给的校验方式）。

## 代码现状（`exploit.py`）
- `parse()`：解码截断 PEM，拿到 n/e/d0/c（已跑通，输出见 `decode_pem.py`）。
- `exploit.coppersmith()`：自实现 Howgrave-Graham 格 + **Decimal 高精度 LLL**（`lll_dec.py`；sympy 自带 LLL 在这类超大整数上 `mfloor(QQ)` 会 float 溢出）。
- root 提取：deg1 精确、deg2 用整数判别式、deg≥3 用 mpmath 高精度 polyroots。
- 合成数据验证：512-bit N + X=2^70（与真实题同样的 X/N^0.25 = 2^-58 比例）时 **(m,t)=(2,1) dim 4 即可成功**；负根也测过。
- 真实数据上目前试过的参数（均 None）：(2,1)/(2,2)/(3,0)/(3,1)/(3,2)/(4,0)/(4,1) 等，
  (3,2) 约 254s。仍在扫更大格（用户提示目标参数 (m,t)=(4,5)、dim 9 量级）。

## 卡点 / 下一步
- 真实数据上还没找到能覆盖误差的小根，怀疑：B 取小了（应 ≥2^457，且用 v>2^1016 的保守放大）；
  或 LLL 精度/参数网格不够；或根提取数值精度不足。
- 下一步建议：
  1. 用 **(m,t)=(4,5) / dim 9** 的格直接打（用户给的参数），B 用 `Δs·(1+s/2^1016)/2`；
  2. φ ≡ 0 (mod 4) 收紧 2 bit；
  3. 若 Decimal LLL 仍慢，改 fpylll/flatter（本机没有）或把 LLL 精度调低 + 用 factor 校验；
  4. 拿到 p,q 后按上面的三重校验（d 高位、k、pow(m,e,n)==c）确认。

## 可复用 TTP
- PEM 截断题：先精确算“截到哪一字节/哪个字段”，再决定是 partial d 还是 partial p。
- 已知 d 高位 → 估 k → 估 φ → 估 p+q → 用 dq/ds 放大到 q/p 的误差界，喂 Coppersmith。
- 大整数格：sympy LLL 会 float 溢出；自己写 Decimal-LLL 或装 fpylll。
- 校验三件套：d 高位逐位比对、k 反算一致、pow(m,e,n)==c。
