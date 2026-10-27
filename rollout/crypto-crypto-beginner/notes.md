# 如何入门密码学 · 笔记

## 关键点
- 附件是一篇密码学入门文章，正文最后给一段脚本：「运行这个脚本，你就会得到你在密码学的第一个flag」。
- 脚本依赖：`Crypto`(pycryptodome)、`gmpy2`、`sympy`、`gmssl.sm3`、`sage.all`（GF / PolynomialRing / EllipticCurve / matrix）。
- 本机现状：Crypto ✔、sympy ✔；**gmpy2 / gmssl / sage 全部缺失**，pip 装 gmssl 也被沙箱临时目录挡住 → 按题面「装不好环境就没法学」的设定，直接纯 Python 重写。
- 脚本做了什么：
  1. `p=nextprime(p0)`、`q=nextprime(q0)`、`n=pq`、`d=65537^{-1} mod φ`；
  2. `GF(257^4)`（模 `X^4+16X^2+187X+3`）里算 `f=(Σ M[i]a^i)^b0`，取 `trace/norm`；
  3. `GF(65537)` 上 `y^2=x^3+2x+3`，`Q=b0*U`；
  4. `k=SM3(a0^b0 mod n || Qx||Qy||trace||norm || s)`；
  5. RSA 解 9 个 `C_i`，每 8 字节拆 4 个 16 位整数，乘 `B=M^{-1} mod 257`，取前 35 字节 `t`；
  6. `w=SM3(s||0)||SM3(s||1)`，`z=t⊕w`，AES-CTR(key=k, nonce=b'', iv=v) 解密。
- 结果：`nex{wEICom3_t0_the_WORLD_01_cRYPto}`。

## 复现实现（solve.py）
- `gmpy2.powmod/invert` → 内置 `pow(a,b,m)` / `pow(a,-1,m)`
- `gmssl.sm3` → 内置 SM3（含 3 个公开测试向量断言）
- `sage GF(257^4)` → 4 次多项式模 `X^4+16X^2+187X+3`，快速幂
- `trace` = Σ_{i=0..3} f^(257^i)；`norm` = f^((257^4-1)/(257-1))，二者都应退化为标量
- `sage EllipticCurve` → double-and-add 点乘（并另写 Montgomery ladder 交叉验证）
- `sage matrix` → 4x4 模 257 高斯消元求逆

## 失败分支（排除理由）
- 直接 `pip install gmssl`：沙箱临时目录报错，装不上 → 不纠缠环境，改纯 Python。
- 不装 sage 而想用 sympy 的 GF：sympy 没有 GF(p^n) 的域元素运算 → 自己写多项式域更快。
- AES 部分：pycryptodome 已装，`MODE_CTR(nonce=b'', initial_value=v)` 与脚本一致，无需替代。
- 结果校验：单看明文可读不够，另做了 13 项数学自检（SM3 向量、GF 费马、EC ladder 等）。

## 时间线
- T0 15:40:38 收到题目 + 附件；读 md，确认是「跑脚本出 flag」。
- T1 15:41:00 依赖盘点：Crypto/sympy 有，gmpy2/gmssl/sage 无；pip 装 gmssl 失败。
- T2 15:41:30 写纯 Python solve.py（SM3 + GF(257^4) + EC + 矩阵求逆）。
- T3 15:42:03 解出 `nex{wEICom3_t0_the_WORLD_01_cRYPto}`。
- T4 15:42:20 写 verify.py：13 项独立校验全过。

## 可复用 TTP
- Crypto 题先做「依赖清单 → 能装则装，不能装就等价重写」，sage 的常用件（GF(p^n)、EC、矩阵）都不难手写。
- SM3 这类国密哈希，自带实现时用公开向量自检（abc / 空串 / abcd×16）。
- 有限域校验套路：`f^(p^n-1)==1`、指数按 `p^n-1` 约简、trace/norm 必须是基域标量。
- 椭圆曲线校验套路：点在曲线上 + 两种点乘算法互算 + 结合律抽查。
- 最终明文用「格式正则（nex{}）+ 全可打印」双条件确认。
