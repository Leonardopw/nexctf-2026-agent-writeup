# 如何入门密码学 · 渗透记录

## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | 如何入门密码学 |
| 类型 | Crypto / 环境搭建 + 组合题（RSA + GF(257^4) + EC + SM3 + AES-CTR） |
| 入口 | 本地附件（attachments/如何入门密码学 (1).md，无远程） |
| 耗时 | 0 日 0 时 1 分 25 秒 |
| LLM | deepseek-flash |
| flag | `nex{wEICom3_t0_the_WORLD_01_cRYPto}` |

## 2.2 目标与授权
- 授权范围：纯本地离线计算，无网络目标
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
附件 md 正文讲解古典/现代密码学，末尾附一段 Python 脚本：依赖 Crypto、gmpy2、sympy、gmssl(sm3)、sage.all；本机只有 Crypto+sympy（gmpy2/gmssl/sage 均缺失）

## 2.4 攻击面
脚本自身：nextprime 生成 p,q -> RSA 解 C -> GF(257^4) 幂/trace/norm -> GF(65537) 椭圆曲线点乘 -> SM3 派生 key -> AES-CTR 解密

## 2.5 漏洞判定
- 类型：Crypto / 环境搭建 + 组合题（RSA + GF(257^4) + EC + SM3 + AES-CTR）
- 位置：脚本最后一行 AES-CTR 解密（key 由 SM3(a0^b0 mod n || j || s) 派生）
- 证据：evidence/step1_solve.txt（纯 Python 复算，输出明文 nex{...}）；evidence/step2_verify.txt（13 项独立校验：SM3 三个公开向量、GF 费马/指数约简/trace-norm 公式、EC 在曲线上 + Montgomery ladder 复算 + 结合律、flag 格式与可打印性）
- 误报排除：SM3 用公开测试向量（abc / 空串 / abcd*16）校验；GF 用 f^(257^4-1)==1 与 b0 mod (p^4-1) 两条独立等式；EC 用点在曲线上 + ladder 复算 + (3*12345)U 结合律；最终明文是合法 nex{...} 且全可打印，不是随机字节

## 2.6 利用链
```
md 脚本依赖装不上（无 sage/gmpy2/gmssl）-> 纯 Python 重写：pow 代 gmpy2.powmod/invert、内置 SM3、GF(257^4)=模 X^4+16X^2+187X+3 的多项式快速幂、trace=Σf^(257^i)、norm=f^((257^4-1)/(257-1))、GF(65537):y^2=x^3+2x+3 上 b0*U、4x4 模 257 求逆
p,q=nextprime(p0),nextprime(q0)；n=pq；d=65537^-1 mod φ
f=(Σ M[i] a^i)^b0；trace=196，norm=51
Q=b0*U=(50921,30098)；j=Qx||Qy||trace||norm
k=SM3(a0^b0 mod n || j || s)（32 字节）
r_i = C_i^d mod n（各 8 字节）-> 每 8 字节拆 4 个 16 位整数，乘 B=M^-1 mod 257 -> t（前 35 字节）
w=SM3(s||0)||SM3(s||1)；z=t⊕w
AES-CTR(key=k, nonce=b'', iv=v).decrypt(z) = nex{wEICom3_t0_the_WORLD_01_cRYPto}
```

## 2.7 影响
无（签到题/教学题）；用于引导选手搭环境并按脚本复现

## 2.8 修复建议
无（题目）。教学向：环境不可用时应能读懂脚本并自行等价实现

## 2.9 复盘
环境装不上就纯 Python 重写 sage/gmssl 部分；13 项交叉校验后明文即 flag。
