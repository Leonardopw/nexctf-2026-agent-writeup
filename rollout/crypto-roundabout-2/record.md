# roundabout · 渗透记录

## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | roundabout |
| 类型 | Crypto / 2x2 矩阵 + RSA（模 p 退化导致因子泄露） |
| 入口 | 本地附件（attachments/chall.py + output.txt，无远程） |
| 耗时 | 0 日 0 时 0 分 27 秒 |
| LLM | deepseek-flash |
| flag | `nex{Ju2HENH3X1AnXINgd41sHu}` |

## 2.2 目标与授权
- 授权范围：纯本地离线计算，无网络目标
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
n 为 1024 位 RSA；e=65537；r=2*(2^127+65537)（偶数）；t=2^64+104729；a=(p,1,1,0)、b=(1,0,1,1)；u=a^r、v=[u,b]、w=v^t，fingerprint=w00+w11；h=fingerprint^e mod n

## 2.4 攻击面
矩阵幂/换位子（commutator）在模 p 与模 q 两个分量上行为不同：模 p 退化，模 q 正常

## 2.5 漏洞判定
- 类型：Crypto / 2x2 矩阵 + RSA（模 p 退化导致因子泄露）
- 位置：chall.py 的 fingerprint = (w[0]+w[3]) % n 与 h = pow(fingerprint, e, n)
- 证据：evidence/step1_solve.txt（因数分解 + 解密出 nex{...}）；evidence/step2_verify.txt（11 项校验：p*q==n、p/q 为 512 位素数、e 与 φ 互素、a mod p=(0,1,1,0)、r 偶数、a^r≡I、commutator≡I、fingerprint≡2 mod p、h≡2^e mod p、pow(m,e,n)==c、明文格式）
- 误报排除：两个独立事实相互印证：模 p 下 u=a^r≡I（r 为偶数，S^2=I）⇒ v=[u,b]≡I ⇒ w≡I ⇒ fingerprint≡2；同时 h≡2^e (mod p) 由 gcd 分解验证；解出的 m 重新加密等于 c，明文为合法 nex{...}

## 2.6 利用链
```
p = gcd((h - 2^e) mod n, n) —— 因 fingerprint ≡ 2 (mod p)
q = n // p（1024 位分解成两个 512 位素数）
d = e^{-1} mod (p-1)(q-1)
m = c^d mod n = bytes_to_long(flag) -> nex{Ju2HENH3X1AnXINgd41sHu}
```

## 2.7 影响
私钥可被恢复（RSA 被分解），任意密文可解；根因是矩阵的模 p 退化把 2 这个常量带进了输出

## 2.8 修复建议
fingerprint 这类派生值不能只由退化情形决定；对 n 的两个素因子做对称性检查；用随机化/哈希后再输出；RSA 本身没问题

## 2.9 复盘
模 p 下 a=(0,1,1,0) 是幂等对换且 r 为偶数，commutator 必为 I → 指纹恒 2；gcd(h-2^e,n) 一把分解。
