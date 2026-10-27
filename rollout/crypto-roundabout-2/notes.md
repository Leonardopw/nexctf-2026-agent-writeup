# roundabout · 笔记

## 关键点
- 附件：`chall.py`（1085 B）+ `output.txt`（n/e/c/h/r/t，1024 位 n）。
- 结构：2×2 矩阵在 `Z/nZ` 上运算（`mul` 是行主序 4 元组），`power` 快速幂，`inverse` 用行列式求逆，`commutator(a,b)=a b a⁻¹ b⁻¹`。
- 参数：`r = 2*(2^127+65537)`（**偶数**）、`t = 2^64+104729`；`a=(p,1,1,0)`、`b=(1,0,1,1)`；`u=a^r`、`v=[u,b]`、`w=v^t`、`fingerprint=w00+w11`，`h=fingerprint^e mod n`。
- 核心缺陷（分模看）：
  - mod p：`a=(p,1,1,0) ≡ (0,1,1,0)=S`，而 `S²=I`；r 为偶数 ⇒ `u=a^r ≡ I`；于是 `v=[u,b] = I`，`w=I`，`fingerprint ≡ 1+1 = 2 (mod p)`；
  - mod q：p 可逆，a 不退化为 S，一切正常。
- 于是 `p | (h - 2^e)`，`gcd((h-2^e) mod n, n)` 直接分解 n，RSA 私钥 `d=e^{-1} mod φ` 解密即得 flag。
- 结果：`nex{Ju2HENH3X1AnXINgd41sHu}`（与 2026-10-24 旧实例一致，本题 flag 是静态的）。

## 失败分支（排除理由）
- 试图用 commutator 的“指纹”本身逆推：fingerprint 是 n 模下的混合值，未知分量 q 不可控 → 不划算。
- 想直接分解 1024 位 n：没有其他泄露点，硬分解不可行 → 必须利用模 p 退化。
- 检验“r 的奇偶性是否关键”：r 为偶数正是 `S^r=I` 的原因；若 r 为奇数会得到 S，指纹就不是 2，说明出题人故意选偶数。
- 单独看 c/h 以为是普通 RSA 广播/共模：e 相同但只有一组 (n,c)，共模攻击不成立 → 排除。

## 时间线
- T0 15:44:29 建骨架、解压附件，读 chall.py。
- T1 15:44:40 分模分析：mod p 退化 → fingerprint≡2；写出 gcd 分解 + 解密。
- T2 15:44:57 solve.py 出明文 `nex{Ju2HENH3X1AnXINgd41sHu}`。
- T3 15:45:10 verify.py 11 项校验全过（含 mod p 矩阵模拟、h≡2^e mod p、重加密一致）。

## 可复用 TTP
- 矩阵/群上的 RSA 变体，先分别模 p、模 q 看退化：元素为 0 的分量常让群结构塌缩成有限阶小群。
- 换位子对可交换元素恒为 I —— 这是最容易被“指纹化”泄露 2 的地方。
- 拿到 `fingerprint ≡ 2 (mod p)` 后，`gcd(h - 2^e, n)` 一把分解，比任何格/共模都便宜。
- 校验套路：素数性 + `pow(m,e,n)==c` + 明文正则；再用独立脚本模拟 mod p 的矩阵幂验证假设。
