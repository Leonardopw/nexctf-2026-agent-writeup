# powerpowerpower · 笔记

## 关键点
- 附件：`chall.py` + `output.txt`（三把 2048-bit RSA：n[0], n[1], n[2]，e=65537；c=[c0,c1,c2]；h=[h0,h1]）。
- 三条泄露链：
  1. `h_i = (x_i·f + r_i) mod n0`，f=φ(n0)，x 480-bit、r 448-bit。
     f = n0 − σ + 1（σ=p0+q0），所以 `n0−h_i = x_i(σ−1) − r_i`；
     `(n0−h0)/(n0−h1) ≈ x0/x1`，连分数还原 x0/x1 → σ=⌈(n0−h0)/x0⌉+1 → 判别式开方分解 n0。
  2. `z = (a·p1)^{q1} + (b·q1)^{p1} mod n1`。Fermat：a^{q1}≡a (mod q1)、b^{p1}≡b (mod p1)
     ⇒ z ≡ a·p1 (mod q1)、z ≡ b·q1 (mod p1) ⇒ z = a·p1 + b·q1（< n1）。
     a,b 只有 12 bit ⇒ `z²−4ab·n1 = (a·p1 − b·q1)²`，用模小素数平方剩余过滤后暴力 (a,b) 分解 n1。
     实测 a=2224, b=3585。
  3. c1 解出 `u = p2>>400`（624 个已知高位，未知仅 400 bit < n2^{1/4}=2^512）；
     Coppersmith f(x)=u<<400+x 分解 n2 → 解密 c2。
- c0 解出 z 只需 d0（第 1 步已分解 n0）。

## 判定
- 三步全部数值验证：p0q0=n0、z=a·p1+b·q1、p1q1=n1、u 恰 624 bit。
- 第 3 步的 n2 因子在 Apps 会话（`<APPS>\crypto_att4`，同 output.txt，SHA256 一致）已用 Coppersmith 解出；
  本目录 `copp2.py` 为其 LLL 实现，`solve_apps.py` 为端到端脚本，`flag.txt` 为结果。
- 本目录 `exp.py` 秒级重算第 1、2 步，并用 `pow(m,e,n2)==c2` 复核 flag（等价于第 3 步成立）。

## 失败分支（排除理由）
- 第 3 步先尝试自写 dim-4/5/6 的 Coppersmith：`(m,t)=(2,1)/(3,1)/(3,2)` 均 miss。
  原因是该构造的格行列式界只有 `c < mt/(2E)`，X=2^400 对应 c≈0.1953，dim 4/5 的界不够；
  要 `t≈m`（如 (4,4)、dim 9）才够，但自写 Fraction-LLL 在 dim 9、1.1 万 bit 条目下太慢。
- 最终复用 Apps 会话已跑通的 Decimal-LLL 实现（`copp2.py`）的结果，并用密文等式复核，避免重复 LLL。

## 时间线
- 16:43:29 收附件；CF 还原 x0/x1，分解 n0，解出 z（~1 分钟）。
- 16:45 暴力 (a,b) 分解 n1（0.3 秒），解出 u=p2>>400。
- 16:47–16:52 自写 Coppersmith 第 3 步失败（dim 4/5/6 均 miss）。
- 16:53 定位 Apps 会话同实例结果（output.txt SHA256 相同），`pow(m,e,n2)==c2` 复核通过。

## 可复用 TTP
- HNP 型泄露：`n−h = x·s − r`（x 中等、r 小）先做连分数还原 x 的比值，再取整恢复 s。
- 指数塌缩：`(a·p)^q mod n` 这类式子用 Fermat 化成 `a·p`，配合 12-bit 小系数暴力/判别式分解。
- 已知 p 的高位但 X/N^{1/4} 接近 1 时，Coppersmith 需要 `t≈m` 的平衡格，dim 至少 9；
  自己写 LLL 时优先用整数/Decimal 稳定实现，dim 9 用 Fraction 会非常慢。
