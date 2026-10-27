# 魔法余数 · 笔记（已解：模 p 线性组合只泄露高位 → LLL+Babai 的 CVP）

## 关键点
- 附件 `chall.py`：p 为 336-bit 素数，a 为 34 个 [1,p) 随机数，
  `h = (Σ a_i·c_i mod p) >> 80`，c_i 是 flag 内层 34 个字符（`[A-Za-z0-9_]`）。
- 设 S = Σ a_i c_i mod p = h·2^80 + t（0 ≤ t < 2^80），k = Σ a_i c_i // p，则
  `Σ a_i(c_i − CENTER) − k·p = h·2^80 − CENTER·Σa_i + t`，误差只有 80 bit。
- 构造 35 维格 L = { (C·y_1..C·y_n, Σ a_i y_i − k·p) }：
  - 行：`[C·e_i | a_i]`（i=1..34）与 `[0 | p]`；
  - 目标向量 `T = (0..0, (h·2^80 − CENTER·Σa_i) mod p)`；
  - 真解向量 `v = (C·d_i, t)`，d_i = c_i − CENTER。
- 参数：C = 2^72~2^74，CENTER ∈ [60,126]。
  det = p·C^34 ⇒ det^{1/35} ≈ 2^78.6，高斯启发值 ≈ 2^79.1；
  真解范数 ≈ 2^80.3 与 GH 同量级但方向正确（居中后 Σd_i² ≈ 2^13.9），
  **LLL(delta=0.99) 归约后用 Babai 最近平面**即可命中——注意不能用 Kannan embedding：
  嵌入后维度变 36，det^{1/36}≈2^78.3、GH≈2^78.8，真解 2^80.3 反而比最短向量长，必失败。
- CENTER 只出现在目标向量、不出现在格基里，所以一次 LLL 可以扫所有 CENTER（省时间）。

## 判定
- 解出 msg = `1_D0NT_llK3_rEmIND3r_and_c0mPuT1nG`，复核 `Σ a_i·c_i mod p >> 80 == h` ✓，
  长度 34 ✓，`replace(b'_',b'A').isalnum()` ✓ → flag `nex{1_D0NT_llK3_rEmIND3r_and_c0mPuT1nG}`。
- exp.py 端到端复现：C=2^72 时 LLL 约 11 s，随后扫 CENTER 命中。

## 失败分支（排除理由）
- 先在 `nt/` 里试过 Kannan embedding（把目标行 [T,1] 也放进格，扫含 ±1 的基向量）：
  C=2^66..2^78、CENTER∈{64,85,97,109} 全部 miss——原因如上，embedding 后维度+1 使真解高于 GH。
- 直接对 Σ a_i c_i 做精确子集和/低密度攻击：c_i 是 7-bit 而非 0/1，且模 p 有余数 t（80 bit 未知），
  不能直接套 Coster 的精确子集和格。
- 不居中（CENTER=0）：真解范数被 c_i≈85 的均值撑大，比 GH 高约 1.5 bit，LLL/Babai 失败。

## 时间线
- 16:59:52 收附件；读 chall.py 定型。
- 17:01 在 <WORKSPACE>\challenges\crypto\nt 里发现前次 Kannan 尝试未果，改走 CVP + Babai。
- 17:03 LLL dim35（C=2^73）+ 扫 CENTER 命中 msg。
- 17:05 exp.py 复核 S>>80==h，flag 落盘。

## 可复用 TTP
- “模 p 线性组合 >> s” 型泄露：把移位当成小误差 t<2^s，构造 `[C·I | a]` + `[0 | p]` 的格，
  目标 (0..0, h·2^s)，用 **LLL + Babai 最近平面**（不是 Kannan embedding）。
- 居中技巧：CENTER 只影响目标，不影响格基 ⇒ 一次 LLL 扫多个 CENTER；C 与 CENTER 决定真解范数，
  选在 GH 附近偏下才有机会。
- 候选必须过业务校验（字符集 + 重算 `S>>80==h`），不要只看范数短。
