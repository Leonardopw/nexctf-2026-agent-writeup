# cubewalk · 笔记（复现 Apps 会话 <APPS>/att17 的解法）

## 关键点
- 附件：`chall.py` + `output.txt`（AES-GCM 密文 + 曲线参数 p,c,start,finish,nonce,tag）。
- 曲线：`x³ + y³ ≡ c (mod p)`，p ≡ 2 (mod 3)，p 为 188-bit 素数。
- 群律（题给）：恒元 None、逆元交换坐标 `(x,y)⁻¹=(y,x)`、`add` 返回第三个交点（交换后的点）。
- **结构**：
  - p ≡ 2 (mod 3) ⇒ `x ↦ x³` 是 F_p 上的双射，每个 x 唯一对应一个 y；
  - 齐次化 `X³+Y³=cZ³`，Z=0 时 `X³+Y³=0` 只有 `[1:-1:0]` 一个无穷远点；
  - ⇒ `#E = p+1`（超奇异，trace 0）。
- **攻击**：p+1 完全光滑（因子 2,3 与 10 个大素数，均 < 2^19），用 Pohlig-Hellman
  （每个素因子内用 BSGS）从 `Q = kG` 恢复 k；p+1 光滑所以 BSGS 的 √order 只有 ~600。
- k 是 186-bit，`kdf(k,p)=sha256('cube-walk/v1\\0' || k.to_bytes(15))` 即 AES-GCM 密钥；
  解密得 flag。ord(G)=p+1，候选 k 唯一（k ∈ [1,p]）。

## 判定
- 复现 Apps 会话 `solver.py`（同一份 chall 的群律 + PH + 解密）：k=64020621376847614579840262301004270478665308573440563380，
  `Q == kG`、`(p+1)G == O`、`#E` 光滑、AES-GCM tag 校验通过，明文 `nex{W313r5tRAss_sTUpid_D4D4SDJILmm}`。
- 附件 `output.txt` 与 Apps 目录的 SHA256 一致（EDB13D0B…），flag 出自 `<APPS>/att17/flag.txt`。

## 失败分支（排除理由）
- 无需解一般 ECDLP：曲线退化到 trace 0 + p+1 光滑，PH 直接可解；不用 Pollard-rho。
- 不需要爆破 k：k 有 186 bit；PH 分解 p+1 后 CRT 唯一恢复。

## 时间线
- 16:55 解包、读 chall.py；确认 p%3==2 与 p+1 光滑。
- 16:56 找到 Apps 目录 `<APPS>/att17`（output.txt 同 SHA256，含 solver.py/flag.txt）。
- 16:57 直接运行 solver.py 复现 k 与 flag；再跑本目录 exp.py 做 9 项校验。

## 可复用 TTP
- 曲线题先看 `p mod 3`：p≡2 (mod 3) 时 x³ 双射，`#E=p+1`，PH 秒解。
- p+1 的光滑性比曲线本身更关键：先 factor(p+1)，再决定 PH/BSGS 规模。
- 群律不标准（恒元 None、逆元是坐标交换）时，直接沿用题给 `add/mul`，别自己推射影公式。
