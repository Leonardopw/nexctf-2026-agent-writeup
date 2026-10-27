# halfkey · 渗透记录

## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | halfkey |
| 类型 | Crypto / RSA 部分密钥泄露（截断 PEM 泄露 d 高 1600 位） |
| 入口 | 本地附件 attachments (15).zip（chall.py + output.txt，无远程） |
| 耗时 | 0 日 0 时 10 分 24 秒（16:27:03 收附件 → 16:37:27 复核出 flag；因子恢复复用同题 Apps 会话 Coppersmith(4,5) dim9，LLL 1046 s） |
| LLM | deepseek-flash |
| flag | `nex{p3m_DEr_aNd_paCkEdsXjaLsdJ4sD}` |

## 2.2 目标与授权
- 授权范围：纯本地离线计算，无网络目标
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
2048-bit RSA，e=65537，p,q 各 1024-bit 且 q-p>2^1016、d≥2047 bit；output.txt 第一行是 key.export_key()[:677]（PKCS#1 私钥 DER 的 base64 截断），恰好截到 d 字段中间：version + 完整 n(257B) + e + d 前 200/256 字节

## 2.4 攻击面
私钥导出被截断却不影响 n/e 完整、d 高 1600 位泄露；d 的低 448 位未知，而 e 小（65537）使 k=(ed-1)/φ 可估且唯一

## 2.5 漏洞判定
- 类型：Crypto / RSA 部分密钥泄露（截断 PEM 泄露 d 高 1600 位）
- 位置：chall.py 的 print(key.export_key()[:677])；截断点落在 d 的 DER INTEGER 值内（field @273 len=256，实际只保留 200 字节）
- 证据：evidence/step1_solve.txt（p*q==n、p/q 均 1024-bit、q-p>2^1016、(d>>448)==d0、k==25487、pow(m,e,n)==c、flag 正则 7 项全 True）；evidence/chall.py、output.txt 原附件
- 误报排除：五重独立校验互相印证：解出的 p,q 相乘等于 n；用 p,q 反算的 d 右移 448 位与 PEM 泄露的 d0 完全一致；k=(ed-1)/φ 恰为 25487（与近似推出的唯一 k 相同）；明文重新加密等于 c；明文命中 nex{...} 正则

## 2.6 利用链
```
截断 PEM → base64 解码得 DER 前缀 477B → 解析 INTEGER 字段得 n、e、d0（d 高 1600 位）→ k=(e·d0)//n+1=25487 → A=k(n+1)-e·d0+1，s0=A//k，q0=(s0+√(s0²-4n))/2 ≥ q 且 |q0-q|<2^452 ≪ n^(1/4) → 对 f(x)=x-q0 做 Coppersmith (m,t)=(4,5) dim9 求小根 x0=q0-q → q=q0-x0，p=n/q → d=e^{-1} mod φ → m=c^d mod n → nex{p3m_DEr_aNd_paCkEdsXjaLsdJ4sD}
```

## 2.7 影响
私钥泄露一半即可恢复完整私钥并解密任意密文；本题直接解出 flag。根因是把私钥按固定长度截断输出，且 e 很小使高位泄露足以恢复因子

## 2.8 修复建议
不要输出私钥的任何片段（哪怕是“前缀”）；必须展示时改为指纹/公钥；RSA 私钥存储加密；e 用 65537 本身没问题，问题是 d 的高位泄露等价于部分密钥泄露攻击面

## 2.9 复盘
关键是发现截断点精确落在 d 字段内、且 s0≥s 使 q0≥q——旧脚本求根方向反了；改为 f(x)=x-q0 后误差 2^452<n^1/4，dim9 格可解。
