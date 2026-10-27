# cubewalk · 渗透记录

## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | cubewalk |
| 类型 | Crypto / 三次曲线 ECDLP（p≡2 mod 3 ⇒ #E=p+1，p+1 光滑 ⇒ Pohlig-Hellman） |
| 入口 | 本地附件 attachments (17).zip（chall.py + output.txt，无远程） |
| 耗时 | 0 日 0 时 6 分 30 秒（16:55 解包 → 17:01 复现复核；Apps 会话 <APPS>/att17 已给出 solver.py） |
| LLM | deepseek-flash |
| flag | `nex{W313r5tRAss_sTUpid_D4D4SDJILmm}` |

## 2.2 目标与授权
- 授权范围：纯本地离线计算，无网络目标
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
曲线 x^3+y^3=c (mod p)，p=360340522821146962221564153109405173567024678061838347697，p≡2 (mod 3)；G=(101943…,230991…)；output 含 AES-GCM 的 nonce/ciphertext/tag；KDF=sha256('cube-walk/v1\0'||k.to_bytes(15))

## 2.4 攻击面
p≡2 (mod 3) ⇒ x↦x^3 双射、无穷远点唯一 ⇒ #E=p+1（超奇异 trace 0）；p+1 完全光滑 ⇒ Q=kG 的离散对可用 Pohlig-Hellman 直接求出

## 2.5 漏洞判定
- 类型：Crypto / 三次曲线 ECDLP（p≡2 mod 3 ⇒ #E=p+1，p+1 光滑 ⇒ Pohlig-Hellman）
- 位置：chall.py 的 add()/mul()（第三次交点群律）与 kdf()：k 直接作为 AES-GCM 密钥派生输入
- 证据：evidence/step1_solve.txt（solver.py 输出：p+1 光滑因子、ord(G)=p+1、k=640206…3380、flag）；evidence/step2_verify.txt（exp.py 9 项校验：p%3==2、G/Q 在曲线上、(p+1)G=O、Q=kG、flag 正则）；evidence/apps_flag.txt（Apps 会话结果，output.txt SHA256 相同）
- 误报排除：复现链条有等式校验：G、Q 均满足 x^3+y^3=c；Q=kG 精确成立；(p+1)G=O 印证 #E=p+1；AES-GCM tag 校验通过（decrypt_and_verify 不抛异常）；明文命中 nex{...} 正则

## 2.6 利用链
```
读 output（p,c,G,Q,nonce,ct,tag）→ 验证 p≡2 (mod 3) ⇒ #E=p+1 → factor(p+1) 全光滑 → Pohlig-Hellman/BSGS 求 k=Q/G → kdf(k,p) 得 AES 密钥 → GCM 解密得 nex{W313r5tRAss_sTUpid_D4D4SDJILmm}
```

## 2.7 影响
密文可直接解密、flag 泄露；根因是参数选择让曲线退化为 #E=p+1 且 p+1 光滑，离散对难度归零

## 2.8 修复建议
选曲线参数时确保 #E 有大素因子（h·q，q 大且素数），或直接用标准曲线（P-256/25519）+ 固定基点；不要用 p≡2 mod 3 的超奇异曲线做 DH；KDF 输入用共享点坐标而非标量 k

## 2.9 复盘
关键在 p%3==2 与 p+1 光滑两点；直接复用 Apps 会话的 solver.py（题给群律 + PH + 解密）复现，k 与 flag 一致，再跑 9 项校验。
