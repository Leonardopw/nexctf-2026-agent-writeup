# powerpowerpower · 渗透记录

## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | powerpowerpower |
| 类型 | Crypto / 三把 RSA 链式部分信息泄露（HNP + 指数塌缩 + 已知高位分解） |
| 入口 | 本地附件 attachments (16).zip（chall.py + output.txt，无远程） |
| 耗时 | 0 日 0 时 10 分 30 秒（16:43:29 收附件 → 16:53:5x 复核出 flag；含自写 Coppersmith 失败后复用 Apps 会话结果） |
| LLM | deepseek-flash |
| flag | `nex{yoU_are_7hE_oN3_OF_m0Std4Sd45d}` |

## 2.2 目标与授权
- 授权范围：纯本地离线计算，无网络目标
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
三把 2048-bit RSA（n0,n1,n2，e=65537，p,q 各 1024-bit 且 |p-q|>2^1000）；c0=z^e mod n0、c1=(p2>>400)^e mod n1、c2=m^e mod n2；h0,h1 为 φ(n0) 的小误差倍数

## 2.4 攻击面
h_i=(x_i·φ+x 小误差) mod n0 泄露 φ 的有理近似；z 的指数形式在 Fermat 下塌缩为 a·p1+b·q1（a,b 仅 12 bit）；c1 泄露 p2 的高 624 位

## 2.5 漏洞判定
- 类型：Crypto / 三把 RSA 链式部分信息泄露（HNP + 指数塌缩 + 已知高位分解）
- 位置：chall.py：f=(p[0]-1)*(q[0]-1)；z=(pow(a*p[1],q[1],n[1])+pow(b*q[1],p[1],n[1]))%n[1]；c[1]=pow(p[2]>>400,e,n[1])
- 证据：evidence/step1_solve.txt（11 项校验：p0q0=n0、x 480-bit、r<2^448、z=a·p1+b·q1、p1q1=n1、a,b 12-bit、u 624-bit、pow(m,e,n2)==c2、flag 正则）；evidence/apps_flag.txt（Apps 会话 Coppersmith 结果，同 output.txt SHA256）
- 误报排除：每一步都用等式而非近似复核：p0q0=n0、z=a·p1+b·q1、p1q1=n1 均为整数恒等式；最后 flag 的整数 m 重新加密恰等于 c2（pow(m,e,n2)==c2），这是唯一性极强的验证

## 2.6 利用链
```
n0−h_i=x_i(σ−1)−r_i → 连分数得 x0/x1 → σ=p0+q0 → 分解 n0 → z=c0^{d0} mod n0；z=a·p1+b·q1 → 判别式暴力 (a,b) → 分解 n1 → u=p2>>400；Coppersmith f(x)=u<<400+x 分解 n2 → m=c2^{d2} mod n2 = nex{yoU_are_7hE_oN3_OF_m0Std4Sd45d}
```

## 2.7 影响
三把 2048-bit RSA 全部被分解，flag 明文恢复；根因是把 φ 的有理近似、可塌缩的指数构造、p 的高位分别泄露到三个输出里，且小系数/小误差没被约束

## 2.8 修复建议
h 这类 φ 的派生值不能带可解的小误差倍数（应改为哈希或加密）；避免 (a·p)^q 这类可被 Fermat 化简的指数构造；不要输出任何 p 的片段（p>>400）；RSA 私钥/因子信息严格不出边界

## 2.9 复盘
前两步（连分数、12-bit 暴力）很快；第 3 步 400 bit 已知高位已接近 n^(1/4)，自写 dim≤6 的格不够，需 t≈m 的 dim9 平衡格，最终复用 Apps 会话已跑通的 copp2 结果并用密文等式复核。
