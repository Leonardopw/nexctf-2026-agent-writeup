#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""halfkey —— 截断 PEM 私钥 → 部分密钥泄露（partial key exposure）

思路（详细推导见 notes.md / record.md）：
  1) output.txt 第一行是 key.export_key()[:677]，正好截在 d 字段中间：
     版本 + 完整 n(257B) + e=65537 + d 的前 200/256 字节 → d 高 1600 位已知，低 448 位丢失。
  2) e·d − 1 = k·φ，φ = n − (p+q) + 1；k = (e·d0)//n + 1 = 25487（唯一使 s=p+q ≥ 2√n 的 k）。
  3) s0 = (k(n+1) − e·d0 + 1)//k ≥ s，故 q0 = (s0+√(s0²−4n))/2 ≥ q，
     误差 |q0 − q| < 2^452 ≪ n^(1/4)=2^512 → 对 f(x)=x−q0 做 Coppersmith 小根（m=4,t=5,dim 9），
     得 x0=q0−q，q=q0−x0。
  4) 本脚本固化该次 Coppersmith 恢复出的 q（同题 Apps 会话已跑通，LLL 约 1046 s），
     只做零依赖复核 + 解密：p*q==n、(d>>448)==d0、k=25487、pow(m,e,n)==c、flag 正则。

用法：python exp.py

依赖：仅标准库（解析 PEM 用 base64；RSA 只做整数运算）
"""
import base64
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EV = HERE / "evidence"
EV.mkdir(exist_ok=True)
FLAG_RE = re.compile(rb"(?:nex|flag|NEX|FLAG)\{[^}]+\}")
E = 65537

# Coppersmith(m=4, t=5, dim 9) 恢复的因子（q 为两者中较大的，满足 q-p > 2^1016）
Q = 154220101430629895877073081806244273469106681478546470732256116937389206749665313547298326748230746296488665882837071034295457576791875685106405026913662349020802777698422798153965589444670446949817898004965559781708717745871443590874960494693793824249530537788565666075220819426856625828214266602837203751901


def parse(att: Path):
    line = (att / "output.txt").read_text(encoding="utf-8").splitlines()[0].strip()
    prefix = eval(line)                                    # b'-----BEGIN...' 的 repr
    raw = base64.b64decode("".join(prefix.decode().split("\n", 1)[1].split()))
    i = 1
    i += 1 + (raw[i] & 0x7F) if raw[i] & 0x80 else 1
    fields = []
    while i < len(raw) and raw[i] == 0x02:
        ln = raw[i + 1]
        j = i + 2
        if ln & 0x80:
            kk = ln & 0x7F
            ln = int.from_bytes(raw[j:j + kk], "big")
            j += kk
        fields.append(raw[j:j + ln])
        i = j + ln
    _, n_b, e_b, d_b = fields[:4]
    n = int.from_bytes(n_b, "big")
    d_leak = int.from_bytes(d_b, "big")                    # d 的高 200 字节
    c = int(re.search(r"c = (\d+)", (att / "output.txt").read_text()).group(1))
    return n, d_leak, len(d_b), c


def main():
    att = HERE / "attachments15"
    if not (att / "output.txt").exists():
        att = HERE / "attachments"
    n, d_leak, d_bytes, c = parse(att)
    tbits = 8 * (256 - d_bytes)
    d0 = d_leak << tbits

    p, q = n // Q, Q
    if p > q:
        p, q = q, p
    d = pow(E, -1, (p - 1) * (q - 1))
    m = pow(c, d, n)
    pt = m.to_bytes((m.bit_length() + 7) // 8, "big")
    flag = FLAG_RE.search(pt)

    checks = {
        "n bits == 2048": n.bit_length() == 2048,
        "d leaked bytes": d_bytes,
        "missing bits": tbits,
        "p*q == n": p * q == n,
        "p,q 1024-bit": p.bit_length() == q.bit_length() == 1024,
        "q - p > 2^1016": q - p > (1 << 1016),
        "(d >> t) == d0": (d >> tbits) == d_leak,
        "k == 25487": (E * d - 1) // ((p - 1) * (q - 1)) == 25487,
        "pow(m,e,n) == c": pow(m, E, n) == c,
        "flag regex": flag is not None,
    }
    lines = [f"{k:<18}: {v}" for k, v in checks.items()]
    lines.append(f"p                  : {p}")
    lines.append(f"q                  : {q}")
    lines.append(f"FLAG               : {flag.group(0).decode() if flag else 'NOT FOUND'}")
    out = "\n".join(lines)
    print(out)
    (EV / "step1_solve.txt").write_text(out + "\n", encoding="utf-8")
    assert all(v for k, v in checks.items() if k != "d leaked bytes"), "校验失败"
    return 0


if __name__ == "__main__":
    sys.exit(main())
