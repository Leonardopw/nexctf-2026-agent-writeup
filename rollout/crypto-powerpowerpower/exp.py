#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""powerpowerpower —— 三把 RSA 密钥的链式部分信息泄露

链路：
  1) n0 的 φ 泄露于 h_i = (x_i·f + r_i) mod n0（x_i 480 bit、r_i 448 bit）：
     f = n0 − σ + 1，σ = p0+q0，于是 n0 − h_i = x_i(σ−1) − r_i，
     (n0−h0)/(n0−h1) ≈ x0/x1 —— 连分数还原 x0/x1，再取 σ = ⌈(n0−h0)/x0⌉+1，
     判别式 σ²−4n0 为平方 → 分解 n0 → d0 → z = c0^d0 mod n0。
  2) z 塌缩为 z = a·p1 + b·q1（Fermat：a^{q1}≡a mod q1，b^{p1}≡b mod p1，a,b 仅 12 bit），
     故 z²−4ab·n1 = (a·p1 − b·q1)²；用模小素数平方剩余过滤后暴力 (a,b) → 分解 n1，
     d1 → u = p2>>400（624 个已知高位）。
  3) u 已知 624/1024 位，未知 400 bit < n2^(1/4)；Coppersmith 于 f(x)=u<<400 + x 分解 n2
     （本脚本复用 Apps 会话 copp2.py 的结果，等价复核为 pow(m,e,n2) == c2）。

脚本本身完整重算 1)+2)（秒级），第 3) 步用密文等式复核 flag，避免重复跑 LLL。

用法：python exp.py
"""
import json
import re
import sys
from math import gcd, isqrt
from pathlib import Path

HERE = Path(__file__).resolve().parent
EV = HERE / "evidence"
EV.mkdir(exist_ok=True)
FLAG_RE = re.compile(rb"(?:nex|flag|NEX|FLAG)\{[^}]+\}")
# Apps 会话（<APPS>\crypto_att4）跑 Coppersmith 解出的 flag；本脚本用 c2 复核
FLAG = b"nex{yoU_are_7hE_oN3_OF_m0Std4Sd45d}"


def load():
    return json.loads((HERE / "attachments" / "output.txt").read_text())


def convergents(a, b, limit):
    p_prev, p = 0, 1
    q_prev, q = 1, 0
    while b:
        t = a // b
        p_prev, p = p, t * p + p_prev
        q_prev, q = q, t * q + q_prev
        a, b = b, a - t * b
        if q and q.bit_length() > limit:
            return
        yield p, q


def step1(n, e, c, h):
    N0 = n[0]
    A0, A1 = N0 - h[0], N0 - h[1]
    for num, den in convergents(A0, A1, 520):
        if den == 0 or num == 0 or gcd(num, den) != 1:
            continue
        base = A0 // num
        for s in (base + 1, base + 2):
            disc = s * s - 4 * N0
            if disc < 0:
                continue
            w = isqrt(disc)
            if w * w != disc:
                continue
            p0, q0 = (s + w) // 2, (s - w) // 2
            if p0 * q0 == N0 and p0 > 1 and q0 > 1:
                f = (p0 - 1) * (q0 - 1)
                d0 = pow(e, -1, f)
                z = pow(c[0], d0, N0)
                return dict(p0=p0, q0=q0, x0=num, x1=den, sigma=s,
                            r0=num * (s - 1) - A0, r1=den * (s - 1) - A1, z=z)
    raise RuntimeError("step1 failed")


def step2(n, e, c, z):
    N1 = n[1]
    M = 16 * 3 * 5 * 7 * 13 * 17
    qr = [False] * M
    for x in range(M):
        qr[(x * x) % M] = True
    Z2 = (z * z) % M
    f4n = (4 * (N1 % M)) % M
    for a in range(2048, 4096):
        ca = (a * f4n) % M
        for b in range(2048, 4096):
            if a == b or gcd(a, b) != 1:
                continue
            if not qr[(Z2 - ca * b) % M]:
                continue
            disc = z * z - 4 * a * b * N1
            if disc < 0:
                continue
            w = isqrt(disc)
            if w * w != disc:
                continue
            for p1 in ((z + w) // (2 * a), (z - w) // (2 * a)):
                if p1 > 1 and N1 % p1 == 0:
                    q1 = N1 // p1
                    d1 = pow(e, -1, (p1 - 1) * (q1 - 1))
                    return dict(a=a, b=b, p1=p1, q1=q1, u=pow(c[1], d1, N1))
    raise RuntimeError("step2 failed")


def main():
    d = load()
    n, e, c, h = d["n"], d["e"], d["c"], d["h"]
    s1 = step1(n, e, c, h)
    s2 = step2(n, e, c, s1["z"])
    m = int.from_bytes(FLAG, "big")
    checks = {
        "p0*q0 == n0": s1["p0"] * s1["q0"] == n[0],
        "p0,q0 1024-bit": s1["p0"].bit_length() == s1["q0"].bit_length() == 1024,
        "x0,x1 480-bit": s1["x0"].bit_length() == s1["x1"].bit_length() == 480,
        "r0,r1 < 2^448": s1["r0"] < (1 << 448) and s1["r1"] < (1 << 448),
        "z == a*p1 + b*q1": s2["a"] * s2["p1"] + s2["b"] * s2["q1"] == s1["z"],
        "p1*q1 == n1": s2["p1"] * s2["q1"] == n[1],
        "a,b 12-bit": 2048 <= s2["a"] < 4096 and 2048 <= s2["b"] < 4096,
        "u bits == 624": s2["u"].bit_length() == 624,
        "m < n2": m < n[2],
        "pow(m,e,n2) == c2": pow(m, e, n[2]) == c[2],
        "flag regex": FLAG_RE.fullmatch(FLAG) is not None,
    }
    lines = [f"{k:<20}: {v}" for k, v in checks.items()]
    lines += [f"a, b                : {s2['a']}, {s2['b']}",
              f"p2>>400 (u)         : {s2['u']}",
              f"FLAG                : {FLAG.decode()}"]
    out = "\n".join(lines)
    print(out)
    (EV / "step1_solve.txt").write_text(out + "\n", encoding="utf-8")
    assert all(checks.values()), "校验失败"
    return 0


if __name__ == "__main__":
    sys.exit(main())
