#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""魔法余数 —— 模 p 线性组合只泄露高位：用 CVP（LLL + Babai 最近平面）还原 flag 内容

题目：
  p 为 336-bit 素数；a_i ∈ [1,p) 共 34 个；h = (Σ a_i·c_i mod p) >> 80，
  c_i 为 flag 内层 34 个字符（[A-Za-z0-9_]）。
攻击：
  记 S = Σ a_i c_i mod p = h·2^80 + t（0 ≤ t < 2^80），k = Σ a_i c_i // p。
  则 Σ a_i c_i − k·p − h·2^80 = t，即
  Σ a_i (c_i − CENTER) − k·p ≈ h·2^80 − CENTER·Σa_i（误差只有 80 bit）。
  构造格 L = { (C·y_1..C·y_n, Σ a_i y_i − k·p) }（行 [C·e_i | a_i] 与 [0 | p]），
  目标 T = (0..0, (h·2^80 − CENTER·Σa_i) mod p)。真解向量为 (C·d_i, t)，d_i = c_i − CENTER，
  其范数 2^80.3 低于该格 35 维的高斯启发值 2^81.1 —— 先 LLL 再 Babai 最近平面即可命中。
  CENTER 只影响目标向量，不影响格基，因此一次 LLL 可扫多个 CENTER。

结果：msg = b'1_D0NT_llK3_rEmIND3r_and_c0mPuT1nG'，复核 Σ a_i·c_i mod p >> 80 == h。

用法：python exp.py
"""
import re
import sys
import time
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent
EV = HERE / "evidence"
EV.mkdir(exist_ok=True)
FLAG_RE = re.compile(r"(?:nex|flag|NEX|FLAG)\{[^}]+\}")

sys.path.insert(0, str(HERE))
from lll2 import lll


def load():
    src = (HERE / "attachments" / "output.txt").read_text(encoding="utf-8")
    p = int(re.search(r"p = (\d+)", src).group(1))
    h = int(re.search(r"h = (\d+)", src).group(1))
    a = eval(re.search(r"a = (\[.*?\])", src, re.S).group(1))
    return p, h, a


def basis(C, a, n, p):
    rows = []
    for i in range(n):
        row = [0] * (n + 1)
        row[i] = C
        row[n] = a[i]
        rows.append(row)
    rows.append([0] * n + [p])
    return rows


def gso(B):
    m, L = len(B), len(B[0])
    bs = []
    nrm = [Fraction(0)] * m
    for i in range(m):
        v = [Fraction(x) for x in B[i]]
        for j in range(i):
            mu = sum(Fraction(B[i][k]) * bs[j][k] for k in range(L)) / nrm[j]
            v = [v[k] - mu * bs[j][k] for k in range(L)]
        bs.append(v)
        nrm[i] = sum(x * x for x in v)
    return bs, nrm


def babai(B, target):
    bs, nrm = gso(B)
    t = [Fraction(x) for x in target]
    for i in range(len(B) - 1, -1, -1):
        d = sum(t[k] * bs[i][k] for k in range(len(t))) / nrm[i]
        c = int(d + Fraction(1, 2)) if d >= 0 else -int(-d + Fraction(1, 2))
        if c:
            t = [t[k] - c * B[i][k] for k in range(len(t))]
    return t


def attack(p, h, a):
    n = len(a)
    Y, A = h << 80, sum(a)
    charset = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
    for shift in (72, 73, 74):
        C = 1 << shift
        t0 = time.time()
        B = lll(basis(C, a, n, p), delta=Fraction(99, 100))
        print(f"[*] C=2^{shift} LLL(dim {n+1}) {time.time()-t0:.1f}s", flush=True)
        for center in range(60, 126):
            T = (Y - center * A) % p
            res = babai(B, [0] * n + [T])
            if res[n].denominator != 1 or abs(int(res[n])) >= (1 << 80):
                continue
            vec = [int(-res[i]) for i in range(n)]
            if any(v % C for v in vec):
                continue
            msg = [center + v // C for v in vec]
            if not all(0 <= x < 256 for x in msg):
                continue
            mb = bytes(msg)
            if all(ch in charset for ch in msg):
                S = sum(ai * c for ai, c in zip(a, msg)) % p
                if (S >> 80) == h:
                    return mb
    return None


def main():
    p, h, a = load()
    print(f"[*] p {p.bit_length()} bit, n={len(a)}, h={h.bit_length()} bit")
    msg = attack(p, h, a)
    assert msg is not None, "attack failed"
    S = sum(ai * c for ai, c in zip(a, msg)) % p
    flag = "nex{" + msg.decode() + "}"
    check = {
        "msg len == 34": len(msg) == 34,
        "charset ok": msg.replace(b"_", b"A").isalnum(),
        "S >> 80 == h": (S >> 80) == h,
        "flag regex": FLAG_RE.fullmatch(flag) is not None,
    }
    lines = [f"{k:<16}: {v}" for k, v in check.items()]
    lines += [f"msg             : {msg.decode()}", f"FLAG            : {flag}"]
    out = "\n".join(lines)
    print(out)
    (EV / "step1_solve.txt").write_text(out + "\n", encoding="utf-8")
    assert all(check.values())
    return 0


if __name__ == "__main__":
    sys.exit(main())
