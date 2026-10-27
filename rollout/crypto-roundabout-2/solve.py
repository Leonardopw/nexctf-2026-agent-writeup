#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""roundabout —— 2x2 矩阵 RSA：模 p 下 a 退化成对换矩阵，commutator 恒为单位阵

关键观察：
  mod p: a=(p,1,1,0) ≡ S=[[0,1],[1,0]]，S^2=I；r 为偶数 → u ≡ I mod p
         → v=[u,b] ≡ I mod p → w ≡ I mod p → fingerprint = w00+w11 ≡ 2 (mod p)
  又 h ≡ fingerprint^e (mod n)，所以 p | (h - 2^e)，直接 gcd 分解 n。

用法：python solve.py [output.txt]
"""
import re
import sys
from math import gcd

from Crypto.Util.number import long_to_bytes

sys.path.insert(0, ".")
txt = open(sys.argv[1] if len(sys.argv) > 1 else "attachments/output.txt").read()
val = dict(re.findall(r"(\w+) = (\d+)", txt))
n, e, c, h = (int(val[k]) for k in ("n", "e", "c", "h"))
print("[*] n bits =", n.bit_length())

# p | h - 2^e
p = gcd((h - pow(2, e, n)) % n, n)
q = n // p
print("[*] p =", hex(p)[:20], "... q =", hex(q)[:20], " ...")
assert p * q == n and 1 < p < n
print("[*] factor OK: p*q==n, p bits=%d q bits=%d" % (p.bit_length(), q.bit_length()))

# 模 p 侧验证：a^r 与 commutator 都退化为 I，fingerprint ≡ 2
a = (p % p, 1, 1, 0)  # ≡ (0,1,1,0)
print("[*] a mod p =", a, "（(0,1,1,0) 即对换矩阵，平方为单位阵）")

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, n)
pt = long_to_bytes(m)
print("[+] plaintext:", pt)

m2 = re.search(rb"nex\{[^}]+\}", pt)
if m2:
    print("[+] FLAG:", m2.group(0).decode())
else:
    print("[-] 未匹配 nex{...}")
