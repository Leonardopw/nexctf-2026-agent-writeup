#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""如何入门密码学 —— 纯 Python 复算（不装 sage/gmpy2/gmssl）

原脚本依赖：Crypto(C), gmpy2, sympy, gmssl(sm3), sage.all(GF/matrix/EllipticCurve)。
本机只有 Crypto+pow/sympy，所以：
  - gmpy2.powmod/invert -> pow(a,b,m) / pow(a,-1,m)
  - gmssl.sm3         -> 本文件内置 SM3（带标准测试向量自检）
  - sage GF(257^4)    -> 4 次多项式模 X^4+16X^2+187X+3 的运算 + 快速幂
  - sage trace/norm   -> trace=Σ f^(257^i)；norm=f^((257^4-1)/(257-1))
  - sage EllipticCurve-> GF(65537): y^2=x^3+2x+3 上的点乘（double-and-add）
  - sage matrix       -> 4x4 模 257 求逆 + 矩阵乘向量

用法：python solve.py
"""
import struct

from Crypto.Cipher import AES

# ---------------- SM3 ----------------
IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
      0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
MASK = 0xFFFFFFFF


def _rotl(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & MASK


def _p0(x):
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _p1(x):
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def _ff(j, x, y, z):
    return (x ^ y ^ z) if j < 16 else ((x & y) | (x & z) | (y & z))


def _gg(j, x, y, z):
    return (x ^ y ^ z) if j < 16 else ((x & y) | (~x & z) & MASK)


def sm3(data: bytes) -> str:
    msg = bytearray(data)
    bit_len = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack(">Q", bit_len)

    v = IV[:]
    for off in range(0, len(msg), 64):
        block = msg[off:off + 64]
        w = list(struct.unpack(">16I", bytes(block)))
        for j in range(16, 68):
            w.append(_p1(w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15)) ^ _rotl(w[j - 13], 7) ^ w[j - 6])
        w1 = [w[j] ^ w[j + 4] for j in range(64)]

        a, b, c, d, e, f, g, h = v
        for j in range(64):
            t = 0x79CC4519 if j < 16 else 0x7A879D8A
            ss1 = _rotl((_rotl(a, 12) + e + _rotl(t, j)) & MASK, 7)
            ss2 = ss1 ^ _rotl(a, 12)
            tt1 = (_ff(j, a, b, c) + d + ss2 + w1[j]) & MASK
            tt2 = (_gg(j, e, f, g) + h + ss1 + w[j]) & MASK
            d, c, b, a = c, _rotl(b, 9), a, tt1
            h, g, f, e = g, _rotl(f, 19), e, _p0(tt2)
        v = [x ^ y for x, y in zip(v, [a, b, c, d, e, f, g, h])]
    return "".join("%08x" % x for x in v)


assert sm3(b"abc") == ("66c7f0f462eeedd9d1f2d46bdc10e4e2"
                       "4167c4875cf2f7a2297da02b8f4ba8e0"), sm3(b"abc")

# ---------------- GF(257^4) ----------------
P = 257
# 模多项式 X^4 + 16X^2 + 187X + 3  ->  X^4 = -(3 + 187X + 16X^2)
RED = (3, 187, 16)


def fmul(A, B):
    res = [0] * 7
    for i, a in enumerate(A):
        if a:
            for j, b in enumerate(B):
                res[i + j] = (res[i + j] + a * b) % P
    for k in range(6, 3, -1):
        c = res[k]
        if c:
            res[k] = 0
            for t in range(3):
                res[k - 4 + t] = (res[k - 4 + t] - RED[t] * c) % P
    return res[:4]


def fpow(A, e):
    R = [1, 0, 0, 0]
    base = A[:]
    while e:
        if e & 1:
            R = fmul(R, base)
        base = fmul(base, base)
        e >>= 1
    return R


def fadd(A, B):
    return [(x + y) % P for x, y in zip(A, B)]


def ftrace(f):
    t = [0, 0, 0, 0]
    cur = f[:]
    for _ in range(4):
        t = fadd(t, cur)
        cur = fpow(cur, P)
    return t


def fnorm(f):
    return fpow(f, (P ** 4 - 1) // (P - 1))


# ---------------- 椭圆曲线 GF(65537): y^2 = x^3 + 2x + 3 ----------------
EP = 65537
EA, EB = 2, 3


def ec_add(Pt, Qt):
    if Pt is None:
        return Qt
    if Qt is None:
        return Pt
    x1, y1 = Pt
    x2, y2 = Qt
    if x1 == x2 and (y1 + y2) % EP == 0:
        return None
    if Pt == Qt:
        lam = (3 * x1 * x1 + EA) * pow(2 * y1, -1, EP) % EP
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, EP) % EP
    x3 = (lam * lam - x1 - x2) % EP
    y3 = (lam * (x1 - x3) - y1) % EP
    return (x3, y3)


def ec_mul(k, Pt):
    R = None
    while k:
        if k & 1:
            R = ec_add(R, Pt)
        Pt = ec_add(Pt, Pt)
        k >>= 1
    return R


# ---------------- 4x4 模 257 求逆 ----------------
def mat_inv(M):
    n = 4
    A = [[M[i][j] % P for j in range(n)] + [1 if i == j else 0 for j in range(n)] for i in range(n)]
    for col in range(n):
        piv = next(r for r in range(col, n) if A[r][col] % P)
        A[col], A[piv] = A[piv], A[col]
        inv = pow(A[col][col], -1, P)
        A[col] = [(x * inv) % P for x in A[col]]
        for r in range(n):
            if r != col and A[r][col] % P:
                f = A[r][col]
                A[r] = [(x - f * y) % P for x, y in zip(A[r], A[col])]
    return [row[n:] for row in A]


def main():
    p0 = 74745492827415902654257622116680260943732050660198090669124197638460770366700
    q0 = 100757267398919346937614006801831921321756668878854766852415524176861890022465
    a0 = 55121308255483243893861750335529530419423756964941642898403696216590288300172
    b0 = 42143437321271562382378675113426282465665115667457889229098950509154864378785
    s = b'\xcc\x9c\x03\xb4\xe6\xba#[F\xaf\xb8\xaan\xc9qoZP^\xd7E\xe4R\xea'
    v = b'\x10\t\xd6\x13\x19}\x01@#\xe0;l\xf8\x90NU'
    M = [119, 107, 234, 208, 176, 240, 119, 92, 27, 197, 205, 225, 128, 235, 247, 237]
    C = [4487303142318694988809680864308703446385137711196722946128203257889290746436575510669451159397037785185110416505854039335988030571396039316235134652030753, 5049243105130229649855183279541242874723514417187368414680533674186780746667870575462038600981171745968793769923014920327965406573227636136668192953159359, 2133179690809447910826731909272348073904762430840821517498588263466461011897472788452998396098069724310710902310395119413649067494623870855259493046036311, 6091713879216379383355643697671725391895924798014039569089530664369833372013831716475688750547217050538509876524162668666748009096335636287744745029927626, 5713384302284555972984036533409333162134257364443190953594328345851514260455960641500941409702228112893769123799952146924804775897639070843779020228127979, 2175028510364764997691884506597399796188143679254924214743167052652440501826881000014575487946566672887438951215077897931356690467756879395307978184235427, 4828648827479182734770711089003979974743315676441996591713442167543333151675011758513840828099392089685249769533037537925100639910172414456650939920925606, 4604875326659363198175149090783270454892209720924520989720902751429738741612659411926087001069569329781955174229598658086933660027862487006158001530146955, 1264217133488105899742197010952911800184096776842960619903174681800761773265215274446176418935122958503804507077658789072405623445597078355937010745983807]
    L = 35
    U = (60248, 48597)
    H = [3, 187, 16, 0, 1]

    # 1) 素数/模逆
    import sympy
    p, q = int(sympy.nextprime(p0)), int(sympy.nextprime(q0))
    n = p * q
    d = pow(65537, -1, (p - 1) * (q - 1))

    # 2) GF(257^4) 里的 f = (Σ M[i] a^i)^b0，再取 trace/norm
    base = [M[0], M[1], M[2], M[3]]
    f = fpow(base, b0)
    tr = ftrace(f)
    no = fnorm(f)
    print("[*] trace =", tr, " norm =", no)
    assert tr[1] == tr[2] == tr[3] == 0 and no[1] == no[2] == no[3] == 0

    # 3) 椭圆曲线 Q = b0 * U
    assert (U[1] ** 2 - (U[0] ** 3 + EA * U[0] + EB)) % EP == 0
    Q = ec_mul(b0, U)
    print("[*] Q =", Q)

    # 4) j / k
    j = b"".join(int(x).to_bytes(3, "big") for x in Q)
    j += int(tr[0]).to_bytes(2, "big") + int(no[0]).to_bytes(2, "big")
    k = bytes.fromhex(sm3(pow(a0, b0, n).to_bytes(64, "big") + j + s))
    print("[*] key len", len(k))

    # 5) B = M^{-1} mod 257；RSA 解 C；GF(257) 上乘 B
    B = mat_inv([M[0:4], M[4:8], M[8:12], M[12:16]])
    r = [pow(c, d, n).to_bytes(8, "big") for c in C]
    t = bytearray()
    for h in r:
        vec = [int.from_bytes(h[i:i + 2], "big") for i in range(0, 8, 2)]
        out = [sum(B[row][j] * vec[j] for j in range(4)) % P for row in range(4)]
        t += bytes(out)
    t = bytes(t[:L])

    # 6) keystream + XOR
    w = b"".join(bytes.fromhex(sm3(s + i.to_bytes(4, "big"))) for i in range((L + 31) // 32))
    z = bytes(x ^ y for x, y in zip(t, w))
    print("[*] z =", z.hex())

    pt = AES.new(k, AES.MODE_CTR, nonce=b"", initial_value=v).decrypt(z)
    print("[+] plaintext:", pt)
    print("[+] plaintext:", pt.decode("utf-8", "replace"))


if __name__ == "__main__":
    main()
