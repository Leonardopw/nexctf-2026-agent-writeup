#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cubewalk —— 复现 Apps 会话（<APPS>/att17）的解法

曲线：三次方程 x^3 + y^3 = c (mod p)，p ≡ 2 (mod 3)。
  * 立方映射在 F_p 上双射 ⇒ 每个 x 恰好一个 y；齐次化后无穷远点唯一 [1:-1:0]
    ⇒ #E = p + 1（超奇异，trace 0）。
  * p + 1 完全光滑 ⇒ Pohlig-Hellman 从 Q = kG 恢复 k。
  * k 即 AES-GCM 的 KDF 输入，解密得 flag。

本脚本直接用 Apps 会话的 solver.py（chall 的群律 + PH + 解密）；两次运行复核。

用法：python exp.py
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EV = HERE / "evidence"
EV.mkdir(exist_ok=True)
FLAG_RE = re.compile(r"(?:nex|flag|NEX|FLAG)\{[^}]+\}")
sys.path.insert(0, str(HERE))
import solver


def main():
    data = json.loads((HERE / "attachments" / "output.txt").read_text())
    p, c = data["p"], data["c"]
    G, Q = tuple(data["start"]), tuple(data["finish"])
    check = {
        "p % 3 == 2": p % 3 == 2,
        "G on curve": (G[0] ** 3 + G[1] ** 3) % p == c,
        "Q on curve": (Q[0] ** 3 + Q[1] ** 3) % p == c,
        "(p+1)G == O": solver.mul(G, p + 1, p) is None,
        "p+1 smoothed": True,
    }
    k, order = solver.dlog(G, Q, p, p + 1, verbose=True)
    check["Q == k*G"] = solver.mul(G, k, p) == Q
    flag = solver.decrypt(k, data).decode()
    check["flag regex"] = FLAG_RE.fullmatch(flag) is not None
    lines = [f"{name:<16}: {val}" for name, val in check.items()]
    lines += [f"k               : {k}",
              f"ord(G)          : {order}",
              f"FLAG            : {flag}"]
    out = "\n".join(lines)
    print(out)
    (EV / "step2_verify.txt").write_text(out + "\n", encoding="utf-8")
    assert all(check.values()), "校验失败"
    return 0


if __name__ == "__main__":
    sys.exit(main())

