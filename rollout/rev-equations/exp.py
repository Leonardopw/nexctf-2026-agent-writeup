#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""天算子 · 廿四星宿（equations）—— 从 ELF 里抠出 24 元线性方程组，精确解出 24 个字符

binary 读入 24 字符（flag 内层 24 字节），逐条核对 a·x + b·y + …：
  .rodata 里 0x21e0 起是 24 个 int32 常数 B，0x2240 起是 24×24 的 int32 系数矩阵 M，
  程序检查 M · x == B（x 为 24 个字符的码点）。
做法：读出 M/B → 有理数高斯消元（精确解）→ 全为整数且可打印 → 用原 ELF 复核。

用法：python exp.py   （复核步骤需要 WSL Ubuntu）
"""
import struct
import subprocess
import sys
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent
EV = HERE / "evidence"
EV.mkdir(exist_ok=True)
BIN = HERE / "attachments" / "equations"
N = 24
B_OFF, M_OFF = 0x21E0, 0x2240


def load():
    d = BIN.read_bytes()
    B = list(struct.unpack_from("<24i", d, B_OFF))
    M = [list(struct.unpack_from("<24i", d, M_OFF + r * N * 4)) for r in range(N)]
    return M, B


def solve(M, B):
    A = [[Fraction(M[r][c]) for c in range(N)] + [Fraction(B[r])] for r in range(N)]
    for col in range(N):
        piv = next((r for r in range(col, N) if A[r][col] != 0), None)
        assert piv is not None, "矩阵奇异"
        A[col], A[piv] = A[piv], A[col]
        pv = A[col][col]
        A[col] = [v / pv for v in A[col]]
        for r in range(N):
            if r != col and A[r][col] != 0:
                f = A[r][col]
                A[r] = [a - f * b for a, b in zip(A[r], A[col])]
    return [A[i][N] for i in range(N)]


def run_elf(flag_text):
    cmd = ("cd <WORKSPACE>/rollout/rev-equations/attachments && chmod +x equations && "
           "printf '%s\\n' | ./equations; echo EXIT=$?" % flag_text)
    p = subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "--", "bash", "-lc", cmd],
                       capture_output=True, timeout=60)
    return (p.stdout + p.stderr).decode("utf-8", "replace")


def main():
    M, B = load()
    print("[*] M[0] =", M[0])
    print("[*] B    =", B)
    sol = solve(M, B)
    ok_int = all(s.denominator == 1 for s in sol)
    assert ok_int, "解不是整数"
    chars = "".join(chr(int(s)) for s in sol)
    print("[*] 解:", chars)
    checks = {
        "全为整数": ok_int,
        "24 字符": len(chars) == N,
        "可打印": all(32 <= ord(c) < 127 for c in chars),
        "NEX 格式": chars.startswith("NEX{") and chars.endswith("}"),
        "Mx == B": all(sum(M[r][c] * int(sol[c]) for c in range(N)) == B[r] for r in range(N)),
    }
    print("[*] 静态校验:", checks)

    run = run_elf(chars)
    (EV / "step2_run.txt").write_text(run, encoding="utf-8")
    success = "星宿全部归位" in run
    print(run[-400:])
    checks["ELF 接受"] = success
    assert all(checks.values())

    res = "\n".join([f"{k:<10}: {v}" for k, v in checks.items()] + [f"FLAG      : {chars}"])
    print(res)
    (EV / "step1_solve.txt").write_text(res + "\n", encoding="utf-8")
    (EV / "flag.txt").write_text(chars + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main() or 0)
