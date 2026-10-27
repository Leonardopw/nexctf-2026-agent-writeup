#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""心魔劫（tribulation）—— SIGILL/UD2 驱动的校验：把“非法指令”当 hypercall 用

题面「崩毁亦是运行，非法亦是指令」：
  main 逐字节循环 23 次，每次把 (index, char) 写进固定内存槽
      mov [0x401a], al ; mov [0x401b], dl ; ud2
  UD2 触发 SIGILL，由程序自带的 handler 解码这两个字节：
      x = ch ^ XOR2[i]; rotl(x,3); x += ADD[i]; x ^= XOR1[i]; rotr(x,2); 与 CMP[i] 比较
  任一字节不符就把 0x4019 置 1；循环结束后 0x4019==0 → ACCESS_GRANTED。
  「心魔善造幻台」：main 在循环前还调了 0x16a0（一个 TEA 风格的分组校验），
  满足它就直接走 0x131c 打印同样的 ACCESS_GRANTED，**完全跳过 ud2 循环**——
  所以光看程序“点头”不算数，要看它是否真的执行了 23 次 UD2（strace 计 SIGILL）。

本脚本：静态逆字节变换得 23 字节真言 → WSL 跑原 ELF 复核
（正确输入 ACCESS_GRANTED 且 SIGILL≈24；23 字节错误输入 ACCESS_DENIED）。

用法：python exp.py
"""
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EV = HERE / "evidence"
EV.mkdir(exist_ok=True)
BIN = HERE / "attachments" / "tribulation"
N = 23


def rotl8(x, n):
    n &= 7
    return ((x << n) | (x >> (8 - n))) & 0xFF


def rotr8(x, n):
    n &= 7
    return ((x >> n) | (x << (8 - n))) & 0xFF


def forward(ch, i, cmp_, x1, add, x2):
    x = ch ^ x2[i]
    x = rotl8(x, 3)
    x = (x + add[i]) & 0xFF
    x ^= x1[i]
    return rotr8(x, 2)


def main():
    d = BIN.read_bytes()
    CMP = list(d[0x22D0:0x22D0 + N])
    XOR1 = list(d[0x22F0:0x22F0 + N])
    ADD = list(d[0x2310:0x2310 + N])
    XOR2 = list(d[0x2330:0x2330 + N])

    flag = bytearray()
    for i in range(N):
        x = CMP[i]
        x = rotl8(x, 2)
        x ^= XOR1[i]
        x = (x - ADD[i]) & 0xFF
        x = rotr8(x, 3)
        x ^= XOR2[i]
        flag.append(x)
    print("[*] 候选:", flag.decode("latin1"), list(flag))

    checks = {
        "长度 23": len(flag) == N,
        "可打印": all(32 <= b < 127 for b in flag),
        "NEX 格式": flag.startswith(b"NEX{") and flag.endswith(b"}"),
        "正向重算一致": all(forward(flag[i], i, CMP, XOR1, ADD, XOR2) == CMP[i] for i in range(N)),
    }
    print("[*] 静态校验:", checks)
    assert all(checks.values())

    # 用脚本跑 WSL，避开嵌套引号问题
    bad = b"NEX{" + b"a" * 18 + b"}"
    assert len(bad) == N
    script = EV / "verify.sh"
    script.write_text(
        "#!/bin/bash\n"
        "cd %s || exit 1\n"
        "printf '%%s' '%s' > /tmp/good.in\n"
        "printf '%%s' '%s' > /tmp/bad.in\n"
        "for f in good bad; do\n"
        "  strace -f -o /tmp/tr.txt ./tribulation < /tmp/$f.in > /tmp/out.txt 2>&1\n"
        "  rc=$?\n"
        "  echo \"$f rc=$rc sigill=$(grep -c SIGILL /tmp/tr.txt) verdict=$(grep -o 'ACCESS_[A-Z]*' /tmp/out.txt || echo none)\"\n"
        "done\n" % (BIN.parent.as_posix().replace("E:", "/mnt/e"), flag.decode(), bad.decode()),
        encoding="utf-8", newline="\n")
    p = subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "--", "bash", str(script).replace("E:", "/mnt/e").replace("\\", "/")],
                       capture_output=True, timeout=120)
    out = (p.stdout + p.stderr).decode("utf-8", "replace")
    (EV / "step2_run.txt").write_text(out, encoding="utf-8")
    print(out)
    info = {}
    for line in out.splitlines():
        m = re.match(r"(good|bad) rc=(\d+) sigill=(\d+) verdict=(\w+)", line)
        if m:
            info[m.group(1)] = (int(m.group(2)), int(m.group(3)), m.group(4))
    assert "good" in info and "bad" in info, out
    checks["good=ACCESS_GRANTED"] = info["good"][2] == "ACCESS_GRANTED"
    checks["bad=ACCESS_DENIED"] = info["bad"][2] == "ACCESS_DENIED"
    checks["good 走了 ud2 循环(>=23 SIGILL)"] = info["good"][1] >= 23
    checks["bad 也走 ud2 循环"] = info["bad"][1] >= 23

    res = "\n".join([f"{k:<26}: {v}" for k, v in checks.items()] +
                    [f"FLAG                      : {flag.decode()}"])
    print(res)
    (EV / "step1_solve.txt").write_text(res + "\n", encoding="utf-8")
    (EV / "flag.txt").write_text(flag.decode() + "\n", encoding="utf-8")
    assert all(checks.values())


if __name__ == "__main__":
    sys.exit(main() or 0)
