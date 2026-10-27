#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""飞升台 · 最终禁制（final_protocol）—— 构造函数里做 ptrace 反调试 + 派生 RC4 密钥，主函数 XXTEA 校验

链路：
  1) .init_array 的构造函数（0x1180）在 main 之前跑：
       - ptrace(PTRACE_TRACEME)：被调试/被跟踪就跳到 0x1381（崩溃/异常路径）——题面「它最厌恶被人注视」；
       - 用 RC4（key = "NEX2025"，.rodata 0x2004）生成 16 字节 keystream，与 0x23b0 的常量异或，
         得到 16 字节 XXTEA 密钥 key16 = "NEX-XXTEA-REAL-K"。
  2) main 读 31 字节，按“小写在前”的自定义 base64 字母表（0x22c0）解码 0x2320 的 44 字符 BLOB，
     得到 32 字节密文；XXTEA（n=8, delta=0x61C88647, 12 轮）解密后与输入比较。
  逆：RC4 派生密钥 → 自定义 base64 解码 → XXTEA 解密 → 明文 NEX{c0nstruct0r_rc4_t34_m4st3r}\\0。

验证：XXTEA 重新加密 == 密文；原 ELF（不 strace，否则 ptrace 反调试触发 SIGSEGV）输入 flag → ACCESS_GRANTED，
错误 31 字节 → ACCESS_DENIED。

用法：python exp.py
"""
import base64
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EV = HERE / "evidence"
EV.mkdir(exist_ok=True)
BIN = HERE / "attachments" / "final_protocol"
M = 0xFFFFFFFF
DELTA = 0x61C88647
N = 31


def rc4_keystream(key: bytes, n: int):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out, i, j = [], 0, 0
    for _ in range(n):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def b64_decode_custom(s: str, alphabet: str) -> bytes:
    rev = {c: i for i, c in enumerate(alphabet)}
    out = bytearray()
    v = 0
    for p, ch in enumerate(s):
        if ch == "=":
            continue
        v = (v << 6) | rev[ch]
    nbits = len([c for c in s if c != "="]) * 6
    nbytes = nbits // 8
    for k in range(nbytes):
        out.append((v >> (nbits - 8 * (k + 1))) & 0xFF)
    return bytes(out)


def xxtea_decrypt(v, k):
    n = len(v)
    rounds = 6 + 52 // n
    total = (rounds * DELTA) & M
    v = list(v)
    y = v[0]
    for _ in range(rounds):
        e = (total >> 2) & 3
        for p in range(n - 1, -1, -1):
            z = v[p - 1]
            mx = ((((z >> 5) ^ ((y << 2) & M)) + ((y >> 3) ^ ((z << 4) & M))) & M) \
                 ^ (((total ^ y) + (k[(p & 3) ^ e] ^ z)) & M)
            v[p] = (v[p] - mx) & M
            y = v[p]
        total = (total - DELTA) & M
    return v


def xxtea_encrypt(v, k):
    n = len(v)
    rounds = 6 + 52 // n
    total = 0
    v = list(v)
    for _ in range(rounds):
        total = (total + DELTA) & M
        e = (total >> 2) & 3
        for p in range(n):
            z = v[p - 1]
            y = v[(p + 1) % n]
            mx = ((((z >> 5) ^ ((y << 2) & M)) + ((y >> 3) ^ ((z << 4) & M))) & M) \
                 ^ (((total ^ y) + (k[(p & 3) ^ e] ^ z)) & M)
            v[p] = (v[p] + mx) & M
    return v


def main():
    d = BIN.read_bytes()
    CONST16 = d[0x23B0:0x23C0]
    KEYSTR = d[0x2004:0x2004 + 7]
    ALPHA = d[0x22C0:0x22C0 + 64].decode()
    BLOB = d[0x2320:0x2320 + 44].decode()
    print("[*] RC4 key:", KEYSTR, "| base64 alphabet:", ALPHA)
    print("[*] BLOB:", BLOB)

    key16 = bytes(CONST16[i] ^ rc4_keystream(KEYSTR, 16)[i] for i in range(16))
    K = list(struct.unpack("<4I", key16))
    print("[*] key16:", key16)

    ct = b64_decode_custom(BLOB, ALPHA)
    print("[*] cipher:", ct.hex(), len(ct))
    pt = struct.pack("<8I", *xxtea_decrypt(list(struct.unpack("<8I", ct)), K))
    print("[*] plain :", pt)
    back = struct.pack("<8I", *xxtea_encrypt(list(struct.unpack("<8I", pt)), K))
    flag = pt[:N].decode("latin-1")
    print("[*] flag  :", flag)

    checks = {
        "明文 31 字节 + \\0": len(pt) == 32 and pt[31] == 0,
        "可打印": all(32 <= b < 127 for b in pt[:N]),
        "NEX 格式": flag.startswith("NEX{") and flag.endswith("}"),
        "XXTEA 重加密==密文": back == ct,
    }
    print("[*] 静态校验:", checks)
    assert all(checks.values())

    bad = "NEX{" + "a" * 26 + "}"
    assert len(bad) == N
    script = EV / "verify.sh"
    script.write_text(
        "#!/bin/bash\n"
        "cd %s || exit 1\n"
        "printf '%%s' '%s' | ./final_protocol > /tmp/good.txt 2>&1; echo \"good rc=$?\" >> /tmp/good.txt\n"
        "printf '%%s' '%s' | ./final_protocol > /tmp/bad.txt 2>&1; echo \"bad rc=$?\" >> /tmp/bad.txt\n"
        "printf '%%s\\n' '=== good ==='; tail -3 /tmp/good.txt\n"
        "printf '%%s\\n' '=== bad ==='; tail -3 /tmp/bad.txt\n"
        "printf '%%s\\n' '=== under strace (anti-debug) ==='\n"
        "printf '%%s' '%s' | strace -f -o /tmp/tr.txt ./final_protocol > /tmp/st.txt 2>&1; echo \"strace rc=$?\" >> /tmp/st.txt\n"
        "tail -2 /tmp/st.txt\n" % (
            BIN.parent.as_posix().replace("E:", "/mnt/e"), flag, bad, flag),
        encoding="utf-8", newline="\n")
    p = subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "--", "bash",
                        str(script).replace("E:", "/mnt/e").replace("\\", "/")],
                       capture_output=True, timeout=120)
    out = (p.stdout + p.stderr).decode("utf-8", "replace")
    (EV / "step2_run.txt").write_text(out, encoding="utf-8")
    print(out)
    checks["good=ACCESS_GRANTED"] = "good rc=0" in out and "ACCESS_GRANTED" in out
    checks["bad=ACCESS_DENIED"] = "bad rc=1" in out and "ACCESS_DENIED" in out
    checks["strace 触发反调试"] = ("Segmentation fault" in out) or ("strace rc=" in out and "rc=139" in out)

    res = "\n".join([f"{k:<22}: {v}" for k, v in checks.items()] + [f"FLAG                  : {flag}"])
    print(res)
    (EV / "step1_solve.txt").write_text(res + "\n", encoding="utf-8")
    (EV / "flag.txt").write_text(flag + "\n", encoding="utf-8")
    assert all(checks.values())


if __name__ == "__main__":
    sys.exit(main() or 0)
