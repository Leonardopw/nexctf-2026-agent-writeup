#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""内门玉牌 · 校验大阵（keycard.exe）—— 内存脱壳 + 自定义编码逆向 + 原程序复核

题面「NEX 封印」= PE 自带一层壳（Disk 上的 exe 里没有明文校验数据，运行后才在内存展开）。
做法：
  1) 启动 keycard.exe，用 ReadProcessMemory 读模块基址 +0x1000..+0x13000（脱壳后的 payload）；
  2) 在 payload 里扫 32 字符的候选串，逐个尝试：
       custom-alphabet base64 解码 -> 逆变换 raw[i] = (b[i]^KEY[i&7]) - i
     命中以 NEX{ 开头且重编码后与原串一致的即 BLOB；
  3) 用原 exe 复核：输入候选，退出码 0 且打印「阵门开启」消息。

用法：python exp.py   （需在 Windows 下运行，exe 为 PE）
"""
import ctypes
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
EV = HERE / "evidence"
EV.mkdir(exist_ok=True)
EXE = HERE / "attachments" / "keycard.exe"
FLAG_RE = re.compile(rb"(?:NEX|nex|FLAG|flag)\{[^}]+\}")

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/"
IDX = {c: i for i, c in enumerate(ALPHABET)}
KEY = b"NEXGATE!"


def b64dec(s):
    raw = bytearray()
    for i in range(0, len(s), 4):
        v = [IDX[c] for c in s[i:i + 4]]
        raw.append(((v[0] << 2) | (v[1] >> 4)) & 0xFF)
        raw.append((((v[1] & 0xF) << 4) | (v[2] >> 2)) & 0xFF)
        raw.append((((v[2] & 0x3) << 6) | v[3]) & 0xFF)
    return bytes(raw)


def b64enc(data):
    out = []
    for i in range(0, len(data), 3):
        b0, b1, b2 = data[i], data[i + 1], data[i + 2]
        out.append(ALPHABET[b0 >> 2])
        out.append(ALPHABET[((b0 << 4) | (b1 >> 4)) & 0x3F])
        out.append(ALPHABET[((b1 << 2) | (b2 >> 6)) & 0x3F])
        out.append(ALPHABET[b2 & 0x3F])
    return "".join(out)


def transform(inp):
    return bytes(((inp[i] + i) & 0xFF) ^ KEY[i & 7] for i in range(len(inp)))


def try_candidate(s):
    try:
        raw = b64dec(s)
    except KeyError:
        return None
    if len(raw) != 24:
        return None
    cand = bytes(((raw[i] ^ KEY[i & 7]) - i) & 0xFF for i in range(len(raw)))
    if cand.startswith(b"NEX{") and cand.endswith(b"}"):
        if b64enc(transform(cand)) == s:
            return cand
    return None


def dump_payload():
    """启动 exe，读运行时展开的 payload。"""
    k32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi
    p = subprocess.Popen([str(EXE)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, cwd=str(EXE.parent))
    time.sleep(1.2)
    h = k32.OpenProcess(0x0410, False, p.pid)   # VM_READ | QUERY_INFORMATION
    assert h, "OpenProcess 失败"
    mods = (ctypes.c_void_p * 2048)()
    need = ctypes.c_ulong(0)
    psapi.EnumProcessModules(h, mods, ctypes.sizeof(mods), ctypes.byref(need))
    base = mods[0]

    def read(addr, size):
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        ok = k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(got))
        return buf.raw[:got.value] if ok else b""

    payload = read(base + 0x1000, 0x12000)
    try:
        p.stdin.write(b"NEX{test}\n"); p.stdin.flush(); p.stdin.close()
    except Exception:
        pass
    time.sleep(0.3)
    if p.poll() is None:
        p.kill()
    p.wait(timeout=5)
    print("[*] 进程 pid=%d 基址=%#x，脱壳 payload %d 字节" % (p.pid, base, len(payload)))
    return payload


def brute(payload):
    found = {}
    for m in re.finditer(rb"[0-9A-Za-z+/]{32}", payload):
        s = m.group(0).decode()
        cand = try_candidate(s)
        if cand:
            print("[*] BLOB = %s -> %s" % (s, cand.decode()))
            found[s] = cand
    return found


def run_exe(flag_text):
    p = subprocess.run([str(EXE)], input=(flag_text + "\n").encode(), cwd=str(EXE.parent),
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
    out = p.stdout.decode("gbk", "replace")
    return p.returncode, out


def main():
    payload = dump_payload()
    (EV / "payload.bin").write_bytes(payload)
    found = brute(payload)
    assert len(found) == 1, "期望唯一候选，实际 %d" % len(found)
    blob, flag = next(iter(found.items()))

    rc, out = run_exe(flag.decode())
    (EV / "run.log").write_text(out, encoding="utf-8")
    print(out)
    print("[*] 原 exe 退出码:", rc)
    assert rc == 0, "原程序拒绝"
    assert flag in out.encode("gbk", "replace") or flag.decode() in out, "程序没回显 flag?"

    ok = (b64enc(transform(flag)) == blob)
    res = "\n".join([
        "blob          : " + blob,
        "flag          : " + flag.decode(),
        "re-encode ok  : %s" % ok,
        "exe exit code : %d" % rc,
        "exe echoed flag: %s" % (flag.decode() in out),
    ])
    (EV / "step1_solve.txt").write_text(res + "\n", encoding="utf-8")
    print(res)


if __name__ == "__main__":
    sys.exit(main() or 0)
