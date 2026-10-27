#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""浣?vs 绛捐瘉瀹?鈥斺€?DSA 楠岀鍦?s 鈮?0 (mod q) 鏃惰缁曡繃

婕忔礊锛?  verify() 鍙仛浜?`s <= 0` 妫€鏌ワ紝闅忓悗 `s %= q`锛涘綋 s 鍙?q 鐨勫€嶆暟锛堝 s = q锛夋椂 s%q == 0锛?  w = pow(0, q-2, q) = 0锛屼簬鏄袱涓寚鏁?h*w銆乺*w 閮戒负 0锛?      pow(g, 0, p) * pow(y, 0, p) % p % q == 1
  鍙 r = 1 灏辨亽鎴愮珛锛屽畬鍏ㄤ笉闇€瑕佺閽?x銆?  鏍瑰洜锛氭病鏍￠獙 s % q != 0锛堜互鍙?r銆乻 鐨勮寖鍥?浜掔礌锛夛紝鏍囧噯 DSA 搴旇姹?0 < s < q 涓?s 鍙€嗐€?
鐢ㄦ硶锛歱ython exp.py
"""
import json
import re
import socket
import sys
from pathlib import Path

HOST, PORT = "219.216.64.241", 35516
EV = Path(__file__).with_name("evidence")
EV.mkdir(exist_ok=True)
FLAG_RE = re.compile(r"(?:nex|flag|NEX|FLAG)\{[^}]+\}")


def recv_until(sock, marker: bytes, buf: bytes = b"") -> bytes:
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else "step1"
    s = socket.create_connection((HOST, PORT), timeout=10)
    banner = recv_until(s, b"\n")
    line = banner.split(b"\n", 1)[0].decode()
    params = json.loads(line)
    q = params["q"]
    print("[*] p bits=%d q bits=%d y=%s..." % (params["p"].bit_length(),
                                               q.bit_length(), str(params["y"])[:24]))

    r, sv = 1, q                       # s 鈮?0 (mod q) -> w = 0 -> 宸﹁竟鎭掍负 1
    payload = f"{r}\n{sv}\n".encode()
    s.sendall(payload)
    rest = banner.split(b"\n", 1)[1] if b"\n" in banner else b""
    resp = recv_until(s, b"\n", rest).decode("utf-8", "replace")
    s.close()

    print("[*] sent r=%d  s=q" % r)
    print("[*] server:", resp.strip())
    (EV / f"{tag}_req.txt").write_text(
        "TCP %s:%d\n<< %s\n>> r=%d\n>> s=q=%d\n" % (HOST, PORT, line, r, sv), encoding="utf-8")
    (EV / f"{tag}_resp.txt").write_text(resp, encoding="utf-8")

    m = FLAG_RE.search(resp)
    assert m, "鏈嬁鍒?flag: %r" % resp
    flag = m.group(0)
    print("[+] FLAG:", flag)
    (EV / f"{tag}_flag.txt").write_text(flag + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

