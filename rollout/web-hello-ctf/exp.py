#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""exp.py —— Hello CTF（签到）

目标：http://6o2bbxsiyusi7iel.neu-nex.fun/
链路：首页注释泄露参数 ?helloctf=1 → 返回 hex → hex 解码得 base64 → base64 解码得 flag
依赖：仅标准库
用法：python exp.py [--url URL]
"""
import argparse
import base64
import re
import sys
import urllib.request

UA = 'exp/1.0 (+authorized-ctf)'


def get(url):
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.status, r.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--url', default='http://6o2bbxsiyusi7iel.neu-nex.fun/')
    args = ap.parse_args()
    base = args.url.rstrip('/')

    # 步骤 1：首页找入口（HTML 注释）
    st, body = get(base + '/')
    html = body.decode('utf-8', 'replace')
    print(f'[1] GET / -> {st}, len={len(body)}')
    m = re.search(r'<!--(.*?)-->', html, re.S)
    if not m:
        print('    [!] 首页没有注释，检查是否换题')
        return 1
    note = m.group(1).strip()
    print(f'    comment: {note}')
    q = re.search(r'\?([A-Za-z0-9_]+)=([A-Za-z0-9_]+)', note)
    if not q:
        print('    [!] 注释里没有参数')
        return 1
    param = f'?{q.group(1)}={q.group(2)}'

    # 步骤 2：拿到 hex
    st, body = get(base + '/' + param)
    hexstr = body.decode('utf-8', 'replace').strip()
    print(f'[2] GET /{param} -> {st}')
    print(f'    hex: {hexstr[:80]}...')

    # 步骤 3：hex -> base64 文本
    b64 = bytes.fromhex(hexstr)
    print(f'[3] hex -> {b64.decode()}')

    # 步骤 4：base64 -> flag
    flag = base64.b64decode(b64).decode('utf-8', 'replace')
    print(f'[4] base64 -> {flag}')

    if not re.fullmatch(r'nex\{[A-Za-z0-9_]+\}', flag):
        print('[-] 结果不符合 flag 格式')
        return 1
    print(f'[+] FLAG: {flag}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
