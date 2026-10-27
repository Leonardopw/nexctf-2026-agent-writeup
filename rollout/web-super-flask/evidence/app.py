# -*- coding: utf-8 -*-
import os
import base64
import pickle
import pickletools
import json
from flask import Flask, request, jsonify, render_template_string, send_file, session, redirect, send_from_directory

app = Flask(__name__)
app.secret_key = 'superbigcup-secret-key-2025'

FLAG_PATH = '/flag'

# flag 读到内存后，立即从环境变量删除，让子进程读不到（RCE 后无法直接拿 flag）
REAL_FLAG = os.environ.get('FLAG', 'flag{TEST_Dynamic_FLAG}')
for key in ['FLAG', 'DASFLAG', 'GZCTF_FLAG']:
    os.environ.pop(key, None)

# 管理员标志位（class pollution 污染目标）
IS_ADMIN = False

# 登录凭据（密码藏在可扫描到的 SQL 文件里）
USERNAME = 'zc'
CORRECT_PASSWORD=<REDACTED>'


def get_flag():
    return REAL_FLAG


# ========== 阶段1：登录 ==========

@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>明日方舟超市</title></head>
<body>
<h1>欢迎来到无聊的明日方舟时间线</h1>
<form action="/login" method="post">
  账号 <input type="text" name="username"><br>
  密码 <input type="password" name="password"><br>
  <button type="submit">登录</button>
</form>
<p style="color:#999">账号是 zc</p>
</body>
</html>
''')


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password=<REDACTED>'password', '')
    if username == USERNAME and password == CORRECT_PASSWORD=<REDACTED>'logged_in'] = True
        return redirect('/shop')
    return '登录失败', 401


# ========== 阶段2：超市 ==========

SHOP_ITEMS = [
    {'id': 'flag',      'name': 'flag',                'desc': '你还真敢买啊'},
    {'id': 'cheese',    'name': '两面包夹芝士',          'desc': '这是军费不能省'},
    {'id': 'pool',      'name': '不知道哪年的夏活卡池',  'desc': '左边这位其实没什么兴趣'},
    {'id': 'damedame',  'name': 'damedame',            'desc': 'ALL'},
    {'id': 'rent',      'name': '出租屋',               'desc': '很多蟑螂'},
    {'id': 'image',     'name': '好像有什么问题的图片',  'desc': '展示 ew.png'},
    {'id': 'xlpj',      'name': 'xlpj',                'desc': 'workworkwork'},
    {'id': 'seaborn',   'name': '海嗣',                 'desc': '阴暗地爬行'},
    {'id': 'furnace',   'name': '魂灵熔炉',             'desc': '还有谁要讲故事'},
    {'id': 'chen',      'name': '假日威龙陈',           'desc': '死仇时代的恨意'},
]


@app.route('/shop')
def shop():
    if not session.get('logged_in'):
        return redirect('/')
    items = ''.join(
        f'<li><a href="/item/{i["id"]}">{i["name"]}</a> —— {i["desc"]}</li>'
        for i in SHOP_ITEMS
    )
    return render_template_string('''
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>超市</title></head>
<body>
<h1>超市</h1>
<p>欢迎，zc。</p>
<ul>''' + items + '''</ul>
<hr>
<h2>进货</h2>
<p><a href="/restock">进货输入框</a></p>
</body>
</html>
''')


# ========== 阶段3：货物详情 / 图片下载（隐写 hint）==========

@app.route('/item/<item_id>')
def item(item_id):
    if not session.get('logged_in'):
        return redirect('/')
    for i in SHOP_ITEMS:
        if i['id'] == item_id:
            if item_id == 'image':
                return send_file('static/ew.png', mimetype='image/png')
            return f'<h1>{i["name"]}</h1><p>{i["desc"]}</p>'
    return '没有这个货', 404


# ========== 阶段4：进货 pickle 反序列化（WAF ban R/i）==========

@app.route('/buy', methods=['POST'])
def buy():
    data = request.get_json(silent=True) or {}
    item = data.get('item', '')
    if item != 'cheese':
        return jsonify({'msg': '这个商品不参与活动'})

    b64 = data.get('data', '')
    try:
        raw = base64.b64decode(b64)
    except Exception:
        return jsonify({'msg': 'data 需要 base64 编码'})

    # WAF：ban REDUCE / INST 操作码，选手用 OBJ 绕过
    try:
        for op, arg, pos in pickletools.genops(raw):
            if op.name in ('REDUCE', 'INST'):
                return jsonify({'msg': '检测到危险操作码'})
    except Exception:
        return jsonify({'msg': 'data 格式错误'})

    try:
        result = pickle.loads(raw)
        return jsonify({'msg': 'ok', 'result': str(result)})
    except Exception:
        return jsonify({'msg': '反序列化出错'})


# ========== 阶段5：进货输入框（class pollution）==========

class Goods:
    def __init__(self):
        self.name = 'unknown'
        self.price = 0


def merge(target, source):
    for key, value in source.items():
        if isinstance(value, dict):
            child = target[key] if isinstance(target, dict) else getattr(target, key)
            merge(child, value)
        else:
            if isinstance(target, dict):
                target[key] = value
            else:
                setattr(target, key, value)


@app.route('/restock', methods=['GET', 'POST'])
def restock():
    if not session.get('logged_in'):
        return redirect('/')
    result = ''
    if request.method == 'POST':
        payload = request.form.get('config', '{}')
        low = payload.lower()
        for bad in ['<script', '{{', '{%', 'jinja']:
            if bad in low:
                return jsonify({'msg': '检测到非法输入'})
        try:
            cfg = json.loads(payload)
            goods = Goods()
            merge(goods, cfg)
            result = f'进货配置已更新: {goods.name}'
        except Exception:
            result = '配置解析失败'
    return render_template_string('''
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>进货</title></head>
<body>
<h1>进货配置</h1>
<form method="post">
  <textarea name="config" rows="5" cols="60">{"name": "新货"}</textarea><br>
  <button type="submit">提交</button>
</form>
<p>''' + result + '''</p>
</body>
</html>
''')


# ========== 阶段6：管理员（污染 IS_ADMIN 后访问）==========

@app.route('/admin')
def admin():
    if not IS_ADMIN:
        return jsonify({'msg': '你不是管理员'}), 403
    return jsonify({'flag': get_flag()})


# ========== 静态文件（泄露 SQL + 图片）==========

@app.route('/static/<path:filename>')
def static_file(filename):
    return send_from_directory('static', filename)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)
