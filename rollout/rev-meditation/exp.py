# -*- coding: utf-8 -*-
"""修仙模拟器（meditation）—— 不肝 27.8 小时，直接作弊拿 flag

关卡：
  PyInstaller + pyarmor 的 Python 前端 + 原生 DLL `meditation_core.dll`（NEX-GUARD-V4）。
  灵力到 99999 时 Python 依次调用 DLL：n1(99999) -> n2(token) -> g1()，
  g1() 先做反调试 / GUI 指纹 / 窗口校验，再解出 flag；任一不过就返回 None，
  前端提示「护法大阵目光一凝：验身未过……」。

作弊点（两处）：
  1) 灵力：`api._power_buf.value = 99999` 直接把 c_long 状态写满，不用慢慢打坐；
  2) 窗口校验：g1 用 EnumWindows 找「同进程 + 可见 + 标题 == 凡人修仙 · 打坐飞升 +
     子孙窗口里类名以 Chrome_ 开头的数量 > 1」的窗口。
     伪造窗口时子窗口必须带 **WS_CHILD (0x40000000)** —— 否则它们会变成顶层窗口，
     FindWindowEx 查不到、计数为 0，验身必败（这就是之前一直返回 None 的原因）。

运行（必须 Windows + Python 3.13，pyarmor_runtime 是 Windows cp313 的 .pyd）：
    <WORKSPACE>/challenges/rev/meditation/py313/python.exe exp.py
"""
import ctypes
import os
import re
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
EV = HERE / "evidence"
EV.mkdir(exist_ok=True)
BASE = os.environ.get('MED_BASE') or r'<WORKSPACE>\challenges\rev\meditation2\meditation.exe_extracted'
FLAG_RE = re.compile(r'NEX\{[^}]+\}')

if not os.path.isdir(BASE):
    sys.exit('找不到 meditation.exe_extracted，请设置 MED_BASE')
if sys.platform != 'win32':
    sys.exit('必须在 Windows 上运行（pyarmor_runtime 是 Windows .pyd）；WSL 里请调用 '
             '<WORKSPACE>/challenges/rev/meditation/py313/python.exe')

sys.path.insert(0, BASE)

user32 = ctypes.windll.user32
LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_ssize_t)


class WNDCLASSW(ctypes.Structure):
    _fields_ = [('style', ctypes.c_uint), ('lpfnWndProc', WNDPROC),
                ('cbClsExtra', ctypes.c_int), ('cbWndExtra', ctypes.c_int),
                ('hInstance', ctypes.c_void_p), ('hIcon', ctypes.c_void_p),
                ('hCursor', ctypes.c_void_p), ('hbrBackground', ctypes.c_void_p),
                ('lpszMenuName', ctypes.c_wchar_p), ('lpszClassName', ctypes.c_wchar_p)]


user32.DefWindowProcW.restype = LRESULT
user32.DefWindowProcW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_ssize_t]
_pc = WNDPROC(lambda h, m, w, l: user32.DefWindowProcW(h, m, w, l))
user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
user32.CreateWindowExW.restype = ctypes.c_void_p
user32.CreateWindowExW.argtypes = [ctypes.c_uint, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint,
                                   ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

WS_VISIBLE = 0x10000000
WS_CHILD = 0x40000000
WS_OVERLAPPEDWINDOW = 0x00CF0000
TITLE = '凡人修仙 · 打坐飞升'


def make_class(name):
    wc = WNDCLASSW()
    wc.lpfnWndProc = _pc
    wc.lpszClassName = name
    user32.RegisterClassW(ctypes.byref(wc))


def build_fake_webview():
    for cls in ('Chrome_WidgetWin_1', 'Chrome_RenderWidgetHostHWND', 'Chrome_WidgetWin_0'):
        make_class(cls)
    top = user32.CreateWindowExW(0, 'Chrome_WidgetWin_1', TITLE,
                                 WS_OVERLAPPEDWINDOW | WS_VISIBLE, 10, 10, 960, 700,
                                 None, None, None, None)
    kids = []
    for i in range(3):
        cls = 'Chrome_RenderWidgetHostHWND' if i % 2 == 0 else 'Chrome_WidgetWin_0'
        kids.append(user32.CreateWindowExW(0, cls, 'render%d' % i, WS_CHILD | WS_VISIBLE,
                                           0, 0, 200, 100, top, None, None, None))
    return top, kids


def main():
    top, kids = build_fake_webview()
    print('[*] 伪造窗口: top=%s children=%s' % (hex(top or 0), [hex(k or 0) for k in kids]))

    wv = types.ModuleType('webview')

    class _Stub:
        def __init__(self, *a, **k):
            pass
        def __getattr__(self, name):
            return lambda *a, **k: None

    wv.create_window = lambda *a, **k: _Stub()
    wv.start = lambda *a, **k: None
    wv.Window = _Stub
    wv.events = types.SimpleNamespace()
    wv.settings = {}
    sys.modules['webview'] = wv

    import meditation_game as m
    m.main()
    print('[*] GUI_SHA =', m.GUI_SHA)
    print('[*] token(99999) =', m._ascend_token(99999))

    api = m.GameApi()
    api._power_buf.value = m.ASCEND_AT      # 作弊：直接写满灵力
    st = api.tick()

    flag = api._flag
    checks = {
        'power == 99999': api.power == m.ASCEND_AT,
        'ascended == True': bool(api.ascended),
        'flag 非空': bool(flag),
        'flag 格式 NEX{...}': bool(flag and FLAG_RE.fullmatch(flag)),
        'gate == flag': m.ascend_gate() == flag,
        'notice 为空': not (st or {}).get('notice'),
    }
    out = '\n'.join([f'{k:<20}: {v}' for k, v in checks.items()] +
                    [f'power               : {api.power}',
                     f'notice              : {(st or {}).get("notice")}',
                     f'FLAG                : {flag}'])
    print(out)
    (EV / 'step1_solve.txt').write_text(out + '\n', encoding='utf-8')
    (EV / 'flag.txt').write_text(str(flag) + '\n', encoding='utf-8')
    assert all(checks.values()), '校验失败'


if __name__ == '__main__':
    main()
