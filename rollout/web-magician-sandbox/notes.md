# 永远的魔法使 · 笔记

## 关键点
- 入口：首页 `<textarea>` + `POST /run`，body `{"code": "..."}`，响应 `{"output": "..."}`。
- 黑名单是**源码子串匹配**，命中即返回 `[沙箱] 检测到危险词: X`。逐词探针结果：
  - 拦：`open`、`read`、`import`、`exec`、`eval`、`subprocess`、`system`、`popen`、`breakpoint`、`help`、`input`
  - 放行：`os`、`sys`、`write`、`compile`、`__builtins__`、`getattr`、`__class__`、`__subclasses__`、`__globals__`、`warnings`、`catch_warnings`、`flag`、`/flag`
- `exec` 环境的 `__builtins__` 是**裁剪过的 dict**：`print('__imp'+'ort__' in __builtins__)` → `False`，`__builtins__['op'+'en']` → `KeyError: 'open'`。
- 真 builtins 的入口：`warnings.catch_warnings` 类在 `().__class__.__base__.__subclasses__()` 里（共 491 个），
  `catch_warnings.__init__.__globals__['__builtins__']` 是解释器真 builtins（含 open / __import__）。
- 绕过：`'op'+'en'`、`'re'+'ad'`、`'__imp'+'ort__'` 运行期拼接，源码里不出现被禁子串。
- 结果：`nex{mAJO_kO1_nIKK1_ty6bpzu7}`（两条路径互证）。

## 失败分支（排除理由）
- `import os` / `open('/flag')` / `exec` / `eval` → 直接危险词，排除"正面调用"。
- `__builtins__['op'+'en']` → `KeyError: 'open'`：说明 builtins 被裁剪，不是过滤层问题，排除"只绕黑名单"。
- `getattr(__builtins__, 'op'+'en')` → `AttributeError: 'dict' object has no attribute 'open'`，确认 exec 传的是 dict 而非 module。
- `print('open' in __builtins__)` 被拦 → 证明过滤发生在**源码文本**层，运行期字符串不受限，这决定了拼接路线。
- 直接 `__import__('os')` → 也是危险词；且 `__import__` 在裁剪 dict 中不存在（step4 证实），必须拿真 builtins 后再导入。

## 时间线
- T0 14:13:17 收到题目，建骨架 + recon（首页 Python 沙箱，/run）。
- T1 14:13:40 基线 `print(1+1)` → 2；试 import/open → 危险词。
- T2 14:13:55 `__builtins__` 探针：被裁剪（KeyError/False），确认不能直取。
- T3 14:14:10 词表枚举黑名单，确认 `catch_warnings`、`getattr`、`subclasses` 均放行。
- T4 14:14:20 `catch_warnings.__init__.__globals__` 取真 builtins → `b['op'+'en']('/flag')` + `getattr(f,'re'+'ad')()`。
- T5 14:14:27 得到 flag；随后用 `os.open/os.read` 独立复核一致。

## 可复用 TTP
- 沙箱过滤先做"字符探针"：把候选词作为字符串字面量发一遍，一次请求就能画出黑名单。
- 源码子串黑名单 = 运行期拼接（`'op'+'en'`）或 `getattr` 取属性即可绕，别硬刚。
- `__builtins__` 被裁剪时，找任意可达对象的 `__globals__` 回真实 builtins；`warnings.catch_warnings` 命中率最高（标准库几乎必被 import）。
- 证明链要两条独立原语：`builtins.open/read` 与 `os.open/os.read` 回显同一 flag，避免单点误报。
