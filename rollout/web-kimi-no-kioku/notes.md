# キミの記憶（Memento Mori · SSTI）· 笔记（已解）

## 关键点
- 题面/`?name=`：名字被当模板渲染，响应只给四种状态：
  - `Hello <name>!`（渲染结果 == 输入）
  - `渲染出来不一样，我不会告诉你任何事情!`（渲染成功但与输入不同）
  - `渲染出错了!`（模板抛异常）
  - `这样的东西我是不会给你渲染的!`（命中关键字黑名单）
- 引擎是 **Jinja2**（`{{ }}` 生效、`config` 存在、`_wrap_close` 等类在 `__subclasses__()` 里）。
- **无回显 → 拿"渲染出错了"当布尔 oracle**：`{{ 1/0 if COND else 1 }}`，COND 真才除零报错。
  配合 `''.__class__.__mro__[1].__subclasses__()` 找到 `os._wrap_close`，取
  `__init__.__globals__['environ']` 即可读环境变量 / 起命令。
- flag 位置：**环境变量 `FLAG`**（不在 `config`、不是模板全局变量）。
- 逐字符外带：`{% if ord(...) >= mid %}{{1/0}}{% endif %}` 不行（沙箱里 `ord` 被改写过，
  `ord('n') >= 111` 也报错），改用字符比较 `G['environ']['FLAG'][i] >= 'm'`，按 ASCII 二分。
- 结果：`nex{C0loR_Y0uR_N19Ht_knvmh44e}`（长度 30，首字符 n，整串相等条件复核为真）。

## 失败分支（排除理由）
- 直接回显 `{{7*7}}` → 被"渲染出来不一样"挡住，说明不给回显，必须走侧信道。
- `flag`/`FLAG`/`config['FLAG']` 均不存在（oracle 判否）；`config` 只有 `SECRET_KEY` 等常规键。
- `{{ open('/etc/passwd').read() }}` → 渲染错误（Jinja 沙箱里 `open` 未定义），
  所以走 `__subclasses__` → `_wrap_close.__init__.__globals__` 拿 `os`/`environ`。
- `{{ self }}`/`{{ cycler }}`/`{{ joiner }}`/`{{ namespace }}`/`{{ lipsum }}`/`{{ session }}`
  命中黑名单（"这样的东西我是不会给你渲染的!"），但不影响 `_wrap_close` 链。
- 用 `ord()` 做二分失败：沙箱里的 `ord` 不是内置（比较行为异常），改用字符比较后正常。

## 时间线
- T0 19:42:32 收题 → recon（nginx，`/` 只有 `?name=` 一个入口）。
- T0+1min：确认 Jinja2 + 四种响应状态，构造除零布尔 oracle。
- T0+2min：定位 `os._wrap_close`，确认环境变量 `FLAG` 存在（长度 30）。
- T0+3min：字符比较二分逐位外带，得 `nex{C0loR_Y0uR_N19Ht_knvmh44e}`，整串相等复核通过。

## 可复用 TTP
- 无回显 SSTI：优先找"可条件触发的报错"（除零/越界/未定义调用），把渲染差异变成布尔 oracle。
- Jinja2 盲注链：`''.__class__.__mro__[1].__subclasses__()` → `_wrap_close`/`catch_warnings`
  → `__init__.__globals__` → `environ`/`popen`/`system`。
- 外带时别依赖 `ord` 等可能被改写的内置，用字符比较（Python 字符串按码点比较）更稳。
