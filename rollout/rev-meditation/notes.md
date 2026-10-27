# 修仙模拟器（meditation）· 笔记（已解）

## 关键点
- 附件 `meditation.exe`（15,977,729 B）：PyInstaller + **pyarmor** 打包的 Python 程序，GUI 用 pywebview，
  前端 `gui/`（index.html/css/js + three.min.js），校验在原生 DLL **`meditation_core.dll`**（字符串 `NEX-GUARD-V4`）。
- 游戏逻辑：`GameApi.tick()` 加灵力，`eat_elixir()` 吃筑基丹；灵力 `>= ASCEND_AT(99999)` 时飞升。
  飞升时 Python 依次调 DLL：`n1(power)` → `n2(token)` → `g1()`；`g1()` 返回 flag 文本或 `None`。
- **作弊点 1（灵力）**：`GameApi._power_buf` 是 `ctypes.c_long`，直接 `api._power_buf.value = 99999`，
  `api.power` 立刻变 99999，然后 `tick()` 触发飞升——不用肝 27.8 小时。
- **作弊点 2（窗口校验）**：`g1()` 里用 `EnumWindows` 找窗口，条件（静态分析 0x21a0 回调 / 0x20f0 计数）：
  - `GetWindowThreadProcessId == 本进程 pid`；
  - `IsWindowVisible == true`；
  - `GetWindowTextW` 的标题 `lstrcmpW` 等于 `凡人修仙 · 打坐飞升`（来自 gui/index.html 的 `<title>`）；
  - 子窗口里类名以 `Chrome_` 开头的数量 **> 1**（0x20f0 用 `wcsncmp(class, L"Chrome_", 7)` 计数）。
  **关键坑**：伪造子窗口必须带 `WS_CHILD (0x40000000)` 样式；否则 CreateWindowExW 会把它们建成顶层窗口，
  `FindWindowExW` 查不到，计数为 0 → `g1()` 恒返回 `None`，前端提示「护法大阵目光一凝：验身未过……」。
- 其它校验（未触发）：`IsDebuggerPresent` / `CheckRemoteDebuggerPresent` 反调试；
  `gui\*` 目录扫描（文件名+内容+总大小参与指纹，即题面“内部哈希不是标准的”）；
  `ptrace` 式反调试对外部 trace 不友好。

## 判定
- 伪造 1 个顶层 `Chrome_WidgetWin_1`（标题/可见/同进程）+ 3 个 **WS_CHILD** 子窗口
  （`Chrome_RenderWidgetHostHWND`/`Chrome_WidgetWin_0`）后：
  - `api._power_buf.value = 99999`；`tick()` → `ascended = True`，`api._flag = NEX{sh0rtcut_1s_4ls0_d4o}`；
  - `ascend_gate()` 返回同一 flag；`notice` 为 `None`。
- 直接用 `core.n1(99999); core.n2(token); core.g1()` 也返回 `b'NEX{sh0rtcut_1s_4ls0_d4o}'`。

## 失败分支（排除理由）
- **只改灵力、不伪造窗口**：`g1()` 返回 `None` → 「验身未过」（窗口计数为 0）。
- **伪造了子窗口但漏了 WS_CHILD**：子窗口变成顶层窗口，`FindWindowExW(top, …)` 查不到，计数仍为 0（最初一直卡在这）。
- 直接跑真实 GUI：本机 pythonnet/.NET 运行时起不来（`ClrError 0x80131509`），且真实 meditation.exe 在本环境启动即退出；
  所以必须 stub webview + 自建窗口。
- 想用 WSL 的 python3 跑：pyc 是 cp313、pyarmor_runtime 是 Windows `.pyd`，必须先换 Windows 版 Python 3.13。

## 时间线
- 18:04 收附件，解包/识别 PyInstaller+pyarmor+DLL；
- 18:1x 找到 `_power_buf` 作弊点，但 `g1()` 一直 `None`；
- 18:2x 静态逆 g1：EnumWindows 回调条件、0x20f0 子窗口计数、`wcsncmp("Chrome_",7)`；
- 18:33 给伪造子窗口补上 `WS_CHILD`，`COUNT(top,0)` 从 0 变 2，`g1()` 返回 flag。

## 可复用 TTP
- PyInstaller + pyarmor 的 Python 程序：先 pyinstxtractor 解包，再用**对应版本**的 python（pyc magic）导入模块，
  stub 掉 GUI 模块后直接调内部 API；pyarmor RFT 的常量仍可在 `func.__code__.co_consts` 里看到。
- 原生 DLL 做校验时，Python 侧的对象（ctypes 句柄/缓冲区）往往就是作弊入口（本例 `_power_buf`）。
- Win32 窗口伪装：子窗口一定要 `WS_CHILD`，否则不是子窗口；配合 EnumWindows/EnumChildWindows 自查计数。
