# 内门玉牌 · 校验大阵（keycard.exe）· 笔记（已解）

## 关键点
- 附件 `keycard.exe`（43,913 B，Windows PE）。题面「阵盘外裹着一层封印，刻着 NEX」= **PE 自带一层壳**：
  Disk 上的 exe 里**没有明文校验数据**（搜不到 BLOB，也没有完整校验逻辑），运行后 payload 才在内存展开。
- 运行表现：打印「黄枫谷内门 - 玉牌校验大阵 v2.4」和阵旗那句「此阵不只看你是谁，还看你站在哪个方位。」，
  读一行玉牌内容，然后判定。
- **脱壳**：启动进程，`OpenProcess` + `ReadProcessMemory` 读模块基址 `+0x1000..+0x13000`（73,728 B payload），
  在 payload 里扫 32 字符的候选串。
- **校验算法**（从 payload 逆向，配合 `NEXGATE!` 字符串）：
  - 长度必须 24；
  - 每个字节按**位置 i** 参与：`f(x)[i] = (x[i] + i) & 0xFF ^ KEY[i & 7]`，KEY = `"NEXGATE!"`
    ——这就是题面「还看你站在哪个方位」：位置 i 参与运算；
  - 结果用**自定义字母表**的 base64 编码：`0123456789ABC…xyz+/`（不是标准 A-Za-z0-9+/），
    得到 BLOB = `00C2EIOvVnauBM8sAjN5OZ3180J7rior`。
- **逆**：自定义 base64 解码 → `raw[i] ^ KEY[i&7] - i` → `NEX{ch41n_0f_tr4nsf0rms}`。
- **复核**：正向重编码得到原 BLOB（逐字节相等）；原 exe 输入该串退出码 0 并回显
  「阵门开启…玉牌内容便是你的战利品: NEX{ch41n_0f_tr4nsf0rms}」；错误输入返回 1。

## 判定
- 重编码 == BLOB（`00C2EIOvVnauBM8sAjN5OZ3180J7rior`）；
- 原 exe：exit 0 + 成功文案 + 回显 flag；错误长度/错误内容均 exit 1。
- 结论：flag = **`NEX{ch41n_0f_tr4nsf0rms}`**（大写 NEX，与本题系列一致）。

## 失败分支（排除理由）
- 直接在磁盘 exe 里搜 BLOB / `NEX{`：**搜不到**（壳没解），只能在内存 dump 里找；
- 标准 base64 解码 BLOB：字母表不同，解出来是乱码，必须用自定义字母表；
- 忽略位置 i（只做 `x^KEY`）：解不出——题面「方位」指的就是 `+i`。

## 时间线
- 17:47:5x 解包，确认 PE，strings 取到「NEXGATE!」与中文提示；
- 17:48:1x 启动 exe + ReadProcessMemory 脱壳，得 73,728 B payload；
- 17:48:2x 扫 BLOB，自定义 base64 + 逆变换得 flag；
- 17:48:35 原 exe 复核 exit 0，落盘证据。

## 可复用 TTP
- 带壳 PE：先比对“磁盘 exe 里有没有明文数据”，没有就走运行时内存 dump（OpenProcess + ReadProcessMemory + EnumProcessModules 取基址）。
- 自定义 base64：字母表不标准时先猜/找映射表（本题字母表就写在 payload 里），别用标准库硬解。
- 变换里出现 `+i`/`^i` 这种**位置相关**项，就是题面“方位”的落点；逆向时别忘了减回去。
