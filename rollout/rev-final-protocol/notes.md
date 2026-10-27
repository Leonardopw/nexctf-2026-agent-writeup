# 飞升台 · 最终禁制（final_protocol）· 笔记（已解）

## 关键点
- 附件 `final_protocol`：ELF64 PIE（14,488 B，stripped）。读 31 字节「协议仙诀」，判定 ACCESS_GRANTED/DENIED。
- 题面「禁制在你叩门之前便已生效 / 吾在你睁眼之前便已苏醒」= **`.init_array` 构造函数在 main 之前运行**：
  - `0x1180` 里先 `call 0x1160`（`ptrace(PTRACE_TRACEME)`），`test rax,rax; js 0x1381` ——
    被调试/被跟踪就跳到异常路径；题面「别放神识去缠它，它最厌恶被人注视」= 反调试。
    实测：**普通运行正常，`strace` 下直接 SIGSEGV（rc=139）**。
  - 接着用 **RC4**（key = `"NEX2025"`，.rodata 0x2004）生成 16 字节 keystream，
    与 0x23b0 的 16 字节常量异或，得到 16 字节 XXTEA 密钥 `key16 = "NEX-XXTEA-REAL-K"`。
- main：自定义 base64 字母表（0x22c0，**小写在前**：`abcdefghijklmnopqrstuvwxyzABC…+/`）解码
  0x2320 的 44 字符 BLOB → 32 字节密文 → **XXTEA**（n=8，delta=0x61C88647，`6+52/8=12` 轮）解密 → 32 字节明文
  → 取前 31 字节与输入比较（末尾 `\0`）。
- 逆：RC4 派生 key16 → 自定义 base64 解码 → XXTEA 解密 → `NEX{c0nstruct0r_rc4_t34_m4st3r}\0`。

## 判定
- 明文 32 字节（31 字符 + `\0`），可打印，NEX 格式；
- XXTEA **重新加密**结果与 0x2320 的密文逐字节相等（re-enc == True）；
- 原 ELF（普通运行）输入 flag：`ACCESS_GRANTED`、rc=0；31 字节错误输入：`ACCESS_DENIED`、rc=1；
  在 `strace` 下运行 → `Segmentation fault`（rc=139），反调试确实生效。

## 失败分支（排除理由）
- 直接 `strace`/调试会触发 ptrace 反调试（SIGSEGV），所以动态侧只能“裸跑”比对回显，不能观察系统调用；
- 只信“程序说 ACCESS_GRANTED”不够：必须用 XXTEA 重加密回代密文 + 错误输入回显双向验证；
- 标准 base64 字母表解 BLOB 会乱码（本题字母表是小写在前），必须用 0x22c0 的 64 字符表；
- 普通 12 轮 TEA 而不是 XXTEA 会解错：轮数 `6+52/8=12`、每轮 8 个分组，按 XXTEA 逆。

## 时间线
- 18:01:5x 解包，反汇编定位 .init_array 构造函数（ptrace + RC4）；
- 18:02:1x 派生 key16、按自定义 base64 解 BLOB；
- 18:02:3x XXTEA 解密得明文，重加密回代相等；
- 18:02:53 原 ELF 裸跑复核 good/bad 与 strace 崩溃，落盘证据。

## 可复用 TTP
- “禁制在叩门前生效” = 看 `.init_array` / TLS callback / `__attribute__((constructor))`；
  密钥常在构造函数里派生（RC4/异或）。
- “厌恶被注视” = ptrace 反调试：`PTRACE_TRACEME` 返回 -1（已被跟踪）就走异常路径；
  静态分析优先，动态验证用裸跑（不要 strace/gdb）。
- 自定义 base64 先读字母表；XXTEA 的轮数随分组数变（n=8 → 12 轮）。
