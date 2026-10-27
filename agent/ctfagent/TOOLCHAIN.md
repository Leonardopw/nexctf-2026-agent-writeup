# CTF 工具链（WSL2 / Ubuntu 24.04）

安装时间：2026-10-24
环境：Ubuntu 24.04.4 LTS（WSL2），Python 3.12.3，默认用户 `leonard`，root 可 `wsl -u root`

> 所有 Python 包装在 `/usr/local/lib/python3.12/dist-packages`（系统级），`leonard` 和 `root` 都可见。

## 一、按类别

| 类别 | 已装工具 |
|---|---|
| **Web** | `nmap`、`sqlmap`、`ffuf`、`gobuster`、`wfuzz`、`dirsearch`、`curl`、`python3-requests` |
| **Crypto** | `pycryptodome`、`gmpy2`、`sympy`、`z3-solver`、`RsaCtfTool`、`hashcat`、`john`、`openssl`、`qrencode` |
| **Pwn** | `pwntools`、`gdb`（默认加载 pwndbg）、`ropper`、`ROPgadget`、`one_gadget`、`patchelf`、`keystone`、`unicorn`、`angr`、`checksec`（`pwn checksec`） |
| **Reverse** | `radare2`、`objdump`、`readelf`、`strings`、`capstone`、`pyelftools`、`gdb`、`java` |
| **Misc / 取证** | `binwalk`、`foremost`、`exiftool`、`steghide`、`zbarimg`、`pngcheck`、`7z`、`pdfimages`、`pdftotext`、`tshark`、`volatility3` |
| **通用** | `socat`、`nc`、`whois`、`dig`、`ruby` |

## 二、验证

```bash
# 一键体检
wsl bash <APPS>/smoke_tools.sh      # 版本 + 功能冒烟
wsl bash <APPS>/check_tools.sh      # 安装清单 Y/N
```

单点验证示例：

```bash
python3 -c "import pwn, z3, Crypto, angr, volatility3; print('py ok')"
nmap -sT -p 80,443 target
sqlmap -u "http://target/item?id=1" --batch --dbs
binwalk -e firmware.bin
r2 -A ./chall
tshark -r traffic.pcapng -Y http
RsaCtfTool --publickey pub.pem --attack all
```

## 三、已知坑 / 注意事项

1. **binwalk 已打补丁**：Ubuntu 的 binwalk 2.3.4 与新版 `capstone` 不兼容（`CS_ARCH_ARM64` 改名为 `CS_ARCH_AARCH64`）。已在 `/usr/lib/python3/dist-packages/binwalk/modules/disasm.py` 用 `getattr` 兼容，升级 capstone 后一般不用再改。
2. **capstone 锁定 5.x**：`capstone 6.x` 会破坏 `angr` / `ropper`（`CS_MODE_RISCVC` 改名）。`leonard` 用户目录已装 5.0.7 覆盖 6.0.0；升级其它包时不要把 capstone 升到 6。
3. **angr 用内置 claripy**：angr 10 自带 `angr.rustylib.claripy`，不要用外部 `claripy` 包构造表达式（会报 `expression must be a boolean`），用 `st.solver.BVS()/st.solver.add()`；`z3-solver` 已锁 **5.3.1**（提供 `libz3.so.5.3`），pip 关于 `claripy 9.x requires z3 4.13` 的警告可忽略。
4. **dirsearch 未装**：与 Debian 自带的 `cryptography` 冲突，且 `ffuf` / `gobuster` / `wfuzz` 已覆盖目录爆破，不装不影响。
5. **nmap 非 root**：agent 以 `leonard` 运行，SYN 扫描要 root，用 `-sT`（TCP connect）即可；需要 `-sS` 时用 `wsl -u root`。
6. **john 是 core 版**（无 jumbo），复杂 hash 优先用 `hashcat`。
7. **RsaCtfTool** 以 editable 方式装在 `<DESKTOP>\ctf-tools\RsaCtfTool`，命令 `RsaCtfTool` 全局可用；跑纯数学攻击时注意 `--attack all` 可能较慢，可按攻击名指定。
8. **Ghidra 未装**（体积大）；`radare2` + `r2 -A` 可顶大部分逆向场景。
9. **SageMath 未装**（apt 包巨大，格基/ECC 题需要时再装：`apt install sagemath`，约 2GB）。

## 四、还没装（按需再补）

| 工具 | 用途 | 安装方式 |
|---|---|---|
| SageMath | 格基、ECC、代数攻击 | `apt install sagemath`（大） |
| Ghidra | 反编译 | 下载 release zip + 解压 |
| frida | 移动端 hook | `pip install frida-tools` |
| qemu-user | 跨架构 pwn | `apt install qemu-user` |
| pwndbg / GEF | gdb 增强 | pwndbg 已在 `~/Desktop/pwndbg`；GEF 在 `/opt/gef.py`（`gdb -ex "source /opt/gef.py"`） |

## 五、Agent 里怎么用

`run_command` 直接在 WSL 里执行，例如：

- `sqlmap -u "http://target/search?name=1" --batch --dbs`
- `nmap -sT -p- -T4 target`
- `ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt`
- `binwalk -eM file.bin`
- `python3 -c "import z3; ..."`

需要保持登录态/并发请求时，优先写 `python3` 脚本（`requests` 已装），或用内置 `http_request` 工具。
