# CTF-Agent（本地版）

一个**零第三方依赖**、面向 CTF 的本地 LLM Agent：多策略并发 + ReAct 工具循环 + 完整 rollout 记录，开箱即用。

- 适配 **DeepSeek / Kimi / GLM / OpenAI 等任意 OpenAI 兼容接口**
- Windows 原生可用（工具默认跑在 **WSL bash**，自动回退 PowerShell）
- 每道题产出 `transcript.jsonl` + `summary.md`，**直接对应 NEXCTF《Agent 工程师》的实测记录字段**

> 仅用于**授权的 CTF 比赛 / 靶场**。请勿用于未授权目标。

---

## 1. 为什么不是 verialabs/ctf-agent 那类项目

`verialabs/ctf-agent`（BSidesSF 2026 冠军）很强，但它要求：

- Python 3.14+ / `uv`
- **Docker**（每个 solver 一个沙箱容器）
- Claude / GPT / Gemini 的 API Key 与 `claude` / `codex` CLI

本机没有 Docker，且只有 DeepSeek 系的 Key，所以这里实现了一个**同思路但轻量**的版本：

| 能力 | verialabs/ctf-agent | 本项目 |
|---|---|---|
| 多模型/多策略并发 | ✅ | ✅（多策略并发，先到先得） |
| 隔离沙箱 | Docker | WSL bash + 独立工作目录 |
| 依赖 | Docker + uv + 多家 Key | **纯标准库，任意 OpenAI 兼容接口** |
| 可改造性 | 大工程 | 单包 ~600 行，适合比赛二次开发 |

---

## 2. 架构

```
                 ┌────────────────────────────┐
   challenge ───▶│  Attempt 1  recon-first    │──┐
   (url/附件)     │  Attempt 2  exploit-first  │  │   每个 Attempt:
                 │  Attempt 3  bypass-first   │  ├─▶ ReAct 循环
                 │  Attempt 4  script-first   │  │     LLM ⇄ tools
                 └────────────────────────────┘  │     (run_command / http_request /
                                                  │      read_file / write_file /
                   第一个拿到 flag 的 Attempt ────┘      list_dir / submit_flag)
                              │
                              ▼
                 runs/<时间>-<题目>/
                   ├─ attempt-N/transcript.jsonl   # 完整 rollout
                   ├─ attempt-N/result.json
                   ├─ run.json                     # 配置 + 结果
                   └─ summary.md                   # WP 可直接粘的实测记录
```

核心设计点：

1. **多策略并发**：同一道题用不同 temperature + 不同提示偏好并行尝试，先拿到 flag 的胜出（对应"swarm"思路，但不需要多模型）。
2. **工具闭环**：模型只通过函数调用行动，所有输出进 rollout，可复盘、可评分。
3. **可插拔**：换模型只改 `.env`；加工具只改 `tools.py`；换提示只改 `prompts.py`。
4. **WP 友好**：`summary.md` 自动生成「题目/难度/类型/耗时/LLM/评价/Flag/Rollout」。

---

## 2.5 工具链（已装）

Agent 的 `run_command` 跑在 WSL2 Ubuntu 24.04 里，已装好常用 CTF 工具（详见 [TOOLCHAIN.md](./TOOLCHAIN.md)）：

| 类别 | 工具 |
|---|---|
| Web | `nmap` `sqlmap` `ffuf` `gobuster` `wfuzz` `dirsearch` |
| Crypto | `pycryptodome` `gmpy2` `sympy` `z3` `RsaCtfTool` `hashcat` `john` `openssl` `qrencode` |
| Pwn | `pwntools` `gdb`(pwndbg) `ropper` `ROPgadget` `patchelf` `keystone` `unicorn` `angr` |
| Reverse | `radare2` `objdump` `readelf` `capstone` `pyelftools` |
| Misc/取证 | `binwalk` `foremost` `exiftool` `steghide` `zbarimg` `pngcheck` `7z` `tshark` `volatility3` |

```bash
# 体检
wsl bash <APPS>/check_tools.sh
wsl bash <APPS>/smoke_tools.sh
```

---

## 3. 快速开始

### 3.1 环境

- Windows 10/11（推荐装 WSL，工具会自动用 WSL bash；没有 WSL 会回退 PowerShell）
- Python 3.10+（系统 Python 或 DSH 自带 Python 均可）
- 无需 `pip install`

### 3.2 配置模型

复制 `.env.example` 为 `.env`，填 Key：

```env
CTF_AGENT_API_KEY=<REDACTED>
CTF_AGENT_BASE_URL=https://api.deepseek.com
CTF_AGENT_MODEL=deepseek-chat
```

或者直接用环境变量：

```powershell
$env:DEEPSEEK_API_KEY=<REDACTED>"
```

### 3.3 先做离线自测（不需要 Key）

```powershell
cd <DESKTOP>\ctf-agent
python -m ctfagent --mock --name mock-test --target http://example.com
```

看到 `flag : nex{mock_ok_1234}` 即说明工具链/日志都正常。

### 3.4 真实解题

```powershell
python -m ctfagent `
  --name "ezlogin" `
  --type web `
  --difficulty "中等" `
  --target "http://ufje6uak19xs76zz.neu-nex.fun" `
  --hint "考的不是上来就直接爆破" `
  --attempts 3 `
  --max-steps 40
```

带附件的题：

```powershell
python -m ctfagent --name roundabout --type crypto --difficulty 简单 `
  --file "<HOME>\Downloads\attachments\chall.py" `
  --file "<HOME>\Downloads\attachments\output.txt" `
  --attempts 2
```

解出后自动追加到 WP（写进 `第 N 题` 与更新日志）：

```powershell
python -m ctfagent --name "某题" --type web --difficulty 中等 `
  --target "http://..." --wp "<DESKTOP>\rollout\Agent工程师wp.md"
```

### 3.5 端到端自测（本地靶场）

```powershell
# 终端 A：起一个本地小靶场（WSL 里跑）
wsl python3 <DESKTOP>/ctf-agent/tests/local_chall.py

# 终端 B：让 Agent 去打
python -m ctfagent --name local-smoke --type web --difficulty 简单 `
  --target http://127.0.0.1:8899 --attempts 2 --max-steps 25
```

实测：2 路并发均在 4 步、约 6 秒内拿到 `nex{l0c4l_sm0ke_t3st_0k}`。

---

## 4. 参数

| 参数 | 说明 |
|---|---|
| `--name` | 题目名字（写进 summary） |
| `--type` | `web/crypto/misc/pwn/rev/forensics` |
| `--difficulty` | 难度（写进 WP 记录） |
| `--target` | 目标 URL / `nc host port` |
| `--hint` | 题面或提示 |
| `--file` | 附件，可多次指定（复制进工作目录） |
| `--attempts` | 并发策略数，1–4 |
| `--max-steps` | 每路最大轮次（默认 40） |
| `--time-budget` | 每路时间预算秒（默认 1800） |
| `--model` / `--base-url` / `--api-key` | 覆盖 `.env` |
| `--shell` | `auto/wsl/bash/powershell` |
| `--run-dir` | 指定输出目录 |
| `--json` | 只打印 JSON 结果 |

---

## 5. 输出物

每次运行生成 `runs/<时间>-<题目>/`：

- `transcript.jsonl`：逐条记录 LLM 输出、tool_call、tool_result、耗时；
- `result.json`：每个 Attempt 的状态/步数/flag/token；
- `summary.md`：人读版总结 + WP 实测记录；
- `attempt-N/work/`：该次尝试的工作目录（exp、下载的文件都在这里）。

---

## 6. 改造成参赛 Agent 的方向（对应模板 Q4/Q7）

1. **加工具**：在 `tools.py` 里加 `web_search`、`nmap`、`sqlmap` 封装、`binwalk`、`z3`、`sage`、浏览器（Playwright）等；每个工具就是一段 schema + 一个 `_tool_xxx`。
2. **加 Planner**：在 `runner.py` 的循环前加一次"出题面分析 → 生成 3 条攻击路线"的 LLM 调用，再由 Attempt 执行路线（Planner-Executor）。
3. **加记忆**：把 `transcript.jsonl` 压缩成"已知事实/失败尝试"注入下一轮，避免重复踩坑。
4. **加评分器**：对每个 tool_result 做启发式打分（新信息量），低分时强制换策略。
5. **加多模型**：`llm_factory` 返回不同 model 的 `LLMClient`，即 verialabs 的多模型 racing。
6. **加沙箱**：把 `Shell` 换成 Docker / firejail / 远程靶机，隔离更彻底。

这些改动都能在 `summary.md` 的「Agent 评价」和 rollout 里体现，正好对应比赛要求的"设计思路 + 实测效果"。

---

## 7. 安全声明

- 仅在比赛/授权靶场使用；
- `run_command` 会真实执行命令，默认工作目录隔离，但**不要**把 `--target` 指向未授权资产；
- 题目结束后建议清理 `runs/` 下的敏感数据。
