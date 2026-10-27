# PwnAgent

**PwnAgent = PwnProof 的 proof-gated pwn 内核 + ctf-agent 的多策略并发/反思/压缩 + ctf-tools 的 GEF 调试能力 + 新增的确定性 pwn 工具链。**

面向授权 CTF / 本地靶场：先做确定性 triage，再按 playbook 并行发起多个 attempt；每个 attempt 先跑确定性 fast path（ret2win / ret2libc / fmtstr probe），失败后才进入模型 ReAct；只有拿到 flag、shell UID 或显式成功标记才算成功。

> 仅用于授权的 CTF 比赛、靶场或自有二进制。远程目标必须显式传 `--host/--port`。

---

## 1. 为什么是“整合”，而不是又一个 wrapper

| 来源 | 复用了什么 | PwnAgent 的增量 |
|---|---|---|
| **PwnProof** (`Desktop/pwnproof`) | 确定性 triage、evidence ledger、proof gate、失败分类、ret2win/fmtstr/ret2libc fast path、libc/heap 事实、`run_exploit` | 多 attempt 并发、策略规划、32 位 ret2libc、offset/libc_match/rop_plan/fmtstr_plan/heap_plan/seccomp/debug/disasm、每 attempt 独立工作区、统一 run summary |
| **ctf-agent** (`Desktop/ctf-agent`) | 多 attempt 线程、planner/reflection/上下文压缩、OpenAI 兼容客户端重试、run 目录与 summary 习惯 | 从“通用 Web/Pwn 工具”改为 pwn-first：triage 结果直接进入 prompt，工具面收敛到 ELF/栈/堆/格式化串，避免 Web 工具干扰 |
| **ctf-tools** (`Desktop/ctf-tools`) | `gef.py`（GDB 增强）；`RsaCtfTool` 作为 hybrid 题的可选外部命令 | debug 工具自动加载 GEF；不复制 GPL 工具，只通过 `run_command` 调用 |

核心不是“让模型自由发挥”，而是**把 pwn 里最容易错的确定性计算从模型手里拿走**：偏移、libc base、gadget、fmtstr 参数下标、tcache/safe-linking、seccomp 允许表。模型只负责把这些结果拼成 exploit 并处理协议/交互。

---

## 2. 架构

```
challenge binary
      │
      ▼
┌─────────────────────┐
│  triage (PwnProof)  │  file/readelf/checksec/objdump/strings
│  + libc candidates  │  → protections, symbols, imports, strings, hypotheses
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ planner (PwnAgent)  │  hypotheses → ranked playbooks
│ ret2win/ret2libc/   │  → 1..N diverse strategies
│ fmtstr/heap/orw/rop │
└─────────┬───────────┘
          ▼
   parallel attempts (threads, first proof wins)
          │
          ├─ copy challenge → attempt-N/work（隔离，不带 exploits/）
          ├─ deterministic fast path（按策略只跑对应生成器）
          └─ ReAct loop
                tools:
                offset / libc_info / libc_match / one_gadget
                rop_plan / fmtstr_plan / heap_plan / seccomp
                debug (GEF) / disasm / gadgets / symbols
                run_exploit / run_command / read/write / ledger
                      │
                      ▼
                proof gate: flag regex / shell UID / success regex
                      │
                      ▼
             summary.md + per-attempt rollout.jsonl/triage.json/evidence.jsonl
```

### 策略

| playbook | 适用 | 确定性 fast path |
|---|---|---|
| `ret2win` | 非 PIE + win 符号 + 栈溢出 | 有（PwnProof） |
| `ret2libc` | NX + 栈溢出 + 可泄露 GOT | 有（64 位 PwnProof，新增 32 位 cdecl） |
| `fmtstr` | 用户可控 format | 有 leak probe（不做自动写） |
| `heap` | malloc/free/UAF/tcache | 无；靠 `heap_plan` + 模型 |
| `orw` | seccomp/prctl | 无；靠 `seccomp` + `rop_plan` |
| `rop` | NX 栈控制、gadget 链 | 无；靠 `gadgets`/`rop_plan` |
| `manual` | 无高置信假设 | 无；靠 `debug`/`disasm` |

---

## 3. 快速开始

```powershell
cd <DESKTOP>\Pwn_agent

# 单文件版（构建产物）
python .\dist\pwnagent.pyz --version
# 或：.\pwnagent.cmd doctor

# 1) 工具链体检（WSL 里的 gdb/pwntools/ROPgadget/one_gadget/seccomp-tools/GEF）
python -m pwnagent doctor

# 2) 只做 triage，不跑模型
python -m pwnagent triage <LOCAL_PATH> --workspace <LOCAL_PATH>

# 3) 只跑确定性 fast path（不需要 API key）
python -m pwnagent heuristic <LOCAL_PATH> `
  --workspace <LOCAL_PATH> --source <LOCAL_PATH> `
  --local-flag "NEXCTF{local_test}"

# 4) 多 attempt 完整 agent（需要 API key）
$env:PWN_AGENT_API_KEY=<REDACTED>"
$env:PWN_AGENT_BASE_URL = "https://api.deepseek.com/v1"
$env:PWN_AGENT_MODEL = "deepseek-chat"
python -m pwnagent solve <LOCAL_PATH> `
  --workspace <LOCAL_PATH> --source <LOCAL_PATH> `
  --attempts 3 --max-steps 18 --local-flag "NEXCTF{local_test}"

# 5) 确定性基准（本地 examples）
python -m pwnagent bench --dir .\examples --limit 3
```

远程：

```powershell
python -m pwnagent solve .\chall --host 10.0.0.10 --port 31337 --attempts 3
```

### 环境变量

| 变量 | 作用 |
|---|---|
| `PWN_AGENT_API_KEY` / `PWNPILOT_API_KEY` / `DEEPSEEK_API_KEY` | OpenAI 兼容 API key |
| `PWN_AGENT_BASE_URL` / `PWNPILOT_BASE_URL` / `DEEPSEEK_BASE_URL` | 默认按 profile；DeepSeek 为 `https://api.deepseek.com` |
| `PWN_AGENT_MODEL` / `PWNPILOT_MODEL` | 显式覆盖；否则跟随当前 DSH 模型 → `.env` → 兜底 `deepseek-chat` |
| `PWN_AGENT_GEF` | GEF 脚本路径；默认找 `Desktop/ctf-tools/gef.py` |
| `PWNPROOF_LIBC` | 比赛中匹配 libc 的显式路径（兼容 PwnProof） |

### 模型是动态的（会跟随你当前使用的模型）

解析优先级：

1. 命令行 `--model` / `--base-url`
2. `PWN_AGENT_MODEL` / `PWN_AGENT_BASE_URL`（显式）
3. `PWN_AGENT_PROFILE`（`deepseek`、`deepseek-flash`、`deepseek-reasoner`、`glm`、`glm-flash`、`openai`）
4. PwnAgent 保存的 active profile（`%LOCALAPPDATA%\PwnAgent\model.json`）
5. **当前 DSH 会话的 `request/context` 模型 + provider**（自动读取最新会话）
6. ctf-agent `.env` 的 `CTF_AGENT_MODEL` / `CTF_AGENT_BASE_URL`
7. 兜底 `deepseek-chat`

```powershell
python -m pwnagent model current          # 当前实际使用的 model/base/profile（不打印 key）
python -m pwnagent model list             # 内置 profile
python -m pwnagent model use deepseek-flash
python -m pwnagent model detect --write   # 读取当前 DSH 模型并保存
```

切到 GLM 时，DSH 检测到 `zai/glm-*` 会使用 Z.ai 的 base；需要本机有 `ZAI_API_KEY` 或 `GLM_API_KEY`，否则 `model current` 会给出 warning，确定性 fast path 仍可用。

### 运行时

- Windows + WSL2 Ubuntu（默认）；所有 ELF/GDB/pwntools 命令通过 `wsl.exe -d Ubuntu -- bash -lc` 执行。
- 也可在 Linux 原生运行：`--runtime native`。
- Python 3.10+；PwnAgent 本体只用标准库，pwntools/ROPgadget/one_gadget/seccomp-tools 由 WSL 提供。

---

## 4. 实测与基准

本机（WSL2 Ubuntu 24.04，pwntools 4.15，gdb + pwndbg + GEF）：

| 用例 | 结果 | 耗时 |
|---|---|---|
| `examples/ret2win`（64 位） | 确定性 ret2win 拿到本地 flag | ~1.3 s |
| `examples/ret2libc`（64 位） | puts@GOT 泄露 → libc base → system，拿到 flag | ~7.2 s |
| `examples/format-string` | leak probe 正常（无 flag，符合预期） | ~1.1 s |
| `tests/`（13 项） | 全部通过 | ~7 s |

确定性路径不调用模型；耗时主要来自 triage 的 readelf/objdump + 一次 exploit 运行。

---

## 5. 目录

```
Pwn_agent/
├── pwnagent/
│   ├── agent.py        # 多 attempt 编排 + proof-gated ReAct
│   ├── planner.py      # hypotheses → 策略
│   ├── tools.py        # 工具 schema + EnhancedToolbox
│   ├── pwn_tools.py    # offset/libc/rop/fmtstr/heap/seccomp/debug/disasm
│   ├── heuristics.py   # 64/32 位 ret2libc、ret2win、fmtstr fast path
│   ├── prompts.py      # pwn 专用 system/initial/reflection
│   ├── config.py       # 扩展 PwnProof + ctf-agent 配置
│   ├── cli.py          # doctor/triage/solve/heuristic/bench/replay
│   └── vendor/pwnproof # 复用 PwnProof 内核（MIT）
├── tests/              # unittest，13 项
├── scripts/            # smoke_tools.py / build_pyz.py
├── docs/               # ARCHITECTURE / INTEGRATION / PLAYBOOKS
├── pyproject.toml
└── README.md
```

## 6. 边界与已知限制

- 模型路径仍是**非确定性**的；相同提示不保证完全相同的步骤，但确定性 fast path 可复现。
- 堆/FSOP 的 `heap_plan` 提供版本化字段与不变量，不自动完成完整利用链；复杂堆题仍需要模型 + 人工判断。
- `one_gadget` 约束、`seccomp` 结果依赖本机工具版本；工具缺失时会降级并明确标注。
- `ctf-tools/RsaCtfTool` 未复制（GPL），仅作为 hybrid 题的外部命令；`gef.py` 通过路径加载，不随包分发。
- 远程测试必须显式提供 host/port；PwnAgent 不会主动扫描网络。
