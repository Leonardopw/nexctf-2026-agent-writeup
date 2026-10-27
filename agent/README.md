# Agent 源码说明（提交包 `agent/`）

本目录包含两套 Agent：

## 1. `dsh-pentest-layer/` —— 本次 35 题实际解题 Agent 的自定义源码

**DSH-Pentest** = **DeepSeek Harness（DSH）** 通用 coding agent 运行时 + 本目录的**渗透特化层**。

- DSH 底座负责：LLM 循环、工具调用（pwsh/read/write/grep/glob/job/subagent/workflow）、上下文压缩、会话与 rollout 持久化、skill 路由。
- 渗透特化层（本目录，唯一自定义部分）负责：`AGENTS.md` 渗透画像与 8 步 kill chain、`pentestctl` CLI、MCP server、`skills/` playbook、`report` / 进度表等 rollout 工具、flag 正则与证据规范。
- 本次 NEXCTF 的 35 题 rollout（`../rollout/`）与完整会话（`../chat/`）都由这套 Agent 实际执行产生。

> **为什么只提交这一层**：DSH 运行时是打包发布的（本机为 `<LOCAL_PATH> 182 MB，非开源、不可再分发），无法随包提交源码；对“做题 Agent”而言，所有自行编写、可复现的部分都在这个渗透特化层里。运行时版本、模型配置（deepseek-flash / reasoningEffort low）与工具边界见 `RUNTIME.md`；配合 DSH 运行时和 `../chat/` 的完整会话，可以逐题复现执行过程。

## 2. `ctfagent/` —— 同期从零自研的独立 CTF Agent（未用于本次 35 题）

2026-10-24 同期按“轻量、零第三方依赖、OpenAI 兼容”的目标从零实现的独立 Agent，参考了 verialabs/ctf-agent 的“多策略并发、先到先得”思路：

- 纯标准库（Python 3.10+），不依赖 Docker / 任何 SDK
- 4 路 attempt 并发（不同 temperature + 不同策略提示）
- 工具：`run_command`、`http_request`、`read_file` / `write_file` / `list_dir`、`lookup`、`submit_flag`
- 每题产出 `transcript.jsonl` + `summary.md`，可直接粘进 wp
- 运行：`cd ctfagent && python -m ctfagent --mock ...`（详见其 `README.md`）

它**没有参与本次 NEXCTF 的 35 题**，作为同周期独立实现一并提交，供对照评审。

## 3. 可执行文件：`DSH-Pentest.exe`（轻量启动器 / 方案一）

提交包根目录的 `DSH-Pentest.exe` 是主 Agent 的一键启动器：

- 双击后自动校验/部署渗透层（`AGENTS.md`、`.mcp.json`、`pentest/`）到工作区（默认 `<WORKSPACE>`，会记忆上次选择），差异文件先备份再覆盖；
- 自动改写 `.mcp.json` 的 `python` 与 `mcp_server.py` 路径；
- 以工作区为 `cwd` 启动已安装的 DeepSeek Harness（默认 `<LOCAL_PATH> Harness.exe`，可用 `--dsh-exe` / `DSH_EXE` 覆盖）；
- 源码与构建脚本：`agent/dsh-pentest-launcher/`（`DSH-Pentest.cs` + `build.ps1` + README）。

> 方案一是“轻量启动器”，**不打包 DSH 本体**；因此需要本机已安装 DSH。若需要完全自包含，需要把 DSH 安装目录一起分发（体积约 500 MB，且涉及第三方许可），未采用。

## 目录

```
agent/
├── README.md                 # 本文件
├── RUNTIME.md                # DSH 运行时版本、模型配置与工具边界
├── dsh-pentest-layer/        # 主 Agent（DSH-Pentest）的渗透特化层源码
│   ├── README.md
│   ├── AGENTS.md             # 渗透画像 / kill chain / 硬规则
│   ├── .mcp.json             # MCP 注册（pentest server）
│   ├── pentest/              # CLI + MCP + skills + selftest
│   └── rollout-tools/        # show_table.py 等 rollout 工具
├── dsh-pentest-launcher/     # DSH-Pentest.exe 启动器源码 + build.ps1
│   ├── DSH-Pentest.cs
│   ├── build.ps1
│   └── README.md
└── ctfagent/                 # 独立自研 Agent（未用于本次 35 题）
    ├── README.md
    ├── TOOLCHAIN.md
    ├── .env.example
    ├── ctfagent/
    └── tests/
```
