# 主 Agent 运行时（DSH）说明

## 版本与位置

- 运行时：**DeepSeek Harness（DSH）**，本机打包路径 `<LOCAL_PATH> 182 MB，Electron asar 包，非开源）。
- 本提交包不包含该运行时（不可再分发、体积大）；只包含其**自定义渗透特化层**（`agent/dsh-pentest-layer/`）与完整会话（`chat/`）。

## 模型配置

来自 DSH 的本机配置（`settings.yaml.imported`，仅列非敏感项）：

```yaml
agent-default-model:
  provider: deepseek-official
  model: deepseek-flash
  reasoningEffort: low
```

即 35 题 rollout 的实际底座为 **deepseek-flash**（reasoning effort: low）。

## 一键启动器

提交包根目录的 `DSH-Pentest.exe`（方案一，源码在 `agent/dsh-pentest-launcher/`）负责：定位渗透层 → 校验/部署到工作区 → 改写 MCP 的 Python/脚本路径 → 以工作区为 `cwd` 启动本机 DSH。它**不包含 DSH 本体**，依赖 `<LOCAL_PATH> Harness.exe`（可用 `--dsh-exe` / `DSH_EXE` 覆盖）。

## DSH 提供、本层依赖的能力

- 工具循环与工具集：`pwsh`（WSL bash / PowerShell）、`read` / `write` / `edit` / `grep` / `glob`、后台 job（`job_list` / `job_output` / `job_kill`）
- 并发与编排：`subagent` / `subagent_fork` / `workflow`、`todo_write`
- 上下文与会话：自动压缩、`session.v4.jsonl.zstd` 会话落盘（`chat/raw/` 即原始格式）
- 技能：`skill` 加载 ctf / ctf-web / ctf-pwn / ctf-crypto / ctf-reverse / ctf-misc / ctf-forensics / ctf-osint / ctf-malware / ctf-ai-ml / ctf-similar-search / ctf-writeup / solve-challenge
- 外部接入：MCP（本层通过 `.mcp.json` 注册 `pentest` server）、`web_search` / `web_fetch`

## 本层与运行时的边界

| 层 | 是否随包提交 | 说明 |
|---|---|---|
| DSH 运行时（LLM loop、工具执行、压缩、会话、skill 路由） | 否 | 打包发布，非开源；提供路径与配置供复现 |
| 渗透特化层（AGENTS.md、pentest CLI/MCP/skills、rollout 规范） | 是（`agent/dsh-pentest-layer/`） | 本次唯一自行编写、可复现的部分 |
| 完整会话/rollout | 是（`chat/`、`rollout/`） | 逐题执行证据 |

> 用相同 DSH 运行时 + 本层源码 + 相同工作区（`AGENTS.md`、`.mcp.json`、`pentest/`）+ 相同的 `deepseek-flash` 配置，可复现 35 题的解题过程。
