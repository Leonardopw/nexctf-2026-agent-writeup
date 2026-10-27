# Integration notes

## 1. PwnProof → PwnAgent

| PwnProof 文件/能力 | 在 PwnAgent 中的位置 | 改动 |
|---|---|---|
| `triage.py` | `vendor/pwnproof/triage.py`，原样复用 | 无 |
| `libc.py` | `vendor/pwnproof/libc.py` + `pwn_tools.libc_offsets` | 新增按 leak 解析 base、`/bin/sh`、hook、one_gadget |
| `runtime.py` | `vendor/pwnproof/runtime.py` | 无 |
| `ledger.py` | `vendor/pwnproof/ledger.py` | 无 |
| `tools.py` 的 `ProofGate`/`Toolbox` | `vendored` + `PwnToolbox` 继承 | 新增 10 个 pwn 工具；基础工具保留 |
| `heuristics.py` | `vendor/.../heuristics.py` | 新增 32 位 ret2libc 生成器、按策略筛选 |
| `agent.py` 单 attempt 循环 | 重写为 `PwnAttempt` + `PwnAgent` | 多 attempt、每 attempt 工作区、reflection/compaction |
| `model.py` | 复用 | 无（OpenAI 兼容 + 重试） |
| `prompt.py` | 复用 failure-focus | 新 system/initial/strategy prompt |

**保留的 PwnProof 优点**：proof gate、evidence ledger、triage-first、失败分类、libc/heap 事实、确定性 ret2win/fmtstr/ret2libc（64 位）。

## 2. ctf-agent → PwnAgent

| ctf-agent 能力 | 在 PwnAgent 中的位置 | 改动 |
|---|---|---|
| `runner.py` 多 attempt 线程 | `agent.PwnAgent.run()` | 策略由 triage 生成，不再用固定 4 种通用提示 |
| 失败反思 / 上下文压缩 | `agent._compact`、`prompts.reflection_message` | 压缩保留 ledger；反思每 5 步 |
| `llm.py` 重试 | 由 PwnProof `ModelClient` 承担 | 同样 OpenAI 兼容、429/5xx 重试 |
| run 目录/summary | `agent._write_summary` | 每 attempt 独立 summary，总 run 汇总 |
| `tools.py` 通用工具 | 只保留对 pwn 有用部分 | `run_command`/`read`/`write`/`run_exploit`；去掉 Web 工具 |

**没有照搬**：ctf-agent 的 Web 专用工具（http_request、lookup web 知识库）不会进入 PwnAgent 的工具面，避免模型在 pwn 题里被无关工具分散。

## 3. ctf-tools → PwnAgent

| 资源 | 用法 | 说明 |
|---|---|---|
| `gef.py` | `debug` 工具在 GDB 脚本里 `source <gef>` | 默认路径 `Desktop/ctf-tools/gef.py`；可用 `PWN_AGENT_GEF` 覆盖 |
| `RsaCtfTool` | 不直接集成 | Pwn 主链路不需要；hybrid 题可通过 `run_command` 调用，且不复制 GPL 代码 |

## 4. 与 PwnProof 的兼容性

- 环境变量 `PWNPROOF_LIBC`、`PWNPROOF_FLAG` 仍可用。
- `pwnproof` 的 proof regex、local flag 注入、artifact 布局保持兼容。
- 旧 `pwnproof` 命令仍可独立运行；PwnAgent 不修改原项目。

## 5. 新增的确定性能力（相对两者）

| 能力 | 工具 | 解决什么问题 |
|---|---|---|
| 偏移 | `offset` | cyclic + GDB 读 `$rsp`/`$rip`，避免手算/猜 |
| libc 解析 | `libc_info` / `libc_match` | 一次拿到 release、symbols、`/bin/sh`、hooks、one_gadget；校验 base 页对齐 |
| ROP/ORW | `rop_plan` | 生成带真实 gadget 偏移的代码片段 |
| fmtstr | `fmtstr_plan` | 生成 leak/write payload 代码，避免下标算错 |
| 堆 | `heap_plan` | 2.39/2.43 tcache/safe-linking/FSOP 字段与公式 |
| seccomp | `seccomp` | 判断 execve 是否可用，决定 ORW |
| 调试 | `debug` | GEF 批量 GDB，回传寄存器/bt/栈 |
| 反汇编 | `disasm` | 只看关键函数/地址范围，省上下文 |
