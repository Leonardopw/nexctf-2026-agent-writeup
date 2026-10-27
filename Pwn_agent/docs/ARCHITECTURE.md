# Architecture

## 1. 数据流

1. `PwnAgent.run()` 在原始 workspace 上做一次 `triage`，得到 `BinaryFacts`。
2. `planner.plan_strategies()` 把 hypotheses 映射成 1..N 个 `Strategy`，按置信度排序并做多样性补齐。
3. 每个 `PwnAttempt` 是一个线程：
   - 复制 challenge 目录到 `run/attempt-N/work`，排除 `exploits/`、`artifacts/`、`.git`；
   - 在该隔离工作区重新 triage（路径/相对 libc 都正确）；
   - 按策略跑唯一对应的 deterministic fast path；
   - 失败后进入 ReAct：`ModelClient.complete(messages, TOOL_SCHEMAS)`；
   - 工具结果回灌；`run_exploit` 的结果由 `ProofGate` 分类（success/crash/heap_integrity/...）；
   - 失败时追加 failure-focus，每 5 步追加 reflection；上下文超过 30 条做压缩（保留 head + ledger + tail）。
4. 第一个拿到 proof 的 attempt 设置 `stop_event`；其余线程在下一步边界退出。
5. 汇总写 `summary.md` + `run.json`；每个 attempt 写 `triage.json`、`evidence.jsonl`、`rollout.jsonl`、`summary.json`、`exploits/`。

## 2. 模块职责

| 模块 | 职责 |
|---|---|
| `config.py` | `PwnAgentConfig`：路径、模型、attempts、time budget、libc、gef、artifact |
| `planner.py` | `Strategy`、`available_playbooks()`、`plan_strategies()` |
| `prompts.py` | system prompt、strategy 特化、initial message、proof/reflection/compaction |
| `tools.py` | `TOOL_SCHEMAS`（PwnProof 基础工具 + 10 个新工具）、`PwnToolbox` |
| `pwn_tools.py` | 确定性 pwn 算法：cyclic/offset、libc、ROP、fmtstr、heap、seccomp、GDB、disasm |
| `heuristics.py` | ret2win、fmtstr probe、64/32 位 ret2libc 生成器 |
| `agent.py` | `PwnAgent`、`PwnAttempt`、`RolloutWriter`、summary |
| `cli.py` | doctor/triage/solve/heuristic/bench/replay |
| `vendor/pwnproof` | triage、runtime、ledger、proof、libc、heuristics 基础 |

## 3. 工具设计原则

- **确定性优先**：能算的（偏移、base、gadget、下标、chunk）不让模型猜。
- **结果有界**：所有工具输出截断到 22k 字符；GDB/objdump 只回 tail。
- **路径安全**：所有文件操作限制在 attempt workspace；`run_command` 有危险命令黑名单。
- **证明门**：`ProofGate` 只认 flag 正则、shell UID/GID、显式 success regex；crash/no_proof 不算成功。
- **可审计**：每个 attempt 的模型消息、工具参数/结果、exploit 文件都落盘。

## 4. 为什么每个 attempt 复制工作区

- 并发 attempt 不能互相覆盖 `exploits/`、`.pwnagent/pattern.bin`、GDB 脚本。
- 复制时排除 `exploits/`，避免模型直接读到历史题解。
- libc/source 的相对路径在副本中仍成立；`PwnAgentConfig` 的 `libc` 会映射到副本。

## 5. 失败分类与下一动作

`ProofGate.inspect()` 分类：
`success` / `io_desync_or_hang` / `crash` / `heap_integrity` / `target_exited` / `missing_dependency` / `no_proof`。

`next_actions` 由 PwnProof 提供，PwnAgent 在失败后把分类和 next_actions 回灌，避免“无变化重跑”。

## 6. 扩展点

- 新 playbook：在 `planner.PROMPTS` 加条目，在 `planner.available_playbooks` 加触发条件。
- 新工具：在 `pwn_tools.py` 实现函数，在 `tools.EXTRA_SCHEMAS` 加 schema，在 `PwnToolbox.dispatch` 注册。
- 新 fast path：在 `heuristics.py` 加生成器，在 `generate_candidate`/`generate_for_strategy` 注册。
- 新 runtime：实现 `LinuxRuntime` 兼容接口，或在 `config.runtime` 增加模式。
