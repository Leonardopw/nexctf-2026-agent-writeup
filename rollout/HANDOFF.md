# 上下文交接 / 提交说明（最终版）

> 生成：2026-10-26 ｜ 状态：**已收尾**。NEXCTF《Agent 工程师》提交包内的 rollout 与总 wp 均以本目录为准。

## 1. 结果概览

- 共解出 **35 题**（`rollout/Agent工程师wp.md` 第 1–35 题），另有 1 个参考目录 `web-shiro-bypass/`（路径归一化绕过，未计入编号）。
- 题型覆盖：Web（上传/注入/Shiro/SSRF/沙箱等）、Pwn（栈/堆/FSOP/ORW）、Crypto（RSA/格/PRNG）、Misc（编码/压缩包）、Reverse（PE+pyarmor/ELF/自定义校验）。
- 每题目录包含：`record.md`（11 项记录）、`findings.json`、`notes.md`、`exp.py`（或 `solve.py`/`exploit.py`）、`evidence/`。
- 汇总与最终实测效果：`rollout/Agent工程师wp.md`；进度表：`rollout/进度表.md`。

## 2. Agent 与底座

- **主 Agent（本次 35 题实际解题）：DSH-Pentest** = DeepSeek Harness（DSH）通用 coding agent + 渗透特化层；特化层源码在提交包 `agent/dsh-pentest-layer/`（`AGENTS.md`、`.mcp.json`、`pentest/` CLI/MCP/skills、rollout 工具）。
- DSH 运行时负责工具循环、上下文压缩、会话/rollout 持久化与 skill 路由，本次以 `deepseek-flash` 驱动；运行时为打包发布（`<LOCAL_PATH> `chat/` 完整会话可复现。
- **独立自研 Agent：ctfagent**（`agent/ctfagent/`）为 2026-10-24 同期从零实现的轻量 CTF Agent（纯标准库、OpenAI 兼容、多策略并发 + ReAct + transcript），**未用于这 35 题**，作为同周期实现一并提交。

## 3. 目录说明

```
rollout/
├── Agent工程师wp.md        # 设计思路 Q1–Q7 + 35 题实测（提交主文档）
├── 进度表.md               # 由 wp 自动生成
├── HANDOFF.md              # 本文件
└── <每题目录>/             # record / findings / notes / exp / evidence
```

- 未解出的尝试目录已按用户要求删除，不在提交包内。
- flag 均来自回显原文 + 正则校验（`flag{}` / `nex{}` / `FLAG{}` / `NEX{}`，大小写照抄）。

## 4. 工具链

`pentest/` 提供 recon / http / bypass / keyprobe / skill / report 与 MCP 服务；`agent/dsh-pentest-layer/` 是主 Agent（DSH-Pentest）的渗透特化层源码，`agent/ctfagent/` 是同期独立自研 Agent。提交包根目录的 `DSH-Pentest.exe` 是轻量启动器（校验/部署层 + 启动 DSH，源码在 `agent/dsh-pentest-launcher/`）。完整环境与工具清单见 `agent/ctfagent/TOOLCHAIN.md`。
