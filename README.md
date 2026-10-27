# NEXCTF 2026 · Agent 工程师 Writeup

**学号 / 姓名**：20251456 / 王奕贺  
**主 Agent**：DSH-Pentest（DeepSeek Harness + 渗透特化层）  
**底座模型**：deepseek-flash  
**最终成绩**：NEXCTF 35 题（Web / Pwn / Crypto / Misc / Reverse）  
**最终 PDF**：[`Agent工程师wp.pdf`](Agent工程师wp.pdf)（21 页，35 个 flag）

> 本仓库用于开源复盘：完整 writeup、DSH 会话 rollout、35 题记录、Agent 源码与赛后整合的 PwnAgent。

---

## 目录

```
.
├── Agent工程师wp.pdf          # 最终提交 PDF
├── Agent工程师wp.md           # PDF 源文件
├── README.md
├── LICENSE
├── THIRD_PARTY_NOTICES.md
├── agent/
│   ├── dsh-pentest-layer/     # AGENTS.md / .mcp.json / pentest CLI+MCP+SKILL
│   ├── dsh-pentest-launcher/  # DSH-Pentest.exe 的 C# 源码与构建脚本
│   └── ctfagent/              # 同期独立自研 CTF Agent（未用于这 35 题）
├── rollout/
│   ├── sessions/              # DSH 完整会话 JSONL（已脱敏）
│   │   ├── INDEX.md
│   │   └── rollout-时间戳-*.jsonl
│   ├── <题目>/                # 35 题 record.md / findings.json / notes.md / exp.py / evidence/
│   ├── 进度表.md
│   └── HANDOFF.md
├── Pwn_agent/                 # 赛后整合：PwnProof + ctf-agent + ctf-tools
└── DSH-Pentest.exe            # 渗透层部署/启动器
```

## Rollout

`rollout/sessions/` 是 DSH 会话导出，每局一个 `rollout-YYYYMMDD-HHMMSS-*.jsonl`，对应关系见 [`rollout/sessions/INDEX.md`](rollout/sessions/INDEX.md)。

脱敏与体积处理：

- 本机绝对路径（`C:\Users\...`、`E:\harmony`、`/mnt/...`）替换为 `<HOME>` / `<WORKSPACE>` / `<LOCAL_PATH>`；
- API key、Bearer token、邮箱替换为 `<REDACTED>` / `<EMAIL>`；
- 超过 1200 字符的工具输出做 head/tail 截断，保留事件、工具调用与关键输出结构；
- 未包含与做题无关的私人会话。

## 复现

### 1. 单题记录

```bash
cd rollout/<题目>
python exp.py        # 或 solve.py / exploit.py
```

本地附件题直接跑；远程题需靶机在线，部分赛后已下线/重置，无法无条件重放。

### 2. Agent 级

- `DSH-Pentest.exe`：将 `agent/dsh-pentest-layer/` 部署到工作区，改写 `.mcp.json`，再以工作区为 `cwd` 启动本机 DSH。
- 详细说明见 `agent/dsh-pentest-layer/README.md`、`agent/RUNTIME.md`。
- 模型为非确定性，按 `record.md` / `rollout/sessions/` 重跑不保证逐步一致。

### 3. PwnAgent

```bash
cd Pwn_agent
python -m pwnagent doctor
python -m pwnagent heuristic examples/ret2win/chall \
  --workspace examples/ret2win --source examples/ret2win/chall.c \
  --local-flag "NEXCTF{demo}"
python -m pwnagent solve examples/ret2libc/chall \
  --workspace examples/ret2libc --source examples/ret2libc/chall.c \
  --attempts 3 --local-flag "NEXCTF{demo}"
```

PwnAgent 将 PwnProof 的 proof gate/triage/确定性 fast path、ctf-agent 的多 attempt/反思/压缩、ctf-tools 的 GEF 调试整合为 pwn-first agent；详见 `Pwn_agent/README.md`。

## 安全与边界

- 所有 Web/Pwn 测试仅针对 NEXCTF 授权靶场；仓库不含密钥、Token、个人邮箱或本机绝对路径。
- `DSH-Pentest.exe` 只是部署/启动器，不包含、不重分发第三方 DSH 运行时。
- 仓库中的 exploit 仅用于比赛复盘与授权靶场，请勿用于未授权目标。

## License

本仓库自有代码与文档采用 MIT License，见 [`LICENSE`](LICENSE)。  
第三方组件与工具许可见 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)。
