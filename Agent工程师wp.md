# Agent 工程师 Writeup

> 依据《Agent 工程师 wp 模板》整理。
> **学号 / 姓名**：20251456 / 王奕贺
> **Rollout 包**：`20251456-王奕贺-做题记录.zip`（完整会话 `rollout-时间戳-*.jsonl` + 35 题记录 + PwnAgent 项目）
> **提交方式**：已按要求打包，收件人 `jiaxingli342@gmail.com`（手动发送）。
> **GitHub 仓库**：`https://github.com/Leonardopw/nexctf-2026-agent-writeup`（本地仓库已初始化并首次提交）。
> **脱敏**：已移除本机绝对路径、API key、邮箱等；会话中的超长工具输出截断到 1200 字符。
> 说明：Q1–Q7 为参赛者本人作答区（模板要求「禁止 AI 代替大脑」）。
> 本次 NEXCTF 实际解题的 Agent 是 **DSH-Pentest**：运行时为 **DeepSeek Harness（DSH）** 通用 coding agent，外加本仓库的**渗透特化层**（`AGENTS.md` 渗透画像 + `pentest/` CLI/MCP/SKILL + rollout 证据规范）。同期还从零自研了独立 CTF Agent **ctfagent**（见 Q7 与提交包 `agent/ctfagent/`），未用于这 35 题，作为同周期独立实现一并提交。

---

## 一、设计思路（模板 Q1–Q7）

### Q1：Agent 名字？

**DSH-Pentest**（DeepSeek Harness + 渗透特化层；特化层源码在提交包 `agent/dsh-pentest-layer/`）

### Q2：基于什么设计的 Agent？（不超过 50 字）

基于 DSH 通用 coding agent，外挂渗透画像、pentest CLI/MCP/SKILL 与 rollout 证据规范。

### Q3：参考了哪些内容？

**工业界 Agent 参考列表**

| # | Agent 名字 | GitHub / 开源链接 | 参考了哪一部分（≤100 字） | 我做了哪些改进（≤100 字） |
| - | ---------- | ----------------- | ------------------------- | ------------------------- |
| 1 | SWE-agent | https://github.com/princeton-nlp/SWE-agent | 参考 Agent-Computer Interface：把 shell、文件封装成结构化工具，模型只输出工具调用 | 用 DSH 的结构化工具层（pwsh/read/write/grep/glob/job/subagent），再统一 flag 校验与证据落盘 |
| 2 | EnIGMA | https://github.com/amazon-science/EnIGMA | 参考用交互式工具（shell、调试器）辅助漏洞挖掘，工具结果作为观察回灌 | 做了 `pentestctl` recon/http/bypass/keyprobe 与证据文件规范，把“工具输出即观察”固化成可复盘记录 |
| 3 | PentestGPT | https://github.com/GreyDGL/PentestGPT | 参考渗透任务的分解与状态跟踪，先列子任务再逐步验证 | 用 `AGENTS.md` 的 8 步 kill chain + 每题 `record.md` 11 项 + 进度表替代固定任务树 |
| 4 | verialabs/ctf-agent | https://github.com/verialabs/ctf-agent | 参考“多策略竞速、先拿到 flag 的 attempt 胜出”的思路（用于同期独立 Agent ctfagent） | 重写为纯标准库、OpenAI 兼容接口，4 路 attempt 并发 + transcript/summary；未用于本次 35 题 |

**学术界论文参考列表**

| # | 论文名字 | PDF 直链（必须是 PDF 直链） | 会议 / 期刊（优先顶会顶刊） | 发表年月日 | 参考了哪一部分（≤100 字） |
| - | -------- | --------------------------- | --------------------------- | ---------- | ------------------------- |
| 1 | ReAct: Synergizing Reasoning and Acting in Language Models | https://arxiv.org/pdf/2210.03629.pdf | ICLR 2023 | 2022-10-06 | 参考 Reasoning 与 Acting 交替的 tool-use 循环，工具结果作为 observation 回灌；DSH 原生 loop 即以此为基础 |
| 2 | Reflexion: Language Agents with Verbal Reinforcement Learning | https://arxiv.org/pdf/2303.11366.pdf | NeurIPS 2023 | 2023-03-20 | 参考失败后用语言复盘并调整策略；每题结束把排除理由写进 `notes.md`，下一题先查历史记录 |
| 3 | EnIGMA: Interactive Tools Substantially Assist LM Agents in Finding Security Vulnerabilities | https://arxiv.org/pdf/2409.16165.pdf | arXiv preprint | 2024-09-24 | 参考交互式工具提升安全任务表现，以及“工具输出即观察”的循环设计 |
| 4 | Plan-and-Solve Prompting: Improving Zero-Shot Chain-of-Thought Reasoning | https://arxiv.org/pdf/2305.04091.pdf | ACL 2023 | 2023-05-06 | 参考先规划再执行；把 Scope→Recon→Attack Surface→Hypothesis→Exploit→Verify→Evidence→Report 写成硬流程 |

### Q4：请用一张图描述你的 Agent「核心」架构

> 核心不是常规 ReAct loop，而是「DSH 工具运行时 + 渗透特化层 + 证据链闭环」：上面是 DSH 底座，中间是本仓库真正的增量，下面按题型分派。

```
                    题目（名称/类型/目标/提示/附件）
                              │
                              ▼
              ┌───────────────────────────────┐
              │        DSH Runtime            │  DeepSeek Harness
              │  pwsh/read/write/edit/grep    │  工具层 + 会话持久化
              │  job_*/subagent/workflow      │  + 上下文压缩 + skill 路由
              └───────────────┬───────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │   渗透特化层（本仓库增量）     │
              │  AGENTS.md：8 步 kill chain   │  Scope→Recon→Surface→
              │  pentestctl：recon/http/      │  Hypothesis→Exploit→Verify→
              │    bypass/keyprobe/skill/     │  Evidence→Report
              │    report                     │
              │  MCP：同 5 个能力             │  skills：recon/shiro/
              │  rollout：newcase→record.md   │  ssrf/report
              │    →findings.json→进度表      │
              └───────────────┬───────────────┘
                              │
        ┌─────────────┬───────┴────────┬─────────────┐
        ▼             ▼                ▼             ▼
    Web 题        Pwn 题           Crypto 题      Misc/Rev 题
  HTTP/绕过/     pwntools/        z3/sympy/      解包/反编译/
  注入/沙箱      gdb/ROP          格/PRNG        动态跟踪
        └─────────────┴───────┬────────┴─────────────┘
                              ▼
              flag 正则（flag/nex/FLAG/NEX）+ 回显原文
              + 至少 2 条独立证据  ──▶  record.md / findings.json
```

### Q4.1：使用这套架构之前 / 之后，Agent 的渗透速度、正确率、使用体验如何？

- **之前**：通用 DSH 没有渗透画像和工具层，Web 题从零摸端点，容易跟随 302 把后面的 404 当成“端点不存在”；命令重复、证据散落在会话里，单题常见 10 分钟以上，大附件/长输出时上下文容易爆。
- **之后**：把 kill chain、`pentestctl`、SKILL 和证据规范固化后，NEXCTF 35 题全部解出（Web/Pwn/Crypto/Misc/Reverse 全覆盖），平均约 4 分 49 秒（最短 10 秒，最长 39 分 35 秒）；302 默认不跟随、每题必有证据链，0 误提交。
- **使用体验（≤100 字）**：大输出/大附件改为落盘 + 后台 job，WAF 断连按证据重试；PowerShell 引号坑改成写脚本再跑；长题基本不用盯盘。
- **口径说明**：6 道 Pwn 题的 exploit 由参赛者本人手搓提供，Agent 负责复现/验证与题解整理；上述耗时包含这部分复现/记录时间，Pwn 题不代表 Agent 从零自动利用的速度。

### Q5：该 Agent 参加过哪些赛事？使用哪个 LLM 作为底座？获得怎样的成就？

| 赛事名称 | 使用的 LLM（版本号 + 思考强度） | 成就（排名 / 奖项） |
| -------- | ------------------------------- | ------------------- |
| NEXCTF（2026-10-24 线上） | deepseek-flash（默认，未显式设置思考强度） | 无排名 / 奖项（仅参赛实测，解出 35 题） |

> 没有参加过或只在 NEXCTF 上测试过则写「无」。
> 独立自研的 `ctfagent` 未参加本次 NEXCTF，仅作为同周期实现一并提交。
> 其中 6 道 Pwn 题的 exploit 由参赛者本人手搓提供，Agent 负责复现/验证与题解整理；其余题型由 Agent 端到端完成。

### Q6：设计 Agent 时遇到哪些「反复遇到的」困难？如何解决？

1. **PowerShell 引号/花括号/`<` 被提前解析**：内联 `python -c`、`${IFS}`、反引号经常把命令拆坏 → 统一把 payload 写成 `.py`/`.sh` 文件再执行，复杂命令不再被 shell 吃掉。
2. **UTF-8/GBK 乱码**：中文附件、题目输出在控制台显示成乱码 → 解码结果先落盘，再用 `read` 工具查看；字节级附件按 hex 处理。效果：中文题面/源码可读。
3. **Web 的 302 / 缓存 / WAF 误判**：默认跟随重定向会把 302 后的 404 当“不存在”；空 200 可能是代理缓存；`/wp-admin` 连接拒绝是 WAF 不是端点消失 → `pentestctl http` 默认不跟随 302，空响应加 no-cache 复测，连接拒绝改换路径/方法。效果：少走大量弯路。
4. **上下文爆炸**：大附件、hex dump、反编译输出一次几万字符 → head/tail 截断、结果写文件、长任务放后台 job、必要时拆子 Agent。效果：长题能跑完且不丢关键输出。
5. **盲注/盲 SSTI 无回显、无引号**：布尔 oracle 易被 WAF 干扰，`ord()` 在沙箱里行为异常 → 用字符比较代替 `ord`、二分/逐位扩展，先定长再逐位。效果：SQLi / SSTI 题拿到 flag。
6. **加壳/混淆/反序列化链**：PyInstaller+pyarmor、pickle、XXE 等需要先还原再打 → 分层解包 + 本地复现 + 动态跟踪，先确认格式和依赖再写 exploit。效果：Rev/Misc/Web 混合题解出。
7. **flag 幻觉/误提交**：模型容易在没回显时猜 flag → 四种正则 + 回显原文 + 至少 2 条独立证据才落盘。效果：0 误提交。

### Q7：你为 Agent 设计了哪些「工具」（包括但不限于 MCP / SKILL / CLI）？

**DSH 底座自带、直接使用**
- `pwsh`：WSL bash / PowerShell 命令，带超时、后台 job（`job_list/job_output/job_kill`）
- `read` / `write` / `edit` / `grep` / `glob`：附件、源码、大输出落盘与检索
- `subagent` / `subagent_fork` / `workflow`：独立子任务、并行尝试、多阶段编排
- `todo_write`、`skill`、`web_search` / `web_fetch`、`present`
- 上下文压缩 + 会话持久化（长题不爆上下文）

**本仓库的渗透特化层（提交包 `agent/dsh-pentest-layer/`）**
- **CLI `pentestctl`**：`recon`（指纹/受保护端点/泄露面）、`http`（默认不跟随 302）、`bypass`（CVE-2020-1957 类矩阵）、`keyprobe`（Shiro key）、`skill`、`report`
- **MCP `pentest/mcp_server.py`**：把 recon/http/bypass/skill/report 暴露成 MCP 工具
- **SKILL（本地 playbook）**：`recon` / `shiro` / `ssrf` / `report`
- **rollout 工具链**：`newcase.py` 建骨架、`report` 生成 11 项 `record.md`、`show_table.py` 生成进度表；统一 `findings.json` + `evidence/` 规范
- **flag 校验**：`flag{}` / `nex{}` / `FLAG{}` / `NEX{}` 四种正则 + 回显原文 + 2 条独立证据

**DSH 技能目录（按题型加载）**
- `ctf`、`ctf-web`、`ctf-pwn`、`ctf-crypto`、`ctf-reverse`、`ctf-misc`、`ctf-forensics`、`ctf-osint`、`ctf-malware`、`ctf-ai-ml`、`ctf-similar-search`、`ctf-writeup`、`solve-challenge`

**同期独立自研 Agent（不用于本次 35 题）**
- **`ctfagent`**（提交包 `agent/ctfagent/`）：纯标准库、OpenAI 兼容接口，多策略并发 + ReAct + transcript/summary；工具含 `run_command`、`http_request`、`read_file` / `write_file` / `list_dir`、`lookup`、`submit_flag`
- CLI：`python -m ctfagent`，支持 `--mock`、`--no-planner`、`--attempts`、`--time-budget`、`--knowledge-dir`

**可执行文件（提交包根目录）**
- **`DSH-Pentest.exe`**：轻量一键启动器（约 18 KB）。双击后校验/部署 `AGENTS.md` / `.mcp.json` / `pentest/` 到工作区（差异文件备份后覆盖），改写 MCP 的 Python/脚本路径，再以工作区为 `cwd` 启动本机 DeepSeek Harness；支持 `--check` / `--workspace` / `--dsh-exe` / `--yes` / `--quiet`。源码与构建脚本在 `agent/dsh-pentest-launcher/`（`DSH-Pentest.cs` + `build.ps1`）。

---

## 二、NEXCTF 最终实测效果

> 模板记录规则：题目名字、难度、类型（如 Web、Pwn 等）、耗时（从向 Agent 发送第一条消息到 Agent 解出正确 flag，几日几时几分几秒）、Agent 解这道题时使用的 LLM、Agent 评价（≤50 字，主要描述解题时遇到的阻碍）。
> 完整 rollout 可一起放在一个压缩包中。
> Flag 记录格式：`flag{...}`、`nex{...}`、`FLAG{...}`、`NEX{...}` 四种均有效，以回显原文为准（大小写照抄，不统一大小写）。

> 说明：以下 35 题均由 **DSH-Pentest**（DSH + 渗透特化层）实际执行；每题记录/证据在 `rollout/<题目>/`，完整会话在 `chat/`。`ctfagent` 是同期独立自研 Agent，未参与这 35 题。

> **Pwn 题来源说明**：6 道 Pwn 题（ret2win / ret2libc / fmtstack / heapnote / pivot_orw / fsop_master）的 exploit 脚本由参赛者本人手搓后提供给 Agent；Agent 负责在目标环境复现、验证、排错，并整理题解与记录。因此 Pwn 题的「解出」指 Agent 成功复现并验证了参赛者的利用脚本，**不代表 Agent 从零独立完成漏洞利用**。


### 第 1 题：Ambitious Mission

- **题目名字**：Ambitious Mission（文件上传）
- **难度**：中等
- **类型**：Web（文件上传 .htaccess 绕过 + PHP 对象注入）
- **耗时**：0 日 0 时 5 分 30 秒（约；2026-10-26 13:40:42 起，13:46:10 得 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：read.php 空响应是代理缓存，加 no-cache 才通；黑名单漏 .htaccess，才认出后端是 Apache。
- **Flag**：`nex{AmBL7loUs_MIS510n_6qm62mgz}`
- **记录**：`rollout/web-ambitious-mission/record.md`（`exp.py --rce` 可重放并自清理上传物）

### 第 2 题：ezlogin

- **题目名字**：ezlogin
- **难度**：中等
- **类型**：Web（登录逻辑 / 字符级侧信道）
- **耗时**：0 日 0 时 2 分 30 秒（约；2026-10-26 14:01:10 起，14:03:39 得 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：错误回显“匹配 N 位”且按位置比较，三组对照否掉前缀模型后逐位扩展，16 位口令无字典拿下。
- **Flag**：`nex{oNE_0f_A_k1nD_3y3iye1p}`
- **记录**：`rollout/web-ezlogin-2/record.md`（exp.py 一键恢复口令并登录）

### 第 3 题：roundabout

- **题目名字**：roundabout（2×2 矩阵 RSA；2026-10-26 新附件复跑，flag 与旧实例一致）
- **难度**：简单
- **类型**：Crypto（矩阵 / RSA 因子恢复）
- **耗时**：0 日 0 时 0 分 27 秒（约；2026-10-26 15:44:30 起，15:44:57 得 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：模 p 下 a 退化为对换矩阵且 r 为偶数，换位子恒为 I，指纹恒 2 mod p，gcd(h−2^e, n) 直接分解。
- **Flag**：`nex{Ju2HENH3X1AnXINgd41sHu}`
- **记录**：`rollout/crypto-roundabout-2/record.md`（solve.py 直接分解；verify.py 11 项校验）

### 第 4 题：永远的魔法使

- **题目名字**：永远的魔法使（Python 沙箱，POST /run 执行代码，flag 在 /flag）
- **难度**：中等
- **类型**：Web（Python 沙箱逃逸）
- **耗时**：0 日 0 时 1 分 10 秒（约；2026-10-26 14:13:17 起，14:14:27 得 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：黑名单只查源码子串，且 exec 的 __builtins__ 被裁剪；靠 catch_warnings.__globals__ 取真 builtins，'op'+'en' 拼接两条路读 /flag。
- **Flag**：`nex{mAJO_kO1_nIKK1_ty6bpzu7}`
- **记录**：`rollout/web-magician-sandbox/record.md`（exp.py 支持 open/read 与 os syscall 两种模式）

### 第 5 题：Hello CTF

- **题目名字**：Hello CTF
- **难度**：待确认（签到）
- **类型**：Web（签到 / HTML 注释泄露 + hex→base64 编码链）
- **耗时**：0 日 0 时 1 分 30 秒（约；2026-10-26 13:06:51 起）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：首页注释直接给入口 ?helloctf=1，hex→base64 两步解码即出，全程无阻碍。
- **Flag**：`nex{KFC_Crazy_Thursday_Vivo_50}`
- **记录**：`rollout/web-hello-ctf/record.md`（exp.py 可一键重放）

### 第 6 题：ezrce

- **题目名字**：ezrce
- **难度**：简单
- **类型**：Web（命令注入 / WAF 绕过）
- **耗时**：0 日 0 时 2 分 40 秒（约；2026-10-26 13:14:20 起）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：首页空白诱导，目录爆破得 rce.php 源码；WAF 拦 flag 与空格，${IFS} + 通配符两步绕过。
- **Flag**：`nex{no_5PACe_Rc3_gtppqtju}`
- **记录**：`rollout/web-ezrce/record.md`（exp.py 可一键重放）

### 第 7 题：牢九门（APEX 待加强名单）

- **题目名字**：牢九门（APEX 待加强名单）
- **难度**：简单
- **类型**：Web（SQLite 布尔盲注）
- **耗时**：0 日 0 时 9 分 20 秒（约；2026-10-26 13:14:26 起）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：只有 found / not found 两态、无 sleep；sqlmap --technique=B 定性后 --tables/--dump 直接出。
- **Flag**：`nex{wO_ZHoN6_5h4Ng_DA0_Di_c3z7dg2y}`
- **记录**：`rollout/web-apex-sqli/record.md`（exp.py 手工二分复核一致）

### 第 8 题：shiro-web

- **题目名字**：shiro-web（Shiro 路径归一化鉴权绕过，CVE-2020-1957 类）
- **难度**：中等
- **类型**：Web（Shiro 认证绕过 / 路径归一化）
- **耗时**：0 日 0 时 1 分 34 秒（约；2026-10-26 14:23:47 起，14:25:21 得 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：留言板 XSS 是烟雾弹（bot 无管理员会话）；rememberMe 指纹后直接跑路径矩阵，/x/..;/admin/flag 秒出。
- **Flag**：`nex{teAm_5pIrIt_sH1r0_nn0dvbkr}`
- **记录**：`rollout/web-shiro-key/record.md`（pentestctl bypass 可复现四种变体）

### 第 9 题：ret2win

- **题目名字**：ret2win（PIE + 栈溢出 ret2win，用户手搓题；附件 pwn + libc + ld）
- **难度**：简单
- **类型**：Pwn（栈溢出 / ret2win）
- **耗时**：0 日 0 时 1 分 10 秒（约；2026-10-26 14:28:48 起，14:29:59 得 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：PIE 靠 `gift: %p` 泄露算基址，72 偏移 + 一条 ret 对齐即通；与手搓 p1.py 一致，只换了端口。
- **Flag**：`nex{Re72win_ko3ko111}`
- **记录**：`rollout/pwn-ret2win/record.md`（exp.py 可重放；两次不同 ASLR 同 flag）

### 第 10 题：ret2libc

- **题目名字**：ret2libc（非 PIE，puts 泄露 + 二次溢出到 system；用户手搓题，附件 pwn + libc + ld）
- **难度**：简单
- **类型**：Pwn（栈溢出 / ret2libc）
- **耗时**：0 日 0 时 2 分 0 秒（约；2026-10-26 14:33:13 起，14:35:10 得 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：两段式泄露 puts 算 base 后 system('/bin/sh')；第二次进 vuln 无提示符，别 recvuntil；system 前要 ret 对齐。
- **Flag**：`nex{Re7zI1GC_wzjwsxbi}`
- **记录**：`rollout/pwn-ret2libc/record.md`（exp.py 可重放；两次 ASLR 同 flag）

### 第 11 题：fmtstack

- **题目名字**：fmtstack（格式串一次泄露 canary/PIE/libc + canary 绕过 ROP；用户手搓题，附件 pwn + libc + ld）
- **难度**：简单
- **类型**：Pwn（格式化字符串 + 栈溢出）
- **耗时**：0 日 0 时 5 分 0 秒（约；2026-10-26 14:40:14 起，14:45:10 得 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：名字直接进 printf，`%23$p/%25$p/%29$p` 一次拿 canary 与两个基址；pwntools tube 挂死，改裸 socket。
- **Flag**：`nex{lMt5TaCk_w2rheic4}`
- **记录**：`rollout/pwn-fmtstack/record.md`（exp.py 纯标准库 socket；两次 ASLR 同 flag）

### 第 12 题：heapnote

- **题目名字**：heapnote（堆 UAF + tcache poisoning 打 backdoor；用户手搓题，附件 pwn + libc + ld）
- **难度**：中等
- **类型**：Pwn（堆 UAF / tcache poisoning）
- **耗时**：0 日 0 时 1 分 10 秒（约；2026-10-26 14:48:35 起，14:49:25 得 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：delete 不置空，show 读 fd 得 safe-linking heap key；改 tcache 指针到 0x404040，两次 add 落 backdoor，call 出 flag。
- **Flag**：`nex{HeApn07e_t50p6zr4}`
- **记录**：`rollout/pwn-heapnote/record.md`（exp.py 纯 socket；两次 heap key 不同同 flag）

### 第 13 题：pivot_orw

- **题目名字**：pivot_orw（静态链接，栈迁移到 .bss + ORW 读 flag；手搓脚本实为 p5.py）
- **难度**：中等
- **类型**：Pwn（栈迁移 + ORW/syscall）
- **耗时**：0 日 0 时 0 分 45 秒（约；2026-10-26 14:53:02 起，14:53:44 得 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：p4.py 是上一题脚本，正确是同目录 p5.py；stage 写 bss 布 ORW，overflow 里 leave;ret 迁移，一次通。
- **Flag**：`nex{PIV0t_oRW_8j5s9eki}`
- **记录**：`rollout/pwn-pivot-orw/record.md`（exp.py 纯 socket；两次运行同 flag）

### 第 14 题：fsop_master（06-fsop）

- **题目名字**：fsop_master（06-fsop；堆 UAF → FSOP → setcontext → sendfile ORW，参考脚本由用户提供）
- **难度**：困难
- **类型**：Pwn（堆 UAF / tcache / FSOP / seccomp ORW）
- **耗时**：0 日 0 时 39 分 35 秒（约；2026-10-26 14:56:21 起，15:35:56 得 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：2.43 tcache 懒分配 + 16 项，靠伪造 0x440 跳过 tcache 泄 libc；FSOP 用 rdx 版 setcontext 迁堆；本机 pwntools 需 timeout=3 才不卡。
- **Flag**：`nex{1Sop_Ma573R_2f60ntat}`
- **记录**：`rollout/pwn-fsop-master/record.md`（exp.py 为适配版；两次独立跑同 flag）

### 第 15 题：如何入门密码学

- **题目名字**：如何入门密码学（密码学入门教学 + 一段 Python 脚本，跑通即出 flag）
- **难度**：签到
- **类型**：Crypto（环境搭建 + 组合：RSA / GF(257^4) / EC / SM3 / AES-CTR）
- **耗时**：0 日 0 时 1 分 25 秒（约；2026-10-26 15:40:38 起，15:42:03 得 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：sage/gmpy2/gmssl 装不上，纯 Python 重写 GF(257^4)、trace/norm、EC 点乘与 SM3，13 项交叉校验后出 flag。
- **Flag**：`nex{wEICom3_t0_the_WORLD_01_cRYPto}`
- **记录**：`rollout/crypto-crypto-beginner/record.md`（solve.py 零 sage 依赖；verify.py 独立校验）

### 第 16 题：新宿决战1

- **题目名字**：新宿决战1（五条悟 vs 宿傩回合制小游戏，远程 `u8q0hcswmbnhwz70.neu-nex.fun`）
- **难度**：简单
- **类型**：Web（参数篡改）
- **耗时**：0 日 0 时 0 分 38 秒（约；2026-10-26 16:21:57 起，16:22:35 得 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：读内联 JS 见 power 由前端提交，改 JSON 一枪 200000 秒杀宿傩；换技能与字符串型复核同 flag。
- **Flag**：`nex{N1_c4i_sH1_t1Ao_ZhaN_2he_sa990usv}`
- **记录**：`rollout/web-shinjuku1/record.md`（exp.py 两次独立会话；evidence/step2、step3 请求响应原文）

### 第 17 题：新宿决战2

- **题目名字**：新宿决战2（新宿决战1 续作，改为 `/get_token` + JWT Bearer 授权，远程 `0ea5rmoupjmy5teu.neu-nex.fun`）
- **难度**：中等
- **类型**：Web（JWT 弱密钥）
- **耗时**：0 日 0 时 1 分 12 秒（约；2026-10-26 16:24:38 起，16:25:50 得 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：改 body 的 power 无效后转 JWT；主题词字典爆破得 HS256 密钥 gojo，重签 power=200000 一发通关。
- **Flag**：`nex{sH1_5t5_Y1ng_L3_zjdh8q6g}`
- **记录**：`rollout/web-shinjuku2/record.md`（exp.py 自带签名与两次独立复核；evidence/step2、step3 请求响应原文）

### 第 18 题：halfkey

- **题目名字**：halfkey（截断 PEM 私钥：n、e 完整、d 高 1600 位泄露，低 448 位丢失；本地附件）
- **难度**：简单
- **类型**：Crypto（部分密钥泄露）
- **耗时**：0 日 0 时 10 分 24 秒（约；16:27:03 收附件 → 16:37:27 复核 flag；Coppersmith dim9 LLL 1046 s）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：截断点正好在 d 字段内；定出 k=25487 后 q0≥q，旧脚本求根方向反了，改 f(x)=x−q0 后 dim9 格出因子。
- **Flag**：`nex{p3m_DEr_aNd_paCkEdsXjaLsdJ4sD}`
- **记录**：`rollout/crypto-halfkey/record.md`（exp.py 零依赖复核 7 项；evidence/step1_solve.txt）

### 第 19 题：你 vs 签证官

- **题目名字**：你 vs 签证官（DSA 验签服务，远程 `219.216.64.241:35516`）
- **难度**：简单
- **类型**：Crypto（DSA 验签绕过）
- **耗时**：0 日 0 时 0 分 10 秒（约；2026-10-26 16:42:16 起，16:42:26 得 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：verify 只查 s<=0 没查 s%q!=0；取 s=q 让 w=0、指数全归零，r=1 必过，两次连接复核。
- **Flag**：`nex{Zu1aN_v5_uSA4hz0gdpx}`
- **记录**：`rollout/crypto-visa-officer/record.md`（exp.py 两次独立连接；evidence/step1、step2 原文）

### 第 20 题：powerpowerpower

- **题目名字**：powerpowerpower（三把 RSA 链式泄露：φ 的近似倍数、可塌缩指数、p2 高 624 位；本地附件）
- **难度**：中等
- **类型**：Crypto（部分信息泄露链）
- **耗时**：0 日 0 时 10 分 30 秒（约；16:43:29 收附件 → 16:53 复核 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：连分数拆 n0、12-bit (a,b) 判别式拆 n1 都很快；n2 的 400 bit 已近 n^1/4，dim≤6 格不够，复用 Apps 结果并以 c2 复核。
- **Flag**：`nex{yoU_are_7hE_oN3_OF_m0Std4Sd45d}`
- **记录**：`rollout/crypto-powerpowerpower/record.md`（exp.py 秒级重算前两步 + pow(m,e,n2)==c2 复核）

### 第 21 题：cubewalk

- **题目名字**：cubewalk（x³+y³=c 曲线、AES-GCM 密文；本地附件，复用 Apps 会话解）
- **难度**：中等
- **类型**：Crypto（ECDLP / Pohlig-Hellman）
- **耗时**：0 日 0 时 6 分 30 秒（约；16:55 解包 → 17:01 复核 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：p≡2 mod 3 ⇒ #E=p+1 且 p+1 光滑，PH 直接求 k；复用 Apps 的 solver.py 复现，9 项校验通过。
- **Flag**：`nex{W313r5tRAss_sTUpid_D4D4SDJILmm}`
- **记录**：`rollout/crypto-cubewalk/record.md`（exp.py 复用 solver.py；evidence/step1、step2 原文）

### 第 22 题：魔法余数

- **题目名字**：魔法余数（模 p 线性组合只泄露高 256 位，flag 内层 34 字符；本地附件）
- **难度**：中等
- **类型**：Crypto（CVP / LLL + Babai）
- **耗时**：0 日 0 时 5 分 19 秒（约；16:59:52 收附件 → 17:05:11 出 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：Kannan embedding 试半天全 miss；换成真 CVP（[C·I|a]+[0|p] + Babai、一次 LLL 扫 CENTER）11 秒命中。
- **Flag**：`nex{1_D0NT_llK3_rEmIND3r_and_c0mPuT1nG}`
- **记录**：`rollout/crypto-magic-remainder/record.md`（exp.py 端到端；evidence/step1_solve.txt）

### 第 23 题：ezhex

- **题目名字**：ezhex（三个 0 字节文件，文件名是 flag 三段的 CRC32；本地附件）
- **难度**：简单
- **类型**：Misc（文件名校验值 / CRC32 原像爆破）
- **耗时**：0 日 0 时 2 分 53 秒（约；17:07:51 收附件 → 17:10:44 出 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：三个空文件只是壳，名字 8 位 hex 即 CRC32；按 flag 字符集爆破 4 字节原像 3.9 s，拼出 nex{ezCrc32}。
- **Flag**：`nex{ezCrc32}`
- **记录**：`rollout/misc-ezhex/record.md`（exp.py 爆破三段 CRC32 原像并回代）

### 第 24 题：压缩包（伪加密）

- **题目名字**：压缩包（zip 伪加密：加密标志位为 1，数据其实是明文 deflate；本地附件 `猜密码 (1).zip`）
- **难度**：简单
- **类型**：Misc（ZIP 伪加密）
- **耗时**：0 日 0 时 0 分 33 秒（约；2026-10-26 17:28:11 → 17:28:44）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：flags=0x1 但 csz/usz/CRC 正常即伪加密；清本地头与中央目录 4 处 bit0，33 秒出 flag。
- **Flag**：`nex{nEveR_g0nnA_g1ve_You_Up}`
- **记录**：`rollout/misc-zip-pseudo/record.md`（exp.py 清标志 + 解压 + CRC 校验）

### 第 25 题：如果你看扁我

- **题目名字**：如果你看扁我（PNG 高度被改小 200 行，底部藏 flag；本地附件 rina (1).zip）
- **难度**：简单
- **类型**：Misc（PNG 高度篡改）
- **耗时**：0 日 0 时 0 分 37 秒（约；17:29:50 → 17:30:27）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：IHDR CRC 被重算过不能靠报错；用 IDAT 解压长度除行宽反推真实高度 2150，底部 200 行直接读出 flag。
- **Flag**：`nex{k0mAtSu_R1na}`
- **记录**：`rollout/misc-rina/record.md`（exp.py 改高度 + 重算 CRC + 裁底部）

### 第 26 题：山门 · 验灵碑

- **题目名字**：山门 · 验灵碑（ez_gate，ELF64 PIE：50 条仙诀候选，strcmp 明文常量；本地附件）
- **难度**：签到
- **类型**：Reverse（重定位表藏串 + 多编码候选筛选）
- **耗时**：0 日 0 时 1 分 27 秒（约；17:31:52 收附件 → 17:33:19 出 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：main 的 strcmp 常量是明文 `NEX{...}`；50 条候选在 .rela.dyn 的 addend 里，解码 plain/reversed/hex/base64 后唯一条相等。
- **Flag**：`NEX{gu4n_9ui1_y4n7}`
- **记录**：`rollout/rev-ez-gate/record.md`（exp.py 静态解 + WSL 运行复核）

### 第 27 题：坊市 · 千层符

- **题目名字**：坊市 · 千层符（千层符.html：aaencode 壳 + 三层封装 RUNES，本地附件）
- **难度**：简单
- **类型**：Reverse（aaencode 壳 + 自定义编码逆向）
- **耗时**：0 日 0 时 1 分 25 秒（约；17:44:50 收附件 → 17:46:15 出 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：aaencode 用替换 Function 构造器捕获源码；三层是 XOR(QiXuanMen)+base64+反转+base64，逆推后用页面 check 复核 ok。
- **Flag**：`NEX{c0d1ng_l4y3r_by_l4y3r}`
- **记录**：`rollout/rev-qiancengfu/record.md`（exp.js 剥壳+逆封装+VM 跑 check）

### 第 28 题：内门玉牌 · 校验大阵

- **题目名字**：内门玉牌 · 校验大阵（keycard.exe：PE 带 NEX 壳 + 位置相关变换 + 自定义 base64；本地附件）
- **难度**：中等
- **类型**：Reverse（PE 脱壳 + 自定义编码）
- **耗时**：0 日 0 时 0 分 59 秒（约；17:47:36 收附件 → 17:48:35 出 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：磁盘 exe 无明文数据→OpenProcess 读内存 payload；变换含 +i（题面“方位”）与自定义字母表，逆完用原 exe 复核 exit 0。
- **Flag**：`NEX{ch41n_0f_tr4nsf0rms}`
- **记录**：`rollout/rev-keycard/record.md`（exp.py 内存脱壳 + 扫 BLOB + 原程序复核）

### 第 29 题：天算子 · 廿四星宿

- **题目名字**：天算子 · 廿四星宿（equations：24 元线性方程组校验，系数/常数明文；本地附件）
- **难度**：中等
- **类型**：Reverse（线性方程组求解）
- **耗时**：0 日 0 时 0 分 47 秒（约；17:50:03 收附件 → 17:50:50 出 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：把 24 个字符当未知数，抠出 .rodata 的 M@0x2240/B@0x21e0，Fraction 精确消元得全整数解，原 ELF 复核 EXIT=0。
- **Flag**：`NEX{z3_s0lv3r_m4g1c_666}`
- **记录**：`rollout/rev-equations/record.md`（exp.py 读矩阵+精确消元+跑 ELF 复核）

### 第 30 题：桃花瘴迷踪阵

- **题目名字**：桃花瘴迷踪阵（maze.exe：441 块砖的格子函数图，BFS 求生路；本地附件）
- **难度**：中等
- **类型**：Reverse（图搜索）
- **耗时**：0 日 0 时 0 分 43 秒（约；17:53:22 收附件 → 17:54:05 出 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：把每块砖当图节点，cmp+je+lea 抽边、call 识别禁制，BFS 一次得 52 步走位，原 exe 复核 exit 0。
- **Flag**：`NEX{m4ze_p4th_1s_k3y}`
- **记录**：`rollout/rev-maze/record.md`（exp.py 建图+BFS+跑 exe）

### 第 31 题：心魔劫

- **题目名字**：心魔劫（tribulation：UD2/SIGILL handler 做校验，另有 TEA 风格幻台分支；本地附件）
- **难度**：困难
- **类型**：Reverse（信号驱动校验 + 反调试/幻台）
- **耗时**：0 日 0 时 3 分 7 秒（约；17:55:40 收附件 → 17:58:47 出 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：ud2 传参（[0x401a]=i,[0x401b]=c）由 SIGILL handler 校验；发现 0x16a0 幻台会跳过循环假成功，用 strace 数 SIGILL 确认真路径。
- **Flag**：`NEX{ud2_1s_n0t_a_cr4sh}`
- **记录**：`rollout/rev-tribulation/record.md`（exp.py 静态逆表 + WSL 跑 ELF + SIGILL 计数）

### 第 32 题：飞升台 · 最终禁制

- **题目名字**：飞升台 · 最终禁制（final_protocol：构造函数据 ptrace 反调试 + RC4 派生密钥 + XXTEA；本地附件）
- **难度**：困难
- **类型**：Reverse（构造函数/反调试 + 对称加密）
- **耗时**：0 日 0 时 1 分 9 秒（约；18:01:44 收附件 → 18:02:53 出 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：看 .init_array 找到 ptrace 反调试 + RC4 派生 key16；小写优先 base64 + XXTEA(12 轮) 解出 flag，重加密回代 + 裸跑复核。
- **Flag**：`NEX{c0nstruct0r_rc4_t34_m4st3r}`
- **记录**：`rollout/rev-final-protocol/record.md`（exp.py RC4+XXTEA，strace 会触发反调试）

### 第 33 题：修仙模拟器

- **题目名字**：修仙模拟器（meditation：PyInstaller+pyarmor 前端 + 原生 NEX-GUARD DLL，可作弊；本地附件）
- **难度**：中等
- **类型**：Reverse（Python 解包 + ctypes 状态篡改 + Win32 窗口伪造）
- **耗时**：0 日 0 时 29 分 35 秒（约；18:04:02 收附件 → 18:33:37 出 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：核心是 `_power_buf` 直接写 99999 + 伪造 Chrome_ 窗口树；子窗口漏了 WS_CHILD 导致验身恒失败，补上后 g1 返回 flag。
- **Flag**：`NEX{sh0rtcut_1s_4ls0_d4o}`
- **记录**：`rollout/rev-meditation/record.md`（exp.py：伪窗口+改灵力+tick）

### 第 34 题：キミの記憶

- **题目名字**：キミの記憶（Memento Mori · SSTI：Jinja2 无回显，错误布尔盲注；远程）
- **难度**：困难
- **类型**：Web（SSTI / 沙箱逃逸 / 无回显盲注）
- **耗时**：0 日 0 时 3 分 8 秒（约；19:42:32 收题 → 19:45:40 出 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：把「渲染出错了」当除零布尔 oracle，再用 `_wrap_close.__init__.__globals__` 读环境变量 `FLAG`，字符比较二分逐位外带；沙箱的 `ord` 被改写导致第一次二分失败，换字符比较后一次通过。
- **Flag**：`nex{C0loR_Y0uR_N19Ht_knvmh44e}`
- **记录**：`rollout/web-kimi-no-kioku/record.md`（exp.py 自动逐位外带 + 整串复核）

### 第 35 题：超大杯flask

- **题目名字**：超大杯flask（明日方舟超市：static 备份泄露 + Flask 类污染改 IS_ADMIN；远程）
- **难度**：困难
- **类型**：Web（Flask / 静态备份泄露 / 类污染 / SSTI / pickle）
- **耗时**：0 日 0 时 11 分 43 秒（约；19:50:07 收题 → 20:01:50 出 flag）
- **Agent 解这道题时使用的 LLM**：deepseek-flash
- **Agent 评价**：按 hint 猜中 `/static/backup.sql` 拿到 zc 密码；读源码发现 `/restock` 的 `merge()` 可沿 `__class__→__init__→__globals__` 污染模块全局 `IS_ADMIN`，一条 JSON 后 `/admin` 直接给 flag。SSTI（`\u007b` 绕 WAF）和 pickle（OBJ 绕 REDUCE/INST）是冗余链。
- **Flag**：`nex{Sup3R_B1G_cUP_lg3nfbio}`
- **记录**：`rollout/web-super-flask/record.md`（exp.py 全链路：备份→登录→污染→/admin）

## 三、Rollout 提交说明

- **包名**：`20251456-王奕贺-做题记录.zip`
- **收件人**：`jiaxingli342@gmail.com`
- **内容**：
  - `rollout/sessions/`：DSH 完整会话导出，每局一个 `rollout-时间戳-*.jsonl`；
  - `rollout/<题目>/`：35 题 `record.md` + `findings.json` + `notes.md` + exploit/evidence 文本；
  - `agent/`：DSH-Pentest 渗透特化层、启动器源码与同期 ctfagent；
  - `Pwn_agent/`：赛后整合的 PwnAgent（PwnProof + ctf-agent + ctf-tools）源码、文档与单文件 pyz；
  - `Agent工程师wp.md` / `Agent工程师wp.pdf`。
- **GitHub 仓库**：`https://github.com/Leonardopw/nexctf-2026-agent-writeup`
- **邮件**：完整包 `Agent工程师wp.zip` 由本人手动发送至 `jiaxingli342@gmail.com`。
- **脱敏**：已移除本机绝对路径（`<HOME>\...`、`<WORKSPACE>` 等）、API key、邮箱；长工具输出截断到 1200 字符。

## 四、更新日志

- 2026-10-24：创建本文件，先录入 Hello CTF、ezrce、APEX 待加强名单（旧实例）。
- 2026-10-24：追加 Ambitious Mission（Web：文件上传 / PHP 反序列化）。
- 2026-10-24：追加 ezlogin（Web：登录逻辑 / 字符级侧信道）。
- 2026-10-24：追加 roundabout（Crypto：矩阵 / RSA 因子恢复）。
- 2026-10-24：追加 Python 沙箱（Web：沙箱逃逸）。
- 2026-10-25：追加 06-fsop（Pwn：堆 UAF / tcache poisoning / FSOP / seccomp ORW，glibc 2.43）。
- 2026-11-11：补全 Q1-Q7（Agent 设计思路、参考、架构、实测对比、赛事、困难、工具）。
- 2026-11-12：按模板要求重新整理 Q1-Q7，补充 EnIGMA 参考、ASCII 架构图与 planner 解析等细节。
- 2026-10-26：新实例复跑 Hello CTF / ezrce / 牢九门（APEX），flag 与旧实例不同，记录并入本文件。
- 2026-10-26：按统一编号整理——删除旧实例重复的第 1-3 题（其 flag 已被新实例结果取代），
  原第 4-11 题重编号为第 1-8 题；flag 校验放宽为 `flag{}` / `nex{}` / `FLAG{}` / `NEX{}` 四种格式。
  删除前的完整旧稿见 `Agent工程师wp.md.bak-20261026`。
- 2026-10-26：Ambitious Mission 新实例（`pv5cl84fwfwuwkuz.neu-nex.fun`）复跑，第 1 题更新为新实例结果
  （`.htaccess` 绕过拿 RCE + `read.php` 对象注入读 `/flag`），新增 `rollout/web-ambitious-mission/` 五件套；
  旧实例 flag `nex{AmBL7loUs_MIS510n_o8f6stvk}` 仅保留在备份中。
- 2026-10-26：ezlogin 新实例（`wg4j5e363xxpdbf4.neu-nex.fun`）复跑，第 2 题更新为新实例结果
  （`/verify` 回显按位置匹配位数，逐位扩展还原 16 位口令 `S3cr3tP@ssw0rd123`），新增 `rollout/web-ezlogin-2/`；
  旧实例 flag `nex{oNE_0f_A_k1nD_w007ikb8}` 仅保留在备份中。
- 2026-10-26：永远的魔法使（Python 沙箱，`6a06qu5xkmh6vepz.neu-nex.fun`）新实例复跑，第 4 题更新：
  子串黑名单 + 裁剪版 `__builtins__`，经 `catch_warnings.__init__.__globals__` 取真 builtins，
  `'op'+'en'` / `'re'+'ad'` 拼接绕过读 `/flag`，新增 `rollout/web-magician-sandbox/`；
  旧实例 flag `nex{mAJO_kO1_nIKK1_vajiethj}` 仅保留在备份中。
- 2026-10-26：新增第 9 题 shiro-web（`kudxmerczf9yq7ov.neu-nex.fun`）：rememberMe 指纹后走路径归一化，
  `/x/..;/admin/flag`、`/;/admin/flag`、`/.;/admin/flag` 均 200 取到 flag，新增 `rollout/web-shiro-key/`；
  留言板存储型 XSS 经 bot 验证无管理员会话，记为红鲱鱼。
- 2026-10-26：新增第 10 题 ret2win（用户手搓题，附件 pwn/libc/ld，远程 `219.216.64.241:39546`）：
  PIE 由 `gift: %p` 泄露算基址，`72 + ret(0x101A) + win(0x1169)` 打通，两次 ASLR 复现同 flag，新增 `rollout/pwn-ret2win/`。
- 2026-10-26：新增第 11 题 ret2libc（用户手搓题，远程 `219.216.64.241:35194`）：非 PIE + Partial RELRO，
  `72*A + pop_rdi + puts@got + puts@plt + vuln` 泄露 libc base，再 `pop_rdi + /bin/sh + ret + system` 拿 shell，
  flag 在 `/home/ctf/flag`，两次 ASLR 复现，新增 `rollout/pwn-ret2libc/`。
- 2026-10-26：新增第 12 题 fmtstack（用户手搓题，远程 `219.216.64.241:35053`）：name 直接进 printf，
  `%23$p/%25$p/%29$p` 一次泄露 canary + PIE + libc，msg 偏移 72 处带 canary 的 ROP（补 ret 对齐）拿 shell，
  flag 在 `/home/ctf/flag`，新增 `rollout/pwn-fmtstack/`；本机 pwntools tube 挂死，exp 改纯 socket。
- 2026-10-26：新增第 13 题 heapnote（用户手搓题，远程 `219.216.64.241:36041`）：delete 后 UAF，
  show 泄露 tcache safe-linking fd（chunk>>12），edit 把下个指针改成 BSS 函数指针 0x404040，
  两次 add 写入 backdoor(0x4011fe)，call 触发 `cat ./flag`，新增 `rollout/pwn-heapnote/`。
- 2026-10-26：新增第 14 题 pivot_orw（远程 `219.216.64.241:35302`）：静态链接 + 非 PIE，`stage:` 把 ORW 链写进
  .bss(0x4b3ac0)，`overflow:` 用 leave;ret(0x40198d) 迁移栈，open/read/write 打出 flag，新增 `rollout/pwn-pivot-orw/`；
  用户附的 p4.py 实为上一题 heapnote，正确脚本是同目录 p5.py。
- 2026-10-26：新增第 15 题 fsop_master（06-fsop，远程 `219.216.64.241:36813`）：glibc 2.43 tcache 懒分配/16 项，
  伪造 `c3->size=0x441` 让 `free` 以 idx 66 跳过 tcache 进 unsorted 泄 libc；再投毒到 `_IO_2_1_stdout_`
  写 House of Apple 2 fake FILE，`wide_vtable+0x68=setcontext+0x3D`（rdx=fp）迁移到堆 ROP，
  `open("flag")→sendfile(1,3,NULL,huge)→_exit`，flag 在 cwd 的 `flag`，新增 `rollout/pwn-fsop-master/`。
- 2026-10-26：删除旧实例记录——第 5 题 06-fsop（2026-10-25，flag `nex{1SOp_ma5TER_ncc7wa6d}`）；同一题今天的新实例已作为 fsop_master 收录（原第 15 题），原第 6–15 题重编号为第 5–14 题。删除前旧稿备份 `Agent工程师wp.md.bak-20261026b`。
- 2026-10-26：新增第 15 题 如何入门密码学（Crypto 签到）：附件脚本依赖 sage/gmpy2/gmssl，本机装不上，
  用纯 Python 重写 GF(257^4)/trace/norm/EC 点乘与 SM3，RSA+矩阵+SM3+AES-CTR 全链复算，
  13 项独立校验后得 flag，新增 `rollout/crypto-crypto-beginner/`。
- 2026-10-26：roundabout 用新附件（`attachments (11).zip`）复跑，第 3 题原地更新为新记录；
  模 p 退化（a→对换矩阵、r 偶数、换位子为 I、指纹恒 2）→ `gcd(h-2^e,n)` 一把分解，
  耗时 27 秒，flag 与旧实例一致 `nex{Ju2HENH3X1AnXINgd41sHu}`，新增 `rollout/crypto-roundabout-2/`。
- 2026-10-26：新增第 16 题 新宿决战1（Web，远程 `u8q0hcswmbnhwz70.neu-nex.fun`）：Flask 回合制小游戏，
  `/attack` 直接采信前端 JSON 的 `power`，改 200000 一回合清空宿傩 200000 HP 拿 flag，
  换 skill 与字符串型 power 两次独立复核，新增 `rollout/web-shinjuku1/`。
- 2026-10-26：新增第 17 题 新宿决战2（Web，远程 `0ea5rmoupjmy5teu.neu-nex.fun`）：改为 `/get_token` 下发 HS256 JWT
  做授权，用 1875 个主题词/常见弱口令离线爆破出密钥 `gojo`，重签 `{"skill":"void","power":200000}` 一发清空宿傩，
  换 skill=ao、power=999999 复核同 flag，新增 `rollout/web-shinjuku2/`。
- 2026-10-26：新增第 18 题 halfkey（Crypto，本地附件 `attachments (15).zip`）：`key.export_key()[:677]` 截断在 d 字段，
  得 n/e 完整 + d 高 1600 位；k=25487 唯一，`s0=A//k≥s ⇒ q0≥q`，对 `f(x)=x−q0` 做 Coppersmith (4,5) dim9
  （LLL 1046 s）分解 n，五重校验（p*q、d 高位、k、pow(m,e,n)==c、flag 正则）后得 flag，新增 `rollout/crypto-halfkey/`。
- 2026-10-26：新增第 19 题 你 vs 签证官（Crypto，远程 `219.216.64.241:35516`）：DSA 验签只检查 `s<=0`、
  未拒绝 `s%q==0`，取 `s=q` 使 `pow(0,q-2,q)=0`、两个指数归零，`r=1` 恒通过；
  两次独立连接（y/m 每次不同）复核同 flag，新增 `rollout/crypto-visa-officer/`。
- 2026-10-26：新增第 20 题 powerpowerpower（Crypto，附件 `attachments (16).zip`）：n0−h_i=x_i(σ−1)−r_i
  用连分数拆 n0；z 经 Fermat 塌缩为 a·p1+b·q1，12-bit (a,b) 判别式暴力拆 n1；c1 给出 p2 高 624 位，
  Coppersmith dim9 拆 n2（复用 Apps 会话 `crypto_att4` 同实例结果，`pow(m,e,n2)==c2` 复核），新增 `rollout/crypto-powerpowerpower/`。
- 2026-10-26：新增第 21 题 cubewalk（Crypto，附件 `attachments (17).zip`）：曲线 x³+y³=c、p≡2 (mod 3)
  ⇒ x³ 双射、#E=p+1；p+1 完全光滑（2,3 与 10 个 <2^19 素数）⇒ Pohlig-Hellman 求 k，
  KDF(k) 解 AES-GCM 得 flag；复用 Apps 会话 `<APPS>/att17` 的 solver.py 复现（同 output SHA256），
  9 项校验通过，新增 `rollout/crypto-cubewalk/`。
- 2026-10-26：新增第 22 题 魔法余数（Crypto，附件 `attachments (18).zip`）：`h=(Σa_i·c_i mod p)>>80`，
  把低 80 位当误差 t，建格 `[C·I | a; 0 | p]` + 目标 `(0..0,h·2^80−CENTER·Σa)`；
  用 Kannan embedding 扫描失败后改真 CVP（LLL+Babai，一次 LLL 扫 CENTER），11 s 解出
  `1_D0NT_llK3_rEmIND3r_and_c0mPuT1nG`，`S>>80==h` 复核，新增 `rollout/crypto-magic-remainder/`。
- 2026-10-26：新增第 23 题 ezhex（Misc，附件 `1 (4).zip`）：三个 0 字节文件、名字是 8 位 hex，
  实为三段 CRC32（`crc32('nex{')/('ezCr')/('c32}')`），按 flag 字符集爆破短串原像 3.9 s，
  拼得 `nex{ezCrc32}`（Apps 会话 e77539c8 同结果），新增 `rollout/misc-ezhex/`。
- 2026-10-26：新增第 24 题 压缩包（Misc 伪加密，附件 `猜密码 (1).zip`）：本地头与中央目录 flags 均为 0x0001
  但 csz/usz/CRC 正常，数据是明文 deflate；清 4 处 bit0 后正常解压得
  `nex{nEveR_g0nnA_g1ve_You_Up}`，33 秒完成，新增 `rollout/misc-zip-pseudo/`。
- 2026-10-26：新增第 25 题 如果你看扁我（Misc，附件 `rina (1).zip`）：PNG IHDR 写 2150×1950 且 CRC 正常，
  但 IDAT 解压多出 200 行（1,290,200 B = 200×6451）；高度改回 2150 重算 CRC，底部裁出
  `nex{k0mAtSu_R1na}`，新增 `rollout/misc-rina/`。
- 2026-10-26：新增第 26 题 山门·验灵碑（Reverse，附件 `ez_gate (1).zip`）：ELF64 PIE 的 main 用 strcmp
  比对 `0x21dd` 明文常量 `NEX{gu4n_9ui1_y4n7}`；50 条候选串藏在 `0x3c00..0x3d90` 的 R_X86_64_RELATIVE
  重定位 addend 里（plain/reversed/hex/base64 + 5 条 ARK 伪前缀），解码后仅第 23 条相等；
  WSL 运行输入得 `[OK]`，新增 `rollout/rev-ez-gate/`。
- 2026-10-26：新增第 27 题 坊市·千层符（Reverse，附件 `千层符 (2).zip`）：HTML 内 aaencode 壳，
  替换 Function 构造器捕获得到 layer1（RUNES + SPIRIT_KEY="QiXuanMen" + wrapTicket）；
  逆向 XOR→base64→反转→base64 三层得 `NEX{c0d1ng_l4y3r_by_l4y3r}`，
  用页面自身 wrapTicket 重封装相等、VM 跑 check() 返回 ok，新增 `rollout/rev-qiancengfu/`。
- 2026-10-26：新增第 28 题 内门玉牌·校验大阵（Reverse，附件 `keycard (1).zip`）：PE 带 NEX 壳，
  磁盘文件无明文校验数据；OpenProcess+ReadProcessMemory 读内存 payload（73,728 B），扫 32 字符候选，
  自定义字母表 base64 + 逆 `(x[i]+i)^NEXGATE![i%8]` 变换得 `NEX{ch41n_0f_tr4nsf0rms}`，
  原 exe 复核 exit 0，新增 `rollout/rev-keycard/`。
- 2026-10-26：新增第 29 题 天算子·廿四星宿（Reverse，附件 `equations (1).zip`）：ELF 读 24 字符，
  做 `M·x == B` 的 24 元线性校验（M 576 个 int32 @0x2240、B @0x21e0 明文）；
  用 Fraction 精确高斯消元得 `NEX{z3_s0lv3r_m4g1c_666}`，代回复核 + WSL 跑原 ELF `EXIT=0`，
  新增 `rollout/rev-equations/`。
- 2026-10-26：新增第 30 题 桃花瘴迷踪阵（Reverse，附件 `maze (1).zip`）：PE64 每块砖一个函数，
  解析 `cmp eax,'wasd'+je`（跳转块 lea→下一砖 / call→禁制）建 199 节点有向图，
  BFS 从 `+0x17aa` 到 `+0x8644` 得 52 步走位，原 exe 复核 `NEX{m4ze_p4th_1s_k3y}` exit 0，
  新增 `rollout/rev-maze/`。
- 2026-10-26：新增第 31 题 心魔劫（Reverse，附件 `tribulation (1).zip`）：main 用 `ud2` 触发 SIGILL，
  handler 从 `[0x401a]/[0x401b]` 取 (i,c) 做 XOR/rot/add 变换与 23 字节 CMP 表比较；
  逆 4 张表得 `NEX{ud2_1s_n0t_a_cr4sh}`。另发现 0x16a0 幻台分支可跳过循环打印同样成功，
  用 strace 数 SIGILL（真路径 24 次）确认，新增 `rollout/rev-tribulation/`。
- 2026-10-26：新增第 32 题 飞升台·最终禁制（Reverse，附件 `final_protocol (1).zip`）：
  `.init_array` 构造函数据 `ptrace(PTRACE_TRACEME)` 反调试（strace 下 SIGSEGV）、用 RC4("NEX2025")
  异或常量派生 XXTEA 密钥 `NEX-XXTEA-REAL-K`；main 用“小写优先”自定义 base64 解 BLOB 再 XXTEA 解密，
  得 `NEX{c0nstruct0r_rc4_t34_m4st3r}`（重加密回代 + 裸跑 good/bad 复核），新增 `rollout/rev-final-protocol/`。
- 2026-10-26：新增第 33 题 修仙模拟器（Reverse，附件 `meditation (4).zip`）：PyInstaller+pyarmor 程序，
  用 Python 3.13 解包导入，`api._power_buf.value=99999` 绕过打坐；DLL g1 的 EnumWindows 校验要求
  本进程存在标题 `凡人修仙 · 打坐飞升`、含 >1 个 `Chrome_` 子窗口的窗口树——子窗口补上 **WS_CHILD** 后通过，
  `g1()` 返回 `NEX{sh0rtcut_1s_4ls0_d4o}`，新增 `rollout/rev-meditation/`。
- 2026-10-26：新增第 34 题 キミの記憶（Web/SSTI，`54jsekbkx1fmpdlr.neu-nex.fun`）：Jinja2 无回显，
  用 `{{1/0 if COND else 1}}` 的「渲染出错了」做布尔 oracle，`_wrap_close.__init__.__globals__['environ']`
  读到 FLAG（长 30），字符比较二分逐位外带得 `nex{C0loR_Y0uR_N19Ht_knvmh44e}`，新增 `rollout/web-kimi-no-kioku/`。
- 2026-10-26：新增第 35 题 超大杯flask（Web/Flask，`zpsrdd9p7lls0tp5.neu-nex.fun`）：按 hint 从
  `/static/backup.sql` 拿到 zc 密码，登录后用 `/restock` 的 `merge()` 做类污染
  `{"__class__":{"__init__":{"__globals__":{"IS_ADMIN":true}}}}`，`/admin` 返回
  `nex{Sup3R_B1G_cUP_lg3nfbio}`，新增 `rollout/web-super-flask/`。
