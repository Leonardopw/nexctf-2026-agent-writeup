"""Rollout logging and WP-ready summary generation."""
from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any


class RunLogger:
    def __init__(self, run_dir: Path, attempt: int):
        self.run_dir = run_dir
        self.attempt = attempt
        self.path = run_dir / f"attempt-{attempt}" / "transcript.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.start = time.time()
        self.events = 0
        self._fh = self.path.open("w", encoding="utf-8")

    def log(self, event: str, **fields: Any) -> None:
        self.events += 1
        record = {
            "ts": datetime.now().isoformat(timespec="milliseconds"),
            "attempt": self.attempt,
            "event": event,
            **fields,
        }
        self._fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._fh.flush()

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass


def _fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    return f"{d} 日 {h} 时 {m} 分 {s} 秒"


def write_summary(run_dir: Path, meta: dict[str, Any], attempts: list[dict[str, Any]]) -> Path:
    solved = [a for a in attempts if a.get("flag")]
    winner = solved[0] if solved else None
    total_time = max((a.get("duration", 0) for a in attempts), default=0)
    lines: list[str] = []
    lines.append(f"# {meta.get('name', 'challenge')} — CTF-Agent 解题记录\n")
    lines.append(f"- 运行时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"- 模型：{meta.get('model')}")
    lines.append(f"- 并发策略数：{len(attempts)}")
    lines.append(f"- 总轮次：{meta.get('steps_total', '?')}")
    if winner:
        lines.append(f"- 状态：**已解出**，flag = `{winner['flag']}`")
    else:
        lines.append("- 状态：未解出")
    lines.append("")
    lines.append("## 各策略表现\n")
    lines.append("| # | 策略 | 状态 | 步数 | 耗时 | tokens |")
    lines.append("|---|------|------|------|------|--------|")
    for a in attempts:
        status = "solved" if a.get("flag") else a.get("status", "unknown")
        lines.append(
            f"| {a['attempt']} | {a.get('strategy', '-')} | {status} | {a.get('steps', 0)} | "
            f"{_fmt_duration(a.get('duration', 0))} | {a.get('tokens', 0)} |"
        )
    lines.append("")
    if winner:
        lines.append("## NEXCTF 实测记录（可直接粘到 WP）\n")
        lines.append(f"- 题目名字：{meta.get('name')}")
        lines.append(f"- 难度：{meta.get('difficulty', '待填写')}")
        lines.append(f"- 类型：{meta.get('ctype')}")
        lines.append(f"- 耗时：{_fmt_duration(total_time)}（从第一条消息到拿到 flag）")
        lines.append(f"- Agent 使用的 LLM：{meta.get('model')}")
        lines.append(f"- Agent 评价：{winner.get('comment', '')}")
        lines.append(f"- Flag：`{winner['flag']}`")
        lines.append(f"- Rollout：`{run_dir}`")
    lines.append("")
    lines.append("## 复现命令\n")
    lines.append("```bash")
    lines.append(meta.get("command", "# 见 run.json"))
    lines.append("```")
    path = run_dir / "summary.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
