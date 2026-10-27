"""Append a solved challenge record to the NEXCTF Agent-Engineer writeup."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any


def _fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    return f"{d} 日 {h} 时 {m} 分 {s} 秒"


def append_record(wp_path: str, result: dict[str, Any], name: str, ctype: str, difficulty: str) -> str:
    path = Path(wp_path)
    if not path.exists():
        return f"[wp] 文件不存在：{path}"
    text = path.read_text(encoding="utf-8")
    numbers = [int(n) for n in re.findall(r"### 第 (\d+) 题", text)]
    index = max(numbers, default=0) + 1
    winner = next((r for r in result.get("results", []) if r.get("flag")), None)
    if not winner:
        return "[wp] 未解出，未写入"
    block = (
        f"\n### 第 {index} 题：{name}\n\n"
        f"- **题目名字**：{name}\n"
        f"- **难度**：{difficulty or '待填写'}\n"
        f"- **类型**：{ctype}\n"
        f"- **耗时**：{_fmt_duration(result.get('duration', 0))}（约；{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 完成）\n"
        f"- **Agent 解这道题时使用的 LLM**：{winner.get('model', '')}\n"
        f"- **Agent 评价**：{winner.get('comment', '')}\n"
        f"- **Flag**：`{winner['flag']}`\n"
    )
    marker = "\n---\n\n## 三、更新日志"
    if marker in text:
        text = text.replace(marker, block + marker, 1)
    else:
        text += "\n" + block
    log_line = f"- {datetime.now().strftime('%Y-%m-%d')}：追加第 {index} 题 {name}（{ctype}），flag 已写入。\n"
    text = text.rstrip("\n") + "\n" + log_line
    path.write_text(text, encoding="utf-8")
    return f"[wp] 已写入第 {index} 题到 {path}"
