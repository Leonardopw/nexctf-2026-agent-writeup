"""Agent loop and multi-attempt orchestration."""
from __future__ import annotations

import copy
import json
import shutil
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .config import Config
from .llm import LLMClient
from .logger import RunLogger, write_summary
from .prompts import STRATEGIES, challenge_prompt, system_for
from .tools import TOOL_SCHEMAS, Shell, Toolbox


def _slug(text: str) -> str:
    keep = [c if (c.isalnum() or c in "-_") else "-" for c in text.strip()]
    slug = "".join(keep).strip("-")
    return slug[:40] or "challenge"


def _copy_files(files: list[str], dest: Path) -> list[str]:
    copied = []
    for raw in files:
        src = Path(raw).expanduser().resolve()
        if not src.exists():
            continue
        target = dest / src.name
        if src.is_dir():
            shutil.copytree(src, target, dirs_exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target)
        copied.append(src.name)
    return copied


def _make_comment(result: dict[str, Any]) -> str:
    steps = result.get("steps", 0)
    tools = result.get("tool_counts", {})
    top = max(tools, key=tools.get) if tools else "工具"
    status = result.get("status", "")
    if result.get("flag"):
        if steps <= 6:
            return f"{steps} 步内直取入口，{top} 用得最多，基本无卡点。"
        return f"共 {steps} 步，主要在 {top} 上迭代；调整思路后拿到 flag。"
    return f"{status}：{steps} 步未出 flag，主要卡在 {top}。"


class Attempt(threading.Thread):
    def __init__(
        self,
        cfg: Config,
        index: int,
        strategy: dict[str, Any],
        run_dir: Path,
        stop_event: threading.Event,
        llm_factory: Callable[[], Any],
        results: list[dict[str, Any]],
        lock: threading.Lock,
    ):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.index = index
        self.strategy = strategy
        self.run_dir = run_dir
        self.stop_event = stop_event
        self.llm_factory = llm_factory
        self.results = results
        self.lock = lock
        self.started = time.time()

    # ------------------------------------------------------------------
    def run(self) -> None:  # noqa: D401
        attempt_dir = self.run_dir / f"attempt-{self.index}"
        workdir = attempt_dir / "work"
        workdir.mkdir(parents=True, exist_ok=True)
        copied = _copy_files(self.cfg.files, workdir)
        logger = RunLogger(self.run_dir, self.index)
        toolbox = Toolbox(workdir, Shell(workdir, self.cfg.shell), self.cfg.flag_regex, self.cfg.max_tool_output)
        llm = self.llm_factory()
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_for(self.strategy)},
            {
                "role": "user",
                "content": challenge_prompt(
                    self.cfg.challenge_name, self.cfg.challenge_type, self.cfg.target,
                    self.cfg.hint, copied, str(workdir), self.cfg.flag_regex, self.cfg.time_budget,
                ),
            },
        ]
        logger.log("start", strategy=self.strategy["name"], model=self.cfg.model, workdir=str(workdir))
        steps = 0
        tool_counts: dict[str, int] = {}
        status = "max_steps"
        last_text = ""
        nudges = 0
        try:
            while steps < self.cfg.max_steps:
                if self.stop_event.is_set():
                    status = "stopped"
                    break
                if time.time() - self.started > self.cfg.time_budget:
                    status = "timeout"
                    break
                steps += 1
                try:
                    reply = llm.chat(messages, TOOL_SCHEMAS, temperature=self.strategy["temperature"])
                except Exception as exc:  # noqa: BLE001
                    logger.log("llm_error", step=steps, error=str(exc))
                    status = "llm_error"
                    break
                messages.append(reply)
                content = (reply.get("content") or "").strip()
                if content:
                    last_text = content
                    logger.log("assistant", step=steps, content=content[:2000])
                tool_calls = reply.get("tool_calls") or []
                if not tool_calls:
                    nudges += 1
                    if nudges > 3:
                        status = "no_tool_calls"
                        break
                    messages.append({
                        "role": "user",
                        "content": "请继续推进：调用工具做下一步验证；如果已经有充分证据，用 submit_flag 提交。",
                    })
                    continue
                nudges = 0
                for call in tool_calls:
                    fn = (call.get("function") or {})
                    name = fn.get("name") or ""
                    try:
                        args = json.loads(fn.get("arguments") or "{}")
                    except Exception:
                        args = {}
                    logger.log("tool_call", step=steps, name=name, args=args)
                    output = toolbox.execute(name, args)
                    tool_counts[name] = tool_counts.get(name, 0) + 1
                    logger.log("tool_result", step=steps, name=name, output=output[:4000])
                    messages.append({
                        "role": "tool",
                        "tool_call_id": call.get("id", ""),
                        "content": output,
                    })
                    if toolbox.flag:
                        status = "solved"
                        break
                if toolbox.flag:
                    break
            if toolbox.flag:
                status = "solved"
        except Exception:  # noqa: BLE001
            logger.log("crash", traceback=traceback.format_exc())
            status = "crash"
        finally:
            duration = time.time() - self.started
            result = {
                "attempt": self.index,
                "strategy": self.strategy["name"],
                "status": status,
                "steps": steps,
                "duration": duration,
                "flag": toolbox.flag,
                "tool_counts": tool_counts,
                "tokens": sum(llm.usage.values()) if hasattr(llm, "usage") else 0,
                "model": self.cfg.model,
                "last_text": last_text[:1000],
            }
            result["comment"] = _make_comment(result)
            logger.log("finish", **{k: v for k, v in result.items() if k != "tool_counts"})
            logger.close()
            (attempt_dir / "result.json").write_text(
                json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            if toolbox.flag:
                self.stop_event.set()
            with self.lock:
                self.results.append(result)

    # ------------------------------------------------------------------
    def stop(self) -> None:
        self.stop_event.set()


def run(cfg: Config, llm_factory: Callable[[], Any] | None = None) -> dict[str, Any]:
    cfg.validate()
    if llm_factory is None:
        def llm_factory() -> LLMClient:  # noqa: F811
            return LLMClient(cfg.base_url, cfg.api_key, cfg.model)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = Path(cfg.run_dir) if cfg.run_dir else (
        Path(__file__).resolve().parent.parent / "runs" / f"{stamp}-{_slug(cfg.challenge_name)}"
    )
    run_dir.mkdir(parents=True, exist_ok=True)

    strategies = STRATEGIES[: max(1, min(cfg.attempts, len(STRATEGIES)))]
    if cfg.attempts > len(strategies):
        strategies = [STRATEGIES[i % len(STRATEGIES)] for i in range(cfg.attempts)]

    stop_event = threading.Event()
    results: list[dict[str, Any]] = []
    lock = threading.Lock()
    threads = [
        Attempt(cfg, i + 1, strategies[i], run_dir, stop_event, llm_factory, results, lock)
        for i in range(len(strategies))
    ]
    started = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    duration = time.time() - started

    meta = {
        "name": cfg.challenge_name,
        "ctype": cfg.challenge_type,
        "target": cfg.target,
        "hint": cfg.hint,
        "difficulty": cfg.difficulty,
        "model": cfg.model,
        "steps_total": sum(r.get("steps", 0) for r in results),
        "duration": duration,
        "command": " ".join(["python", "-m", "ctfagent", "--name", cfg.challenge_name, "--target", cfg.target]),
    }
    (run_dir / "run.json").write_text(
        json.dumps({"config": copy.deepcopy(cfg.__dict__), "results": results}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    summary = write_summary(run_dir, meta, results)
    winner = next((r for r in results if r.get("flag")), None)
    return {
        "run_dir": str(run_dir),
        "summary": str(summary),
        "flag": winner["flag"] if winner else None,
        "results": results,
        "duration": duration,
    }
