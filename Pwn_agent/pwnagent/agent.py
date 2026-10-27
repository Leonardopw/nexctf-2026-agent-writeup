"""Multi-attempt, proof-gated PwnAgent orchestrator.

Design blend:
- PwnProof: deterministic triage, evidence ledger, proof gate, failure classes,
  libc/heap tools, single-attempt ReAct loop.
- ctf-agent: parallel attempts with different strategies, time budget,
  reflection/compaction, run summaries.
"""

from __future__ import annotations

import json
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import PwnAgentConfig
from .heuristics import generate_candidate, generate_for_strategy
from .planner import Strategy, available_playbooks, plan_strategies
from .prompts import (
    SYSTEM_PROMPT,
    compaction_note,
    initial_message,
    proof_required_message,
    reflection_message,
    strategy_system_prompt,
)
from .tools import TOOL_SCHEMAS, PwnToolbox
from .vendor.pwnproof.ledger import EvidenceLedger
from .vendor.pwnproof.model import ModelClient, ModelError
from .vendor.pwnproof.prompt import failure_focus_message
from .vendor.pwnproof.runtime import LinuxRuntime
from .vendor.pwnproof.triage import triage

COPY_IGNORE = shutil.ignore_patterns(
    "exploits", "artifacts", "__pycache__", ".git", ".pwnagent", "*.bak-*"
)
MAX_CONTEXT_MESSAGES = 30
KEEP_RECENT_MESSAGES = 22
SHRINK_TOOL_CHARS = 3500


class RolloutWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq = 0

    def event(self, kind: str, payload: Any) -> None:
        with self._lock:
            self._seq += 1
            record = {
                "seq": self._seq,
                "time": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "event": kind,
                "payload": payload,
            }
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")


def _copy_challenge(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dst, dirs_exist_ok=True, ignore=COPY_IGNORE)


def _relative_target(binary: Path, workspace: Path) -> Path:
    try:
        return binary.relative_to(workspace)
    except ValueError:
        return Path(binary.name)


def _shrink_old_tools(messages: list[dict[str, Any]]) -> int:
    tool_indexes = [i for i, m in enumerate(messages) if m.get("role") == "tool"]
    if len(tool_indexes) <= 6:
        return 0
    changed = 0
    for i in tool_indexes[:-6]:
        content = messages[i].get("content") or ""
        if len(content) > SHRINK_TOOL_CHARS:
            messages[i]["content"] = content[:SHRINK_TOOL_CHARS] + "\n... [old tool output compressed]"
            changed += 1
    return changed


def _compact(messages: list[dict[str, Any]], ledger: EvidenceLedger) -> bool:
    if len(messages) <= MAX_CONTEXT_MESSAGES:
        return False
    _shrink_old_tools(messages)
    head = messages[:2]
    tail = messages[-KEEP_RECENT_MESSAGES:]
    while tail and tail[0].get("role") == "tool":
        tail = tail[1:]
    note = {"role": "user", "content": compaction_note(ledger.summary(30))}
    messages[:] = head + [note] + tail
    return True


class PwnAttempt(threading.Thread):
    def __init__(
        self,
        config: PwnAgentConfig,
        strategy: Strategy,
        index: int,
        run_dir: Path,
        stop_event: threading.Event,
        results: list[dict[str, Any]],
        lock: threading.Lock,
        fast_only: bool = False,
    ) -> None:
        super().__init__(daemon=True)
        self.config = config
        self.strategy = strategy
        self.index = index
        self.run_dir = run_dir
        self.stop_event = stop_event
        self.results = results
        self.lock = lock
        self.fast_only = fast_only
        self.started = time.monotonic()
        self.attempt_dir = run_dir / f"attempt-{index}"
        self.rollout = RolloutWriter(self.attempt_dir / "rollout.jsonl")
        self.toolbox: PwnToolbox | None = None
        self.ledger: EvidenceLedger | None = None
        self.facts = None
        self.attempt_config: PwnAgentConfig | None = None
        self.total_usage: dict[str, int] = {}
        self.tool_counts: dict[str, int] = {}
        self.steps = 0
        self.last_status = ""
        self.last_next: list[str] = []

    # ------------------------------------------------------------------
    def run(self) -> None:
        try:
            self._run_inner()
        except Exception as exc:  # noqa: BLE001
            self._finish("crash", reason=f"{type(exc).__name__}: {exc}", flags=[])

    def _run_inner(self) -> None:
        if self.stop_event.is_set():
            self._finish("stopped", reason="another attempt finished first", flags=[])
            return
        workdir = self.attempt_dir / "work"
        _copy_challenge(self.config.workspace, workdir)
        target = workdir / _relative_target(self.config.binary, self.config.workspace)
        source = None
        if self.config.source:
            source = workdir / _relative_target(self.config.source, self.config.workspace)
        exploit_dir = workdir / "exploits"
        exploit_dir.mkdir(parents=True, exist_ok=True)

        libc = self.config.libc
        if libc:
            try:
                libc = str(workdir / Path(libc).resolve().relative_to(self.config.workspace.resolve()))
            except ValueError:
                pass

        self.attempt_config = PwnAgentConfig(
            binary=target,
            workspace=workdir,
            source=source,
            name=self.config.name,
            description=self.config.description,
            host=self.config.host,
            port=self.config.port,
            flag_pattern=self.config.flag_pattern,
            success_patterns=self.config.success_patterns,
            model=self.config.model,
            base_url=self.config.base_url,
            api_key=<REDACTED>
            temperature=self.strategy.temperature,
            max_steps=self.config.max_steps,
            request_timeout=self.config.request_timeout,
            command_timeout=self.config.command_timeout,
            attempts=1,
            time_budget=self.config.time_budget,
            playbooks=(self.strategy.name,),
            distro=self.config.distro,
            runtime=self.config.runtime,
            local_flag=self.config.local_flag,
            libc=libc,
            gef_path=self.config.gef_path,
            artifact_root=self.attempt_dir / "artifacts",
        )
        runtime = LinuxRuntime(workdir, distro=self.config.distro, mode=self.config.runtime)
        self.rollout.event(
            "attempt_start",
            {
                "attempt": self.index,
                "strategy": self.strategy.name,
                "focus": self.strategy.focus,
                "binary": str(target),
                "workspace": str(workdir),
                "model": self.config.model,
                "runtime": runtime.mode,
            },
        )
        facts = triage(target, workdir, runtime, source=source)
        self.facts = facts
        (self.attempt_dir / "triage.json").write_text(
            json.dumps(facts.to_dict(include_raw=True), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        self.rollout.event("triage", facts.to_dict())
        self.ledger = EvidenceLedger(self.attempt_dir / "evidence.jsonl")
        for hypothesis in facts.hypotheses[:5]:
            self.ledger.add("hypothesis", f"{hypothesis.playbook} ({hypothesis.confidence:.2f}): {hypothesis.reason}")
        self.toolbox = PwnToolbox(self.attempt_config, runtime, facts, self.ledger, self.attempt_dir)

        # deterministic fast path for the matching playbook
        if self.stop_event.is_set():
            self._finish("stopped", reason="another attempt finished first", flags=[])
            return
        candidate = (
            generate_candidate(facts, workdir, exploit_dir)
            if self.fast_only
            else generate_for_strategy(self.strategy.name, facts, workdir, exploit_dir)
        )
        if candidate is not None:
            self.rollout.event("heuristic_candidate", str(candidate))
            result = self.toolbox.dispatch(
                "run_exploit",
                {"path": str(candidate.relative_to(workdir)), "timeout_seconds": 30},
            )
            self.rollout.event("heuristic_result", json.loads(result))
            if self.toolbox.captured_flags:
                self._finish(
                    "success",
                    reason=f"deterministic {self.strategy.name} candidate produced proof",
                    flags=self.toolbox.captured_flags,
                )
                return
        if self.fast_only:
            self._finish(
                "no_proof",
                reason=(
                    "no deterministic candidate produced proof"
                    if candidate is not None
                    else "no deterministic ret2win/ret2libc/fmtstr candidate matched"
                ),
                flags=[],
            )
            return

        client = ModelClient(
            base_url=self.config.base_url,
            api_key=<REDACTED>
            model=self.config.model,
            timeout=self.config.request_timeout,
            temperature=self.strategy.temperature,
        )
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": strategy_system_prompt(SYSTEM_PROMPT, self.strategy)},
            {"role": "user", "content": initial_message(self.config, facts, self.strategy)},
        ]
        self.rollout.event("initial_context", messages)
        final_reason = "max steps reached without proof"
        nudges = 0

        for step in range(1, self.config.max_steps + 1):
            self.steps = step
            if self.stop_event.is_set():
                final_reason = "stopped: another attempt produced proof"
                break
            if time.monotonic() - self.started > self.config.time_budget:
                final_reason = "attempt time budget exhausted"
                break

            if len(messages) > MAX_CONTEXT_MESSAGES:
                if _compact(messages, self.ledger):
                    self.rollout.event("compact", {"step": step, "messages": len(messages)})

            try:
                reply = client.complete(messages, TOOL_SCHEMAS)
            except ModelError as exc:
                final_reason = f"model error: {exc}"
                self.rollout.event("model_error", str(exc))
                break

            self._merge_usage(reply.usage)
            assistant = dict(reply.message)
            assistant.setdefault("role", "assistant")
            messages.append(assistant)
            self.rollout.event(
                "model",
                {"step": step, "message": assistant, "usage": reply.usage},
            )
            tool_calls = assistant.get("tool_calls") or []
            if not tool_calls:
                nudges += 1
                if nudges > 3:
                    final_reason = "model stopped calling tools without proof"
                    break
                messages.append({"role": "user", "content": proof_required_message()})
                self.rollout.event("proof_gate", "no tool call")
                continue
            nudges = 0

            attempted = False
            for call in tool_calls:
                function = call.get("function", {})
                name = str(function.get("name", ""))
                raw = function.get("arguments", "{}")
                try:
                    arguments = json.loads(raw) if isinstance(raw, str) else (raw or {})
                except json.JSONDecodeError:
                    arguments = {}
                self.tool_counts[name] = self.tool_counts.get(name, 0) + 1
                output = self.toolbox.dispatch(name, arguments)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.get("id", ""),
                        "name": name,
                        "content": output,
                    }
                )
                self.rollout.event(
                    "tool",
                    {"step": step, "name": name, "arguments": arguments, "result": output},
                )
                if name == "run_exploit":
                    attempted = True
                if self.toolbox.captured_flags:
                    break

            if self.toolbox.captured_flags:
                self._finish(
                    "success",
                    reason="proof captured from exploit output",
                    flags=self.toolbox.captured_flags,
                )
                return

            if attempted and self.toolbox.attempts:
                last = self.toolbox.attempts[-1]
                self.last_status = last.status
                self.last_next = list(last.next_actions)
                if last.status != "success":
                    messages.append(
                        {"role": "user", "content": failure_focus_message(last.status, last.next_actions)}
                    )
                    self.rollout.event("failure_focus", last.status)
            if step % 5 == 0:
                messages.append(
                    {"role": "user", "content": reflection_message(step, self.last_status or "unknown", self.last_next)}
                )
                self.rollout.event("reflection", {"step": step, "status": self.last_status})

        self._finish("no_proof", reason=final_reason, flags=[])

    # ------------------------------------------------------------------
    def _merge_usage(self, usage: dict[str, int]) -> None:
        for key, value in usage.items():
            self.total_usage[key] = self.total_usage.get(key, 0) + value

    def _finish(self, status: str, *, reason: str, flags: list[str]) -> None:
        duration = round(time.monotonic() - self.started, 3)
        summary = {
            "agent": "PwnAgent",
            "version": "0.1.0",
            "attempt": self.index,
            "strategy": self.strategy.name,
            "focus": self.strategy.focus,
            "status": status,
            "reason": reason,
            "flags": list(dict.fromkeys(flags)),
            "challenge": self.config.name,
            "binary": str(self.config.binary),
            "model": self.config.model,
            "duration_seconds": duration,
            "steps": self.steps,
            "tool_counts": self.tool_counts,
            "usage": self.total_usage,
            "artifact_dir": str(self.attempt_dir),
            "triage_path": str(self.attempt_dir / "triage.json"),
            "rollout_path": str(self.attempt_dir / "rollout.jsonl"),
            "evidence_path": str(self.attempt_dir / "evidence.jsonl"),
        }
        (self.attempt_dir / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        self.rollout.event("finish", summary)
        if flags:
            self.stop_event.set()
        with self.lock:
            self.results.append(summary)


def _write_summary(run_dir: Path, meta: dict[str, Any], results: list[dict[str, Any]]) -> Path:
    lines = [
        f"# PwnAgent run: {meta['name']}",
        "",
        f"- target: `{meta['binary']}`",
        f"- model: `{meta['model']}`",
        f"- started: {meta['started']}",
        f"- duration: {meta['duration']:.1f}s",
        f"- attempts: {len(results)}",
        f"- strategies: {', '.join(meta['strategies'])}",
        "",
        "| # | strategy | status | flags | time |",
        "|---|---|---|---|---|",
    ]
    for item in results:
        flags = ", ".join(item.get("flags") or []) or "-"
        lines.append(
            f"| {item.get('attempt')} | {item.get('strategy')} | {item.get('status')} | {flags} | {item.get('duration_seconds')}s |"
        )
    winner = next((item for item in results if item.get("flags")), None)
    lines += ["", "## Result", ""]
    if winner:
        lines.append(f"**PROOF:** `{', '.join(winner['flags'])}` via `{winner['strategy']}`")
    else:
        lines.append("No proof. See each attempt's `rollout.jsonl` and `summary.json`.")
    path = run_dir / "summary.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


class PwnAgent:
    def __init__(self, config: PwnAgentConfig) -> None:
        self.config = config
        self.started = time.monotonic()
        self.run_dir: Path | None = None

    def run(self) -> dict[str, Any]:
        config = self.config
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        slug = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in config.name)[:40] or "pwn"
        self.run_dir = config.artifact_root / f"{stamp}-{slug}"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        runtime = LinuxRuntime(config.workspace, distro=config.distro, mode=config.runtime)
        facts = triage(config.binary, config.workspace, runtime, source=config.source)
        strategies = plan_strategies(facts, attempts=config.attempts, requested=config.playbooks)
        (self.run_dir / "run.json").write_text(
            json.dumps(
                {
                    "config": {
                        "binary": str(config.binary),
                        "workspace": str(config.workspace),
                        "name": config.name,
                        "model": config.model,
                        "attempts": config.attempts,
                        "max_steps": config.max_steps,
                    },
                    "playbooks": [
                        {"name": name, "confidence": confidence, "reason": reason}
                        for name, confidence, reason in available_playbooks(facts)
                    ],
                    "strategies": [strategy.__dict__ for strategy in strategies],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        (self.run_dir / "triage.json").write_text(
            json.dumps(facts.to_dict(include_raw=True), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        results: list[dict[str, Any]] = []
        lock = threading.Lock()
        stop_event = threading.Event()
        attempts = [
            PwnAttempt(config, strategy, index + 1, self.run_dir, stop_event, results, lock)
            for index, strategy in enumerate(strategies)
        ]
        if config.parallel:
            for attempt in attempts:
                attempt.start()
            for attempt in attempts:
                attempt.join()
        else:
            for attempt in attempts:
                attempt.start()
                attempt.join()
                if stop_event.is_set():
                    break

        duration = time.monotonic() - self.started
        results.sort(key=lambda item: item.get("attempt", 0))
        winner = next((item for item in results if item.get("flags")), None)
        meta = {
            "name": config.name,
            "binary": str(config.binary),
            "model": config.model,
            "started": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration": duration,
            "strategies": [strategy.name for strategy in strategies],
        }
        summary_path = _write_summary(self.run_dir, meta, results)
        return {
            "run_dir": str(self.run_dir),
            "summary": str(summary_path),
            "flag": winner["flags"][0] if winner else None,
            "flags": winner["flags"] if winner else [],
            "strategy": winner["strategy"] if winner else None,
            "results": results,
            "duration": duration,
        }

    def heuristic_only(self) -> dict[str, Any]:
        """Run deterministic fast paths only; no model/API key required."""

        config = self.config
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        slug = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in config.name)[:40] or "pwn"
        self.run_dir = config.artifact_root / f"{stamp}-{slug}-fast"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        strategy = Strategy("fast", 0.0, "deterministic fast paths", "", ())
        results: list[dict[str, Any]] = []
        lock = threading.Lock()
        stop_event = threading.Event()
        attempt = PwnAttempt(
            config, strategy, 1, self.run_dir, stop_event, results, lock, fast_only=True
        )
        attempt.start()
        attempt.join()
        duration = time.monotonic() - self.started
        winner = next((item for item in results if item.get("flags")), None)
        meta = {
            "name": config.name,
            "binary": str(config.binary),
            "model": "(deterministic only)",
            "started": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration": duration,
            "strategies": ["fast"],
        }
        summary_path = _write_summary(self.run_dir, meta, results)
        return {
            "run_dir": str(self.run_dir),
            "summary": str(summary_path),
            "flag": winner["flags"][0] if winner else None,
            "flags": winner["flags"] if winner else [],
            "strategy": winner["strategy"] if winner else None,
            "results": results,
            "duration": duration,
        }
