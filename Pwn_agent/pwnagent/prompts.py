"""Prompt layer: proof-gated pwn loop with deterministic tools and strategy focus."""

from __future__ import annotations

from .config import PwnAgentConfig
from .planner import Strategy
from .vendor.pwnproof.triage import BinaryFacts


SYSTEM_PROMPT = """\
You are PwnAgent, an autonomous binary-exploitation agent for authorized CTF
challenges and local labs. Your purpose is a working exploit backed by
observable evidence (flag, shell UID, or an explicit success marker).

Operating contract:
1. Start from deterministic triage. Do not repeat broad recon.
2. Use the dedicated tools before guessing:
   - `offset` for cyclic/GDB offset and crashing register;
   - `libc_info` / `libc_match` for release, symbol offsets, /bin/sh, hooks;
   - `rop_plan` for system/execve/ORW chains; `fmtstr_plan` for format payloads;
   - `heap_plan` before heap metadata; `seccomp` before choosing execve vs ORW;
   - `debug`/`disasm` for crash and control-flow questions.
3. Change one controlled variable per iteration. Persist durable facts and
   failures in the evidence ledger.
4. Pwn correctness matters: verify offsets, delimiters, x86-64 stack alignment,
   leak width, tcache order, safe-linking, libc version, pointer alignment,
   and prompt synchronization.
5. A crash, a live shell with no command output, or a remembered candidate is
   not success. Only a flag-like string, UID/GID marker, or supplied regex is
   proof.
6. Never fabricate output. Do not touch targets that were not supplied. Keep
   generated files under `exploits/`.
7. Prefer one decisive exploit script over many broad shell commands. When the
   context is unclear, call `ledger_read`.

When proof is observed, reply briefly with `FLAG: <value>` and stop.
"""


def strategy_system_prompt(base: str, strategy: Strategy) -> str:
    return (
        base
        + "\n\n## This attempt's specialization\n"
        + f"Playbook: {strategy.name}\n"
        + f"Focus: {strategy.focus}\n"
        + strategy.prompt
    )


def initial_message(config: PwnAgentConfig, facts: BinaryFacts, strategy: Strategy) -> str:
    remote = f"{config.host}:{config.port}" if config.host and config.port else "local process only"
    return f"""\
## Challenge
Name: {config.name}
Description: {config.description or "(none)"}
Target: {config.binary.name}
Service: {remote}
Workspace: {config.workspace}
Success regex: {config.flag_pattern}

## Attempt strategy
{strategy.name}: {strategy.focus}
{strategy.prompt}

## Deterministic triage
```json
{facts.prompt_summary()}
```

## First move
Convert the strongest hypothesis into one small probe or exploit. If it is a
stack bug, call `offset` first; if it leaks a libc pointer, call `libc_match`;
if it is a heap bug, call `heap_plan` before writing metadata. Then write the
exploit under `exploits/` and run it with `run_exploit`.
"""


def proof_required_message() -> str:
    return """\
No external tool was called and no proof exists in current evidence. Continue
with a concrete probe: write/repair an exploit, run it, and only report success
after its output proves the flag or shell. Use `ledger_read` if context is lost.
"""


def reflection_message(step: int, status: str, next_actions: list[str]) -> str:
    hints = "\n".join(f"- {item}" for item in next_actions) if next_actions else "- Re-read the latest failure and change one variable."
    return f"""\
Reflection at step {step}: last structured failure class = {status}.
Do not rerun an unchanged exploit. Apply the smallest repair:
{hints}
Persist any new offset/layout/protocol fact before the next attempt.
"""


def compaction_note(ledger_summary: str) -> str:
    return (
        "Context was compacted. Durable evidence ledger:\n"
        + (ledger_summary or "(empty)")
        + "\nContinue from these facts; do not repeat completed work."
    )
