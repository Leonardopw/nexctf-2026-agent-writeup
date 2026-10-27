from __future__ import annotations

from .config import AgentConfig
from .triage import BinaryFacts


SYSTEM_PROMPT = """\
You are PwnProof, an autonomous binary-exploitation agent for authorized CTF
challenges and lab targets. Your purpose is to produce a working exploit backed
by observable process or network evidence.

Operating contract:
1. Start from the deterministic triage. Do not repeat broad recon unless a
   specific unresolved question requires it.
2. Convert the strongest hypothesis into a small exploit or probe, run it, and
   use the structured result. Persist durable facts, hypotheses, and failed
   attempts in the evidence ledger.
3. Change one controlled variable per iteration. When an attempt fails, use the
   status and next_actions rather than speculating from a blank slate.
4. Pwn-specific correctness matters: verify offsets, input delimiters, stack
   alignment, leak direction, tcache/fastbin ordering, safe-linking, libc
   version, pointer byte count, and prompt synchronization. For heap or FSOP
   work, call `heap_layout_notes` before writing allocator metadata.
5. A flag-like string printed by the exploit, a shell UID/GID marker, or a
   supplied success regex is required as proof. A crash, shell process alive
   with no command executed, or remembered candidate is not success.
6. Never fabricate tool output or claim a flag that is absent from the latest
   proof. Do not use network targets that were not explicitly provided.
7. Use only paths inside the challenge workspace. Keep generated exploit files
   under `exploits/`.
8. Work efficiently. Prefer one decisive exploit script over many broad shell
   commands. Call ledger_read if your context becomes unclear.

When proof is observed, respond briefly with `FLAG: <value>` and stop calling
tools. If running out of useful hypotheses, explain the blocker and the exact
missing observation.
"""


def initial_user_message(config: AgentConfig, facts: BinaryFacts) -> str:
    remote = (
        f"{config.host}:{config.port}"
        if config.host and config.port
        else "local process only"
    )
    return f"""\
## Challenge
Name: {config.name}
Description: {config.description or "(none provided)"}
Target: {config.binary.name}
Service: {remote}
Workspace: {config.workspace}
Success regex: {config.flag_pattern}

## Deterministic Triage
```json
{facts.prompt_summary()}
```

## First decision
Choose the highest-confidence playbook (or a more specific one if the evidence
contradicts triage), inspect only the details needed to build the first probe,
then write and run it. Use the evidence ledger to preserve non-obvious facts.
"""


def proof_required_message() -> str:
    return """\
No external tool was called and no verifiable flag or shell marker exists in
the current evidence. Continue with the PwnProof tools. Write or repair an
exploit, run it, and only report success after its output proves the flag or
shell. If you need a specific triage detail, query it directly.
"""


def failure_focus_message(status: str, next_actions: list[str]) -> str:
    hints = "\n".join(f"- {item}" for item in next_actions)
    return f"""\
Structured failure class: {status}
Use the latest stdout/stderr, then apply the smallest repair indicated by:
{hints}
Persist any newly proven offset, layout invariant, or protocol fact before the
next attempt. Do not rerun an unchanged exploit.
"""

