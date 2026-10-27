"""Deterministic planner: turn ELF facts into diverse exploit attempts."""

from __future__ import annotations

from dataclasses import dataclass, field

from .vendor.pwnproof.triage import BinaryFacts, Hypothesis


@dataclass(frozen=True)
class Strategy:
    name: str
    temperature: float
    focus: str
    prompt: str
    tools: tuple[str, ...] = field(default_factory=tuple)


def _hypothesis_map(facts: BinaryFacts) -> dict[str, float]:
    return {item.playbook: item.confidence for item in facts.hypotheses}


def _protection(facts: BinaryFacts, key: str) -> str:
    return str(facts.protections.get(key, "")).lower()


def _has_win(facts: BinaryFacts) -> bool:
    names = {"win", "get_shell", "give_shell", "backdoor", "shell", "print_flag", "cat_flag"}
    return any(name in facts.symbols for name in names)


def _has_nx(facts: BinaryFacts) -> bool:
    nx = _protection(facts, "nx")
    return "enabled" in nx and "disabled" not in nx


def available_playbooks(facts: BinaryFacts) -> list[tuple[str, float, str]]:
    """Return (playbook, confidence, reason) ranked by evidence."""
    hyps = _hypothesis_map(facts)
    out: list[tuple[str, float, str]] = []

    def add(name: str, confidence: float, reason: str) -> None:
        out.append((name, round(confidence, 3), reason))

    if _has_win(facts) and hyps.get("stack_overflow", 0) >= 0.6:
        add("ret2win", max(hyps.get("ret2win", 0.0), 0.92), "win-like symbol plus stack overflow")
    if hyps.get("stack_overflow", 0) >= 0.6 and _has_nx(facts):
        add("ret2libc", max(hyps.get("ret2libc", 0.0), 0.82), "NX stack overflow; libc leak/return path")
    if hyps.get("format_string", 0) >= 0.6:
        add("fmtstr", max(hyps["format_string"], 0.9), "user-controlled printf-family format")
    if hyps.get("heap_exploitation", 0) >= 0.6:
        add("heap", max(hyps["heap_exploitation"], 0.78), "allocator APIs present; inspect UAF/overflow/tcache")
    if hyps.get("sandbox_escape_or_orw", 0) >= 0.6:
        add("orw", max(hyps["sandbox_escape_or_orw"], 0.8), "seccomp/prctl; ORW or sandbox escape")
    if hyps.get("mprotect_shellcode", 0) >= 0.5:
        add("shellcode", max(hyps["mprotect_shellcode"], 0.7), "mprotect/mmap imported; RWX transition")
    if hyps.get("stack_overflow", 0) >= 0.6 and _has_nx(facts):
        add("rop", 0.7, "stack control with NX; gadgets/ret2csu/syscall")
    if not out:
        add("manual", 0.45, "no high-confidence primitive; inspect protocol/disassembly")

    # de-duplicate and sort
    seen: set[str] = set()
    ranked: list[tuple[str, float, str]] = []
    for name, confidence, reason in sorted(out, key=lambda item: item[1], reverse=True):
        if name in seen:
            continue
        seen.add(name)
        ranked.append((name, confidence, reason))
    return ranked


PROMPTS: dict[str, tuple[float, str, str]] = {
    "ret2win": (
        0.05,
        "ret2win / direct control-flow hijack",
        "Find the exact offset with the `offset` tool (cyclic + GDB), verify the win symbol, "
        "check x86-64 stack alignment, then write the smallest ret2win exploit.",
    ),
    "ret2libc": (
        0.10,
        "ret2libc: leak -> libc base -> system('/bin/sh')",
        "Use `offset` first. Leak a GOT entry with puts/printf/write, use `libc_match` to derive "
        "the base and symbol offsets, then build stage 2 with `rop_plan`. Verify alignment and prompts.",
    ),
    "fmtstr": (
        0.12,
        "format string: locate argument index, leak, then write",
        "Use `fmtstr_plan` for a leak/write payload. First map which stack index contains your input "
        "(`%p` scan), then leak libc/stack, then write GOT/return/hook. Prefer `%N$` only when accepted.",
    ),
    "heap": (
        0.18,
        "heap: audit ownership -> UAF/overflow -> tcache/fastbin/FSOP",
        "Before writing metadata call `heap_plan` with the libc release. Verify chunk sizes, tcache "
        "counts, safe-linking, and the exact libc hook/vtable symbols. One controlled variable per run.",
    ),
    "orw": (
        0.15,
        "sandbox/ORW: enumerate seccomp, then open/read/write",
        "Call `seccomp` to enumerate allowed syscalls. If execve is blocked, use ORW via `rop_plan` "
        "or shellcode; put the flag path in a writable region and avoid null bytes.",
    ),
    "shellcode": (
        0.15,
        "shellcode: get a writable+executable region, then jump",
        "Check NX/mprotect; use `offset` and `rop_plan` to call mprotect/read, then jump to shellcode. "
        "Keep the shellcode small and verify the exact byte count.",
    ),
    "rop": (
        0.20,
        "ROP: gadget discovery, ret2csu, syscall chains",
        "Use `gadgets`, `rop_plan`, and `disasm`. If direct pop rdi/rsi/rdx are missing, use ret2csu "
        "or libc gadgets. Verify the chain on a local process before remote.",
    ),
    "manual": (
        0.35,
        "manual protocol analysis and staged probing",
        "Read the binary's interaction, use `disasm` and `debug`, form one small hypothesis, and "
        "test it with a probe. Persist every confirmed offset/protocol fact in the ledger.",
    ),
}


def plan_strategies(facts: BinaryFacts, *, attempts: int = 3, requested: tuple[str, ...] = ()) -> list[Strategy]:
    ranked = available_playbooks(facts)
    if requested:
        order = {name: index for index, name in enumerate(requested)}
        ranked = [item for item in ranked if item[0] in order]
        ranked.sort(key=lambda item: order[item[0]])
        for name in requested:
            if name not in {item[0] for item in ranked} and name in PROMPTS:
                ranked.append((name, 0.4, "requested playbook"))
    if not ranked:
        ranked = [("manual", 0.45, "fallback")]

    chosen: list[tuple[str, float, str]] = []
    for item in ranked:
        if item[0] not in {entry[0] for entry in chosen}:
            chosen.append(item)
        if len(chosen) >= attempts:
            break

    # diversity fallback: add a generic ROP/manual attempt when under-subscribed
    for fallback in ("rop", "manual"):
        if len(chosen) >= attempts:
            break
        if fallback not in {entry[0] for entry in chosen}:
            chosen.append((fallback, 0.4, "diversity fallback"))

    strategies: list[Strategy] = []
    for name, confidence, reason in chosen[:attempts]:
        temperature, focus, prompt = PROMPTS.get(name, PROMPTS["manual"])
        strategies.append(
            Strategy(
                name=name,
                temperature=temperature,
                focus=f"{focus} (confidence {confidence:.2f}: {reason})",
                prompt=prompt,
            )
        )
    return strategies
