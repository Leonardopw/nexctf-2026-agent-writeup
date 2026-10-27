from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import AgentConfig
from .ledger import EvidenceLedger
from .runtime import CommandResult, LinuxRuntime, check_command, safe_relative_path, shlex_quote
from .triage import BinaryFacts


MAX_TOOL_RESULT_CHARS = 22_000


TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "get_triage",
            "description": "Return the deterministic ELF triage and ranked exploit hypotheses.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a text file inside the challenge workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "max_chars": {"type": "integer", "default": 20000},
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Create or replace a text file inside the challenge workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_command",
            "description": (
                "Run a bounded Linux shell command in the challenge workspace. "
                "Use this for objdump, readelf, checksec, GDB batch mode, ROPgadget, "
                "and short direct probes."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "timeout_seconds": {"type": "integer", "default": 30},
                },
                "required": ["command"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "symbols",
            "description": "List matching ELF symbols and addresses. Main, vuln, win-like names are prioritized.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filter": {
                        "type": "string",
                        "description": "Optional case-insensitive regular expression or substring.",
                        "default": "",
                    }
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "gadgets",
            "description": "Search ROP gadgets with ROPgadget and return a bounded list.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filter": {
                        "type": "string",
                        "description": "Optional regex such as 'pop rdi' or 'syscall'.",
                        "default": "",
                    }
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "libc_identify",
            "description": (
                "Return local libc candidates from the challenge workspace, "
                "PWNPROOF_LIBC, and the analysis runtime. Candidates are not "
                "runtime-confirmed until matched against a process mapping or leak."
            ),
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "heap_layout_notes",
            "description": (
                "Return version-aware glibc tcache, safe-linking, allocator "
                "invariant, and wide-FILE/FSOP facts. Use before writing heap "
                "metadata so field layouts are not guessed."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "libc_release": {
                        "type": "string",
                        "description": "Optional release such as 2.39 or 2.43.",
                    },
                    "chunk_size": {
                        "type": "integer",
                        "description": "Optional chunk size including the 0x10 header.",
                    },
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_exploit",
            "description": (
                "Execute a pwntools or standard-library exploit file against the challenge. "
                "The runner sets TARGET, TARGET_NAME, TARGET_DIR, HOST, and PORT. "
                "Success must be observable in stdout/stderr."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "timeout_seconds": {"type": "integer", "default": 45},
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ledger_write",
            "description": "Persist a compact reusable fact, hypothesis, failure, plan, or success.",
            "parameters": {
                "type": "object",
                "properties": {
                    "kind": {
                        "type": "string",
                        "enum": ["fact", "hypothesis", "failure", "success", "artifact", "plan"],
                    },
                    "text": {"type": "string"},
                },
                "required": ["kind", "text"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ledger_read",
            "description": "Read recent persistent evidence before choosing a new strategy.",
            "parameters": {
                "type": "object",
                "properties": {"limit": {"type": "integer", "default": 30}},
                "additionalProperties": False,
            },
        },
    },
]


@dataclass
class Attempt:
    number: int
    path: str
    command: str
    exit_code: int | None
    status: str
    evidence: list[str]
    stdout: str
    stderr: str
    timed_out: bool
    duration_seconds: float
    next_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "number": self.number,
            "path": self.path,
            "command": self.command,
            "exit_code": self.exit_code,
            "status": self.status,
            "evidence": self.evidence,
            "stdout": self.stdout[-5000:],
            "stderr": self.stderr[-5000:],
            "timed_out": self.timed_out,
            "duration_seconds": self.duration_seconds,
            "next_actions": self.next_actions,
        }


class ProofGate:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.flag_pattern = re.compile(config.flag_pattern)
        self.user_patterns = [re.compile(item, re.MULTILINE) for item in config.success_patterns]

    def inspect(self, result: CommandResult) -> tuple[str, list[str], list[str]]:
        text = f"{result.stdout}\n{result.stderr}"
        evidence: list[str] = []
        flags: list[str] = []
        for match in self.flag_pattern.finditer(text):
            value = match.group(0).strip()
            if value.lower() in {"flag{flag}", "flag{placeholder}", "ctf{placeholder}"}:
                continue
            flags.append(value)
            evidence.append(f"proof pattern matched: {value}")
        for pattern in self.user_patterns:
            match = pattern.search(text)
            if match:
                value = match.group(0).strip()
                flags.append(value)
                evidence.append(f"custom success marker matched: {value}")
        shell_markers = re.findall(
            r"(?im)^uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\).*$",
            text,
        )
        evidence.extend(f"shell marker: {item}" for item in shell_markers)
        if flags:
            return "success", list(dict.fromkeys(flags)), evidence
        if result.timed_out:
            return "io_desync_or_hang", [], evidence
        lowered = f"{text}\n{result.exit_code}".lower()
        classifications = [
            ("missing_dependency", ("modulenotfounderror", "no module named", "command not found")),
            ("crash", ("sigsegv", "segmentation fault", "exit=139", "exit=-11")),
            ("heap_integrity", ("unaligned tcache", "double free", "malloc():", "free(): invalid", "sigabrt")),
            ("target_exited", ("eoferror", "eof", "brokenpipe", "exit=1")),
        ]
        for label, tokens in classifications:
            if any(token in lowered for token in tokens):
                return label, [], evidence
        return "no_proof", [], evidence

    @staticmethod
    def next_actions(status: str) -> list[str]:
        table = {
            "io_desync_or_hang": [
                "Synchronize on the exact prompt; avoid a fixed sleep where recvuntil is possible.",
                "Check whether the target exited and the client is waiting forever.",
            ],
            "crash": [
                "Verify the offset with a cyclic pattern and inspect the crash PC.",
                "If control reached a win/API function, check x86-64 stack alignment.",
            ],
            "heap_integrity": [
                "Re-derive safe-linking as (chunk_user >> 12) ^ target_user.",
                "Verify tcache count, LIFO pop order, and chunk headers before re-running.",
            ],
            "target_exited": [
                "Find the last successfully consumed prompt before the EOF.",
                "Do not send line-oriented input when the binary reads an exact byte count.",
            ],
            "missing_dependency": [
                "Use the environment-provided modules or rewrite the short probe with stdlib.",
                "Inspect doctor output and install only the missing analysis dependency.",
            ],
            "no_proof": [
                "A run without an observable flag or UID is not success; inspect its output.",
                "Change one controlled variable at a time and persist the new fact.",
            ],
        }
        return table.get(status, [])


def heap_layout_facts(
    requested_release: str = "",
    chunk_size: int | None = None,
) -> dict[str, Any]:
    release = requested_release.strip() or "unknown"
    if release.startswith("2.43"):
        tcache = {
            "release": "2.43",
            "max_bins": 76,
            "capacity_per_bin": 16,
            "slot_type": "uint16_t remaining slots",
            "slot_array_offset": "0x00",
            "entry_array_offset": "0x98",
            "entry_next_offset": "0x00",
            "entry_key_offset": "0x08",
        }
    elif release.startswith("2.39"):
        tcache = {
            "release": "2.39",
            "max_bins": 64,
            "capacity_per_bin": 7,
            "slot_type": "uint16_t counts",
            "slot_array_offset": "0x00",
            "entry_array_offset": "0x80",
            "entry_next_offset": "0x00",
            "entry_key_offset": "0x08",
        }
    else:
        tcache = {
            "release": release,
            "note": (
                "Exact tcache capacity, counter semantics, and entry-array "
                "offset are release-specific. Verify them from the bundled "
                "libc/source before building metadata writes."
            ),
        }

    result: dict[str, Any] = {
        "libc_release": release,
        "tcache": tcache,
        "safe_linking": {
            "stored_next": "target ^ (address_of_next_field >> 12)",
            "recover_target": "stored_next ^ (address_of_next_field >> 12)",
            "note": "Never hard-code a runtime address; derive it from the leak.",
        },
        "allocator_invariants": [
            "For a forged chunk P of size S, N=P+S is the physical next chunk.",
            "If N appears free, unlink_chunk(N) checks chunksize(N) == prev_size(next_chunk(N)).",
            "Keep PREV_INUSE and prev_size consistent on every touched boundary.",
            "Read tcache slot remaining capacity before assuming another free stays in tcache.",
        ],
        "fsop_house_of_apple_2": {
            "flush_trigger": {
                "FILE+0x20": "_IO_write_base = 0",
                "FILE+0x28": "_IO_write_ptr = 1",
                "FILE+0x68": "_chain = 0",
                "FILE+0xc0": "_mode = 0",
            },
            "wide_chain": [
                "FILE+0xd8 = &_IO_wfile_jumps",
                "FILE+0xa0 = fake_wide",
                "fake_wide+0x18 = 0",
                "fake_wide+0x30 = 0",
                "fake_wide+0xe0 = fake_wide_vtable",
                "fake_wide_vtable+0x68 = setcontext+61",
            ],
            "setcontext_61": {
                "registers": {
                    "FILE+0x68": "rdi",
                    "FILE+0x70": "rsi",
                    "FILE+0x78": "rbp",
                    "FILE+0x88": "rdx",
                    "FILE+0xa0": "rsp (also _wide_data)",
                    "FILE+0xa8": "RIP",
                },
                "pivot_note": (
                    "Use a separate ROP chain: set FILE+0x78 to its address "
                    "and FILE+0xa8 to leave; ret. This avoids overlapping "
                    "the wide-data fields at _wide_data."
                ),
            },
        },
    }
    if chunk_size is not None:
        if chunk_size < 0x20 or chunk_size & 0xF:
            raise ValueError("chunk_size must be aligned and at least 0x20")
        result["chunk_size"] = {
            "size": hex(chunk_size),
            "tcache_index_formula": "(chunksize - 0x20) / 0x10",
            "tcache_index": (chunk_size - 0x20) // 0x10,
        }
    return result


class Toolbox:
    def __init__(
        self,
        config: AgentConfig,
        runtime: LinuxRuntime,
        facts: BinaryFacts,
        ledger: EvidenceLedger,
        artifact_dir: Path,
    ) -> None:
        self.config = config
        self.runtime = runtime
        self.facts = facts
        self.ledger = ledger
        self.artifact_dir = artifact_dir
        self.attempt_dir = artifact_dir / "attempts"
        self.attempt_dir.mkdir(parents=True, exist_ok=True)
        self.proof = ProofGate(config)
        self.attempts: list[Attempt] = []
        self.captured_flags: list[str] = []
        self.last_proof: list[str] = []

    def dispatch(self, name: str, arguments: dict[str, Any]) -> str:
        handlers = {
            "get_triage": self._get_triage,
            "read_file": self._read_file,
            "write_file": self._write_file,
            "run_command": self._run_command,
            "symbols": self._symbols,
            "gadgets": self._gadgets,
            "libc_identify": self._libc_identify,
            "heap_layout_notes": self._heap_layout_notes,
            "run_exploit": self._run_exploit,
            "ledger_write": self._ledger_write,
            "ledger_read": self._ledger_read,
        }
        handler = handlers.get(name)
        if handler is None:
            return json.dumps({"ok": False, "error": f"unknown tool: {name}"})
        try:
            payload = handler(arguments or {})
            rendered = json.dumps(payload, ensure_ascii=False, indent=2)
        except Exception as exc:
            rendered = json.dumps(
                {"ok": False, "error": f"{type(exc).__name__}: {exc}"},
                ensure_ascii=False,
                indent=2,
            )
        if len(rendered) > MAX_TOOL_RESULT_CHARS:
            rendered = (
                rendered[:MAX_TOOL_RESULT_CHARS]
                + f"\n... [tool output truncated at {MAX_TOOL_RESULT_CHARS} chars]"
            )
        return rendered

    def _get_triage(self, _args: dict[str, Any]) -> dict:
        return {"ok": True, "triage": self.facts.to_dict()}

    def _read_file(self, args: dict[str, Any]) -> dict:
        path = safe_relative_path(self.config.workspace, str(args.get("path", "")))
        limit = max(1, min(int(args.get("max_chars", 20_000)), 80_000))
        if not path.is_file():
            raise FileNotFoundError(path)
        data = path.read_text(encoding="utf-8", errors="replace")
        return {
            "ok": True,
            "path": str(path.relative_to(self.config.workspace)),
            "truncated": len(data) > limit,
            "content": data[:limit],
        }

    def _write_file(self, args: dict[str, Any]) -> dict:
        path = safe_relative_path(self.config.workspace, str(args.get("path", "")))
        content = str(args.get("content", ""))
        if len(content) > 200_000:
            raise ValueError("file content exceeds 200000 character limit")
        if path.suffix.lower() not in {
            ".py", ".c", ".h", ".sh", ".txt", ".md", ".json", ".gdb", ".sage", ".js"
        }:
            raise ValueError("refusing to write unsupported file type")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        relative = str(path.relative_to(self.config.workspace))
        self.ledger.add("artifact", f"wrote {relative} ({len(content)} chars)")
        return {"ok": True, "path": relative, "chars": len(content)}

    def _run_command(self, args: dict[str, Any]) -> dict:
        command = str(args.get("command", "")).strip()
        if not command:
            raise ValueError("command is required")
        check_command(command)
        timeout = max(1, min(int(args.get("timeout_seconds", 30)), 180))
        result = self.runtime.run(
            command,
            timeout=timeout,
            env={"PWNPROOF_FLAG": ""},
        )
        return {
            "ok": result.exit_code == 0,
            "command": command,
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "duration_seconds": result.duration_seconds,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    def _symbols(self, args: dict[str, Any]) -> dict:
        pattern = str(args.get("filter", "")).strip()
        target = shlex_quote(self._target_relative())
        result = self.runtime.run(f"readelf -sW {target}", timeout=20)
        rows: list[dict[str, str]] = []
        for line in result.combined.splitlines():
            if " FUNC " not in line and " OBJECT " not in line:
                continue
            match = re.search(
                r"^\s*\d+:\s+([0-9a-fA-F]+)\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)",
                line,
            )
            if not match:
                continue
            address, symbol = match.groups()
            symbol = symbol.split("@", 1)[0]
            if pattern and not re.search(pattern, symbol, re.IGNORECASE):
                continue
            rows.append({"name": symbol, "address": f"0x{int(address, 16):x}"})
        return {"ok": True, "symbols": rows[:300]}

    def _gadgets(self, args: dict[str, Any]) -> dict:
        pattern = str(args.get("filter", "")).strip()
        target = shlex_quote(self._target_relative())
        local = f"ROPgadget --binary {target} --only 'pop|ret|syscall|leave'"
        if pattern:
            local += f" --re {shlex_quote(pattern)}"
        result = self.runtime.run(local, timeout=60)
        lines = [
            line.strip()
            for line in result.combined.splitlines()
            if " : " in line and ("0x" in line or "Addr" in line or "Gadgets" in line)
        ]
        if not lines:
            fallback = self.runtime.run(
                f"objdump -d -Mintel --no-show-raw-insn {target} | grep -E 'pop|ret|syscall|leave'",
                timeout=30,
            )
            lines = fallback.combined.splitlines()[:160]
        return {"ok": True, "gadgets": lines[:200], "runtime": self.runtime.mode}

    def _libc_identify(self, _args: dict[str, Any]) -> dict:
        candidates = [item.to_dict() for item in self.facts.libc_candidates]
        return {
            "ok": True,
            "candidates": candidates,
            "count": len(candidates),
            "note": (
                "These are local file candidates, not proof of the libc mapped "
                "by the target. Confirm with a runtime leak or process mapping."
            ),
        }

    def _heap_layout_notes(self, args: dict[str, Any]) -> dict:
        release = str(args.get("libc_release", "")).strip()
        if not release:
            releases = [
                str(item.release)
                for item in self.facts.libc_candidates
                if item.release
            ]
            release = releases[0] if len(set(releases)) == 1 else "unknown"
        chunk_size = args.get("chunk_size")
        if chunk_size is not None:
            chunk_size = int(chunk_size)
        return {
            "ok": True,
            "facts": heap_layout_facts(release, chunk_size),
            "candidate_releases": sorted(
                {
                    str(item.release)
                    for item in self.facts.libc_candidates
                    if item.release
                }
            ),
            "note": (
                "Release facts are advisory until a runtime leak or mapping "
                "matches the bundled libc."
            ),
        }

    def _run_exploit(self, args: dict[str, Any]) -> dict:
        script = safe_relative_path(self.config.workspace, str(args.get("path", "")))
        if not script.is_file():
            raise FileNotFoundError(script)
        if script.suffix.lower() not in {".py", ".sh"}:
            raise ValueError("exploit must be a .py or .sh file")
        timeout = max(1, min(int(args.get("timeout_seconds", 45)), 180))
        target = self._target_relative()
        target_dir = str(Path(target).parent.as_posix())
        script_rel = str(script.relative_to(self.config.workspace).as_posix())
        interpreter = "python3" if script.suffix.lower() == ".py" else "bash"
        env_prefix = (
            f"TARGET={shlex_quote(target)} TARGET_NAME={shlex_quote(self.config.name)} "
            f"TARGET_DIR={shlex_quote(target_dir)} "
            f"HOST={shlex_quote(self.config.host or '')} "
            f"PORT={shlex_quote(str(self.config.port or ''))} "
        )
        command = f"{env_prefix}{interpreter} {shlex_quote(script_rel)}"
        result = self.runtime.run(
            command,
            timeout=timeout,
            env={"PWNPROOF_FLAG": self.config.local_flag},
        )
        status, captured_values, proof_evidence = self.proof.inspect(result)
        attempt = Attempt(
            number=len(self.attempts) + 1,
            path=script_rel,
            command=command,
            exit_code=result.exit_code,
            status=status,
            evidence=proof_evidence,
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=result.timed_out,
            duration_seconds=result.duration_seconds,
            next_actions=self.proof.next_actions(status),
        )
        self.attempts.append(attempt)
        attempt_path = self.attempt_dir / f"attempt-{attempt.number:03d}.json"
        attempt_path.write_text(
            json.dumps(attempt.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        if status == "success":
            self.captured_flags = list(dict.fromkeys(self.captured_flags + captured_values))
            self.last_proof = proof_evidence
            self.ledger.add("success", "proof: " + "; ".join(proof_evidence))
        else:
            diagnostic = self._failure_diagnostic(result)
            self.ledger.add(
                "failure",
                f"attempt {attempt.number} {status}: {diagnostic}",
            )
        return {
            "ok": status == "success",
            "status": status,
            "proof": proof_evidence,
            "captured_values": captured_values,
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "duration_seconds": result.duration_seconds,
            "stdout_tail": result.stdout[-6000:],
            "stderr_tail": result.stderr[-6000:],
            "next_actions": attempt.next_actions,
            "attempt_artifact": str(attempt_path),
        }

    def _ledger_write(self, args: dict[str, Any]) -> dict:
        entry = self.ledger.add(str(args.get("kind", "")), str(args.get("text", "")))
        return {"ok": True, "entry": entry.__dict__}

    def _ledger_read(self, args: dict[str, Any]) -> dict:
        limit = max(1, min(int(args.get("limit", 30)), 100))
        return {"ok": True, "ledger": self.ledger.summary(limit)}

    def _target_relative(self) -> str:
        try:
            return self.config.binary.relative_to(self.config.workspace).as_posix()
        except ValueError:
            return self.config.binary.name

    @staticmethod
    def _failure_diagnostic(result: CommandResult) -> str:
        text = (result.stdout + "\n" + result.stderr).lower()
        if result.timed_out:
            return "process exceeded timeout; likely waiting for input or unsynchronized"
        if "sigsegv" in text or "segmentation fault" in text or result.exit_code in {-11, 139}:
            last = ("\n".join((result.stdout + "\n" + result.stderr).splitlines()[-4:])).strip()
            return f"segmentation fault; tail={last[:300]}"
        if "eof" in text or "brokenpipe" in text:
            return "target or transport closed before the client finished sending"
        if "no module named" in text or "modulenotfounderror" in text:
            return "Python dependency missing in the selected runtime"
        tail = "\n".join((result.stdout + "\n" + result.stderr).splitlines()[-4:]).strip()
        return f"no proof marker; exit={result.exit_code}; tail={tail[:300]}"

