from __future__ import annotations

import json
import re
import hashlib
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .libc import LibcCandidate, identify_libc_candidates
from .runtime import LinuxRuntime, is_probably_elf, safe_relative_path, shlex_quote


@dataclass
class Hypothesis:
    playbook: str
    confidence: float
    reason: str


@dataclass
class BinaryFacts:
    path: str
    sha256: str = ""
    file_type: str = ""
    arch: str = ""
    bits: int | None = None
    elf_type: str = ""
    entry: str = ""
    protections: dict[str, str] = field(default_factory=dict)
    symbols: dict[str, str] = field(default_factory=dict)
    suspicious_functions: list[str] = field(default_factory=list)
    interesting_strings: list[str] = field(default_factory=list)
    source_signals: list[str] = field(default_factory=list)
    libc_candidates: list[LibcCandidate] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    recommended_tools: list[str] = field(default_factory=list)
    raw: dict[str, str] = field(default_factory=dict)

    def to_dict(self, include_raw: bool = False) -> dict:
        data = asdict(self)
        if not include_raw:
            data.pop("raw", None)
        return data

    def prompt_summary(self) -> str:
        facts = {
            "path": self.path,
            "sha256": self.sha256,
            "file_type": self.file_type,
            "arch": self.arch,
            "bits": self.bits,
            "elf_type": self.elf_type,
            "entry": self.entry,
            "protections": self.protections,
            "candidate_symbols": self.symbols,
            "suspicious_functions": self.suspicious_functions,
            "interesting_strings": self.interesting_strings[:30],
            "source_signals": self.source_signals,
            "libc_candidates": [item.to_dict() for item in self.libc_candidates],
            "hypotheses": [asdict(item) for item in self.hypotheses],
            "recommended_tools": self.recommended_tools,
        }
        return json.dumps(facts, ensure_ascii=False, indent=2)


SUSPICIOUS_IMPORTS = {
    "gets",
    "strcpy",
    "strcat",
    "sprintf",
    "vsprintf",
    "scanf",
    "sscanf",
    "read",
    "fgets",
    "printf",
    "puts",
    "system",
    "execve",
    "popen",
    "mprotect",
    "mmap",
    "prctl",
    "seccomp",
    "malloc",
    "calloc",
    "realloc",
    "free",
}

CANDIDATE_SYMBOL_RE = re.compile(
    r"(?i)^(?:win|backdoor|get_shell|give_shell|shell|flag|print_flag|cat_flag|"
    r"read_flag|vuln|vulnerable|main)$"
)
FLAG_LIKE_RE = re.compile(r"[A-Za-z0-9_]{2,32}\{[^{}\r\n]{1,256}\}")
PATH_STRING_RE = re.compile(r"(?i)(?:^|/)(?:flag|secret|password|key)(?:\.[a-z0-9]+)?$")


def _run(runtime: LinuxRuntime, command: str, timeout: int = 30) -> str:
    result = runtime.run(command, timeout=timeout)
    return result.combined


def _parse_checksec(text: str) -> dict[str, str]:
    protections: dict[str, str] = {}
    patterns = {
        "relro": r"RELRO\s*:\s*([^\r\n]+)",
        "canary": r"Stack\s*:\s*([^\r\n]+)",
        "nx": r"NX\s*:\s*([^\r\n]+)",
        "pie": r"PIE\s*:\s*([^\r\n]+)",
        "rpath": r"RPATH\s*:\s*([^\r\n]+)",
        "runpath": r"RUNPATH\s*:\s*([^\r\n]+)",
        "fortify": r"FORTIFY\s*:\s*([^\r\n]+)",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            protections[key] = match.group(1).strip()
    return protections


def _parse_symbols(text: str) -> tuple[dict[str, str], set[str]]:
    candidates: dict[str, str] = {}
    imports: set[str] = set()
    symbol_line = re.compile(
        r"^\s*\d+:\s+([0-9a-fA-F]+)\s+\d+\s+"
        r"(FUNC|IFUNC|OBJECT|NOTYPE|SECTION)\s+"
        r"(\S+)\s+(\S+)\s+(\S+)\s+(\S+)"
    )
    for line in text.splitlines():
        match = symbol_line.search(line)
        if not match:
            continue
        address, kind, _bind, _visibility, ndx, name = match.groups()
        clean = name.split("@", 1)[0]
        if ndx == "UND":
            imports.add(clean)
        if kind in {"FUNC", "IFUNC"} or CANDIDATE_SYMBOL_RE.search(clean):
            if address.lower() not in {"0", "0000000000000000"}:
                candidates[clean] = f"0x{int(address, 16):x}"
    return candidates, imports


def _parse_header(text: str) -> tuple[int | None, str, str, str]:
    bits = None
    class_match = re.search(r"Class:\s+ELF(\d+)", text)
    if class_match:
        bits = int(class_match.group(1))
    machine_match = re.search(r"Machine:\s+([^\r\n]+)", text)
    machine = machine_match.group(1).strip() if machine_match else ""
    type_match = re.search(r"Type:\s+([^\r\n]+)", text)
    elf_type = type_match.group(1).strip() if type_match else ""
    entry_match = re.search(r"Entry point address:\s+(0x[0-9a-fA-F]+)", text)
    entry = entry_match.group(1) if entry_match else ""
    return bits, machine, elf_type, entry


def _source_signals(path: Path | None) -> list[str]:
    if path is None or not path.exists():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    signals: list[str] = []
    checks = [
        (r"\bgets\s*\(", "source uses gets() without a length bound"),
        (r"\bstrcpy\s*\(", "source uses strcpy()"),
        (r"\bsprintf\s*\(", "source uses sprintf()"),
        (r"\bprintf\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)", "printf uses user-controlled format"),
        (r"\bfree\s*\([^)]*\).*?\bfree\s*\([^)]*\)", "multiple frees may create a UAF/double-free"),
        (r"\bexecve?\s*\(", "source calls exec*"),
        (r"\bseccomp\s*\(|\bprctl\s*\(", "source may install seccomp restrictions"),
        (r"\bsystem\s*\(", "source calls system()"),
        (r"\bchar\s+\w+\s*\[\s*(\d+)\s*\]", "source declares a fixed stack buffer"),
    ]
    for pattern, label in checks:
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            signals.append(label)
    for match in re.finditer(r"\bchar\s+\w+\s*\[\s*(\d+)\s*\]", text):
        signals.append(f"possible stack buffer size {match.group(1)}")
    return list(dict.fromkeys(signals))


def _rank_hypotheses(
    facts: BinaryFacts,
    imports: set[str],
    disasm: str,
) -> list[Hypothesis]:
    implications: list[Hypothesis] = []
    canary = facts.protections.get("canary", "").lower()
    nx = facts.protections.get("nx", "").lower()
    pie = facts.protections.get("pie", "").lower()
    source_text = "\n".join(facts.source_signals).lower()
    import_set = {item.lower() for item in imports}

    if "format" in source_text or (
        "printf" in import_set
        and re.search(r"call\s+[^<\n]*<printf@plt>", disasm, re.IGNORECASE)
        and any("printf" in sig.lower() for sig in facts.source_signals)
    ):
        implications.append(
            Hypothesis("format_string", 0.94, "printf-family call may consume a user-controlled format")
        )
    if "gets" in import_set or "gets" in source_text:
        confidence = 0.96 if "no canary" in canary or "disabled" in canary else 0.76
        implications.append(
            Hypothesis("stack_overflow", confidence, "gets() is an unbounded stack write")
        )
    if any(item in import_set for item in {"strcpy", "strcat", "sprintf", "scanf", "read"}):
        implications.append(
            Hypothesis(
                "bounded_input_audit",
                0.68,
                "input length belongs to the surrounding code, not the libc call alone",
            )
        )
    if any(item in import_set for item in {"malloc", "free", "calloc", "realloc"}):
        implications.append(
            Hypothesis(
                "heap_exploitation",
                0.72,
                "heap allocator APIs are present; inspect ownership, UAF, and size transitions",
            )
        )
    if any(item in import_set for item in {"system", "execve", "popen"}):
        implications.append(
            Hypothesis("command_execution_target", 0.89, "binary already imports a command execution primitive")
        )
    if any(item in import_set for item in {"mprotect", "mmap"}):
        implications.append(
            Hypothesis("mprotect_shellcode", 0.62, "RWX transition APIs are imported")
        )
    if any(item in import_set for item in {"seccomp", "prctl"}):
        implications.append(
            Hypothesis("sandbox_escape_or_orw", 0.82, "syscall filtering may require open/read/write or an escape primitive")
        )
    if ("no pie" in pie or "no pie" in facts.file_type.lower()) and facts.symbols:
        implications.append(
            Hypothesis("ret2win", 0.86, "non-PIE code exposes stable function addresses")
        )
    elif ("enabled" in pie or "pie enabled" in pie) and (not nx or "disabled" in nx):
        implications.append(Hypothesis("ret2shellcode", 0.7, "PIE with executable stack/regions needs a leak or relative control"))
    if "system" in import_set and ("enabled" in nx or "nx enabled" in nx) and "canary" not in source_text:
        implications.append(Hypothesis("ret2libc", 0.72, "NX directs control flow through libc; leaks may be needed"))
    if not implications:
        implications.append(
            Hypothesis("manual_protocol_analysis", 0.45, "no high-confidence primitive from initial imports")
        )
    implications.sort(key=lambda item: item.confidence, reverse=True)
    return implications


def triage(
    binary: Path,
    workspace: Path,
    runtime: LinuxRuntime,
    *,
    source: Path | None = None,
    timeout: int = 30,
) -> BinaryFacts:
    workspace = workspace.resolve()
    binary = binary.resolve()
    if not binary.exists():
        raise FileNotFoundError(binary)
    if not is_probably_elf(binary):
        raise ValueError(f"not an ELF binary: {binary}")
    relative = safe_relative_path(workspace, binary.relative_to(workspace).as_posix())
    target = shlex_quote(relative.relative_to(workspace).as_posix())

    bundle = (
        f"printf '\\n[FILE]\\n'; file {target}; "
        f"printf '\\n[HEADER]\\n'; readelf -hW {target}; "
        f"printf '\\n[SYMBOLS]\\n'; readelf -sW {target}; "
        f"printf '\\n[DYNAMIC]\\n'; readelf -dW {target}; "
        f"printf '\\n[SEGMENTS]\\n'; readelf -lW {target}; "
        f"printf '\\n[CHECKSEC]\\n'; checksec --file={target} 2>&1; "
        f"printf '\\n[DISASM]\\n'; objdump -d -Mintel --no-show-raw-insn {target}; "
        f"printf '\\n[STRINGS]\\n'; strings -a -n 4 {target}"
    )
    raw_bundle = _run(runtime, bundle, timeout=max(timeout, 60))
    sections: dict[str, str] = {}
    current = ""
    for line in raw_bundle.splitlines():
        section_match = re.fullmatch(r"\[([A-Z]+)]", line.strip())
        if section_match:
            current = section_match.group(1).lower()
            sections[current] = ""
        elif current:
            sections[current] += line + "\n"

    facts = BinaryFacts(path=str(binary))
    facts.sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
    facts.raw = sections
    facts.file_type = sections.get("file", "").strip().splitlines()[0] if sections.get("file", "").strip() else ""
    facts.bits, facts.arch, facts.elf_type, facts.entry = _parse_header(sections.get("header", ""))
    facts.protections = _parse_checksec(sections.get("checksec", ""))
    parsed_symbols, imports = _parse_symbols(sections.get("symbols", ""))
    facts.symbols = {
        name: address
        for name, address in parsed_symbols.items()
        if CANDIDATE_SYMBOL_RE.search(name) or name in {"main", "vuln", "vulnerable"}
    }
    facts.suspicious_functions = sorted(
        {name.split("@", 1)[0] for name in imports if name.split("@", 1)[0] in SUSPICIOUS_IMPORTS}
    )

    string_lines = [line.strip() for line in sections.get("strings", "").splitlines() if line.strip()]
    interesting: list[str] = []
    for line in string_lines:
        if (
            FLAG_LIKE_RE.search(line)
            or PATH_STRING_RE.search(line)
            or any(
                token in line.lower()
                for token in ("/bin/sh", "flag", "win", "shell", "secret", "password", "denied", "canary")
            )
        ):
            interesting.append(line)
    facts.interesting_strings = list(dict.fromkeys(interesting))[:80]
    facts.source_signals = _source_signals(source)
    facts.libc_candidates = identify_libc_candidates(
        runtime,
        workspace,
        facts.bits,
        dynamic_elf=sections.get("dynamic", ""),
    )
    facts.hypotheses = _rank_hypotheses(facts, imports, sections.get("disasm", ""))

    tools: list[str] = ["run_command", "triage", "ledger_write", "ledger_read"]
    if "format_string" in {item.playbook for item in facts.hypotheses}:
        tools += ["build_format_probe", "run_exploit"]
    if "ret2win" in {item.playbook for item in facts.hypotheses}:
        tools += ["symbols", "gadgets", "run_exploit"]
    if "ret2libc" in {item.playbook for item in facts.hypotheses}:
        tools += ["libc_identify", "run_exploit"]
    if "heap_exploitation" in {item.playbook for item in facts.hypotheses}:
        tools += ["gdb_command", "heap_layout_notes"]
    if any("mprotect" in item.playbook or "sandbox" in item.playbook for item in facts.hypotheses):
        tools += ["shellcode", "syscall_audit"]
    facts.recommended_tools = list(dict.fromkeys(tools))
    return facts

