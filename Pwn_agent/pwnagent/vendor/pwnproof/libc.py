from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .runtime import LinuxRuntime, shlex_quote


@dataclass
class LibcCandidate:
    path: str
    source: str
    sha256: str = ""
    build: str = ""
    release: str = ""
    symbols: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "source": self.source,
            "sha256": self.sha256,
            "build": self.build,
            "release": self.release,
            "symbols": self.symbols,
            "runtime_confirmed": False,
        }


def parse_libc_version(text: str) -> tuple[str, str]:
    """Return (build description, release) from common glibc/musl strings."""

    for line in text.splitlines():
        if "GNU C Library" in line:
            build_match = re.search(r"GNU C Library \(([^)]+)\)", line)
            release_match = re.search(
                r"(?:stable\s+)?release\s+version\s+([0-9]+(?:\.[0-9]+)+)",
                line,
                re.IGNORECASE,
            )
            build = build_match.group(1).strip() if build_match else line.strip()
            release = release_match.group(1) if release_match else ""
            return build, release
        if "musl libc" in line:
            version_match = re.search(
                r"musl libc[^\r\n]*?version\s+([0-9]+(?:\.[0-9]+)+)",
                text,
                re.IGNORECASE,
            )
            return line.strip(), version_match.group(1) if version_match else ""
    return "", ""


def parse_libc_symbols(text: str, names: tuple[str, ...] = ("puts", "system")) -> dict[str, str]:
    wanted = set(names)
    symbols: dict[str, str] = {}
    symbol_line = re.compile(
        r"^\s*\d+:\s+([0-9a-fA-F]+)\s+\d+\s+"
        r"(FUNC|IFUNC)\s+\S+\s+\S+\s+\S+\s+(\S+)"
    )
    for line in text.splitlines():
        match = symbol_line.search(line)
        if not match:
            continue
        address, _kind, raw_name = match.groups()
        name = raw_name.split("@", 1)[0]
        if name in wanted and int(address, 16) != 0:
            symbols[name] = f"0x{int(address, 16):x}"
    return symbols


def _workspace_reference(path: Path, workspace: Path) -> str | None:
    resolved = path.expanduser().resolve()
    try:
        return resolved.relative_to(workspace.resolve()).as_posix()
    except ValueError:
        return None


def candidate_references(
    workspace: Path,
    bits: int | None,
    *,
    explicit: str | None = None,
) -> list[tuple[str, str]]:
    workspace = workspace.resolve()
    references: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(reference: str, source: str) -> None:
        if reference and reference not in seen:
            seen.add(reference)
            references.append((reference, source))

    explicit = explicit or os.environ.get("PWNPROOF_LIBC")
    if explicit:
        requested = Path(explicit.strip()).expanduser()
        if not requested.is_absolute():
            requested = workspace / requested
        relative = _workspace_reference(requested, workspace)
        if relative:
            add(relative, "environment")

    for name in ("libc.so.6", "libc"):
        path = workspace / name
        if path.is_file():
            add(name, "workspace")
    for path in sorted(workspace.glob("libc-*.so")):
        if path.is_file():
            relative = _workspace_reference(path, workspace)
            if relative:
                add(relative, "workspace")

    if bits == 64:
        system_paths = (
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "/lib64/libc.so.6",
        )
    elif bits == 32:
        system_paths = (
            "/lib/i386-linux-gnu/libc.so.6",
            "/usr/lib/i386-linux-gnu/libc.so.6",
            "/lib32/libc.so.6",
        )
    else:
        system_paths = ()
    for path in system_paths:
        add(path, "system")
    return references


def _parse_sections(text: str) -> dict[str, str]:
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


def identify_libc_candidates(
    runtime: LinuxRuntime,
    workspace: Path,
    bits: int | None,
    *,
    dynamic_elf: str = "",
) -> list[LibcCandidate]:
    """Inspect local libc files without executing the challenge or loader."""

    if "libc.so" not in dynamic_elf.lower():
        return []

    candidates: list[LibcCandidate] = []
    seen_hashes: set[str] = set()
    for reference, source in candidate_references(workspace, bits):
        quoted = shlex_quote(reference)
        command = (
            f"if test -r {quoted}; then "
            "printf '[EXISTS]\\n1\\n'; "
            f"printf '[SHA]\\n'; sha256sum {quoted} | cut -d' ' -f1; "
            f"printf '[VERSION]\\n'; strings -a -n 7 {quoted} | "
            "grep -m1 -E 'GNU C Library|musl libc' || true; "
            f"printf '[SYMBOLS]\\n'; readelf --dyn-syms -W {quoted} | "
            "grep -E ' (puts|system)(@@|@)' | head -10 || true; "
            "else printf '[EXISTS]\\n0\\n'; fi"
        )
        result = runtime.run(command, timeout=30)
        sections = _parse_sections(result.combined)
        if sections.get("exists", "").strip() != "1":
            continue
        digest = sections.get("sha", "").strip().splitlines()
        sha256 = digest[0].strip().lower() if digest and re.fullmatch(r"[0-9a-fA-F]{64}", digest[0].strip()) else ""
        if sha256 and sha256 in seen_hashes:
            continue
        build, release = parse_libc_version(sections.get("version", ""))
        symbols = parse_libc_symbols(sections.get("symbols", ""))
        if not (build or release or symbols):
            continue
        candidate = LibcCandidate(
            path=reference,
            source=source,
            sha256=sha256,
            build=build,
            release=release,
            symbols=symbols,
        )
        candidates.append(candidate)
        if sha256:
            seen_hashes.add(sha256)
    return candidates
