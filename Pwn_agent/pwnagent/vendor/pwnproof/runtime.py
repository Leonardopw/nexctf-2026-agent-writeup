from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


MAX_CAPTURE_CHARS = 120_000


@dataclass
class CommandResult:
    command: str
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    duration_seconds: float = 0.0

    @property
    def combined(self) -> str:
        marker = f"\n[exit={self.exit_code}]"
        if self.timed_out:
            marker += " [timeout]"
        return f"{self.stdout}\n{self.stderr}{marker}".strip()


def _clip(text: str, limit: int = MAX_CAPTURE_CHARS) -> str:
    if len(text) <= limit:
        return text
    head = limit // 3
    tail = limit - head
    return f"{text[:head]}\n... [{len(text) - limit} chars omitted] ...\n{text[-tail:]}"


def _windows_to_wsl(path: Path) -> str:
    resolved = str(path.resolve())
    drive = Path(resolved).drive.rstrip(":")
    rest = resolved[len(Path(resolved).drive) :].replace("\\", "/")
    return f"/mnt/{drive.lower()}{rest}"


class LinuxRuntime:
    """Run Linux-only pwn tools natively or through an installed WSL distro."""

    def __init__(
        self,
        workspace: Path,
        *,
        distro: str = "Ubuntu",
        mode: str = "auto",
    ) -> None:
        self.workspace = workspace.resolve()
        self.distro = distro
        if mode not in {"auto", "native", "wsl"}:
            raise ValueError("runtime mode must be auto, native, or wsl")
        if mode == "auto":
            mode = "wsl" if sys.platform == "win32" else "native"
        self.mode = mode
        if self.mode == "wsl" and shutil.which("wsl.exe") is None:
            raise RuntimeError("WSL is required on Windows but wsl.exe was not found")

    def _command(self, command: str) -> list[str]:
        if self.mode == "native":
            return ["bash", "-lc", command]
        linux_workspace = _windows_to_wsl(self.workspace)
        wrapped = f"cd {shlex_quote(linux_workspace)} && {command}"
        return ["wsl.exe", "-d", self.distro, "--", "bash", "-lc", wrapped]

    def run(
        self,
        command: str,
        *,
        timeout: int = 30,
        env: dict[str, str] | None = None,
        cwd: Path | None = None,
    ) -> CommandResult:
        run_cwd = (cwd or self.workspace).resolve()
        if self.mode == "native":
            argv = ["bash", "-lc", command]
        else:
            wrapped = f"cd {shlex_quote(_windows_to_wsl(run_cwd))} && {command}"
            argv = ["wsl.exe", "-d", self.distro, "--", "bash", "-lc", wrapped]

        run_env = os.environ.copy()
        if env:
            run_env.update(env)
        if self.mode == "wsl" and env:
            forwarded = [name for name in env if name != "WSLENV"]
            existing = [item for item in run_env.get("WSLENV", "").split(":") if item]
            for name in forwarded:
                if name not in existing:
                    existing.append(name)
            if existing:
                run_env["WSLENV"] = ":".join(existing)
        import time

        started = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                cwd=str(self.workspace) if self.mode == "native" else None,
                env=run_env,
                capture_output=True,
                timeout=timeout,
            )
            stdout = _clip(proc.stdout.decode("utf-8", errors="replace"))
            stderr = _clip(proc.stderr.decode("utf-8", errors="replace"))
            return CommandResult(
                command=command,
                exit_code=proc.returncode,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=round(time.monotonic() - started, 3),
            )
        except subprocess.TimeoutExpired as exc:
            stdout = _clip((exc.stdout or b"").decode("utf-8", errors="replace"))
            stderr = _clip((exc.stderr or b"").decode("utf-8", errors="replace"))
            return CommandResult(
                command=command,
                exit_code=None,
                stdout=stdout,
                stderr=f"{stderr}\ncommand timed out after {timeout}s".strip(),
                timed_out=True,
                duration_seconds=round(time.monotonic() - started, 3),
            )

    def doctor(self) -> dict[str, object]:
        commands = ["python3", "gcc", "gdb", "objdump", "readelf", "file", "checksec", "ROPgadget"]
        result = self.run("command -v " + " ".join(commands), timeout=15)
        found = {
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip().startswith("/")
        }
        pwn = self.run(
            "python3 -c \"import pwn; print(getattr(pwn, '__version__', 'installed'))\"",
            timeout=15,
        )
        return {
            "runtime": self.mode,
            "distro": self.distro if self.mode == "wsl" else None,
            "workspace": str(self.workspace),
            "tools": sorted(found),
            "pwntools": pwn.combined if pwn.exit_code == 0 else None,
            "ready": result.exit_code == 0,
        }


def shlex_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def is_probably_elf(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def safe_relative_path(root: Path, candidate: str) -> Path:
    if not candidate or "\x00" in candidate:
        raise ValueError("path is empty or contains a NUL byte")
    root = root.resolve()
    path = (root / candidate).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path escapes workspace: {candidate}") from exc
    return path


_SHELL_FORBIDDEN = (
    re.compile(r"(^|[;&|]\s*)(?:rm\s+-rf\s+/(?:\s|$)|mkfs(?:\.|\s)|shutdown(?:\s|$)|reboot(?:\s|$))"),
    re.compile(r":\(\)\s*\{\s*:\|:&\s*\};:"),
    re.compile(r"(?:>|>>)\s*/(?:etc|boot)/|(?:>|>>)\s*/dev/(?:sd|nvme|disk|mem|kmem)"),
)


def check_command(command: str) -> None:
    for pattern in _SHELL_FORBIDDEN:
        if pattern.search(command):
            raise ValueError("command rejected by workspace safety guard")

