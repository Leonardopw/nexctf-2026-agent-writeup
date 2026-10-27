"""PwnAgent configuration.

Extends the working assumptions of PwnProof and ctf-agent:
- PwnProof's proof-gated, binary-first configuration fields.
- ctf-agent's multi-attempt/time-budget/model configuration.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from .vendor.pwnproof.config import DEFAULT_FLAG_PATTERN
from .model_config import resolve_model_settings


def _load_dotenv() -> None:
    """Load the user's existing ctf-agent .env without printing secrets."""
    candidates = [
        os.getenv("PWN_AGENT_ENV", ""),
        str(Path(__file__).resolve().parent.parent / ".env"),
        str(Path.cwd() / ".env"),
        r"<DESKTOP>\ctf-agent\.env",
    ]
    for item in candidates:
        if not item:
            continue
        path = Path(item)
        if not path.is_file():
            continue
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if not key or not value:
                    continue
                os.environ.setdefault(key, value)
        except OSError:
            continue
        break


_load_dotenv()


def _env(*names: str, default: str = "") -> str:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return default


def default_gef_path() -> str:
    candidates = [
        os.getenv("PWN_AGENT_GEF", ""),
        r"<DESKTOP>\ctf-tools\gef.py",
        "/opt/gef.py",
        str(Path.home() / "gef.py"),
    ]
    for item in candidates:
        if item and Path(item).is_file():
            return item
    return ""


@dataclass
class PwnAgentConfig:
    binary: Path
    workspace: Path
    source: Path | None = None
    name: str = "pwn"
    description: str = ""
    host: str | None = None
    port: int | None = None

    # proof / model
    flag_pattern: str = DEFAULT_FLAG_PATTERN
    success_patterns: Sequence[str] = field(default_factory=tuple)
    model: str = ""
    base_url: str = ""
    api_key: str = field(default="", repr=False)
    provider: str = ""
    profile: str = ""
    model_source: str = ""
    model_warning: str = ""
    temperature: float = 0.15
    max_steps: int = 18
    request_timeout: int = 180
    command_timeout: int = 30

    # orchestration
    attempts: int = 3
    time_budget: int = 600
    attempt_timeout: int = 900
    playbooks: tuple[str, ...] = ()
    parallel: bool = True

    # runtime
    distro: str = "Ubuntu"
    runtime: str = "auto"
    local_flag: str = field(default="", repr=False)
    libc: str | None = None
    gef_path: str = field(default_factory=default_gef_path)
    artifact_root: Path = field(default_factory=lambda: Path("artifacts"))

    allow_remote: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        self.binary = self.binary.expanduser().resolve()
        self.workspace = self.workspace.expanduser().resolve()
        if self.source is not None:
            self.source = self.source.expanduser().resolve()
        if self.libc:
            raw = self.libc
            if raw.startswith("/") and os.name == "nt":
                # Linux absolute path for the WSL runtime; keep it verbatim.
                self.libc = raw
            else:
                libc_path = Path(raw).expanduser()
                if not libc_path.is_absolute():
                    libc_path = self.workspace / libc_path
                self.libc = str(libc_path.resolve())
        self.artifact_root = self.artifact_root.expanduser().resolve()
        settings = resolve_model_settings(self.model, self.base_url, self.api_key)
        self.model = settings.model
        self.base_url = settings.base_url
        self.api_key=<REDACTED>
        self.provider = settings.provider
        self.profile = settings.profile
        self.model_source = settings.source
        self.model_warning = settings.warning
        self.allow_remote = bool(self.host and self.port)
        if (self.host is None) != (self.port is None):
            raise ValueError("--host and --port must be supplied together")
        if self.attempts < 1:
            raise ValueError("--attempts must be positive")
        if self.max_steps < 1:
            raise ValueError("--max-steps must be positive")
        if self.time_budget < 10:
            raise ValueError("--time-budget must be at least 10 seconds")
        if not self.binary.is_file():
            raise FileNotFoundError(f"binary does not exist: {self.binary}")
