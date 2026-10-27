from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence


DEFAULT_FLAG_PATTERN = (
    r"(?i)(?:"
    r"[A-Z0-9_]+\{[^{}\r\n]{1,256}\}"
    r"|uid=[0-9]+\([^)]+\)\s+gid=[0-9]+\([^)]+\)"
    r")"
)


@dataclass
class AgentConfig:
    binary: Path
    workspace: Path
    source: Path | None = None
    name: str = "pwn"
    description: str = ""
    host: str | None = None
    port: int | None = None
    flag_pattern: str = DEFAULT_FLAG_PATTERN
    model: str = field(default_factory=lambda: os.getenv("PWNPILOT_MODEL", "deepseek-chat"))
    base_url: str = field(
        default_factory=lambda: os.getenv("PWNPILOT_BASE_URL", "https://api.deepseek.com/v1")
        .rstrip("/")
    )
    api_key: str = field(
        default_factory=lambda: os.getenv("PWNPILOT_API_KEY")
        or os.getenv("DEEPSEEK_API_KEY", "")
    )
    max_steps: int = 24
    command_timeout: int = 30
    request_timeout: int = 180
    distro: str = "Ubuntu"
    runtime: str = "auto"
    temperature: float = 0.1
    local_flag: str = field(default="", repr=False)
    artifact_root: Path = field(default_factory=lambda: Path("artifacts"))
    allow_remote: bool = field(init=False, default=False)
    success_patterns: Sequence[str] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        self.binary = self.binary.expanduser().resolve()
        self.workspace = self.workspace.expanduser().resolve()
        if self.source is not None:
            self.source = self.source.expanduser().resolve()
        self.artifact_root = self.artifact_root.expanduser().resolve()
        self.allow_remote = bool(self.host and self.port)
        if (self.host is None) != (self.port is None):
            raise ValueError("--host and --port must be supplied together")
        if self.max_steps < 1:
            raise ValueError("--max-steps must be positive")
        if self.command_timeout < 1:
            raise ValueError("--command-timeout must be positive")

