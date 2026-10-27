"""Global configuration for the CTF agent.

Priority: CLI args > environment variables > config.json > defaults.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


@dataclass
class Config:
    # LLM
    base_url: str = "https://api.deepseek.com"
    model: str = "deepseek-chat"
    api_key: str = ""
    temperature: float = 0.3
    # Loop
    max_steps: int = 40
    time_budget: int = 1800          # seconds per attempt
    max_tokens: int = 8192           # LLM output budget per call (reasoning models need more)
    max_tool_output: int = 20000     # chars kept per tool result
    command_timeout: int = 120       # seconds per shell command
    network_timeout: int = 30        # seconds for curl/wget/pip/git style commands
    # Context management (token efficiency)
    compact_every: int = 8           # LLM-summarise history every N steps; 0 disables
    compact_threshold: int = 60000   # compact early when context exceeds this many chars
    compact_history_chars: int = 24000  # chars of history sent to the summariser
    compact_keep_recent: int = 2     # recent tool outputs kept verbatim in the summary
    shrink_tool_output: int = 1200   # old tool outputs are compressed to this many chars
    keep_recent_tools: int = 3       # never shrink the last N tool outputs
    # Challenge
    flag_regex: str = r"nex\{[^}]{1,200}\}"
    challenge_name: str = "unknown"
    challenge_type: str = "web"
    difficulty: str = ""
    target: str = ""
    hint: str = ""
    files: list[str] = field(default_factory=list)
    # Runtime
    attempts: int = 1
    workdir: str = ""
    shell: str = "auto"              # auto | wsl | powershell | bash
    mock: bool = False
    verbose: bool = True
    run_dir: str = ""

    @classmethod
    def load(cls, **overrides: Any) -> "Config":
        _load_dotenv(PROJECT_DIR / ".env")
        data = _load_json(PROJECT_DIR / "config.json")
        env_map = {
            "base_url": os.environ.get("CTF_AGENT_BASE_URL") or os.environ.get("OPENAI_BASE_URL"),
            "model": os.environ.get("CTF_AGENT_MODEL"),
            "api_key": os.environ.get("CTF_AGENT_API_KEY") or os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("OPENAI_API_KEY"),
            "temperature": os.environ.get("CTF_AGENT_TEMPERATURE"),
            "max_steps": os.environ.get("CTF_AGENT_MAX_STEPS"),
        }
        merged: dict[str, Any] = {}
        for key, value in env_map.items():
            if value not in (None, ""):
                merged[key] = value
        merged.update({k: v for k, v in data.items() if v is not None})
        merged.update({k: v for k, v in overrides.items() if v is not None})
        cfg = cls()
        for key, value in merged.items():
            if not hasattr(cfg, key):
                continue
            cur = getattr(cfg, key)
            try:
                if isinstance(cur, bool):
                    value = bool(value) if not isinstance(value, str) else value.lower() in ("1", "true", "yes")
                elif isinstance(cur, int):
                    value = int(value)
                elif isinstance(cur, float):
                    value = float(value)
            except Exception:
                continue
            setattr(cfg, key, value)
        return cfg

    def validate(self) -> list[str]:
        problems = []
        if not self.api_key and not self.mock:
            problems.append("缺少 API Key：请设置环境变量 DEEPSEEK_API_KEY 或在 .env 中填写")
        if not self.target and not self.files:
            problems.append("至少提供 --target 或 --files 之一")
        return problems
