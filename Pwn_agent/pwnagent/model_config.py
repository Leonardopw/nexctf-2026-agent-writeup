"""Dynamic model/provider resolution.

PwnAgent must follow the model the user is actually using, not a hard-coded
name. Resolution order (highest first):
1. explicit --model/--base-url/--api-key
2. PwnAgent saved active profile (`%LOCALAPPDATA%\\PwnAgent\\model.json`)
3. PWN_AGENT_PROFILE / PWN_AGENT_MODEL / PWN_AGENT_BASE_URL env
4. the current DSH session's request/context model+provider (if readable)
5. the ctf-agent .env (CTF_AGENT_MODEL / CTF_AGENT_BASE_URL)
6. deepseek-chat fallback

Keys are never printed or written to logs; only key-presence is reported.
"""

from __future__ import annotations

import glob
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

PROFILES: dict[str, dict[str, str]] = {
    "deepseek": {
        "provider": "deepseek-official",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-chat",
        "key_env": "DEEPSEEK_API_KEY",
    },
    "deepseek-flash": {
        "provider": "deepseek-official",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-flash",
        "key_env": "DEEPSEEK_API_KEY",
    },
    "deepseek-reasoner": {
        "provider": "deepseek-official",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-reasoner",
        "key_env": "DEEPSEEK_API_KEY",
    },
    "glm": {
        "provider": "zai",
        "base_url": "https://api.z.ai/api/paas/v4",
        "model": "glm-4.6",
        "key_env": "ZAI_API_KEY",
    },
    "glm-flash": {
        "provider": "zai",
        "base_url": "https://api.z.ai/api/paas/v4",
        "model": "glm-5.3-flash",
        "key_env": "ZAI_API_KEY",
    },
    "openai": {
        "provider": "openai",
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4.1-mini",
        "key_env": "OPENAI_API_KEY",
    },
}

_KEY_NAMES = (
    "PWN_AGENT_API_KEY",
    "DEEPSEEK_API_KEY",
    "ZAI_API_KEY",
    "GLM_API_KEY",
    "OPENAI_API_KEY",
    "CTF_AGENT_API_KEY",
)


@dataclass
class ModelSettings:
    model: str
    base_url: str
    api_key: str
    provider: str = ""
    profile: str = ""
    source: str = ""
    warning: str = ""

    def public(self) -> dict:
        return {
            "model": self.model,
            "base_url": self.base_url,
            "provider": self.provider,
            "profile": self.profile,
            "source": self.source,
            "key_present": bool(self.api_key),
            "warning": self.warning,
        }


def _saved_path() -> Path:
    base = os.getenv("LOCALAPPDATA") or str(Path.home() / ".local" / "share")
    return Path(base) / "PwnAgent" / "model.json"


def saved_active() -> dict:
    try:
        return json.loads(_saved_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_active(settings: ModelSettings) -> Path:
    path = _saved_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = settings.public()
    payload.pop("key_present", None)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _profile_for(provider: str, model: str) -> str:
    provider = (provider or "").lower()
    model = (model or "").lower()
    if "glm" in model or provider in {"zai", "zhipu", "bigmodel"}:
        return "glm-flash" if "flash" in model else "glm"
    if "deepseek" in provider or "deepseek" in model:
        if "reason" in model:
            return "deepseek-reasoner"
        if "flash" in model:
            return "deepseek-flash"
        return "deepseek"
    if provider == "openai":
        return "openai"
    return ""


def _key_for(profile: str) -> str:
    if profile in PROFILES:
        name = PROFILES[profile]["key_env"]
        value = os.getenv(name, "")
        if value:
            return value
    if profile.startswith("deepseek"):
        names = ("DEEPSEEK_API_KEY", "CTF_AGENT_API_KEY", "PWN_AGENT_API_KEY")
    elif profile.startswith("glm"):
        names = ("ZAI_API_KEY", "GLM_API_KEY", "PWN_AGENT_API_KEY")
    elif profile == "openai":
        names = ("OPENAI_API_KEY", "PWN_AGENT_API_KEY")
    else:
        names = ("PWN_AGENT_API_KEY",)
    for name in names:
        value = os.getenv(name, "")
        if value:
            return value
    return ""


def _zstd_decompress(path: Path) -> str | None:
    try:
        from compression import zstd  # Python 3.14+ Windows build

        return zstd.decompress(path.read_bytes()).decode("utf-8", "replace")
    except Exception:
        pass
    try:
        import zstandard  # optional

        with zstandard.ZstdDecompressor().stream_reader(path.open("rb")) as reader:
            return reader.read().decode("utf-8", "replace")
    except Exception:
        return None


_DETECT_CACHE: dict[str, tuple[float, str, str]] = {}
_DETECT_FINAL: tuple[str, str, str] | None = None
_DETECT_AT = 0.0


def detect_dsh_model(force: bool = False) -> tuple[str, str, str]:
    """Return (provider, model, source) from the latest DSH session."""
    global _DETECT_FINAL, _DETECT_AT
    if not force and _DETECT_FINAL is not None and time.time() - _DETECT_AT < 15:
        return _DETECT_FINAL
    try:
        paths = glob.glob(str(Path.home() / ".dsh" / "sessions" / "**" / "session.v4.jsonl.zstd"), recursive=True)
        if not paths:
            return "", "", ""
        path = Path(max(paths, key=lambda item: os.path.getmtime(item)))
        mtime = os.path.getmtime(path)
        cached = _DETECT_CACHE.get(str(path))
        if cached and cached[0] == mtime and not force:
            _DETECT_FINAL = (cached[1], cached[2], "dsh-session-cache")
            _DETECT_AT = time.time()
            return _DETECT_FINAL
        text = _zstd_decompress(path)
        if text is None:
            return "", "", ""
        provider = model = ""
        for line in text.splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("type") != "request/context":
                continue
            data = event.get("data") or {}
            if data.get("model"):
                provider = str(data.get("provider") or provider)
                model = str(data["model"])
        if model:
            _DETECT_CACHE[str(path)] = (mtime, provider, model)
            _DETECT_FINAL = (provider, model, "dsh-session")
            _DETECT_AT = time.time()
            return _DETECT_FINAL
    except Exception:
        pass
    return "", "", ""


def detect_dsh_settings() -> tuple[str, str]:
    """Fallback: DSH default agent model from settings.yaml.imported."""
    path = Path.home() / ".dsh" / "settings.yaml.imported"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "", ""
    provider = model = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("provider:"):
            provider = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("model:"):
            model = stripped.split(":", 1)[1].strip()
    return provider, model


def resolve_model_settings(
    explicit_model: str = "",
    explicit_base: str = "",
    explicit_key: str = "",
) -> ModelSettings:
    model = explicit_model.strip()
    base = explicit_base.strip().rstrip("/")
    key = explicit_key.strip()
    provider = ""
    profile = ""
    source = "explicit" if (model or base or key) else ""

    # 1) saved active profile (explicit PWN_AGENT_PROFILE wins)
    env_profile = os.getenv("PWN_AGENT_PROFILE", "").strip()
    if env_profile in PROFILES:
        profile = env_profile
        provider = PROFILES[profile]["provider"]
        base = base or PROFILES[profile]["base_url"]
        model = model or PROFILES[profile]["model"]
        source = source or "PWN_AGENT_PROFILE"
    else:
        saved = saved_active()
        if saved.get("profile") in PROFILES and not model:
            profile = saved["profile"]
            provider = PROFILES[profile]["provider"]
            base = base or saved.get("base_url") or PROFILES[profile]["base_url"]
            model = model or saved.get("model") or PROFILES[profile]["model"]
            source = source or "saved-profile"
        elif saved.get("model") and not model:
            model = saved["model"]
            base = base or saved.get("base_url", "")
            provider = saved.get("provider", "")
            source = source or "saved-model"

    # 2) env model/base
    if not model:
        model = os.getenv("PWN_AGENT_MODEL", "").strip()
        if model:
            source = source or "PWN_AGENT_MODEL"
    if not base:
        base = os.getenv("PWN_AGENT_BASE_URL", "").strip().rstrip("/")
        if base:
            source = source or "PWN_AGENT_BASE_URL"

    # 3) current DSH model (auto)
    auto = os.getenv("PWN_AGENT_AUTO_MODEL", "1") != "0"
    if auto and not model:
        dsh_provider, dsh_model, dsh_source = detect_dsh_model()
        if not dsh_model:
            dsh_provider, dsh_model = detect_dsh_settings()
            dsh_source = "dsh-settings"
        if dsh_model:
            provider = provider or dsh_provider
            profile = _profile_for(dsh_provider, dsh_model)
            model = dsh_model
            if profile in PROFILES:
                base = base or PROFILES[profile]["base_url"]
            source = source or dsh_source

    # 4) ctf-agent .env values
    if not model:
        model = os.getenv("CTF_AGENT_MODEL", "").strip()
        if model:
            source = source or "CTF_AGENT_MODEL"
    if not base:
        base = os.getenv("CTF_AGENT_BASE_URL", "").strip().rstrip("/")
        if base:
            source = source or "CTF_AGENT_BASE_URL"

    # 5) fallback
    if not model:
        model = "deepseek-chat"
        source = source or "fallback"
    if not profile:
        profile = _profile_for(provider, model)
    if not base:
        base = PROFILES.get(profile, {}).get("base_url", "https://api.deepseek.com")
    if not key:
        key = _key_for(profile)
    warning = ""
    if not key:
        if profile.startswith("glm"):
            warning = "no ZAI_API_KEY/GLM_API_KEY for the current DSH GLM model; set one to enable model calls"
        else:
            warning = "no API key for the resolved model; deterministic fast paths still work"
    return ModelSettings(
        model=model, base_url=base, api_key=key, provider=provider, profile=profile,
        source=source, warning=warning,
    )


def current_summary() -> dict:
    return resolve_model_settings().public()
