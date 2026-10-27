from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


class ModelError(RuntimeError):
    pass


@dataclass
class ModelReply:
    message: dict[str, Any]
    usage: dict[str, int]
    raw: dict[str, Any]


class ModelClient:
    """Small OpenAI-compatible Chat Completions client with tool-calling."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout: int = 180,
        temperature: float = 0.1,
        retries: int = 4,
    ) -> None:
        self.endpoint = base_url.rstrip("/") + "/chat/completions"
        self.api_key=<REDACTED>
        self.model = model
        self.timeout = timeout
        self.temperature = temperature
        self.retries = retries

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> ModelReply:
        if not self.api_key:
            raise ModelError(
                "No API key configured. Set PWNPILOT_API_KEY or DEEPSEEK_API_KEY, "
                "or run `pwnproof heuristic`."
            )
        payload = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
            "temperature": self.temperature,
        }
        data = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            request = urllib.request.Request(
                self.endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers=data,
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = json.loads(response.read().decode("utf-8"))
                choices = raw.get("choices", [])
                if not choices or "message" not in choices[0]:
                    raise ModelError("model response did not contain choices[0].message")
                usage = {
                    key: int(value)
                    for key, value in (raw.get("usage") or {}).items()
                    if isinstance(value, (int, float))
                }
                return ModelReply(message=choices[0]["message"], usage=usage, raw=raw)
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                last_error = ModelError(f"HTTP {exc.code}: {body[:1200]}")
                if exc.code in {408, 409, 425, 429, 500, 502, 503, 504} and attempt < self.retries:
                    time.sleep(min(12, 1.5 * (2**attempt)) + random.random())
                    continue
                break
            except (urllib.error.URLError, TimeoutError, ValueError) as exc:
                last_error = ModelError(f"model request failed: {exc}")
                if attempt < self.retries:
                    time.sleep(min(12, 1.5 * (2**attempt)) + random.random())
                    continue
                break
        raise ModelError(str(last_error or "model request failed"))

