"""Minimal OpenAI-compatible chat client (works with DeepSeek, Kimi, GLM, OpenAI...)."""
from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.request
from typing import Any


class LLMError(RuntimeError):
    pass


class LLMClient:
    def __init__(self, base_url: str, api_key: str, model: str, timeout: int = 120):
        self.base_url = base_url.rstrip("/")
        self.api_key=<REDACTED>
        self.model = model
        self.timeout = timeout
        self.usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        self.calls = 0

    # ------------------------------------------------------------------ HTTP
    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = self.base_url + path
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }
        last_err: Exception | None = None
        for attempt in range(5):
            try:
                req = urllib.request.Request(url, data=body, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8", "replace"))
                usage = data.get("usage") or {}
                for key in self.usage:
                    self.usage[key] += int(usage.get(key) or 0)
                self.calls += 1
                return data
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", "replace")[:500]
                last_err = LLMError(f"HTTP {exc.code}: {detail}")
                if exc.code in (429, 500, 502, 503, 504):
                    time.sleep(min(30, 2 ** attempt) + random.random())
                    continue
                raise last_err
            except Exception as exc:  # network
                last_err = exc
                time.sleep(min(30, 2 ** attempt) + random.random())
        raise LLMError(f"LLM request failed after retries: {last_err}")

    # ------------------------------------------------------------------ API
    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        data = self._post("/chat/completions", payload)
        choices = data.get("choices") or []
        if not choices:
            raise LLMError(f"no choices in response: {str(data)[:500]}")
        message = choices[0].get("message") or {}
        # Normalise reasoning-model fields, keeping only what the API accepts back.
        out = {"role": "assistant", "content": message.get("content") or ""}
        if message.get("tool_calls"):
            out["tool_calls"] = message["tool_calls"]
        if message.get("reasoning_content"):
            out["reasoning_content"] = message["reasoning_content"]
        return out
