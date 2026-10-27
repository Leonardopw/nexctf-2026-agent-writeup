"""A scripted mock LLM used for offline smoke tests (`--mock`)."""
from __future__ import annotations

import json
from typing import Any


class MockLLM:
    def __init__(self):
        self.step = 0
        self.usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        self._id = 0

    def _call(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        self._id += 1
        return {
            "id": f"call_{self._id}",
            "type": "function",
            "function": {"name": name, "arguments": json.dumps(args, ensure_ascii=False)},
        }

    def chat(self, messages: list[dict[str, Any]], tools=None, temperature: float = 0.3, max_tokens: int = 4096) -> dict[str, Any]:
        self.step += 1
        self.usage["total_tokens"] += 50
        if self.step == 1:
            return {"role": "assistant", "content": "先做一次环境侦察。", "tool_calls": [
                self._call("run_command", {"command": "echo MOCK_RECON_OK && pwd && ls -la"}),
            ]}
        if self.step == 2:
            return {"role": "assistant", "content": "写一个利用脚本。", "tool_calls": [
                self._call("write_file", {"path": "exp.py", "content": "print('hello from exp')"}),
            ]}
        if self.step == 3:
            return {"role": "assistant", "content": "运行脚本验证。", "tool_calls": [
                self._call("run_command", {"command": "python3 exp.py"}),
            ]}
        if self.step == 4:
            return {"role": "assistant", "content": "拿到 mock flag，提交。", "tool_calls": [
                self._call("submit_flag", {"flag": "nex{mock_ok_1234}"}),
            ]}
        return {"role": "assistant", "content": "已完成。", "tool_calls": []}
