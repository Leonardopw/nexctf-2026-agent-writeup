"""Tool definitions and execution for the CTF agent."""
from __future__ import annotations

import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- schemas
TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "run_command",
            "description": (
                "在 Linux 环境（WSL/bash）或 PowerShell 中执行一条 shell 命令并返回 stdout/stderr。"
                "用于探测目标、运行脚本、编译、读取系统文件等。命令在本次任务的工作目录中执行。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "要执行的命令"},
                    "timeout": {"type": "integer", "description": "超时秒数，默认 120", "default": 120},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "发送 HTTP 请求，返回状态码、响应头和响应体（自动处理常见编码，最多返回 20000 字符）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "default": "GET"},
                    "headers": {"type": "object", "description": "请求头字典"},
                    "body": {"type": "string", "description": "请求体"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "读取工作目录（或绝对路径）下的文本文件；二进制会以十六进制摘要返回。",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "写入文件（相对路径基于工作目录），用于保存 exp、脚本、字典等。",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_dir",
            "description": "列出目录内容。",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string", "default": "."}},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_flag",
            "description": "提交找到的 flag。只有在确认 flag 正确时才调用，调用后会结束本题。",
            "parameters": {
                "type": "object",
                "properties": {"flag": {"type": "string"}},
                "required": ["flag"],
            },
        },
    },
]


# --------------------------------------------------------------------------- shell
def _to_wsl_path(path: str) -> str:
    p = Path(path).resolve()
    drive = p.drive.rstrip(":").lower()
    rest = str(p)[len(p.drive):].replace("\\", "/")
    return f"/mnt/{drive}{rest}"


class Shell:
    """Runs commands in WSL bash, native bash, or PowerShell."""

    def __init__(self, workdir: Path, mode: str = "auto"):
        self.workdir = workdir
        self.mode = self._resolve(mode)

    @staticmethod
    def _resolve(mode: str) -> str:
        if mode != "auto":
            return mode
        if platform.system() == "Windows":
            if shutil.which("wsl"):
                return "wsl"
            if shutil.which("bash"):
                return "bash"
            return "powershell"
        return "bash"

    def run(self, command: str, timeout: int = 120) -> str:
        try:
            if self.mode == "wsl":
                wd = _to_wsl_path(str(self.workdir))
                proc = subprocess.run(
                    ["wsl.exe", "-e", "bash", "-lc", f"cd {shlex.quote(wd)} && {command}"],
                    capture_output=True, timeout=timeout,
                )
            elif self.mode == "bash":
                proc = subprocess.run(
                    ["/bin/bash", "-lc", command],
                    capture_output=True, timeout=timeout, cwd=str(self.workdir),
                )
            else:
                proc = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                    capture_output=True, timeout=timeout, cwd=str(self.workdir),
                )
            out = (proc.stdout or b"").decode("utf-8", "replace")
            err = (proc.stderr or b"").decode("utf-8", "replace")
            text = out
            if err.strip():
                text += ("\n[stderr]\n" if text else "[stderr]\n") + err
            if not text.strip():
                text = f"[exit code {proc.returncode}, no output]"
            elif proc.returncode != 0:
                text += f"\n[exit code {proc.returncode}]"
            return text
        except subprocess.TimeoutExpired:
            return f"[timeout after {timeout}s]"
        except Exception as exc:  # noqa: BLE001
            return f"[shell error] {exc}"


# --------------------------------------------------------------------------- tools
class Toolbox:
    def __init__(self, workdir: Path, shell: Shell, flag_regex: str, max_output: int = 20000):
        self.workdir = workdir
        self.shell = shell
        self.flag_re = re.compile(flag_regex)
        self.max_output = max_output
        self.flag: str | None = None
        self.notes: list[str] = []

    # -- helpers -----------------------------------------------------------
    def _truncate(self, text: str) -> str:
        if len(text) > self.max_output:
            return text[: self.max_output] + f"\n...[truncated {len(text) - self.max_output} chars]"
        return text

    def _resolve(self, path: str) -> Path:
        p = Path(path)
        return p if p.is_absolute() else (self.workdir / p)

    def _scan_flag(self, text: str) -> None:
        if self.flag:
            return
        m = self.flag_re.search(text)
        if m:
            self.flag = m.group(0)

    # -- execution ---------------------------------------------------------
    def execute(self, name: str, args: dict[str, Any]) -> str:
        try:
            result = getattr(self, f"_tool_{name}")(args or {})
        except Exception as exc:  # noqa: BLE001
            result = f"[tool error] {type(exc).__name__}: {exc}"
        if name != "submit_flag":
            self._scan_flag(result)
        return self._truncate(result)

    def _tool_run_command(self, args: dict[str, Any]) -> str:
        cmd = str(args.get("command", "")).strip()
        if not cmd:
            return "[error] empty command"
        timeout = int(args.get("timeout") or 120)
        return self.shell.run(cmd, timeout=min(timeout, 600))

    def _tool_http_request(self, args: dict[str, Any]) -> str:
        url = str(args.get("url", ""))
        method = str(args.get("method") or "GET").upper()
        headers = {str(k): str(v) for k, v in (args.get("headers") or {}).items()}
        body = args.get("body")
        data = body.encode("utf-8") if isinstance(body, str) else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                text = raw.decode("utf-8", "replace")
                head = "\n".join(f"{k}: {v}" for k, v in resp.getheaders())
                return f"HTTP {resp.status}\n{head}\n\n{text}"
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            text = raw.decode("utf-8", "replace")
            head = "\n".join(f"{k}: {v}" for k, v in exc.headers.items())
            return f"HTTP {exc.code}\n{head}\n\n{text}"
        except Exception as exc:  # noqa: BLE001
            return f"[http error] {exc}"

    def _tool_read_file(self, args: dict[str, Any]) -> str:
        path = self._resolve(str(args.get("path", "")))
        if not path.exists():
            return f"[error] no such file: {path}"
        raw = path.read_bytes()
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return f"[binary file, {len(raw)} bytes]\n" + raw[:512].hex()

    def _tool_write_file(self, args: dict[str, Any]) -> str:
        path = self._resolve(str(args.get("path", "")))
        path.parent.mkdir(parents=True, exist_ok=True)
        content = str(args.get("content", ""))
        path.write_text(content, encoding="utf-8")
        return f"[ok] wrote {len(content)} chars to {path}"

    def _tool_list_dir(self, args: dict[str, Any]) -> str:
        path = self._resolve(str(args.get("path") or "."))
        if not path.exists():
            return f"[error] no such dir: {path}"
        rows = []
        for child in sorted(path.iterdir(), key=lambda p: p.name):
            kind = "DIR " if child.is_dir() else "FILE"
            size = "" if child.is_dir() else f"{child.stat().st_size:>10}"
            rows.append(f"{kind} {size} {child.name}")
        return "\n".join(rows) or "[empty]"

    def _tool_submit_flag(self, args: dict[str, Any]) -> str:
        flag = str(args.get("flag", "")).strip()
        if not self.flag_re.fullmatch(flag):
            return f"[rejected] {flag!r} 不符合 flag 格式 {self.flag_re.pattern}"
        self.flag = flag
        return f"[accepted] flag={flag}"
