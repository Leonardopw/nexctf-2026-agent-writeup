"""Tool schemas and dispatch for PwnAgent.

PwnProof supplies the proof-gated file/command/exploit/ledger tools. This module
adds deterministic pwn construction tools (offset, libc, ROP, fmtstr, heap,
seccomp, GDB/GEF, disassembly) and keeps every result bounded.
"""

from __future__ import annotations

import json
from typing import Any

from . import pwn_tools
from .vendor.pwnproof.tools import MAX_TOOL_RESULT_CHARS, TOOL_SCHEMAS as BASE_SCHEMAS, Toolbox as BaseToolbox


EXTRA_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "offset",
            "description": (
                "Find the saved return-address offset with a cyclic pattern and GDB. "
                "Use this before building any stack payload. Returns the offset and the crashing register."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "length": {"type": "integer", "default": 512},
                    "input_mode": {"type": "string", "enum": ["line", "raw"], "default": "line"},
                    "buffer_size": {"type": "integer", "description": "Optional source-known buffer size."},
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "libc_info",
            "description": "Read a bundled libc: version, symbol offsets, /bin/sh offset, hooks, one_gadget candidates.",
            "parameters": {
                "type": "object",
                "properties": {
                    "libc": {"type": "string", "description": "Workspace-relative libc path; defaults to discovered libc."},
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "libc_match",
            "description": (
                "Resolve a runtime leak to a libc base and all known symbol addresses. "
                "Example: leak=0x7f... symbol=puts. Validates page alignment."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "leak": {"type": "string"},
                    "symbol": {"type": "string", "default": "puts"},
                    "libc": {"type": "string"},
                },
                "required": ["leak"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "one_gadget",
            "description": "Return one_gadget execve offsets and constraints for the bundled libc.",
            "parameters": {
                "type": "object",
                "properties": {"libc": {"type": "string"}},
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fmtstr_plan",
            "description": (
                "Generate a pwntools format-string leak/write snippet. "
                "Find the stack argument index first; target is an address (GOT/return/hook)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "value": {"type": "string", "default": "0"},
                    "index": {"type": "integer", "default": 6},
                    "mode": {"type": "string", "enum": ["leak", "write"], "default": "write"},
                    "bits": {"type": "integer", "enum": [32, 64]},
                    "write_size": {"type": "string", "enum": ["byte", "short", "int"], "default": "short"},
                },
                "required": ["target"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "rop_plan",
            "description": (
                "Build a ret2libc/execve/ORW ROP snippet with gadget addresses. "
                "goal=system|execve|orw; base is the libc base (0 to fill later)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "goal": {"type": "string", "enum": ["system", "execve", "orw", "srop", "ret2dlresolve"], "default": "system"},
                    "libc": {"type": "string"},
                    "base": {"type": "string", "default": "0"},
                    "offset": {"type": "integer", "default": 72},
                    "writable": {"type": "string", "default": "0"},
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "heap_plan",
            "description": (
                "Return version-aware tcache/safe-linking/FSOP facts and a plan snippet. "
                "Call before writing heap metadata; pass the libc release or let it infer."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "release": {"type": "string"},
                    "chunk_size": {"type": "integer"},
                    "libc": {"type": "string"},
                    "goal": {"type": "string", "enum": ["tcache", "fsop"], "default": "tcache"},
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "seccomp",
            "description": "Inventory seccomp filters (seccomp-tools if installed) and recommend execve vs ORW.",
            "parameters": {
                "type": "object",
                "properties": {"binary": {"type": "string"}},
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "debug",
            "description": (
                "Run a bounded GDB batch (GEF loaded when available) with an input file and "
                "optional breakpoint; returns registers, backtrace, and stack."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "input_path": {"type": "string"},
                    "breakpoint": {"type": "string"},
                    "commands": {"type": "array", "items": {"type": "string"}},
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "disasm",
            "description": "Show bounded Intel disassembly for a symbol or address range.",
            "parameters": {
                "type": "object",
                "properties": {
                    "symbol": {"type": "string"},
                    "address": {"type": "string"},
                    "length": {"type": "integer", "default": 60},
                },
                "additionalProperties": False,
            },
        },
    },
]

TOOL_SCHEMAS: list[dict[str, Any]] = BASE_SCHEMAS + EXTRA_SCHEMAS


class PwnToolbox(BaseToolbox):
    """PwnProof toolbox plus deterministic pwn construction helpers."""

    def dispatch(self, name: str, arguments: dict[str, Any]) -> str:
        handlers = {
            "offset": self._offset,
            "libc_info": self._libc_info,
            "libc_match": self._libc_match,
            "one_gadget": self._one_gadget,
            "fmtstr_plan": self._fmtstr_plan,
            "rop_plan": self._rop_plan,
            "heap_plan": self._heap_plan,
            "seccomp": self._seccomp,
            "debug": self._debug,
            "disasm": self._disasm,
        }
        handler = handlers.get(name)
        if handler is None:
            return super().dispatch(name, arguments)
        try:
            payload = handler(arguments or {})
        except Exception as exc:  # noqa: BLE001
            payload = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        rendered = json.dumps(payload, ensure_ascii=False, indent=2)
        if len(rendered) > MAX_TOOL_RESULT_CHARS:
            rendered = rendered[:MAX_TOOL_RESULT_CHARS] + "\n... [truncated]"
        return rendered

    # ------------------------------------------------------------------
    def _offset(self, args: dict[str, Any]) -> dict:
        result = pwn_tools.find_offset(
            self.config,
            self.runtime,
            self.facts,
            length=int(args.get("length", 512)),
            input_mode=str(args.get("input_mode", "line")),
            buffer_size=args.get("buffer_size"),
        )
        if result.get("offset") is not None:
            self.ledger.add("fact", f"return-address offset = {result['offset']} ({result.get('evidence','')})")
        return result

    def _libc_info(self, args: dict[str, Any]) -> dict:
        return pwn_tools.libc_offsets(self.config, self.runtime, self.facts, libc=args.get("libc"))

    def _libc_match(self, args: dict[str, Any]) -> dict:
        result = pwn_tools.libc_match(
            self.config,
            self.runtime,
            self.facts,
            leak=args.get("leak", ""),
            symbol=str(args.get("symbol", "puts")),
            libc=args.get("libc"),
        )
        if result.get("base"):
            self.ledger.add("fact", f"libc base {result['base']} from {args.get('symbol','puts')} leak")
        return result

    def _one_gadget(self, args: dict[str, Any]) -> dict:
        info = pwn_tools.libc_offsets(self.config, self.runtime, self.facts, libc=args.get("libc"))
        return {"ok": True, "release": info.get("release"), "one_gadgets": info.get("one_gadgets", [])}

    def _fmtstr_plan(self, args: dict[str, Any]) -> dict:
        return pwn_tools.fmtstr_plan(
            self.config,
            self.runtime,
            self.facts,
            target=args.get("target", "0"),
            value=args.get("value", "0"),
            index=int(args.get("index", 6)),
            mode=str(args.get("mode", "write")),
            bits=args.get("bits"),
            write_size=str(args.get("write_size", "short")),
        )

    def _rop_plan(self, args: dict[str, Any]) -> dict:
        return pwn_tools.rop_plan(
            self.config,
            self.runtime,
            self.facts,
            goal=str(args.get("goal", "system")),
            libc=args.get("libc"),
            base=args.get("base", "0"),
            offset=int(args.get("offset", 72)),
            writable=args.get("writable", "0"),
        )

    def _heap_plan(self, args: dict[str, Any]) -> dict:
        result = pwn_tools.heap_plan(
            self.config,
            self.runtime,
            self.facts,
            release=str(args.get("release", "")),
            chunk_size=args.get("chunk_size"),
            libc=args.get("libc"),
            goal=str(args.get("goal", "tcache")),
        )
        self.ledger.add("plan", f"heap plan: {result.get('goal')} release={result.get('libc_release','?')}")
        return result

    def _seccomp(self, args: dict[str, Any]) -> dict:
        return pwn_tools.seccomp_inventory(
            self.config, self.runtime, self.facts, binary=args.get("binary")
        )

    def _debug(self, args: dict[str, Any]) -> dict:
        return pwn_tools.debug_session(
            self.config,
            self.runtime,
            self.facts,
            input_path=args.get("input_path"),
            breakpoint=args.get("breakpoint"),
            commands=args.get("commands"),
        )

    def _disasm(self, args: dict[str, Any]) -> dict:
        return pwn_tools.disassemble(
            self.config,
            self.runtime,
            symbol=args.get("symbol"),
            address=args.get("address"),
            length=int(args.get("length", 60)),
        )
