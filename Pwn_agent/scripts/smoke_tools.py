"""Smoke-test deterministic pwn tools against a local example."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pwnagent.config import PwnAgentConfig
from pwnagent.pwn_tools import (
    debug_session,
    find_offset,
    fmtstr_plan,
    heap_plan,
    libc_offsets,
    rop_plan,
    seccomp_inventory,
)
from pwnagent.vendor.pwnproof.runtime import LinuxRuntime
from pwnagent.vendor.pwnproof.triage import triage


def main() -> int:
    example = Path(r"<DESKTOP>\pwnproof\examples\ret2win")
    config = PwnAgentConfig(binary=example / "chall", workspace=example)
    runtime = LinuxRuntime(config.workspace, distro=config.distro, mode=config.runtime)
    facts = triage(config.binary, config.workspace, runtime, source=example / "chall.c")

    print("== offset")
    print(json.dumps(find_offset(config, runtime, facts), ensure_ascii=False, indent=2)[:1500])

    print("== libc_info")
    info = libc_offsets(config, runtime, facts, libc="/lib/x86_64-linux-gnu/libc.so.6")
    print(json.dumps({k: info[k] for k in ("ok", "release", "binsh_offset", "one_gadgets")}, ensure_ascii=False, indent=2)[:1200])
    print("system:", info["symbols"].get("system"), "puts:", info["symbols"].get("puts"))

    print("== fmtstr_plan")
    plan = fmtstr_plan(config, runtime, facts, target="0x404060", value="0x4011b6", index=6, mode="write")
    print(plan["code"][:500])

    print("== rop_plan")
    rop = rop_plan(config, runtime, facts, goal="system", libc="/lib/x86_64-linux-gnu/libc.so.6", base=0, offset=72)
    print(json.dumps({k: rop.get(k) for k in ("ok", "error", "gadgets")}, ensure_ascii=False, indent=2)[:1000])
    print(rop.get("code", "")[:500])

    print("== heap_plan")
    heap = heap_plan(config, runtime, facts, release="2.39", chunk_size=0x30, goal="tcache")
    print(json.dumps({k: heap.get(k) for k in ("ok", "goal", "libc_symbols")}, ensure_ascii=False, indent=2)[:800])

    print("== seccomp")
    print(json.dumps(seccomp_inventory(config, runtime, facts), ensure_ascii=False, indent=2)[:800])

    print("== debug")
    dbg = debug_session(config, runtime, facts, breakpoint="win", commands=["x/4i $rip"])
    print(json.dumps({k: dbg.get(k) for k in ("ok", "exit_code", "timed_out")}, ensure_ascii=False, indent=2))
    print(dbg.get("gdb", "")[-1200:])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
