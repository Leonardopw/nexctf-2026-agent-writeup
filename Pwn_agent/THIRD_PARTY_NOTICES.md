# Third-party notices

## PwnProof

- Source: `<DESKTOP>\pwnproof`
- License: MIT (see `vendor/pwnproof` original project LICENSE)
- Reused: triage, runtime, ledger, proof gate, libc discovery, base tools,
  deterministic ret2win/format/ret2libc generators, model client.
- PwnAgent vendors the subset needed under `pwnagent/vendor/pwnproof/`.

## ctf-agent

- Source: `<DESKTOP>\ctf-agent`
- Reused design: multi-attempt orchestration, planner/reflection/context
  compaction, run/summary layout. PwnAgent reimplements the loop around the
  PwnProof core rather than importing the web-oriented toolbox.

## GEF

- Source: `<DESKTOP>\ctf-tools\gef.py`
- License: MIT (GEF upstream)
- Not redistributed; the `debug` tool loads it from the user's path when
  available (`PWN_AGENT_GEF` or `Desktop/ctf-tools/gef.py`).

## RsaCtfTool

- Source: `<DESKTOP>\ctf-tools\RsaCtfTool`
- License: GPL-3.0 (upstream)
- Not redistributed and not imported. Hybrid challenges may call it through
  `run_command` if the user has it installed.

## Other runtime tools

`pwntools` (MIT), `ROPgadget` (BSD), `one_gadget` (MIT), `seccomp-tools` (MIT),
`gdb`/`binutils` (GPL) are external WSL tools; they are invoked, not vendored.
