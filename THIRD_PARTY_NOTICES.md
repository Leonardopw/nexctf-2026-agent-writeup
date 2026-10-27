# Third-party notices

## PwnProof

- Reused under `Pwn_agent/pwnagent/vendor/pwnproof/`.
- License: MIT (original license reproduced at `Pwn_agent/pwnagent/vendor/pwnproof/LICENSE`).
- Reused: triage, runtime, evidence ledger, proof gate, libc discovery, deterministic ret2win/format-string/ret2libc, model client.

## ctf-agent

- Design reference and source under `agent/ctfagent/`.
- Reused design: multi-attempt orchestration, planner/reflection/context compaction, run/summary layout.

## GEF

- `ctf-tools/gef.py` is loaded by PwnAgent's `debug` tool when available.
- License: MIT (upstream GEF). Not redistributed in this repository.

## RsaCtfTool

- Optional external tool for hybrid crypto challenges.
- License: GPL-3.0 (upstream). Not redistributed and not imported; invoked via `run_command` if installed.

## Runtime tools

`pwntools` (MIT), `ROPgadget` (BSD), `one_gadget` (MIT), `seccomp-tools` (MIT), `gdb`/`binutils` (GPL) are external tools invoked by the agent; they are not vendored here.

## DeepSeek Harness

- The DSH runtime is a third-party packaged application and is **not** redistributed.
- `DSH-Pentest.exe` is the author's launcher/deployer only; it does not include the DSH runtime.
