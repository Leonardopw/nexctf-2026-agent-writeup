# Local examples

These are the PwnProof acceptance targets, copied without their `exploits/`
solutions so the agent cannot read the answer:

- `ret2win/chall` + `chall.c`: non-PIE x86-64, `gets` overflow, `win` prints
  `PWNPROOF_FLAG`.
- `ret2libc/chall` + `chall.c`: x86-64, NX, `puts@GOT` leak + `system("/bin/sh")`.
- `format-string/chall` + `chall.c`: `printf(buf)` probe target (no flag by
  design; used to test the leak probe).

Run:

```powershell
python -m pwnagent bench --dir .\examples --limit 3
python -m pwnagent heuristic .\examples\ret2win\chall `
  --workspace .\examples\ret2win --source .\examples\ret2win\chall.c `
  --local-flag "NEXCTF{local_demo}"
```
