"""PwnAgent command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from .agent import PwnAgent
from .config import PwnAgentConfig, default_gef_path
from .model_config import (
    PROFILES,
    ModelSettings,
    current_summary,
    detect_dsh_model,
    detect_dsh_settings,
    resolve_model_settings,
    save_active,
)
from .heuristics import generate_candidate
from .planner import available_playbooks
from .vendor.pwnproof.runtime import LinuxRuntime
from .vendor.pwnproof.triage import triage


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwnagent",
        description="PwnAgent: multi-attempt, proof-gated binary exploitation agent (PwnProof + ctf-agent + ctf-tools).",
    )
    parser.add_argument("--version", action="version", version="PwnAgent 0.1.0")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser, *, solve: bool = False) -> None:
        p.add_argument("binary")
        p.add_argument("--source")
        p.add_argument("--workspace")
        p.add_argument("--host")
        p.add_argument("--port", type=int)
        p.add_argument("--name", default="pwn")
        p.add_argument("--description", default="")
        p.add_argument("--flag-regex", default=None)
        p.add_argument("--local-flag", default="")
        p.add_argument("--libc", default=None)
        p.add_argument("--distro", default="Ubuntu")
        p.add_argument("--runtime", choices=["auto", "native", "wsl"], default="auto")
        p.add_argument("--artifact-root", default=None)
        p.add_argument("--gef", default=None)
        if solve:
            p.add_argument("--attempts", type=int, default=3)
            p.add_argument("--max-steps", type=int, default=18)
            p.add_argument("--time-budget", type=int, default=600)
            p.add_argument("--playbook", action="append", default=[])
            p.add_argument("--model", default=None)
            p.add_argument("--base-url", default=None)
            p.add_argument("--no-parallel", action="store_true")
            p.add_argument("--fast-only", action="store_true", help="Skip model; only deterministic fast paths")

    doctor = sub.add_parser("doctor", help="Check the pwn toolchain and runtime")
    doctor.add_argument("--distro", default="Ubuntu")
    doctor.add_argument("--runtime", choices=["auto", "native", "wsl"], default="auto")
    doctor.add_argument("--workspace", default=".")

    model = sub.add_parser("model", help="Show/switch the active OpenAI-compatible model")
    model.add_argument("action", choices=["list", "current", "use", "detect"])
    model.add_argument("name", nargs="?", help="profile name or model name for 'use'")
    model.add_argument("--base-url", default="")
    model.add_argument("--provider", default="")
    model.add_argument("--write", action="store_true", help="persist the detected/selected model")

    inspect = sub.add_parser("triage", help="ELF facts + ranked playbooks")
    common(inspect)
    inspect.add_argument("--raw", action="store_true")

    solve = sub.add_parser("solve", help="Run multi-attempt PwnAgent")
    common(solve, solve=True)

    heur = sub.add_parser("heuristic", help="Deterministic fast paths only (no API key)")
    common(heur)

    bench = sub.add_parser("bench", help="Benchmark deterministic paths on example directories")
    bench.add_argument("--dir", default=None, help="Directory containing <case>/chall binaries")
    bench.add_argument("--limit", type=int, default=10)
    bench.add_argument("--local-flag", default="NEXCTF{pwnagent_bench}")
    bench.add_argument("--distro", default="Ubuntu")
    bench.add_argument("--runtime", choices=["auto", "native", "wsl"], default="auto")

    replay = sub.add_parser("replay", help="Show a run summary and recent rollout events")
    replay.add_argument("run_dir")
    replay.add_argument("--events", type=int, default=10)

    return parser


def _binary(args: argparse.Namespace) -> Path:
    path = Path(args.binary).expanduser().resolve()
    if not path.is_file():
        raise SystemExit(f"binary not found: {path}")
    return path


def _config(args: argparse.Namespace, *, attempts: int | None = None) -> PwnAgentConfig:
    binary = _binary(args)
    workspace = Path(args.workspace).expanduser().resolve() if args.workspace else binary.parent
    artifact_root = (
        Path(args.artifact_root).expanduser().resolve()
        if args.artifact_root
        else workspace / "artifacts"
    )
    kwargs = dict(
        binary=binary,
        workspace=workspace,
        source=Path(args.source).expanduser().resolve() if args.source else None,
        name=args.name,
        description=args.description,
        host=args.host,
        port=args.port,
        local_flag=args.local_flag,
        libc=args.libc,
        distro=args.distro,
        runtime=args.runtime,
        gef_path=args.gef or default_gef_path(),
        artifact_root=artifact_root,
    )
    if getattr(args, "flag_regex", None):
        kwargs["flag_pattern"] = args.flag_regex
    if getattr(args, "model", None):
        kwargs["model"] = args.model
    if getattr(args, "base_url", None):
        kwargs["base_url"] = args.base_url.rstrip("/")
    if attempts is None:
        attempts = getattr(args, "attempts", None)
    if attempts is not None:
        kwargs["attempts"] = attempts
    if getattr(args, "max_steps", None):
        kwargs["max_steps"] = args.max_steps
    if getattr(args, "time_budget", None):
        kwargs["time_budget"] = args.time_budget
    if getattr(args, "playbook", None):
        kwargs["playbooks"] = tuple(args.playbook)
    if getattr(args, "no_parallel", False):
        kwargs["parallel"] = False
    return PwnAgentConfig(**kwargs)


def _doctor(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser().resolve()
    runtime = LinuxRuntime(workspace, distro=args.distro, mode=args.runtime)
    report = runtime.doctor()
    extras: dict[str, object] = {}
    for name, command in {
        "one_gadget": "one_gadget --version 2>&1 | head -1",
        "seccomp-tools": "seccomp-tools --version 2>&1 | head -1",
        "ROPgadget": "ROPgadget --version 2>&1 | head -1",
        "patchelf": "patchelf --version 2>&1 | head -1",
    }.items():
        result = runtime.run(command, timeout=10)
        extras[name] = result.combined.strip()[:200]
    extras["gef"] = default_gef_path() or "missing"
    report["extras"] = extras
    report["model"] = current_summary()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report.get("ready") else 1


def _triage(args: argparse.Namespace) -> int:
    config = _config(args)
    runtime = LinuxRuntime(config.workspace, distro=config.distro, mode=config.runtime)
    facts = triage(config.binary, config.workspace, runtime, source=config.source)
    payload = facts.to_dict(include_raw=args.raw)
    payload["playbooks"] = [
        {"name": name, "confidence": confidence, "reason": reason}
        for name, confidence, reason in available_playbooks(facts)
    ]
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def _solve(args: argparse.Namespace) -> int:
    config = _config(args)
    agent = PwnAgent(config)
    result = agent.heuristic_only() if args.fast_only else agent.run()
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0 if result.get("flag") else 1


def _bench(args: argparse.Namespace) -> int:
    base = Path(args.dir).expanduser().resolve() if args.dir else Path.cwd() / "examples"
    cases = sorted({p.parent for p in base.glob("*/chall")})
    cases += sorted({p.parent for p in base.glob("*/*/chall")})
    if not cases:
        print(f"no <case>/chall binaries under {base}", file=sys.stderr)
        return 2
    rows = []
    for case in cases[: max(1, args.limit)]:
        binary = case / "chall"
        sources = sorted(case.glob("*.c"))
        source = sources[0] if sources else None
        config = PwnAgentConfig(
            binary=binary,
            workspace=case,
            source=source,
            name=case.name,
            local_flag=args.local_flag,
            distro=args.distro,
            runtime=args.runtime,
            attempts=1,
            max_steps=1,
            time_budget=60,
            artifact_root=base / "_bench_artifacts",
        )
        started = time.time()
        result = PwnAgent(config).heuristic_only()
        rows.append(
            {
                "case": case.name,
                "flag": result.get("flag"),
                "status": (result.get("results") or [{}])[0].get("status", "?"),
                "seconds": round(time.time() - started, 2),
            }
        )
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 0 if all(row["flag"] for row in rows) else 1


def _replay(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    summary = run_dir / "summary.json"
    if summary.exists():
        print(summary.read_text(encoding="utf-8"))
    for path in sorted(run_dir.glob("attempt-*/rollout.jsonl")):
        print(f"\n== {path}")
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for line in lines[-max(1, args.events) :]:
            print(line[:800])
    return 0


def _model(args: argparse.Namespace) -> int:
    if args.action == "list":
        payload = {
            "profiles": {
                name: {"model": item["model"], "base_url": item["base_url"], "provider": item["provider"]}
                for name, item in PROFILES.items()
            },
            "current": current_summary(),
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    if args.action == "current":
        print(json.dumps(current_summary(), ensure_ascii=False, indent=2))
        return 0
    if args.action == "detect":
        provider, model, source = detect_dsh_model(force=True)
        if not model:
            provider, model = detect_dsh_settings()
            source = "dsh-settings"
        payload = {"provider": provider, "model": model, "source": source or "not-found"}
        if model and args.write:
            profile = ""
            for name, item in PROFILES.items():
                if item["model"] == model:
                    profile = name
                    break
            if not profile:
                for name, item in PROFILES.items():
                    if item["provider"] == provider:
                        profile = name
                        break
            base = PROFILES.get(profile, {}).get("base_url", os.getenv("PWN_AGENT_BASE_URL", "https://api.deepseek.com"))
            settings = ModelSettings(model=model, base_url=base, api_key="", provider=provider, profile=profile, source=source)
            payload["saved"] = str(save_active(settings))
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    if args.action == "use":
        if not args.name:
            print("usage: pwnagent model use <profile-or-model> [--base-url URL]", file=sys.stderr)
            return 2
        name = args.name
        if name in PROFILES:
            item = PROFILES[name]
            settings = ModelSettings(
                model=item["model"],
                base_url=item["base_url"],
                api_key="",
                provider=item["provider"],
                profile=name,
                source="model-use",
            )
        else:
            settings = resolve_model_settings(explicit_model=name, explicit_base=args.base_url)
            settings.profile = args.provider or settings.profile
            settings.provider = args.provider or settings.provider
            settings.source = "model-use"
        path = save_active(settings)
        print(json.dumps({"saved": str(path), "active": settings.public()}, ensure_ascii=False, indent=2))
        return 0
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "doctor":
        return _doctor(args)
    if args.command == "model":
        return _model(args)
    if args.command == "triage":
        return _triage(args)
    if args.command == "solve":
        return _solve(args)
    if args.command == "heuristic":
        return _solve(argparse.Namespace(**{**vars(args), "fast_only": True}))
    if args.command == "bench":
        return _bench(args)
    if args.command == "replay":
        return _replay(args)
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
