"""Command line entry point: `python -m ctfagent ...`."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import Config
from .mock import MockLLM
from .runner import run
from .wp import append_record


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ctfagent", description="CTF-Agent: 本地 CTF 解题 Agent")
    p.add_argument("--name", default="challenge", help="题目名字")
    p.add_argument("--type", dest="ctype", default="web", help="题目类型：web/crypto/misc/pwn/rev/forensics")
    p.add_argument("--target", default="", help="目标 URL 或地址")
    p.add_argument("--hint", default="", help="题面/提示")
    p.add_argument("--file", action="append", default=[], dest="files", help="附件路径，可多次指定")
    p.add_argument("--attempts", type=int, default=1, help="并发策略数（1-4）")
    p.add_argument("--max-steps", type=int, default=40, help="每个策略最大轮次")
    p.add_argument("--time-budget", type=int, default=1800, help="每个策略时间预算（秒）")
    p.add_argument("--model", default=None, help="模型名，如 deepseek-chat")
    p.add_argument("--base-url", default=None, help="OpenAI 兼容 API 地址")
    p.add_argument("--api-key", default=None, help="API Key（也可用 DEEPSEEK_API_KEY）")
    p.add_argument("--temperature", type=float, default=None)
    p.add_argument("--shell", default=None, choices=["auto", "wsl", "bash", "powershell"])
    p.add_argument("--run-dir", default="", help="指定输出目录")
    p.add_argument("--difficulty", default="", help="难度（写入 summary 的 WP 记录）")
    p.add_argument("--mock", action="store_true", help="离线自测：使用脚本化假模型")
    p.add_argument("--wp", default="", help="解出后把实测记录追加到指定 WP Markdown 文件")
    p.add_argument("--json", action="store_true", help="只输出 JSON 结果")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    overrides = {
        "challenge_name": args.name,
        "challenge_type": args.ctype,
        "difficulty": args.difficulty,
        "target": args.target,
        "hint": args.hint,
        "files": args.files,
        "attempts": args.attempts,
        "max_steps": args.max_steps,
        "time_budget": args.time_budget,
        "model": args.model,
        "base_url": args.base_url,
        "api_key": args.api_key,
        "temperature": args.temperature,
        "shell": args.shell,
        "run_dir": args.run_dir or None,
        "mock": args.mock,
    }
    cfg = Config.load(**overrides)
    problems = cfg.validate()
    if problems:
        for msg in problems:
            print(f"[!] {msg}", file=sys.stderr)
        print("提示：复制 .env.example 为 .env 并填入 DEEPSEEK_API_KEY，或 export DEEPSEEK_API_KEY=<REDACTED>", file=sys.stderr)
        if not cfg.mock:
            return 2

    factory = (lambda: MockLLM()) if cfg.mock else None
    result = run(cfg, llm_factory=factory)
    if args.wp and result.get("flag"):
        print(append_record(args.wp, result, cfg.challenge_name, cfg.challenge_type, cfg.difficulty))
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("=" * 60)
        print(f"run dir : {result['run_dir']}")
        print(f"summary : {result['summary']}")
        print(f"flag    : {result['flag']}")
        print(f"time    : {result['duration']:.1f}s")
        for r in result["results"]:
            print(f"  - attempt {r['attempt']} [{r['strategy']}] status={r['status']} steps={r['steps']} flag={r['flag']}")
    return 0 if result["flag"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
