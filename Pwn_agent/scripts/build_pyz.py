"""Build a single-file pwnagent.pyz (stdlib zipapp)."""

from __future__ import annotations

import shutil
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"


def main() -> int:
    DIST.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        staging = Path(td)
        shutil.copytree(ROOT / "pwnagent", staging / "pwnagent")
        (staging / "__main__.py").write_text(
            "import sys\nfrom pwnagent.cli import main\nsys.exit(main())\n",
            encoding="utf-8",
        )
        target = DIST / "pwnagent.pyz"
        if target.exists():
            target.unlink()
        zipapp.create_archive(staging, target=target, interpreter="/usr/bin/env python3")
    print(target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
