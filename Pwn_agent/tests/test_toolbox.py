import json
import shutil
import tempfile
import unittest
from pathlib import Path

from pwnagent.config import PwnAgentConfig
from pwnagent.tools import PwnToolbox
from pwnagent.vendor.pwnproof.ledger import EvidenceLedger
from pwnagent.vendor.pwnproof.runtime import LinuxRuntime
from pwnagent.vendor.pwnproof.triage import triage

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "ret2win"


@unittest.skipUnless(shutil.which("wsl.exe"), "WSL is required for the pwn toolchain")
class ToolboxTests(unittest.TestCase):
    def test_offset_and_libc_dispatch(self):
        with tempfile.TemporaryDirectory() as td:
            config = PwnAgentConfig(binary=EXAMPLE / "chall", workspace=EXAMPLE)
            runtime = LinuxRuntime(EXAMPLE)
            facts = triage(config.binary, EXAMPLE, runtime, source=EXAMPLE / "chall.c")
            ledger = EvidenceLedger(Path(td) / "evidence.jsonl")
            toolbox = PwnToolbox(config, runtime, facts, ledger, Path(td))
            offset = json.loads(toolbox.dispatch("offset", {}))
            self.assertEqual(offset["offset"], 72)
            info = json.loads(toolbox.dispatch("libc_info", {"libc": "/lib/x86_64-linux-gnu/libc.so.6"}))
            self.assertTrue(info["ok"])
            self.assertIn("system", info["symbols"])


if __name__ == "__main__":
    unittest.main()
