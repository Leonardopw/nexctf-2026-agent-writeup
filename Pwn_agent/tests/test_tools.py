import shutil
import unittest
from pathlib import Path

from pwnagent.config import PwnAgentConfig
from pwnagent.pwn_tools import fmtstr_plan, libc_match, libc_offsets
from pwnagent.vendor.pwnproof.runtime import LinuxRuntime
from pwnagent.vendor.pwnproof.triage import triage

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "ret2win"
LIBC = "/lib/x86_64-linux-gnu/libc.so.6"


@unittest.skipUnless(shutil.which("wsl.exe"), "WSL is required for the pwn toolchain")
class ToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = PwnAgentConfig(binary=EXAMPLES / "chall", workspace=EXAMPLES)
        cls.runtime = LinuxRuntime(cls.config.workspace)
        cls.facts = triage(cls.config.binary, cls.config.workspace, cls.runtime, source=EXAMPLES / "chall.c")

    def test_libc_offsets(self):
        info = libc_offsets(self.config, self.runtime, self.facts, libc=LIBC)
        self.assertTrue(info["ok"])
        self.assertIn("puts", info["symbol_offsets"])
        self.assertIn("system", info["symbol_offsets"])
        self.assertGreater(info["symbol_offsets"]["system"], 0)
        self.assertIsNotNone(info["binsh_offset"])

    def test_libc_match_page_aligned(self):
        base = 0x7F0000000000
        info = libc_offsets(self.config, self.runtime, self.facts, libc=LIBC)
        leak = base + info["symbol_offsets"]["puts"]
        matched = libc_match(self.config, self.runtime, self.facts, leak=leak, symbol="puts", libc=LIBC)
        self.assertEqual(int(matched["base"], 16), base)

    def test_fmtstr_plan_emits_code(self):
        plan = fmtstr_plan(self.config, self.runtime, self.facts, target="0x404060", value="0x4011b6")
        self.assertIn("fmtstr_payload", plan["code"])


if __name__ == "__main__":
    unittest.main()
