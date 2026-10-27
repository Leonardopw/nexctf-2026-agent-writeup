import shutil
import tempfile
import unittest
from pathlib import Path

from pwnagent.agent import PwnAgent
from pwnagent.config import PwnAgentConfig

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "ret2win"


@unittest.skipUnless(shutil.which("wsl.exe"), "WSL is required for the pwn toolchain")
@unittest.skipUnless((EXAMPLE / "chall").is_file(), "PwnProof ret2win example is missing")
class IntegrationTests(unittest.TestCase):
    def test_deterministic_ret2win_end_to_end(self):
        with tempfile.TemporaryDirectory() as td:
            config = PwnAgentConfig(
                binary=EXAMPLE / "chall",
                workspace=EXAMPLE,
                source=EXAMPLE / "chall.c",
                local_flag="NEXCTF{unittest_ret2win}",
                artifact_root=Path(td),
                attempts=1,
                max_steps=1,
            )
            result = PwnAgent(config).heuristic_only()
            self.assertEqual(result["flag"], "NEXCTF{unittest_ret2win}")
            self.assertTrue(Path(result["summary"]).is_file())


if __name__ == "__main__":
    unittest.main()
