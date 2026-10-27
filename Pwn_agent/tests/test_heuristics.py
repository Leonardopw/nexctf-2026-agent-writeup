import unittest

from pwnagent.heuristics import generate_ret2libc32, supports_ret2libc32
from pwnagent.pwn_tools import cyclic
from pwnagent.vendor.pwnproof.triage import BinaryFacts, Hypothesis


def facts32():
    return BinaryFacts(
        path="chall",
        bits=32,
        arch="Intel 80386",
        protections={"nx": "NX enabled", "canary": "No canary found", "pie": "No PIE (0x8048000)"},
        symbols={"main": "0x80484d6"},
        suspicious_functions=["gets", "puts"],
        source_signals=["source uses gets() without a length bound", "possible stack buffer size 100"],
        hypotheses=[Hypothesis("stack_overflow", 0.95, "gets"), Hypothesis("ret2libc", 0.8, "NX")],
    )


class HeuristicTests(unittest.TestCase):
    def test_cyclic_has_unique_4grams(self):
        pattern = cyclic(400)
        self.assertEqual(len(pattern), 400)
        grams = {pattern[i:i + 4] for i in range(len(pattern) - 3)}
        self.assertEqual(len(grams), len(pattern) - 3)

    def test_ret2libc32_supported(self):
        self.assertTrue(supports_ret2libc32(facts32()))

    def test_ret2libc32_generates_expected_flow(self):
        script = generate_ret2libc32(facts32(), None)
        self.assertIsNotNone(script)
        self.assertIn("stage1", script)
        self.assertIn("puts_got", script)
        self.assertIn("libc.symbols[\"system\"]", script)
        self.assertIn("offset = 104", script)

    def test_pie_blocks_ret2libc32_fast_path(self):
        facts = facts32()
        facts.protections["pie"] = "PIE enabled"
        self.assertIsNone(generate_ret2libc32(facts, None))


if __name__ == "__main__":
    unittest.main()
