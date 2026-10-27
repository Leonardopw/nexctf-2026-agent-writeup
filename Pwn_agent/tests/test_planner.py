import unittest

from pwnagent.planner import available_playbooks, plan_strategies
from pwnagent.vendor.pwnproof.triage import BinaryFacts, Hypothesis


def make_facts(**overrides):
    values = dict(
        path="chall",
        bits=64,
        arch="Advanced Micro Devices X86-64",
        protections={"nx": "NX enabled", "canary": "No canary found", "pie": "No PIE (0x400000)"},
        symbols={"win": "0x4011b6", "main": "0x4011ed"},
        suspicious_functions=["gets", "puts", "printf"],
        hypotheses=[
            Hypothesis("stack_overflow", 0.96, "gets"),
            Hypothesis("ret2win", 0.92, "win symbol"),
            Hypothesis("ret2libc", 0.82, "NX + leak"),
            Hypothesis("format_string", 0.90, "printf"),
            Hypothesis("heap_exploitation", 0.72, "malloc/free"),
        ],
    )
    values.update(overrides)
    return BinaryFacts(**values)


class PlannerTests(unittest.TestCase):
    def test_ranked_playbooks_include_known_paths(self):
        names = [item[0] for item in available_playbooks(make_facts())]
        self.assertIn("ret2win", names)
        self.assertIn("ret2libc", names)
        self.assertIn("fmtstr", names)
        self.assertIn("heap", names)

    def test_three_strategies_are_diverse(self):
        strategies = plan_strategies(make_facts(), attempts=3)
        names = [item.name for item in strategies]
        self.assertEqual(len(names), 3)
        self.assertEqual(len(set(names)), 3)
        self.assertIn("ret2win", names)

    def test_requested_playbook_is_honored(self):
        strategies = plan_strategies(make_facts(), attempts=2, requested=("heap", "fmtstr"))
        self.assertEqual([item.name for item in strategies], ["heap", "fmtstr"])

    def test_fallback_without_hypotheses(self):
        facts = make_facts(hypotheses=[])
        strategies = plan_strategies(facts, attempts=2)
        self.assertTrue(strategies)
        self.assertEqual(strategies[0].name, "manual")


if __name__ == "__main__":
    unittest.main()
