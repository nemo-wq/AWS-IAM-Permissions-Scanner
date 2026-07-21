import json
import unittest
from pathlib import Path

from iam_exposure.rules import evaluate_inventory, load_ruleset


class BenchmarkTests(unittest.TestCase):
    def test_all_synthetic_scenarios(self):
        root = Path(__file__).parents[1] / "benchmarks" / "scenarios"
        for path in sorted(root.glob("*.json")):
            with self.subTest(path=path.name):
                scenario = json.loads(path.read_text(encoding="utf-8"))
                findings = evaluate_inventory(scenario["inventory"], load_ruleset())
                ids = {finding["id"] for finding in findings}
                self.assertTrue(set(scenario.get("expected_present", [])).issubset(ids))
                self.assertTrue(set(scenario.get("expected_absent", [])).isdisjoint(ids))


if __name__ == "__main__":
    unittest.main()
