import tempfile
import unittest
from pathlib import Path

from iam_exposure.report import render_html, write_outputs


class ReportTests(unittest.TestCase):
    def test_report_contains_summary_and_finding(self):
        inventory = {
            "account": {"account_id": "111111111111", "alias": "demo"},
            "collection": {"generated_at": "2026-04-17T00:00:00+00:00", "warnings": []},
        }
        findings = [
            {
                "id": "iam.attach-user-policy",
                "title": "Can attach policies to users",
                "category": "self-escalation",
                "severity": "critical",
                "confidence": "high",
                "status": "confirmed",
                "principal": "alice",
                "principal_type": "user",
                "business_impact": "Privilege escalation.",
                "recommended_action": "Remove the permission.",
                "attack_path": "user:alice -> group:Admins -> iam:AttachUserPolicy",
            }
        ]
        ruleset = {"description": "test rules", "rules": [{"source": ["pathfinding.cloud"]}]}
        html = render_html(inventory, findings, ruleset)
        self.assertIn("AWS IAM Exposure Review", html)
        self.assertIn("Can attach policies to users", html)
        self.assertIn("pathfinding.cloud", html)
        self.assertIn("Severity Breakdown", html)
        self.assertIn("Risk Trend", html)
        self.assertIn("Collection Coverage", html)
        self.assertIn("Attack Graph", html)
        self.assertIn("Policies", html)

    def test_write_outputs(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            write_outputs(out, {"account": {}, "collection": {"warnings": []}}, [], {"rules": []}, ["html", "json", "csv", "sarif"])
            self.assertTrue((out / "report.html").exists())
            self.assertTrue((out / "findings.json").exists())
            self.assertTrue((out / "findings.csv").exists())
            self.assertTrue((out / "findings.sarif").exists())
            self.assertTrue((out / "inventory.json").exists())
            self.assertTrue((out / "ruleset.json").exists())
            self.assertTrue((out / "graph.json").exists())
            self.assertTrue((out / "summary.json").exists())
            self.assertTrue((out / "history.json").exists())
            self.assertTrue((out / "evidence" / "collection-warnings.json").exists())

    def test_write_outputs_accumulates_history(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            payload = {"account": {}, "collection": {"warnings": []}}
            write_outputs(out, payload, [], {"rules": []}, ["json"])
            write_outputs(out, payload, [], {"rules": []}, ["json"])
            history = (out / "history.json").read_text(encoding="utf-8")
            self.assertIn("generated_at", history)


if __name__ == "__main__":
    unittest.main()
