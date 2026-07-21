import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import iam_exposure
from iam_exposure.updates import load_and_verify_rule_bundle


class PublicApiTests(unittest.TestCase):
    def test_public_interfaces_are_importable_without_loading_aws_client(self):
        for name in (
            "collect_inventory",
            "evaluate_snapshot",
            "build_attack_graph",
            "find_attack_paths",
            "diff_snapshots",
            "render_report",
            "load_and_verify_rule_bundle",
        ):
            self.assertTrue(callable(getattr(iam_exposure, name)))

    def test_rule_bundle_digest_is_verified(self):
        bundle = {
            "id": "test-1",
            "name": "Test rules",
            "rules": [
                {
                    "id": "test.rule",
                    "name": "Test rule",
                    "category": "test",
                    "severity": "high",
                    "required_permissions": ["iam:PassRole"],
                    "source": ["test"],
                    "business_impact": "Test impact",
                    "recommendation": "Test remediation",
                }
            ],
        }
        raw = json.dumps(bundle).encode("utf-8")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "rules.json"
            path.write_bytes(raw)
            verified = load_and_verify_rule_bundle(path, expected_sha256=hashlib.sha256(raw).hexdigest())
        self.assertEqual(verified["id"], "test-1")


if __name__ == "__main__":
    unittest.main()
