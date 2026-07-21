import unittest

from iam_exposure.lifecycle import add_fingerprints, diff_findings


def finding(severity="high", status="likely"):
    return {
        "id": "passrole.lambda-create-function",
        "title": "PassRole through Lambda",
        "category": "iam-passrole-path",
        "severity": severity,
        "confidence": "high",
        "status": status,
        "principal": "alice",
        "principal_type": "user",
        "target_capability": "Lambda execution role",
        "evidence": [{"permission": "iam:PassRole"}, {"permission": "lambda:CreateFunction"}],
    }


class LifecycleTests(unittest.TestCase):
    def test_fingerprint_is_stable_when_severity_changes(self):
        before = add_fingerprints([finding("high")], "111111111111")[0]
        after = add_fingerprints([finding("critical")], "111111111111")[0]
        self.assertEqual(before["fingerprint"], after["fingerprint"])

    def test_worsened_path_is_identified(self):
        result = diff_findings([finding("high")], [finding("critical")], account_id="111111111111")
        self.assertEqual(result["current_findings"][0]["lifecycle"], "worsened")

    def test_incomplete_collection_does_not_resolve_path(self):
        result = diff_findings([finding()], [], account_id="111111111111", collection_complete=False)
        self.assertEqual(result["changes"][0]["lifecycle"], "unverified")
        self.assertEqual(result["counts"].get("resolved", 0), 0)

    def test_rule_change_is_separate_from_environment_change(self):
        current = finding()
        current["principal"] = "bob"
        result = diff_findings(
            [finding()],
            [finding(), current],
            account_id="111111111111",
            previous_ruleset_id="bundle-1",
            current_ruleset_id="bundle-2",
        )
        bob = next(item for item in result["current_findings"] if item["principal"] == "bob")
        self.assertEqual(bob["change_reason"], "rule_change")

    def test_resolved_path_can_reopen(self):
        previous = add_fingerprints([finding()], "111111111111")[0]
        previous["lifecycle"] = "resolved"
        result = diff_findings([previous], [finding()], account_id="111111111111")
        self.assertEqual(result["current_findings"][0]["lifecycle"], "reopened")


if __name__ == "__main__":
    unittest.main()
