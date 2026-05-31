import unittest

from iam_exposure.policy import extract_allow_grants
from iam_exposure.rules import evaluate_inventory, load_ruleset


def policy(actions, resource="*"):
    return {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": actions, "Resource": resource}}


class RuleEngineTests(unittest.TestCase):
    def test_user_inherits_group_privilege_escalation(self):
        inventory = {
            "account": {"account_id": "111111111111"},
            "users": [{"name": "alice", "access_keys": [], "password_enabled": False, "mfa_enabled": True}],
            "roles": [],
            "principals": [{"type": "user", "name": "alice"}],
            "grants": extract_allow_grants(
                policy("iam:AttachUserPolicy"),
                "group-inline:Admins/Escalate",
                "user",
                "alice",
                inherited_via="group:Admins",
            ),
        }
        findings = evaluate_inventory(inventory, load_ruleset())
        attach = next(item for item in findings if item["id"] == "iam.attach-user-policy")
        self.assertEqual(attach["severity"], "critical")
        self.assertIn("group:Admins", attach["attack_path"])

    def test_passrole_path_is_likely_with_broad_passrole(self):
        grants = []
        grants.extend(extract_allow_grants(policy(["iam:PassRole", "lambda:CreateFunction"]), "user-inline:bob/Lambda", "user", "bob"))
        inventory = {
            "account": {"account_id": "111111111111"},
            "users": [{"name": "bob", "access_keys": [], "password_enabled": False, "mfa_enabled": True}],
            "roles": [{"name": "PrivilegedLambda", "arn": "arn:aws:iam::111111111111:role/PrivilegedLambda"}],
            "principals": [{"type": "user", "name": "bob"}],
            "grants": grants,
        }
        findings = evaluate_inventory(inventory, load_ruleset())
        item = next(item for item in findings if item["id"] == "passrole.lambda-create-function")
        self.assertEqual(item["status"], "likely")

    def test_external_role_trust_without_external_id(self):
        inventory = {
            "account": {"account_id": "111111111111"},
            "users": [],
            "roles": [
                {
                    "name": "VendorRole",
                    "arn": "arn:aws:iam::111111111111:role/VendorRole",
                    "trust_policy": {
                        "Statement": {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                            "Action": "sts:AssumeRole",
                        }
                    },
                }
            ],
            "principals": [{"type": "role", "name": "VendorRole"}],
            "grants": [],
        }
        findings = evaluate_inventory(inventory, load_ruleset())
        self.assertTrue(any(item["id"] == "trust.external-assume-role-without-external-id" for item in findings))

    def test_credential_findings_respect_high_threshold(self):
        inventory = {
            "account": {},
            "users": [{"name": "carol", "access_keys": [], "password_enabled": True, "mfa_enabled": False}],
            "roles": [],
            "principals": [{"type": "user", "name": "carol"}],
            "grants": [],
        }
        findings = evaluate_inventory(inventory, load_ruleset(), severity_threshold="high")
        self.assertEqual([item["id"] for item in findings], ["credential.console-password-without-mfa"])


if __name__ == "__main__":
    unittest.main()
