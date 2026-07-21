import unittest

from iam_exposure.policy import effective_grant_for_action, extract_policy_grants


def document(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


class EffectivePolicyTests(unittest.TestCase):
    def test_explicit_deny_blocks_identity_allow(self):
        grants = extract_policy_grants(
            document(
                {"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"},
                {"Effect": "Deny", "Action": "iam:AttachUserPolicy", "Resource": "*"},
            ),
            "user-inline:alice/test",
            "user",
            "alice",
        )
        self.assertIsNone(effective_grant_for_action(grants, "iam:AttachUserPolicy"))

    def test_permissions_boundary_must_allow_action(self):
        identity = extract_policy_grants(
            document({"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"}),
            "identity",
            "user",
            "alice",
        )
        boundary = extract_policy_grants(
            document({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}),
            "boundary",
            "user",
            "alice",
            policy_scope="permissions-boundary",
        )
        self.assertIsNone(effective_grant_for_action(identity + boundary, "iam:AttachUserPolicy"))

    def test_conditional_allow_is_reported_as_constrained_without_context(self):
        grants = extract_policy_grants(
            document(
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}},
                }
            ),
            "identity",
            "user",
            "alice",
        )
        decision = effective_grant_for_action(grants, "iam:PassRole")
        self.assertIsNotNone(decision)
        self.assertTrue(decision["constrained"])
        self.assertIn("allow-condition-not-evaluated", decision["uncertainties"])

    def test_scp_deny_blocks_action(self):
        identity = extract_policy_grants(
            document({"Effect": "Allow", "Action": "iam:*", "Resource": "*"}),
            "identity",
            "role",
            "Developer",
        )
        scp = extract_policy_grants(
            document({"Effect": "Deny", "Action": "iam:AttachRolePolicy", "Resource": "*"}),
            "scp:p-deny",
            "global",
            "*",
            policy_scope="scp",
        )
        self.assertIsNone(effective_grant_for_action(identity + scp, "iam:AttachRolePolicy"))

    def test_not_resource_is_preserved_for_target_validation(self):
        grants = extract_policy_grants(
            document({"Effect": "Deny", "Action": "s3:GetObject", "NotResource": "arn:aws:s3:::approved/*"}),
            "identity",
            "user",
            "alice",
        )
        self.assertEqual(grants[0]["not_resources"], ["arn:aws:s3:::approved/*"])


if __name__ == "__main__":
    unittest.main()
