
import unittest

from Detection.idor import detect_idor


class IDORDetectionTests(unittest.TestCase):

    def test_explicit_authorization_denial_is_detected(self):
        result = detect_idor({
            "authorization": {
                "decision": "deny",
                "reason": "access_policy",
            },
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "IDOR-001",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_ownership_mismatch_is_detected(self):
        result = detect_idor({
            "authorization": {
                "decision": "allow",
                "reason": "ownership_mismatch",
            },
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "IDOR-002",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_both_indicators_are_preserved(self):
        result = detect_idor({
            "authorization": {
                "decision": "deny",
                "reason": "ownership_mismatch",
            },
        })

        rule_ids = [item["rule_id"] for item in result["evidence"]]

        self.assertTrue(result["rule_detected"])
        self.assertIn("IDOR-001", rule_ids)
        self.assertIn("IDOR-002", rule_ids)

    def test_allowed_request_without_mismatch_is_not_detected(self):
        result = detect_idor({
            "authorization": {
                "decision": "allow",
                "reason": "authorized",
            },
        })

        self.assertFalse(result["rule_detected"])
        self.assertEqual(result["evidence"], [])

    def test_missing_authorization_context_is_not_detected(self):
        result = detect_idor({
            "path": "/users/123/documents/456",
        })

        self.assertFalse(result["rule_detected"])

    def test_empty_event_is_not_detected(self):
        result = detect_idor({})

        self.assertFalse(result["rule_detected"])
        self.assertEqual(result["evidence"], [])

    def test_invalid_event_type_is_rejected(self):
        with self.assertRaises(TypeError):
            detect_idor("not a dictionary")


if __name__ == "__main__":
    unittest.main()
