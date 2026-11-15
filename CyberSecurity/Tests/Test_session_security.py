
import unittest

from Detection.session_security import detect_session_security


class SessionSecurityTests(unittest.TestCase):

    def test_unchanged_session_after_authentication_is_detected(self):
        result = detect_session_security({
            "session": {
                "event_type": "authentication",
                "authenticated": True,
                "session_id_before": "session-old",
                "session_id_after": "session-old",
            },
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "SESSION-001",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_rotated_session_after_authentication_is_not_detected(self):
        result = detect_session_security({
            "session": {
                "event_type": "authentication",
                "authenticated": True,
                "session_id_before": "session-old",
                "session_id_after": "session-new",
            },
        })

        self.assertFalse(result["rule_detected"])

    def test_session_reuse_after_logout_is_detected(self):
        result = detect_session_security({
            "session": {
                "event_type": "request",
                "used_after_logout": True,
            },
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "SESSION-002",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_both_indicators_are_preserved(self):
        result = detect_session_security({
            "session": {
                "event_type": "authentication",
                "authenticated": True,
                "session_id_before": "same-id",
                "session_id_after": "same-id",
                "used_after_logout": True,
            },
        })

        rule_ids = [item["rule_id"] for item in result["evidence"]]
        self.assertIn("SESSION-001", rule_ids)
        self.assertIn("SESSION-002", rule_ids)

    def test_failed_authentication_is_not_flagged_for_session_rotation(self):
        result = detect_session_security({
            "session": {
                "event_type": "authentication",
                "authenticated": False,
                "session_id_before": "same-id",
                "session_id_after": "same-id",
            },
        })

        self.assertFalse(result["rule_detected"])

    def test_missing_session_context_is_not_detected(self):
        result = detect_session_security({
            "path": "/account",
        })

        self.assertFalse(result["rule_detected"])
        self.assertEqual(result["evidence"], [])

    def test_empty_event_is_not_detected(self):
        result = detect_session_security({})

        self.assertFalse(result["rule_detected"])

    def test_invalid_event_type_is_rejected(self):
        with self.assertRaises(TypeError):
            detect_session_security("not a dictionary")


if __name__ == "__main__":
    unittest.main()
