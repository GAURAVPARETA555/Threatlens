
import unittest

from Detection.xss import detect_xss


class XSSDetectionTests(unittest.TestCase):

    def test_normal_request_is_not_detected(self):
        event = {
            "path": "/search",
            "query": {"q": "laptop"},
            "body": {},
        }

        result = detect_xss(event)

        self.assertFalse(result["rule_detected"])
        self.assertIsNone(result["attack_type"])
        self.assertEqual(result["evidence"], [])

    def test_script_element_is_detected(self):
        event = {
            "path": "/search",
            "query": {"q": "<script>alert(1)</script>"},
            "body": {},
        }

        result = detect_xss(event)

        self.assertTrue(result["rule_detected"])
        self.assertEqual(
            result["attack_type"],
            "Cross-Site Scripting (XSS)",
        )
        self.assertIn(
            "XSS-001",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_event_handler_is_detected(self):
        event = {
            "path": "/comment",
            "query": {},
            "body": {"comment": '<img src="x" onerror="alert(1)">'},
        }

        result = detect_xss(event)

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "XSS-002",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_javascript_uri_is_detected(self):
        event = {
            "path": "/redirect",
            "query": {"url": "javascript:alert(1)"},
            "body": {},
        }

        result = detect_xss(event)

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "XSS-003",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_url_encoded_script_element_is_detected(self):
        event = {
            "path": "/search",
            "query": {
                "q": "%3Cscript%3Ealert(1)%3C%2Fscript%3E"
            },
            "body": {},
        }

        result = detect_xss(event)

        self.assertTrue(result["rule_detected"])

    def test_nested_request_data_is_supported(self):
        event = {
            "path": "/comment",
            "query": {},
            "body": {
                "comment": {
                    "text": "<script>alert(1)</script>"
                }
            },
        }

        result = detect_xss(event)

        self.assertTrue(result["rule_detected"])

    def test_empty_request_is_not_detected(self):
        result = detect_xss({})

        self.assertFalse(result["rule_detected"])
        self.assertEqual(result["evidence"], [])

    def test_multiple_indicators_are_recorded(self):
        event = {
            "path": "/comment",
            "query": {
                "q": "<script>alert(1)</script>"
            },
            "body": {
                "comment": '<img src="x" onerror="alert(1)">'
            },
        }

        result = detect_xss(event)
        detected_rule_ids = {
            item["rule_id"] for item in result["evidence"]
        }

        self.assertTrue(result["rule_detected"])
        self.assertIn("XSS-001", detected_rule_ids)
        self.assertIn("XSS-002", detected_rule_ids)


if __name__ == "__main__":
    unittest.main()
