
import unittest

from Detection.path_traversal import detect_path_traversal


class PathTraversalDetectionTests(unittest.TestCase):

    def test_normal_path_is_not_detected(self):
        result = detect_path_traversal({
            "path": "/products/details",
            "query": {"id": "123"},
            "body": {},
        })

        self.assertFalse(result["rule_detected"])
        self.assertIsNone(result["attack_type"])
        self.assertEqual(result["evidence"], [])

    def test_parent_directory_traversal_is_detected(self):
        result = detect_path_traversal({
            "path": "/download",
            "query": {"file": "../../private/data.txt"},
            "body": {},
        })

        self.assertTrue(result["rule_detected"])
        self.assertEqual(result["attack_type"], "Path Traversal")
        self.assertIn(
            "PTRAV-001",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_url_encoded_traversal_is_detected(self):
        result = detect_path_traversal({
            "path": "/download",
            "query": {"file": "%2e%2e%2f%2e%2e%2fprivate%2fdata.txt"},
            "body": {},
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "PTRAV-001",
            [item["rule_id"] for item in result["evidence"]],
        )
        self.assertIn(
            "PTRAV-002",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_backslash_traversal_is_detected(self):
        result = detect_path_traversal({
            "path": "/download",
            "query": {"file": r"..\..\private\data.txt"},
            "body": {},
        })

        self.assertTrue(result["rule_detected"])

    def test_sensitive_file_path_is_detected(self):
        result = detect_path_traversal({
            "path": "/download",
            "query": {"file": "/etc/passwd"},
            "body": {},
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "PTRAV-003",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_nested_request_data_is_supported(self):
        result = detect_path_traversal({
            "path": "/download",
            "query": {},
            "body": {
                "options": {
                    "filename": "../../private/data.txt"
                }
            },
        })

        self.assertTrue(result["rule_detected"])

    def test_empty_request_is_not_detected(self):
        result = detect_path_traversal({})

        self.assertFalse(result["rule_detected"])
        self.assertEqual(result["evidence"], [])

    def test_invalid_event_type_is_rejected(self):
        with self.assertRaises(TypeError):
            detect_path_traversal("not a dictionary")


if __name__ == "__main__":
    unittest.main()
