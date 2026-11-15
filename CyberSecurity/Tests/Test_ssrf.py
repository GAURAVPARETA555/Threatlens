
import unittest

from Detection.ssrf import detect_ssrf


class SSRFDetectionTests(unittest.TestCase):

    def test_normal_public_url_is_not_detected(self):
        result = detect_ssrf({
            "path": "/preview",
            "query": {"url": "https://example.com/page"},
        })

        self.assertFalse(result["rule_detected"])
        self.assertEqual(result["evidence"], [])

    def test_loopback_ipv4_is_detected(self):
        result = detect_ssrf({
            "path": "/preview",
            "query": {"url": "http://127.0.0.1/admin"},
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "SSRF-001",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_loopback_ipv6_is_detected(self):
        result = detect_ssrf({
            "path": "/preview",
            "query": {"url": "http://[::1]/"},
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "SSRF-001",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_private_ip_is_detected(self):
        result = detect_ssrf({
            "path": "/preview",
            "query": {"url": "http://192.168.1.10/"},
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "SSRF-002",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_link_local_ip_is_detected(self):
        result = detect_ssrf({
            "path": "/preview",
            "query": {"url": "http://169.254.169.254/latest/meta-data/"},
        })

        self.assertTrue(result["rule_detected"])
        rule_ids = [item["rule_id"] for item in result["evidence"]]
        self.assertIn("SSRF-002", rule_ids)
        self.assertIn("SSRF-003", rule_ids)

    def test_cloud_metadata_hostname_is_detected(self):
        result = detect_ssrf({
            "path": "/preview",
            "body": {
                "url": "http://metadata.google.internal/computeMetadata/v1/"
            },
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "SSRF-003",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_url_encoded_url_is_detected(self):
        result = detect_ssrf({
            "path": "/preview",
            "query": {
                "url": "http%3A%2F%2F127.0.0.1%2Fadmin"
            },
        })

        self.assertTrue(result["rule_detected"])

    def test_empty_request_is_not_detected(self):
        result = detect_ssrf({})

        self.assertFalse(result["rule_detected"])
        self.assertEqual(result["evidence"], [])

    def test_localhost_hostname_is_detected(self):
        result = detect_ssrf({
            "path": "/preview",
            "query": {"url": "http://localhost/admin"},
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "SSRF-001",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_localhost_with_port_is_detected(self):
        result = detect_ssrf({
            "path": "/fetch",
            "body": {"url": "http://localhost:8080/metrics"},
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "SSRF-001",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_localhost_localdomain_is_detected(self):
        result = detect_ssrf({
            "path": "/fetch",
            "query": {"url": "http://localhost.localdomain/secret"},
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "SSRF-001",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_subdomain_localhost_is_detected(self):
        result = detect_ssrf({
            "path": "/fetch",
            "query": {"url": "http://internal.localhost/"},
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "SSRF-001",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_unspecified_address_0_0_0_0_is_detected(self):
        result = detect_ssrf({
            "path": "/fetch",
            "query": {"url": "http://0.0.0.0:5000/"},
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "SSRF-001",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_alternative_cloud_metadata_host_is_detected(self):
        result = detect_ssrf({
            "path": "/fetch",
            "query": {"url": "http://instance-data/latest/meta-data/"},
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "SSRF-003",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_malformed_url_does_not_crash(self):
        result = detect_ssrf({
            "path": "/fetch",
            "query": {"url": "http://[invalid:bracketed/path"},
        })

        self.assertFalse(result["rule_detected"])
        self.assertEqual(result["evidence"], [])

    def test_unsupported_input_types_handled_safely(self):
        result = detect_ssrf({
            "path": "/fetch",
            "body": {
                "number": 12345,
                "null_val": None,
                "nested_array": [True, False, None],
            },
        })

        self.assertFalse(result["rule_detected"])

    def test_invalid_event_type_is_rejected(self):
        with self.assertRaises(TypeError):
            detect_ssrf("not a dictionary")


if __name__ == "__main__":
    unittest.main()
