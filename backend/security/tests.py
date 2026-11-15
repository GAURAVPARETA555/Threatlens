from unittest.mock import patch

from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase

from security.models import SecurityEvent, Alert

SQLI = "' UNION SELECT username, password FROM users --"
ML_MALICIOUS = {"prediction": "malicious", "confidence": 0.95}
ML_DOWN = {"prediction": "unknown", "confidence": 0}


class AnalyzePipelineTests(APITestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(
            username="tester", password="pass12345"
        )
        self.client.force_authenticate(user)

    def _event(self, payload):
        return SecurityEvent.objects.create(
            source_ip="203.0.113.7",
            endpoint="/api/products",
            raw_payload=payload,
        )

    def _analyze(self, event, ml_result, extra=None):
        body = {"event_id": event.id}
        body.update(extra or {})
        # The ML service is replaced with a fixed answer, so the
        # test never depends on a running ML server.
        with patch("security.views.predict_attack", return_value=ml_result):
            return self.client.post(
                "/api/detections/analyze/", body, format="json"
            )

    def test_sqli_with_malicious_ml_is_critical_and_alerts(self):
        r = self._analyze(self._event({"query": {"q": SQLI}}), ML_MALICIOUS)
        self.assertEqual(r.status_code, 201)
        self.assertTrue(r.data["rule_detected"])
        self.assertEqual(r.data["final_severity"], "critical")
        self.assertEqual(Alert.objects.count(), 1)

    def test_sqli_with_ml_down_still_alerts(self):
        r = self._analyze(self._event({"query": {"q": SQLI}}), ML_DOWN)
        self.assertEqual(r.data["final_severity"], "high")
        self.assertEqual(Alert.objects.count(), 1)

    def test_attack_row_is_linked(self):
        r = self._analyze(self._event({"query": {"q": SQLI}}), ML_DOWN)
        self.assertIsNotNone(r.data["attack"])

    def test_clean_event_creates_no_alert(self):
        r = self._analyze(self._event({"query": {"q": "laptop"}}), ML_DOWN)
        self.assertFalse(r.data["rule_detected"])
        self.assertEqual(Alert.objects.count(), 0)

    def test_clean_event_with_malicious_ml_is_medium_without_alert(self):
        r = self._analyze(self._event({"query": {"q": "laptop"}}), ML_MALICIOUS)
        self.assertEqual(r.data["final_risk_score"], 47.5)
        self.assertEqual(r.data["final_severity"], "medium")
        self.assertEqual(Alert.objects.count(), 0)

    def test_client_cannot_inject_rule_result(self):
        event = self._event({"query": {"q": "laptop"}})
        r = self._analyze(
            event, ML_DOWN,
            extra={"rule_detected": True, "severity": "critical"},
        )
        self.assertFalse(r.data["rule_detected"])

    def test_unknown_event_returns_404(self):
        with patch("security.views.predict_attack", return_value=ML_DOWN):
            r = self.client.post(
                "/api/detections/analyze/", {"event_id": 99999}, format="json"
            )
        self.assertEqual(r.status_code, 404)