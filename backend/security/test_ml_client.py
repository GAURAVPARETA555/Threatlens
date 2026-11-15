from unittest.mock import Mock, patch

import requests
from django.test import SimpleTestCase

from security.ml_client import predict_attack

POST = "security.ml_client.requests.post"
UNKNOWN = {"prediction": "unknown", "confidence": 0.0}


def ok_response(body):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = body
    return response


class PredictAttackTests(SimpleTestCase):
    def call(self):
        return predict_attack(25, 15, 2)

    @patch(POST)
    def test_valid_malicious_response(self, post):
        post.return_value = ok_response({"prediction": "malicious", "confidence": 0.94})
        self.assertEqual(self.call(), {"prediction": "malicious", "confidence": 0.94})

    @patch(POST)
    def test_valid_benign_response(self, post):
        post.return_value = ok_response({"prediction": "benign", "confidence": 0.91})
        self.assertEqual(self.call(), {"prediction": "benign", "confidence": 0.91})

    @patch(POST)
    def test_label_is_normalised_to_lowercase(self, post):
        post.return_value = ok_response({"prediction": " Malicious ", "confidence": 0.9})
        self.assertEqual(self.call()["prediction"], "malicious")

    @patch(POST)
    def test_extra_fields_are_ignored(self, post):
        post.return_value = ok_response(
            {"prediction": "benign", "confidence": 0.8, "model_version": "1.0.0"}
        )
        self.assertEqual(self.call(), {"prediction": "benign", "confidence": 0.8})

    @patch(POST)
    def test_sends_the_agreed_field_names(self, post):
        post.return_value = ok_response({"prediction": "benign", "confidence": 0.8})
        self.call()
        self.assertEqual(
            post.call_args.kwargs["json"],
            {"request_rate": 25, "failed_logins": 15, "special_characters": 2},
        )

    @patch(POST)
    def test_connection_error_returns_unknown(self, post):
        post.side_effect = requests.ConnectionError()
        self.assertEqual(self.call(), UNKNOWN)

    @patch(POST)
    def test_timeout_returns_unknown(self, post):
        post.side_effect = requests.Timeout()
        self.assertEqual(self.call(), UNKNOWN)

    @patch(POST)
    def test_http_error_returns_unknown(self, post):
        response = Mock()
        response.raise_for_status.side_effect = requests.HTTPError("503")
        post.return_value = response
        self.assertEqual(self.call(), UNKNOWN)

    @patch(POST)
    def test_invalid_json_returns_unknown(self, post):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.side_effect = ValueError("not json")
        post.return_value = response
        self.assertEqual(self.call(), UNKNOWN)

    @patch(POST)
    def test_unknown_label_returns_unknown(self, post):
        post.return_value = ok_response({"prediction": "attack", "confidence": 0.9})
        self.assertEqual(self.call(), UNKNOWN)

    @patch(POST)
    def test_text_confidence_returns_unknown(self, post):
        post.return_value = ok_response({"prediction": "malicious", "confidence": "high"})
        self.assertEqual(self.call(), UNKNOWN)

    @patch(POST)
    def test_null_confidence_returns_unknown(self, post):
        post.return_value = ok_response({"prediction": "malicious", "confidence": None})
        self.assertEqual(self.call(), UNKNOWN)

    @patch(POST)
    def test_missing_confidence_returns_unknown(self, post):
        post.return_value = ok_response({"prediction": "malicious"})
        self.assertEqual(self.call(), UNKNOWN)

    @patch(POST)
    def test_nan_confidence_returns_unknown(self, post):
        post.return_value = ok_response({"prediction": "malicious", "confidence": float("nan")})
        self.assertEqual(self.call(), UNKNOWN)

    @patch(POST)
    def test_non_object_body_returns_unknown(self, post):
        post.return_value = ok_response(["malicious", 0.9])
        self.assertEqual(self.call(), UNKNOWN)

    @patch(POST)
    def test_confidence_above_one_is_clamped(self, post):
        post.return_value = ok_response({"prediction": "malicious", "confidence": 1.2})
        self.assertEqual(self.call()["confidence"], 1.0)