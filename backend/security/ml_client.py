import logging
import math

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

VALID_PREDICTIONS = ("malicious", "benign")


def _unknown():
    return {"prediction": "unknown", "confidence": 0.0}


def predict_attack(request_rate, failed_logins, special_characters):
    """
    Ask the ML service whether the traffic looks malicious.

    Sends:    {"request_rate", "failed_logins", "special_characters"}
    Expects:  {"prediction": "malicious" | "benign", "confidence": 0..1}
    Returns:  {"prediction": str, "confidence": float}
              Any failure or unusable answer returns
              {"prediction": "unknown", "confidence": 0.0}.
    """
    payload = {
        "request_rate": request_rate,
        "failed_logins": failed_logins,
        "special_characters": special_characters,
    }
    ml_url = getattr(settings, "ML_SERVICE_URL", "http://127.0.0.1:8001/predict/")
    timeout = getattr(settings, "ML_SERVICE_TIMEOUT", 10)

    try:
        response = requests.post(ml_url, json=payload, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        prediction = str(data["prediction"]).strip().lower()
        confidence = float(data["confidence"])
    except (requests.RequestException, KeyError, ValueError, TypeError) as exc:
        logger.warning("ML service unavailable or returned an invalid response: %s", exc)
        return _unknown()

    if prediction not in VALID_PREDICTIONS or not math.isfinite(confidence):
        logger.warning("ML service returned an unusable result: %r", data)
        return _unknown()

    return {
        "prediction": prediction,
        "confidence": max(0.0, min(1.0, confidence)),
    }