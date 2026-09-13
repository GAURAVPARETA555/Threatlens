#for memebr 3 ml services
import requests
from django.conf import settings


def predict_attack(
    request_rate,
    failed_logins,
    special_characters,
):
    payload = {
        "request_rate": request_rate,
        "failed_logins": failed_logins,
        "special_characters": special_characters,
    }

    ml_url = getattr(
        settings,
        "ML_SERVICE_URL",
        "http://127.0.0.1:8001/predict/",
    )

    try:
        response = requests.post(
            ml_url,
            json=payload,
            timeout=10,
        )

        response.raise_for_status()

        data = response.json()

        return {
            "prediction": data.get(
                "prediction",
                "unknown",
            ),
            "confidence": float(
                data.get("confidence", 0)
            ),
        }

    except requests.RequestException:
        return {
            "prediction": "unknown",
            "confidence": 0,
        }