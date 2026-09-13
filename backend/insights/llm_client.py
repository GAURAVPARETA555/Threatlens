import json
import requests

from django.conf import settings


def generate_ai_analysis(detection):
    event = detection.event
    attack = detection.attack

    attack_name = attack.name if attack else "Unknown Attack"
    attack_category = attack.category if attack else "Unknown"
    owasp_mapping = attack.owasp_mapping if attack else ""
    mitre_mapping = attack.mitre_mapping if attack else ""

    prompt = f"""
You are a cybersecurity analyst.

Analyze this security detection.

Attack type: {attack_name}
Category: {attack_category}
OWASP: {owasp_mapping}
MITRE: {mitre_mapping}

Source IP: {event.source_ip}
Endpoint: {event.endpoint}
Request rate: {event.request_rate}
Failed login count: {event.failed_login_count}
Special character count: {event.special_char_count}

Rule detected: {detection.rule_detected}
Rule confidence: {detection.rule_confidence}
Rule evidence: {detection.rule_evidence}

ML prediction: {detection.ml_prediction}
ML confidence: {detection.ml_confidence}

Final risk score: {detection.final_risk_score}/100
Final severity: {detection.final_severity}

Return ONLY valid JSON:

{{
    "explanation": "Explain what happened and why this detection was made.",
    "impact": "Explain the possible security impact.",
    "recommended_mitigation": "Give practical defensive mitigation steps."
}}
"""

    api_url = getattr(settings, "LLM_API_URL", "")
    api_key = getattr(settings, "LLM_API_KEY", "")
    model = getattr(settings, "LLM_MODEL", "")

    print("======================================")
    print("GROQ CONFIGURATION")
    print("API URL:", api_url)
    print("API KEY PRESENT:", bool(api_key))
    print("MODEL:", model)
    print("======================================")

    if not api_url:
        raise ValueError("LLM_API_URL is empty.")

    if not api_key:
        raise ValueError("LLM_API_KEY is empty.")

    if not model:
        raise ValueError("LLM_MODEL is empty.")

    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity analyst. "
                    "Return only valid JSON."
                ),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        "temperature": 0.2,
        "response_format": {
            "type": "json_object"
        },
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        print("Calling Groq...")

        response = requests.post(
            api_url,
            json=payload,
            headers=headers,
            timeout=60,
        )

        print("Groq status:", response.status_code)
        print("Groq response:", response.text)

        response.raise_for_status()

        data = response.json()

        content = (
            data["choices"][0]["message"]["content"]
        )

        if not content:
            raise ValueError(
                "Groq returned an empty content response."
            )

        content = content.strip()

        # Handle accidental markdown fences.
        if content.startswith("```"):
            content = content.replace(
                "```json",
                "",
                1,
            )
            content = content.replace(
                "```",
                "",
                1,
            )
            content = content.strip()

        result = json.loads(content)

        return {
            "explanation": result.get(
                "explanation",
                "No explanation returned.",
            ),
            "impact": result.get(
                "impact",
                "No impact analysis returned.",
            ),
            "recommended_mitigation": result.get(
                "recommended_mitigation",
                "No mitigation recommendations returned.",
            ),
        }

    except requests.RequestException as e:
        print("======================================")
        print("GROQ REQUEST ERROR")
        print(str(e))
        print("======================================")

        raise

    except json.JSONDecodeError as e:
        print("======================================")
        print("GROQ JSON ERROR")
        print("Invalid content:", content)
        print("Error:", str(e))
        print("======================================")

        raise ValueError(
            f"Groq returned invalid JSON: {content}"
        )

    except Exception as e:
        print("======================================")
        print("GROQ ERROR")
        print(type(e).__name__, str(e))
        print("======================================")

        raise

def generate_ai_report(summary):
    prompt = f"""
You are a senior cybersecurity analyst preparing a security report.

Analyze the following security monitoring statistics.

Security statistics:
{json.dumps(summary, indent=2)}

Prepare a concise but useful executive-level security report.

Return ONLY valid JSON in exactly this structure:

{{
    "executive_summary": "Summarize the overall security situation.",
    "threat_assessment": "Explain the major threats and their severity.",
    "key_findings": [
        "Important security finding 1",
        "Important security finding 2"
    ],
    "risk_assessment": "Explain the overall risk level and why.",
    "recommendations": [
        "Practical defensive recommendation 1",
        "Practical defensive recommendation 2",
        "Practical defensive recommendation 3"
    ]
}}

Do not invent statistics that are not present in the provided data.
Base your conclusions only on the supplied security statistics.
"""

    api_url = getattr(settings, "LLM_API_URL", "")
    api_key = getattr(settings, "LLM_API_KEY", "")
    model = getattr(settings, "LLM_MODEL", "")

    if not api_url:
        raise ValueError("LLM_API_URL is empty.")

    if not api_key:
        raise ValueError("LLM_API_KEY is empty.")

    if not model:
        raise ValueError("LLM_MODEL is empty.")

    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a senior cybersecurity analyst. "
                    "Return only valid JSON."
                ),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        "temperature": 0.2,
        "response_format": {
            "type": "json_object"
        },
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        print("======================================")
        print("GENERATING AI SECURITY REPORT")
        print("MODEL:", model)
        print("======================================")

        response = requests.post(
            api_url,
            json=payload,
            headers=headers,
            timeout=60,
        )

        print("Groq report status:", response.status_code)
        print("Groq report response:", response.text)

        response.raise_for_status()

        data = response.json()

        content = data["choices"][0]["message"]["content"]

        if not content:
            raise ValueError(
                "Groq returned an empty report response."
            )

        content = content.strip()

        if content.startswith("```"):
            content = content.replace("```json", "", 1)
            content = content.replace("```", "", 1)
            content = content.strip()

        result = json.loads(content)

        return {
            "executive_summary": result.get(
                "executive_summary",
                "No executive summary returned.",
            ),
            "threat_assessment": result.get(
                "threat_assessment",
                "No threat assessment returned.",
            ),
            "key_findings": result.get(
                "key_findings",
                [],
            ),
            "risk_assessment": result.get(
                "risk_assessment",
                "No risk assessment returned.",
            ),
            "recommendations": result.get(
                "recommendations",
                [],
            ),
        }

    except requests.RequestException as e:
        print("======================================")
        print("GROQ REPORT REQUEST ERROR")
        print(str(e))
        print("======================================")
        raise

    except json.JSONDecodeError as e:
        print("======================================")
        print("GROQ REPORT JSON ERROR")
        print("Invalid content:", content)
        print("Error:", str(e))
        print("======================================")

        raise ValueError(
            f"Groq returned invalid report JSON: {content}"
        )

    except Exception as e:
        print("======================================")
        print("GROQ REPORT ERROR")
        print(type(e).__name__, str(e))
        print("======================================")
        raise