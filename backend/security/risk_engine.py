SEVERITY_ORDER = ["low", "medium", "high", "critical"]

# PLACEHOLDER weights: the team must agree on these numbers.
RULE_SEVERITY_WEIGHT = {
    "low": 0.25,
    "medium": 0.5,
    "high": 0.8,
    "critical": 1.0,
}


def _severity_from_score(score):
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def calculate_risk(
    rule_detected,
    rule_severity,
    ml_prediction,
    ml_confidence,
    rule_confidence=None,
):
    """
    Combine the cybersecurity rule result and the ML prediction.

    - Rule confidence is a bounded heuristic signal based on corroborating
      deterministic findings. Severity remains the fallback for compatibility.
    - ML contributes its confidence only when it predicts "malicious".
    - A rule finding sets a minimum final severity, so a confirmed
      high-severity rule hit still alerts when the ML service is down.

    Current project assumption: 50% rule signal, 50% ML signal.
    """

    ml_confidence = max(0.0, min(1.0, float(ml_confidence)))
    rule_severity = str(rule_severity or "").lower()

    if rule_detected:
        if rule_confidence is None:
            rule_score = RULE_SEVERITY_WEIGHT.get(rule_severity, 0.5)
        else:
            rule_score = max(0.0, min(1.0, float(rule_confidence)))
    else:
        rule_score = 0.0

    ml_score = (
        ml_confidence
        if str(ml_prediction).lower() == "malicious"
        else 0.0
    )

    final_score = round(
        ((rule_score * 0.5) + (ml_score * 0.5)) * 100, 2
    )

    severity = _severity_from_score(final_score)

    # Severity floor for deterministic rule findings.
    if rule_detected and rule_severity in SEVERITY_ORDER:
        if SEVERITY_ORDER.index(rule_severity) > SEVERITY_ORDER.index(severity):
            severity = rule_severity

    return final_score, severity