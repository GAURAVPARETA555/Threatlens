def calculate_risk(rule_detected,rule_confidence,ml_prediction,ml_confidence,
):
    """
    Combine cybersecurity rule detection and ML prediction.

    Current project assumption:
    50% rule confidence
    50% ML confidence
    """

    rule_confidence = max(0, min(1, float(rule_confidence)))
    ml_confidence = max(0, min(1, float(ml_confidence)))

    rule_score = rule_confidence if rule_detected else 0

    ml_score = (
        ml_confidence
        if str(ml_prediction).lower() == "malicious"
        else 0
    )

    final_score = (
        (rule_score * 0.5) +
        (ml_score * 0.5)
    ) * 100

    if final_score >= 85:
        severity = "critical"
    elif final_score >= 65:
        severity = "high"
    elif final_score >= 40:
        severity = "medium"
    else:
        severity = "low"

    return round(final_score, 2), severity