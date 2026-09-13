from django.db.models import Count, Avg
from django.utils import timezone

from security.models import (
    DetectionResult,
    Alert,
    SecurityEvent,
)


def build_security_summary():
    detections = DetectionResult.objects.all()

    total_detections = detections.count()

    critical_count = detections.filter(
        final_severity="critical"
    ).count()

    high_count = detections.filter(
        final_severity="high"
    ).count()

    medium_count = detections.filter(
        final_severity="medium"
    ).count()

    low_count = detections.filter(
        final_severity="low"
    ).count()

    malicious_count = detections.filter(
        ml_prediction__iexact="malicious"
    ).count()

    rule_detected_count = detections.filter(
        rule_detected=True
    ).count()

    open_alerts = Alert.objects.filter(
        status="open"
    ).count()

    investigating_alerts = Alert.objects.filter(
        status="investigating"
    ).count()

    resolved_alerts = Alert.objects.filter(
        status="resolved"
    ).count()

    average_risk = detections.aggregate(
        average=Avg("final_risk_score")
    )["average"]

    attack_distribution = list(
        detections
        .values("attack__name")
        .annotate(count=Count("id"))
        .order_by("-count")
    )

    severity_distribution = {
        "critical": critical_count,
        "high": high_count,
        "medium": medium_count,
        "low": low_count,
    }

    summary = {
        "generated_at": timezone.now().isoformat(),

        "total_security_events": (
            SecurityEvent.objects.count()
        ),

        "total_detections": total_detections,

        "rule_detected_count": rule_detected_count,

        "malicious_ml_predictions": malicious_count,

        "average_risk_score": round(
            average_risk or 0,
            2,
        ),

        "severity_distribution": (
            severity_distribution
        ),

        "alert_summary": {
            "open": open_alerts,
            "investigating": investigating_alerts,
            "resolved": resolved_alerts,
        },

        "attack_distribution": (
            attack_distribution
        ),
    }

    date_range_start = (
        detections
        .order_by("created_at")
        .values_list(
            "created_at",
            flat=True,
        )
        .first()
    )

    date_range_end = (
        detections
        .order_by("-created_at")
        .values_list(
            "created_at",
            flat=True,
        )
        .first()
    )

    return {
        "summary": summary,
        "date_range_start": date_range_start,
        "date_range_end": date_range_end,
    }