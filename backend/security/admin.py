from django.contrib import admin

from .models import (
    Attack,
    SecurityEvent,
    DetectionResult,
    Alert,
    Scan,
)


@admin.register(Attack)
class AttackAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "name",
        "category",
        "default_severity",
    )

    search_fields = (
        "name",
        "category",
    )


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "timestamp",
        "source_ip",
        "endpoint",
        "request_rate",
        "failed_login_count",
    )

    search_fields = (
        "source_ip",
        "endpoint",
    )


@admin.register(DetectionResult)
class DetectionResultAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "event",
        "rule_detected",
        "ml_prediction",
        "final_risk_score",
        "final_severity",
    )

    list_filter = (
        "final_severity",
        "rule_detected",
        "ml_prediction",
    )


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "detection",
        "status",
        "assigned_to",
        "created_at",
        "resolved_at",
    )

    list_filter = (
        "status",
    )


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "target",
        "requested_by",
        "status",
        "started_at",
        "completed_at",
    )

    list_filter = (
        "status",
    )