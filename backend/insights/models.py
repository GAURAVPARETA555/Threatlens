from django.conf import settings
from django.db import models

from security.models import DetectionResult


class AIAnalysis(models.Model):
    detection = models.OneToOneField(
        DetectionResult,
        on_delete=models.CASCADE,
        related_name="ai_analysis",
    )
    explanation = models.TextField()
    impact = models.TextField(blank=True)
    recommended_mitigation = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"AI Analysis - Detection #{self.detection_id}"


class Report(models.Model):
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="security_reports",
    )
    date_range_start = models.DateTimeField(null=True, blank=True)
    date_range_end = models.DateTimeField(null=True, blank=True)
    summary_json = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Security Report #{self.id}"