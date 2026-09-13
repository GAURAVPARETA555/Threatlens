from django.conf import settings
from django.db import models


class Attack(models.Model):
    SEVERITY_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]

    name = models.CharField(max_length=100)
    category = models.CharField(max_length=100)
    owasp_mapping = models.CharField(max_length=100, blank=True)
    mitre_mapping = models.CharField(max_length=100, blank=True)
    default_severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES,
        default="low",
    )

    def __str__(self):
        return self.name


class SecurityEvent(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    source_ip = models.GenericIPAddressField()
    endpoint = models.CharField(max_length=255)

    raw_payload = models.JSONField(default=dict, blank=True)

    request_rate = models.FloatField(default=0)
    failed_login_count = models.IntegerField(default=0)
    special_char_count = models.IntegerField(default=0)

    def __str__(self):
        return f"{self.source_ip} - {self.endpoint}"


class DetectionResult(models.Model):
    SEVERITY_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]

    event = models.ForeignKey(
        SecurityEvent,
        on_delete=models.CASCADE,
        related_name="detections",
    )

    attack = models.ForeignKey(
        Attack,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="detections",
    )

    rule_detected = models.BooleanField(default=False)
    rule_confidence = models.FloatField(default=0)
    rule_evidence = models.TextField(blank=True)

    ml_prediction = models.CharField(
        max_length=50,
        blank=True,
    )
    ml_confidence = models.FloatField(default=0)

    final_risk_score = models.FloatField(default=0)

    final_severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES,
        default="low",
    )

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return (
            f"Detection #{self.id} - "
            f"{self.final_severity} - "
            f"{self.final_risk_score}"
        )


class Alert(models.Model):
    STATUS_CHOICES = [
        ("open", "Open"),
        ("investigating", "Investigating"),
        ("resolved", "Resolved"),
    ]

    detection = models.ForeignKey(
        DetectionResult,
        on_delete=models.CASCADE,
        related_name="alerts",
    )

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="open",
    )

    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="security_alerts",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Alert #{self.id} - {self.status}"


class Scan(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="scans",
    )

    target = models.CharField(max_length=255)

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="pending",
    )

    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Scan #{self.id} - {self.target}"