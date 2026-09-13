from rest_framework import serializers

from .models import (
    Attack,
    SecurityEvent,
    DetectionResult,
    Alert,
    Scan,
)


class AttackSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attack
        fields = "__all__"


class SecurityEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityEvent
        fields = "__all__"


class DetectionResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = DetectionResult
        fields = "__all__"


class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = "__all__"


class ScanSerializer(serializers.ModelSerializer):
    requested_by = serializers.PrimaryKeyRelatedField(
        read_only=True
    )
    class Meta:
        model = Scan
        fields = "__all__"


class DetectionAnalyzeSerializer(serializers.Serializer):
    event_id = serializers.IntegerField()

    rule_detected = serializers.BooleanField()
    rule_confidence = serializers.FloatField(
        min_value=0,
        max_value=1,
    )
    attack_type = serializers.CharField(
        required=False,
        allow_blank=True,
    )
    evidence = serializers.CharField(
        required=False,
        allow_blank=True,
    )
    severity = serializers.CharField(
        required=False,
        allow_blank=True,
    )