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
    # Read-only convenience fields so the dashboard needs no extra calls.
    attack_name = serializers.SerializerMethodField()
    source_ip = serializers.CharField(source="event.source_ip", read_only=True)
    endpoint = serializers.CharField(source="event.endpoint", read_only=True)

    class Meta:
        model = DetectionResult
        fields = "__all__"

    def get_attack_name(self, obj):
        return obj.attack.name if obj.attack else None


class AlertSerializer(serializers.ModelSerializer):
    # Read-only convenience fields taken from the linked detection/event.
    severity = serializers.CharField(source="detection.final_severity", read_only=True)
    risk_score = serializers.FloatField(source="detection.final_risk_score", read_only=True)
    attack_name = serializers.SerializerMethodField()
    source_ip = serializers.CharField(source="detection.event.source_ip", read_only=True)
    endpoint = serializers.CharField(source="detection.event.endpoint", read_only=True)

    class Meta:
        model = Alert
        fields = "__all__"
        read_only_fields = ["detection", "created_at", "resolved_at"]

    def get_attack_name(self, obj):
        attack = obj.detection.attack
        return attack.name if attack else None


class ScanSerializer(serializers.ModelSerializer):
    requested_by = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Scan
        fields = "__all__"


class DetectionAnalyzeSerializer(serializers.Serializer):
    """
    The client only says WHICH event to analyze.
    The rule result is computed on the server by Member 4's engine,
    so it cannot be forged by the caller.
    """
    event_id = serializers.IntegerField(min_value=1)