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
        """
    The client only says WHICH event to analyze.
    The rule result is computed on the server by Member 4's engine,
    so it cannot be forged by the caller.
    """
        event_id = serializers.IntegerField(min_value=1)

