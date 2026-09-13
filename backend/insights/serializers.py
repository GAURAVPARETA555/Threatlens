from rest_framework import serializers

from .models import AIAnalysis, Report


class AIAnalysisSerializer(serializers.ModelSerializer):
    detection_id = serializers.IntegerField(
        source="detection.id",
        read_only=True,
    )

    class Meta:
        model = AIAnalysis
        fields = [
            "id",
            "detection_id",
            "explanation",
            "impact",
            "recommended_mitigation",
            "created_at",
            "updated_at",
        ]


class ReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = "__all__"
        read_only_fields = [
            "generated_by",
            "created_at",
        ]