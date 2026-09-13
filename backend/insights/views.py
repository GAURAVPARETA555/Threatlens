from django.shortcuts import get_object_or_404

from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from security.models import DetectionResult

from .models import AIAnalysis, Report
from .serializers import (
    AIAnalysisSerializer,
    ReportSerializer,
)
from .llm_client import (
    generate_ai_analysis,
    generate_ai_report,
)
from .report_service import build_security_summary


class AIAnalysisView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, detection_id):
        detection = get_object_or_404(
            DetectionResult,
            id=detection_id,
        )

        ai_result = generate_ai_analysis(detection)

        analysis, created = AIAnalysis.objects.update_or_create(
            detection=detection,
            defaults={
                "explanation": ai_result["explanation"],
                "impact": ai_result["impact"],
                "recommended_mitigation": ai_result[
                    "recommended_mitigation"
                ],
            },
        )

        serializer = AIAnalysisSerializer(analysis)

        return Response(
            serializer.data,
            status=(
                status.HTTP_201_CREATED
                if created
                else status.HTTP_200_OK
            ),
        )

    def get(self, request, detection_id):
        detection = get_object_or_404(
            DetectionResult,
            id=detection_id,
        )

        analysis = get_object_or_404(
            AIAnalysis,
            detection=detection,
        )

        serializer = AIAnalysisSerializer(analysis)

        return Response(serializer.data)


class ReportSummaryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        report_data = build_security_summary()

        report = Report.objects.create(
            generated_by=request.user,

            date_range_start=(
                report_data["date_range_start"]
            ),

            date_range_end=(
                report_data["date_range_end"]
            ),

            summary_json=(
                report_data["summary"]
            ),
        )

        serializer = ReportSerializer(report)

        return Response(
            serializer.data,
            status=status.HTTP_200_OK,
        )


class AIReportView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        report_data = build_security_summary()

        summary = report_data["summary"]

        ai_report = generate_ai_report(summary)

        final_report = {
            "statistics": summary,
            "ai_analysis": ai_report,
        }

        report = Report.objects.create(
            generated_by=request.user,

            date_range_start=(
                report_data["date_range_start"]
            ),

            date_range_end=(
                report_data["date_range_end"]
            ),

            summary_json=final_report,
        )

        serializer = ReportSerializer(report)

        return Response(
            serializer.data,
            status=status.HTTP_201_CREATED,
        )


class ReportListView(generics.ListAPIView):
    queryset = Report.objects.all().order_by("-created_at")
    serializer_class = ReportSerializer
    permission_classes = [IsAuthenticated]