from django.urls import path

from .views import (
    AIAnalysisView,
    ReportSummaryView,
    ReportListView,
    AIReportView,
)

urlpatterns = [
    path(
        "ai/explain/<int:detection_id>/",
        AIAnalysisView.as_view(),
        name="ai-explain",
    ),
    path(
        "reports/summary/",
        ReportSummaryView.as_view(),
        name="report-summary",
    ),
    path(
        "reports/",
        ReportListView.as_view(),
        name="report-list",
    ),
    path(
    "reports/ai-summary/",
    AIReportView.as_view(),
    name="ai-report",
),
]