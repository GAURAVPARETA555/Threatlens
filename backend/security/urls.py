from django.urls import path

from .views import (
    SecurityEventCreateView,
    SecurityEventListView,
    DetectionAnalyzeView,
    DetectionListView,
    AlertListView,
    AlertUpdateView,
    ScanCreateView,
    ScanDetailView,
)


urlpatterns = [

    # Security Events
    path(
        "events/",
        SecurityEventCreateView.as_view(),
        name="event-create",
    ),

    path(
        "events/list/",
        SecurityEventListView.as_view(),
        name="event-list",
    ),

    # Detection
    path(
        "detections/analyze/",
        DetectionAnalyzeView.as_view(),
        name="detection-analyze",
    ),

    path(
        "detections/",
        DetectionListView.as_view(),
        name="detection-list",
    ),

    # Alerts
    path(
        "alerts/",
        AlertListView.as_view(),
        name="alert-list",
    ),

    path(
        "alerts/<int:pk>/",
        AlertUpdateView.as_view(),
        name="alert-update",
    ),

    # Scans
    path(
        "scans/",
        ScanCreateView.as_view(),
        name="scan-create",
    ),

    path(
        "scans/<int:pk>/",
        ScanDetailView.as_view(),
        name="scan-detail",
    ),
]