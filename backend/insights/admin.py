from django.contrib import admin

from .models import AIAnalysis, Report


@admin.register(AIAnalysis)
class AIAnalysisAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "detection",
        "created_at",
        "updated_at",
    )

    search_fields = (
        "explanation",
        "impact",
        "recommended_mitigation",
    )


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "generated_by",
        "date_range_start",
        "date_range_end",
        "created_at",
    )

    list_filter = (
        "created_at",
    )