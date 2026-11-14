import logging

from django.shortcuts import get_object_or_404
from django.utils import timezone

from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from Integration.exceptions import IntegrationError

from .models import (
    Attack,
    SecurityEvent,
    DetectionResult,
    Alert,
    Scan,
)

from .serializers import (
    SecurityEventSerializer,
    DetectionResultSerializer,
    AlertSerializer,
    ScanSerializer,
    DetectionAnalyzeSerializer,
)

from .risk_engine import calculate_risk
from .ml_client import predict_attack
from .rule_client import run_rules

logger = logging.getLogger(__name__)


class SecurityEventCreateView(generics.CreateAPIView):
    queryset = SecurityEvent.objects.all()
    serializer_class = SecurityEventSerializer
    permission_classes = [IsAuthenticated]


class SecurityEventListView(generics.ListAPIView):
    serializer_class = SecurityEventSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = SecurityEvent.objects.all().order_by("-timestamp")

        source_ip = self.request.query_params.get("source_ip")
        endpoint = self.request.query_params.get("endpoint")

        if source_ip:
            queryset = queryset.filter(source_ip=source_ip)

        if endpoint:
            queryset = queryset.filter(endpoint__icontains=endpoint)

        return queryset


class DetectionAnalyzeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = DetectionAnalyzeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        event = get_object_or_404(
            SecurityEvent,
            id=serializer.validated_data["event_id"],
        )

        # -----------------------------
        # Member 4 rule engine (computed on the server)
        # -----------------------------

        try:
            rule = run_rules(event)
        except IntegrationError as exc:
            return Response(
                {"detail": f"Event rejected by rule engine: {exc}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception:
            logger.exception("Rule engine failed for event %s", event.id)
            return Response(
                {"detail": "Rule engine failure."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # -----------------------------
        # Link to the Attack catalog (create if missing)
        # -----------------------------

        attack = None

        if rule["attack_type"]:
            attack = Attack.objects.filter(
                name__iexact=rule["attack_type"]
            ).first()

            if attack is None:
                attack = Attack.objects.create(
                    name=rule["attack_type"],
                    category="Uncategorized",
                    default_severity=rule["severity"] or "low",
                )

        # -----------------------------
        # Member 3 ML service
        # -----------------------------

        ml_result = predict_attack(
            request_rate=event.request_rate,
            failed_logins=event.failed_login_count,
            special_characters=event.special_char_count,
        )

        ml_prediction = ml_result["prediction"]
        ml_confidence = ml_result["confidence"]

        # -----------------------------
        # Final risk
        # -----------------------------

        final_score, final_severity = calculate_risk(
            rule_detected=rule["rule_detected"],
            rule_severity=rule["severity"],
            ml_prediction=ml_prediction,
            ml_confidence=ml_confidence,
        )

        detection = DetectionResult.objects.create(
            event=event,
            attack=attack,
            rule_detected=rule["rule_detected"],
            rule_confidence=rule["rule_confidence"],
            rule_evidence=rule["evidence"],
            ml_prediction=ml_prediction,
            ml_confidence=ml_confidence,
            final_risk_score=final_score,
            final_severity=final_severity,
        )

        # -----------------------------
        # Create alert for high risk
        # -----------------------------

        if final_severity in ["high", "critical"]:
            Alert.objects.create(
                detection=detection,
                status="open",
            )

        return Response(
            DetectionResultSerializer(detection).data,
            status=status.HTTP_201_CREATED,
        )


class DetectionListView(generics.ListAPIView):
    serializer_class = DetectionResultSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = DetectionResult.objects.all().order_by("-created_at")

        severity = self.request.query_params.get("severity")

        if severity:
            queryset = queryset.filter(final_severity=severity)

        return queryset


class AlertListView(generics.ListAPIView):
    serializer_class = AlertSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = Alert.objects.all().order_by("-created_at")

        severity = self.request.query_params.get("severity")
        status_filter = self.request.query_params.get("status")

        if severity:
            queryset = queryset.filter(detection__final_severity=severity)

        if status_filter:
            queryset = queryset.filter(status=status_filter)

        return queryset


class AlertUpdateView(generics.UpdateAPIView):
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer
    permission_classes = [IsAuthenticated]

    def perform_update(self, serializer):
        instance = serializer.save()

        if instance.status == "resolved":
            instance.resolved_at = timezone.now()
            instance.save(update_fields=["resolved_at"])


class ScanCreateView(generics.CreateAPIView):
    serializer_class = ScanSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(requested_by=self.request.user)


class ScanDetailView(generics.RetrieveAPIView):
    queryset = Scan.objects.all()
    serializer_class = ScanSerializer
    permission_classes = [IsAuthenticated]