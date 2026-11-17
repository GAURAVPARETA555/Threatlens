import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  Bot,
  BrainCircuit,
  Calculator,
  Code,
  Crosshair,
  Info,
  Loader2,
  Radio,
  Shield,
  Sparkles,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { SeverityBadge } from "@/components/shared/SeverityBadge";
import { RiskGauge } from "@/components/shared/RiskGauge";
import { CodeBlock } from "@/components/shared/CodeBlock";
import { listDetections, listEvents } from "@/api/security";
import { getAIExplanation, generateAIExplanation } from "@/api/insights";
import { queryKeys } from "@/api/queryKeys";
import { useAuth } from "@/hooks/useAuth";
import type { DetectionResult, Severity, SecurityEvent } from "@/api/schemas";

export function DetectionDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const isViewer = user?.role === "viewer";
  const detectionId = Number(id);

  // Fetch detection record from list
  const {
    data: detectionsData,
    isLoading: isDetectionLoading,
  } = useQuery({
    queryKey: queryKeys.detections.all,
    queryFn: () => listDetections({ page_size: 100 }),
  });

  const detection: DetectionResult | undefined = detectionsData?.results?.find(
    (d) => d.id === detectionId,
  );

  // Fetch associated event
  const { data: eventsData, isLoading: isEventsLoading } = useQuery({
    queryKey: queryKeys.events.all,
    queryFn: () => listEvents({ page_size: 100 }),
    enabled: !!detection?.event,
  });

  const event: SecurityEvent | undefined = eventsData?.results?.find(
    (e) => e.id === detection?.event,
  );

  // Query AI explanation
  const {
    data: aiExplanation,
    isLoading: isAILoading,
  } = useQuery({
    queryKey: queryKeys.ai.explanation(detectionId),
    queryFn: () => getAIExplanation(detectionId),
    retry: false,
    enabled: !!detectionId,
  });

  // Generate AI Explanation mutation
  const aiMutation = useMutation({
    mutationFn: () => generateAIExplanation(detectionId),
    onSuccess: (data) => {
      queryClient.setQueryData(queryKeys.ai.explanation(detectionId), data);
    },
    onError: (err: any) => {
      alert(err.response?.data?.detail || "Failed to contact Groq Cloud AI service.");
    },
  });

  if (isDetectionLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-32 w-full" />
        <div className="grid grid-cols-2 gap-4">
          <Skeleton className="h-48 w-full" />
          <Skeleton className="h-48 w-full" />
        </div>
      </div>
    );
  }

  if (!detection) {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-center border border-dashed border-border rounded">
        <Crosshair className="h-8 w-8 text-muted-foreground mb-3" />
        <h3 className="text-sm font-semibold text-foreground">Detection #{id} Not Found</h3>
        <p className="text-xs text-muted-foreground mt-1">
          The requested detection ID does not exist or has been pruned.
        </p>
        <Button
          variant="outline"
          size="sm"
          onClick={() => navigate("/detections")}
          className="mt-4 h-8 text-xs font-mono"
        >
          <ArrowLeft className="h-3 w-3 mr-1" /> Back to Detections
        </Button>
      </div>
    );
  }

  // Risk Score calculation details
  // Formula: Final Risk Score = ((Rule Confidence * 0.5) + (ML Confidence * 0.5)) * 100
  // Note when severity floor raised the final severity above the score-only band (85/65/40 thresholds)
  const scoreFromBands = (score: number): Severity => {
    if (score >= 85) return "critical";
    if (score >= 65) return "high";
    if (score >= 40) return "medium";
    return "low";
  };
  const bandSeverity = scoreFromBands(detection.final_risk_score);
  const severityFloorTriggered = detection.final_severity !== bandSeverity;

  return (
    <div className="space-y-5">
      {/* Navigation & Header */}
      <div className="flex items-center gap-3">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => navigate(-1)}
          className="h-8 w-8 p-0 text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs text-muted-foreground">Detection #{detection.id}</span>
          <span className="text-muted-foreground">/</span>
          <span className="font-mono text-xs text-foreground font-semibold">Incident Analysis</span>
        </div>
      </div>

      {/* Hero Header Card */}
      <Card className="border-border bg-card">
        <CardContent className="p-4 md:p-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-1.5">
              <div className="flex items-center gap-2.5">
                <SeverityBadge severity={detection.final_severity as Severity} />
                <span className="font-mono text-xs text-muted-foreground">
                  Recorded: {new Date(detection.created_at).toLocaleString()}
                </span>
              </div>
              <h2 className="text-lg font-bold tracking-tight text-foreground">
                {detection.attack ? `Attack Signature #${detection.attack}` : "Uncategorized Threat Signature"}
              </h2>
              <div className="flex items-center gap-3 text-xs font-mono text-muted-foreground">
                <span>Associated Event ID: #{detection.event}</span>
                <span>•</span>
                <span>Rule Signal: {detection.rule_detected ? "TRIGGERED" : "CLEAN"}</span>
                <span>•</span>
                <span>ML Intent: {detection.ml_prediction.toUpperCase() || "UNKNOWN"}</span>
              </div>
            </div>

            {/* Segmented Risk Gauge */}
            <div className="w-full md:w-64 border-t md:border-t-0 md:border-l border-border pt-4 md:pt-0 md:pl-6">
              <span className="text-[10px] font-mono uppercase text-muted-foreground block mb-1">
                Composite Risk Score
              </span>
              <RiskGauge score={detection.final_risk_score} />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* "How the score was built" calculation breakdown */}
      <Card className="border-border bg-card">
        <CardHeader className="pb-2">
          <div className="flex items-center gap-2">
            <Calculator className="h-4 w-4 text-teal-400" />
            <CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
              Risk Calculation Mechanics
            </CardTitle>
          </div>
          <CardDescription className="text-xs text-muted-foreground">
            Hybrid aggregation of deterministic rule signatures and ML prediction probabilities
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Rule Component */}
            <div className="p-3.5 rounded border border-border bg-muted/20 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-foreground flex items-center gap-1.5">
                  <Shield className="h-3.5 w-3.5 text-teal-400" />
                  Deterministic Rule Engine (50% weight)
                </span>
                <span
                  className={`text-[10px] font-mono px-1.5 py-0.5 rounded uppercase font-semibold ${
                    detection.rule_detected
                      ? "bg-teal-500/10 text-teal-400 border border-teal-500/20"
                      : "text-muted-foreground"
                  }`}
                >
                  {detection.rule_detected ? "Signature Matched" : "No Rule Trigger"}
                </span>
              </div>
              <div className="text-xs font-mono space-y-1 text-muted-foreground">
                <div>
                  Evidence:{" "}
                  <span className="text-foreground">
                    {detection.rule_evidence || "No signature payload evidence matched."}
                  </span>
                </div>
                <div>
                  Rule Confidence Signal:{" "}
                  <span className="text-foreground font-semibold">
                    {detection.rule_confidence.toFixed(2)}
                  </span>
                </div>
              </div>
            </div>

            {/* Machine Learning Component */}
            <div className="p-3.5 rounded border border-border bg-muted/20 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-foreground flex items-center gap-1.5">
                  <BrainCircuit className="h-3.5 w-3.5 text-teal-400" />
                  ML Classifier Pipeline (50% weight)
                </span>
                <span
                  className={`text-[10px] font-mono px-1.5 py-0.5 rounded uppercase font-semibold ${
                    detection.ml_prediction.toLowerCase() === "malicious"
                      ? "bg-severity-high/10 text-severity-high border border-severity-high/20"
                      : "text-muted-foreground"
                  }`}
                >
                  {detection.ml_prediction || "UNKNOWN"}
                </span>
              </div>
              <div className="text-xs font-mono space-y-1 text-muted-foreground">
                <div>
                  Model Classification:{" "}
                  <span className="text-foreground uppercase font-semibold">
                    {detection.ml_prediction || "None"}
                  </span>
                </div>
                <div>
                  Inference Confidence:{" "}
                  <span className="text-foreground font-semibold">
                    {(detection.ml_confidence * 100).toFixed(1)}% ({detection.ml_confidence.toFixed(4)})
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Mathematical formulation block */}
          <div className="p-3 rounded border border-border bg-muted/10 font-mono text-xs space-y-2">
            <div className="text-[11px] text-muted-foreground">
              Formula: <span className="text-teal-400 font-semibold">Final Risk Score = ((Rule Confidence × 0.5) + (ML Confidence × 0.5)) × 100</span>
            </div>
            <div className="text-[11px] text-foreground">
              Calculation: (({detection.rule_confidence} × 0.5) + ({detection.ml_confidence} × 0.5)) × 100 ={" "}
              <span className="font-bold text-teal-400">{detection.final_risk_score.toFixed(2)}</span>
            </div>

            {/* Severity Floor Elevation Note */}
            {severityFloorTriggered && (
              <div className="mt-2 p-2 rounded border border-amber-500/20 bg-amber-500/10 text-amber-400 text-[11px] flex items-start gap-2">
                <Info className="h-4 w-4 shrink-0 mt-0.5" />
                <div>
                  <span className="font-semibold">Deterministic Severity Floor Applied:</span> Calculated score band
                  corresponded to <span className="uppercase font-bold">{bandSeverity}</span>, but a verified deterministic
                  rule signature elevated the incident's final severity floor to{" "}
                  <span className="uppercase font-bold underline">{detection.final_severity}</span>.
                </div>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Telemetry features & Raw Payload block */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Telemetry Features */}
        <Card className="border-border bg-card">
          <CardHeader className="pb-2">
            <div className="flex items-center gap-2">
              <Radio className="h-4 w-4 text-teal-400" />
              <CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                Extracted Telemetry Features
              </CardTitle>
            </div>
            <CardDescription className="text-xs text-muted-foreground">
              Feature vector fed into heuristic and ML classification pipelines
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 font-mono text-xs">
            {isEventsLoading ? (
              <div className="space-y-2">
                <Skeleton className="h-6 w-full" />
                <Skeleton className="h-6 w-full" />
                <Skeleton className="h-6 w-full" />
              </div>
            ) : event ? (
              <>
                <div className="flex items-center justify-between p-2 rounded bg-muted/20 border border-border">
                  <span className="text-muted-foreground">Source IP:</span>
                  <span className="font-bold text-foreground">{event.source_ip}</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded bg-muted/20 border border-border">
                  <span className="text-muted-foreground">Endpoint URI:</span>
                  <span className="text-teal-400 font-semibold">{event.endpoint}</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded bg-muted/20 border border-border">
                  <span className="text-muted-foreground">Request Rate:</span>
                  <span className="text-foreground">{event.request_rate.toFixed(1)} req/sec</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded bg-muted/20 border border-border">
                  <span className="text-muted-foreground">Failed Login Attempts:</span>
                  <span className={event.failed_login_count > 5 ? "text-severity-critical font-bold" : "text-foreground"}>
                    {event.failed_login_count}
                  </span>
                </div>
                <div className="flex items-center justify-between p-2 rounded bg-muted/20 border border-border">
                  <span className="text-muted-foreground">Special Characters Count:</span>
                  <span className={event.special_char_count > 3 ? "text-severity-high font-bold" : "text-foreground"}>
                    {event.special_char_count}
                  </span>
                </div>
              </>
            ) : (
              <div className="text-muted-foreground">Event data not cached.</div>
            )}
          </CardContent>
        </Card>

        {/* Raw Event Payload */}
        <Card className="border-border bg-card">
          <CardHeader className="pb-2">
            <div className="flex items-center gap-2">
              <Code className="h-4 w-4 text-teal-400" />
              <CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                Raw Event Payload
              </CardTitle>
            </div>
            <CardDescription className="text-xs text-muted-foreground">
              Exact JSON parameters intercepted from ingest pipeline
            </CardDescription>
          </CardHeader>
          <CardContent>
            {isEventsLoading ? (
              <Skeleton className="h-48 w-full" />
            ) : event?.raw_payload ? (
              <CodeBlock
                code={event.raw_payload}
                title={`Event #${event.id} Raw Telemetry Stream`}
                maxHeight="max-h-60"
              />
            ) : (
              <div className="p-4 border border-dashed border-border rounded text-center text-xs text-muted-foreground">
                No raw payload recorded for this event.
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* AI Incident Explanation Panel */}
      <Card className="border-border bg-card">
        <CardHeader className="flex flex-row items-center justify-between pb-2 border-b border-border">
          <div className="flex items-center gap-2.5">
            <div className="flex h-6 w-6 items-center justify-center rounded bg-teal-500/10 text-teal-400 border border-teal-500/20">
              <Bot className="h-3.5 w-3.5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <CardTitle className="text-xs font-bold uppercase tracking-wider text-foreground">
                  Groq LLM Incident Analysis
                </CardTitle>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-teal-500/10 text-teal-400 border border-teal-500/20 uppercase font-semibold">
                  AI-Generated
                </span>
              </div>
              <CardDescription className="text-xs text-muted-foreground">
                Deep-dive attack explanation, impact projection, and remediation playbook
              </CardDescription>
            </div>
          </div>

          {!aiExplanation && (
            <Button
              size="sm"
              disabled={aiMutation.isPending || isViewer}
              title={isViewer ? "Viewers cannot trigger AI analysis" : "Request Groq LLM explanation"}
              onClick={() => aiMutation.mutate()}
              className="h-8 bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium gap-1.5"
            >
              {aiMutation.isPending ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  <span>Synthesizing...</span>
                </>
              ) : (
                <>
                  <Sparkles className="h-3.5 w-3.5" />
                  <span>Generate Explanation</span>
                </>
              )}
            </Button>
          )}
        </CardHeader>

        <CardContent className="pt-4">
          {isAILoading ? (
            <div className="space-y-3">
              <Skeleton className="h-4 w-3/4" />
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-5/6" />
            </div>
          ) : aiExplanation ? (
            <div className="space-y-4 text-xs">
              {/* Situational Explanation */}
              <div className="space-y-1">
                <span className="font-mono text-teal-400 font-semibold uppercase text-[11px] block">
                  Situational Explanation
                </span>
                <p className="leading-relaxed text-foreground whitespace-pre-wrap font-sans">
                  {aiExplanation.explanation}
                </p>
              </div>

              {/* Impact Analysis */}
              {aiExplanation.impact && (
                <div className="space-y-1 pt-2 border-t border-border">
                  <span className="font-mono text-severity-high font-semibold uppercase text-[11px] block">
                    Security Impact Assessment
                  </span>
                  <p className="leading-relaxed text-foreground whitespace-pre-wrap font-sans">
                    {aiExplanation.impact}
                  </p>
                </div>
              )}

              {/* Recommended Mitigation Playbook */}
              {aiExplanation.recommended_mitigation && (
                <div className="space-y-1 pt-2 border-t border-border">
                  <span className="font-mono text-teal-400 font-semibold uppercase text-[11px] block">
                    Recommended Mitigation Playbook
                  </span>
                  <p className="leading-relaxed text-foreground whitespace-pre-wrap font-sans">
                    {aiExplanation.recommended_mitigation}
                  </p>
                </div>
              )}

              <div className="pt-2 text-[10px] font-mono text-muted-foreground border-t border-border flex items-center justify-between">
                <span>Model: Groq Cloud (openai/gpt-oss-120b)</span>
                <span>Generated: {new Date(aiExplanation.created_at).toLocaleString()}</span>
              </div>
            </div>
          ) : (
            <div className="py-6 text-center text-xs text-muted-foreground border border-dashed border-border rounded">
              No AI analysis has been generated for this incident yet. Click &quot;Generate Explanation&quot;
              above to query Groq LLM for real-time attack forensics.
            </div>
          )}
        </CardContent>
      </Card>

      {/* Footnote on synthetic telemetry training */}
      <div className="text-[11px] font-mono text-muted-foreground border-t border-border pt-3">
        * Note: The machine learning classifier is trained on synthetic telemetry data simulating distributed web application attack vectors and normal baseline traffic distributions.
      </div>
    </div>
  );
}
