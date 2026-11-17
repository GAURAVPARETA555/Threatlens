import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import {
  FileText,
  Sparkles,
  Printer,
  Loader2,
  ChevronRight,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { DataTable } from "@/components/shared/DataTable";
import { EmptyState } from "@/components/shared/EmptyState";
import { listReports, generateAIReport, getReportSummary } from "@/api/insights";
import { queryKeys } from "@/api/queryKeys";
import { useAuth } from "@/hooks/useAuth";
import type { Report } from "@/api/schemas";

export function ReportsPage() {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const isViewer = user?.role === "viewer";

  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(10);
  const [selectedReport, setSelectedReport] = React.useState<Report | null>(null);

  // Query historical reports
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: queryKeys.reports.list({ page, page_size: pageSize }),
    queryFn: () => listReports({ page, page_size: pageSize }),
  });

  // Latest summary query
  const { data: latestSummary } = useQuery({
    queryKey: queryKeys.reports.summary,
    queryFn: getReportSummary,
  });

  // Generate AI Executive Report mutation
  const aiReportMutation = useMutation({
    mutationFn: () => generateAIReport(),
    onSuccess: (newReport) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.reports.all });
      setSelectedReport(newReport);
    },
    onError: (err: any) => {
      alert(err.response?.data?.detail || "Failed to generate AI executive report.");
    },
  });

  // Set the first report as selected if none selected
  React.useEffect(() => {
    if (!selectedReport && data?.results?.length) {
      setSelectedReport(data.results[0]);
    } else if (!selectedReport && latestSummary) {
      setSelectedReport(latestSummary);
    }
  }, [data, latestSummary, selectedReport]);

  const handlePrint = () => {
    window.print();
  };

  const columns: ColumnDef<Report, any>[] = [
    {
      accessorKey: "id",
      header: "Report ID",
      cell: ({ row }) => (
        <span className="font-mono text-muted-foreground text-[11px]">#{row.original.id}</span>
      ),
    },
    {
      accessorKey: "created_at",
      header: "Generated Date",
      cell: ({ row }) => (
        <span className="font-mono text-[11px] text-muted-foreground">
          {new Date(row.original.created_at).toLocaleString()}
        </span>
      ),
    },
    {
      id: "type",
      header: "Report Classification",
      cell: ({ row }) => {
        const isAI = !!(row.original.summary_json as any)?.ai_analysis;
        return isAI ? (
          <span className="inline-flex items-center gap-1 rounded bg-teal-500/10 text-teal-400 px-2 py-0.5 text-xs font-mono font-medium border border-teal-500/20">
            <Sparkles className="h-3 w-3" /> AI EXECUTIVE
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 rounded bg-muted text-muted-foreground px-2 py-0.5 text-xs font-mono font-medium border border-border">
            <FileText className="h-3 w-3" /> TELEMETRY METRICS
          </span>
        );
      },
    },
    {
      id: "actions",
      header: "View",
      cell: ({ row }) => (
        <Button
          size="sm"
          variant={selectedReport?.id === row.original.id ? "secondary" : "ghost"}
          onClick={() => setSelectedReport(row.original)}
          className="h-7 text-xs font-mono gap-1"
        >
          <span>Select</span>
          <ChevronRight className="h-3 w-3" />
        </Button>
      ),
    },
  ];

  // Helper to extract AI analysis text/object
  const aiData = (selectedReport?.summary_json as any)?.ai_analysis;
  const statsData =
    (selectedReport?.summary_json as any)?.statistics ??
    (selectedReport?.summary_json as any);

  return (
    <div className="space-y-6">
      {/* Top action bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-bold text-foreground tracking-tight">Executive Intelligence Reports</h2>
          <p className="text-xs text-muted-foreground">
            Automated metrics aggregation and Groq LLM security synthesis
          </p>
        </div>

        <div className="flex items-center gap-2">
          {selectedReport && (
            <Button
              variant="outline"
              size="sm"
              onClick={handlePrint}
              className="h-8 text-xs font-mono gap-1.5"
            >
              <Printer className="h-3.5 w-3.5" />
              <span>Print / Export PDF</span>
            </Button>
          )}

          <Button
            size="sm"
            disabled={aiReportMutation.isPending || isViewer}
            title={isViewer ? "Viewers cannot trigger AI reports" : "Run Groq LLM executive synthesis"}
            onClick={() => aiReportMutation.mutate()}
            className="h-8 bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium gap-1.5"
          >
            {aiReportMutation.isPending ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                <span>Synthesizing Report...</span>
              </>
            ) : (
              <>
                <Sparkles className="h-3.5 w-3.5" />
                <span>Generate AI Executive Report</span>
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Selected Report Presentation (Printable Area) */}
      {selectedReport ? (
        <Card className="border-border bg-card print:border-none print:shadow-none print:p-0">
          <CardHeader className="pb-4 border-b border-border">
            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-teal-400 font-bold uppercase tracking-wider">
                    ThreatLens SOC
                  </span>
                  <span className="text-muted-foreground text-xs">•</span>
                  <span className="font-mono text-xs text-muted-foreground">
                    Report #{selectedReport.id}
                  </span>
                </div>
                <CardTitle className="text-lg font-bold tracking-tight">
                  Security Telemetry & Threat Posture Assessment
                </CardTitle>
                <CardDescription className="text-xs text-muted-foreground font-mono">
                  Generated: {new Date(selectedReport.created_at).toLocaleString()}
                </CardDescription>
              </div>

              {aiData && (
                <div className="hidden sm:flex flex-col items-end">
                  <span className="inline-flex items-center gap-1 rounded bg-teal-500/10 text-teal-400 px-2 py-0.5 text-xs font-mono font-medium border border-teal-500/20">
                    <Sparkles className="h-3 w-3" /> AI EXECUTIVE SYNTHESIS
                  </span>
                  <span className="text-[10px] font-mono text-muted-foreground mt-1">
                    Powered by Groq Cloud
                  </span>
                </div>
              )}
            </div>
          </CardHeader>

          <CardContent className="pt-6 space-y-6">
            {/* KPI Summary Block */}
            {statsData && typeof statsData === "object" && (
              <div className="space-y-2">
                <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground font-mono">
                  Telemetry Aggregates
                </h3>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="p-3 rounded border border-border bg-muted/20">
                    <span className="text-[11px] text-muted-foreground block">Events Recorded</span>
                    <span className="font-mono text-lg font-bold text-foreground">
                      {statsData.total_security_events ?? "—"}
                    </span>
                  </div>
                  <div className="p-3 rounded border border-border bg-muted/20">
                    <span className="text-[11px] text-muted-foreground block">Detections Evaluated</span>
                    <span className="font-mono text-lg font-bold text-foreground">
                      {statsData.total_detections ?? "—"}
                    </span>
                  </div>
                  <div className="p-3 rounded border border-border bg-muted/20">
                    <span className="text-[11px] text-muted-foreground block">Avg Risk Score</span>
                    <span className="font-mono text-lg font-bold text-teal-400">
                      {statsData.average_risk_score ?? "—"}
                    </span>
                  </div>
                  <div className="p-3 rounded border border-border bg-muted/20">
                    <span className="text-[11px] text-muted-foreground block">Malicious Predictions</span>
                    <span className="font-mono text-lg font-bold text-severity-high">
                      {statsData.malicious_ml_predictions ?? "—"}
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* AI Synthesized Prose */}
            {aiData ? (
              <div className="space-y-5 pt-2 border-t border-border">
                {typeof aiData === "string" ? (
                  <div className="prose prose-invert max-w-none text-xs leading-relaxed font-sans whitespace-pre-wrap">
                    {aiData}
                  </div>
                ) : (
                  <>
                    {aiData.executive_summary && (
                      <div className="space-y-1.5">
                        <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-teal-400">
                          1. Executive Summary
                        </h4>
                        <p className="text-xs leading-relaxed text-foreground whitespace-pre-wrap font-sans">
                          {aiData.executive_summary}
                        </p>
                      </div>
                    )}

                    {aiData.key_findings && (
                      <div className="space-y-1.5 pt-3 border-t border-border">
                        <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-severity-high">
                          2. Key Security Findings
                        </h4>
                        <p className="text-xs leading-relaxed text-foreground whitespace-pre-wrap font-sans">
                          {aiData.key_findings}
                        </p>
                      </div>
                    )}

                    {aiData.strategic_recommendations && (
                      <div className="space-y-1.5 pt-3 border-t border-border">
                        <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-teal-400">
                          3. Strategic Recommendations & Hardening
                        </h4>
                        <p className="text-xs leading-relaxed text-foreground whitespace-pre-wrap font-sans">
                          {aiData.strategic_recommendations}
                        </p>
                      </div>
                    )}
                  </>
                )}
              </div>
            ) : (
              <div className="p-4 border border-dashed border-border rounded text-center text-xs text-muted-foreground">
                This is a raw metrics snapshot. Click &quot;Generate AI Executive Report&quot; above to
                synthesize executive narrative prose with Groq LLM.
              </div>
            )}
          </CardContent>
        </Card>
      ) : null}

      {/* Historical Reports Table */}
      <div className="space-y-2 pt-4">
        <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground font-mono">
          Saved Report Archive
        </h3>
        <DataTable
          columns={columns}
          data={data?.results ?? []}
          isLoading={isLoading}
          isError={isError}
          errorMessage={(error as any)?.message || "Failed to load reports."}
          onRetry={refetch}
          totalCount={data?.count ?? 0}
          currentPage={page}
          pageSize={pageSize}
          onPageChange={setPage}
          onPageSizeChange={setPageSize}
          emptyState={
            <EmptyState
              icon={FileText}
              title="No Saved Reports"
              description="Generate a report to start compiling executive security intelligence."
            />
          }
        />
      </div>
    </div>
  );
}
