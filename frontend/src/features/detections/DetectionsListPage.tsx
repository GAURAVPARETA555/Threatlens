import * as React from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { Crosshair, ExternalLink, Filter } from "lucide-react";
import { Button } from "@/components/ui/button";
import { DataTable } from "@/components/shared/DataTable";
import { SeverityBadge } from "@/components/shared/SeverityBadge";
import { EmptyState } from "@/components/shared/EmptyState";
import { listDetections } from "@/api/security";
import { queryKeys } from "@/api/queryKeys";
import type { DetectionResult, Severity } from "@/api/schemas";

export function DetectionsListPage() {
  const navigate = useNavigate();
  const [severityFilter, setSeverityFilter] = React.useState<string>("");
  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(10);

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: queryKeys.detections.list({
      severity: severityFilter || undefined,
      page,
      page_size: pageSize,
    }),
    queryFn: () =>
      listDetections({
        severity: severityFilter || undefined,
        page,
        page_size: pageSize,
      }),
  });

  const columns: ColumnDef<DetectionResult, any>[] = [
    {
      accessorKey: "id",
      header: "Detection ID",
      cell: ({ row }) => (
        <span className="font-mono text-muted-foreground text-[11px]">#{row.original.id}</span>
      ),
    },
    {
      accessorKey: "created_at",
      header: "Timestamp",
      cell: ({ row }) => (
        <span className="font-mono text-[11px] text-muted-foreground">
          {new Date(row.original.created_at).toLocaleString()}
        </span>
      ),
    },
    {
      accessorKey: "event",
      header: "Associated Event",
      cell: ({ row }) => (
        <span className="font-mono text-[11px] text-teal-400">Event #{row.original.event}</span>
      ),
    },
    {
      accessorKey: "final_severity",
      header: "Severity",
      cell: ({ row }) => <SeverityBadge severity={row.original.final_severity as Severity} />,
    },
    {
      accessorKey: "final_risk_score",
      header: "Risk Score",
      cell: ({ row }) => {
        const score = row.original.final_risk_score;
        let colorClass = "text-severity-low";
        if (score >= 85) colorClass = "text-severity-critical";
        else if (score >= 65) colorClass = "text-severity-high";
        else if (score >= 40) colorClass = "text-severity-medium";

        return (
          <div className="flex items-center gap-2">
            <span className={`font-mono font-bold text-xs ${colorClass}`}>{score.toFixed(1)}</span>
            <span className="text-[10px] text-muted-foreground font-mono">/ 100</span>
          </div>
        );
      },
    },
    {
      accessorKey: "rule_detected",
      header: "Rule Signal",
      cell: ({ row }) => (
        <span
          className={`font-mono text-[11px] px-1.5 py-0.5 rounded ${
            row.original.rule_detected
              ? "bg-teal-500/10 text-teal-400 border border-teal-500/20"
              : "text-muted-foreground"
          }`}
        >
          {row.original.rule_detected ? "MATCHED" : "NONE"}
        </span>
      ),
    },
    {
      accessorKey: "ml_prediction",
      header: "ML Prediction",
      cell: ({ row }) => (
        <span
          className={`font-mono text-[11px] uppercase ${
            row.original.ml_prediction.toLowerCase() === "malicious"
              ? "text-severity-high font-semibold"
              : "text-muted-foreground"
          }`}
        >
          {row.original.ml_prediction || "UNKNOWN"} (
          {(row.original.ml_confidence * 100).toFixed(0)}%)
        </span>
      ),
    },
    {
      id: "actions",
      header: "Details",
      cell: ({ row }) => (
        <Button
          size="sm"
          variant="ghost"
          onClick={() => navigate(`/detections/${row.original.id}`)}
          className="h-7 text-xs font-mono text-muted-foreground hover:text-foreground gap-1"
        >
          <span>Inspect</span>
          <ExternalLink className="h-3 w-3" />
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Filter className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-xs text-muted-foreground font-medium">Filter Severity:</span>
          <div className="flex items-center gap-1">
            {["", "critical", "high", "medium", "low"].map((sev) => (
              <Button
                key={sev || "all"}
                size="sm"
                variant={severityFilter === sev ? "secondary" : "ghost"}
                onClick={() => {
                  setSeverityFilter(sev);
                  setPage(1);
                }}
                className={`h-7 px-2.5 text-xs font-mono uppercase ${
                  severityFilter === sev
                    ? "bg-teal-500/10 text-teal-400 border border-teal-500/20 font-bold"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {sev || "ALL"}
              </Button>
            ))}
          </div>
        </div>
      </div>

      {/* Detections Data Table */}
      <DataTable
        columns={columns}
        data={data?.results ?? []}
        isLoading={isLoading}
        isError={isError}
        errorMessage={(error as any)?.message || "Failed to load detections list."}
        onRetry={refetch}
        totalCount={data?.count ?? 0}
        currentPage={page}
        pageSize={pageSize}
        onPageChange={setPage}
        onPageSizeChange={setPageSize}
        onRowClick={(row) => navigate(`/detections/${row.id}`)}
        emptyState={
          <EmptyState
            icon={Crosshair}
            title="No Detections Found"
            description="No threat detections match the current severity filters or none have been evaluated."
            actionLabel="View All Telemetry Events"
            onAction={() => navigate("/events")}
          />
        }
      />
    </div>
  );
}
