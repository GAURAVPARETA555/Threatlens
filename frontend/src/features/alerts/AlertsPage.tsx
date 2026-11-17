import * as React from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import {
  BellRing,
  ExternalLink,
  Filter,
  Loader2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { DataTable } from "@/components/shared/DataTable";
import { EmptyState } from "@/components/shared/EmptyState";
import { listAlerts, updateAlertStatus } from "@/api/security";
import { queryKeys } from "@/api/queryKeys";
import { useAuth } from "@/hooks/useAuth";
import type { Alert, AlertStatus } from "@/api/schemas";

export function AlertsPage() {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const isViewer = user?.role === "viewer";

  const [statusFilter, setStatusFilter] = React.useState<string>("");
  const [severityFilter, setSeverityFilter] = React.useState<string>("");
  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(10);

  const queryKey = queryKeys.alerts.list({
    status: statusFilter || undefined,
    severity: severityFilter || undefined,
    page,
    page_size: pageSize,
  });

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey,
    queryFn: () =>
      listAlerts({
        status: statusFilter || undefined,
        severity: severityFilter || undefined,
        page,
        page_size: pageSize,
      }),
  });

  // Optimistic Mutation for alert status change
  const statusMutation = useMutation({
    mutationFn: ({ id, nextStatus }: { id: number; nextStatus: AlertStatus }) =>
      updateAlertStatus(id, nextStatus),
    onMutate: async ({ id, nextStatus }) => {
      // Cancel ongoing queries
      await queryClient.cancelQueries({ queryKey });

      // Snapshot previous data
      const previousData = queryClient.getQueryData(queryKey);

      // Optimistically update
      queryClient.setQueryData(queryKey, (old: any) => {
        if (!old?.results) return old;
        return {
          ...old,
          results: old.results.map((alert: Alert) =>
            alert.id === id ? { ...alert, status: nextStatus } : alert,
          ),
        };
      });

      return { previousData };
    },
    onError: (err: any, _vars, context) => {
      // Rollback on error
      if (context?.previousData) {
        queryClient.setQueryData(queryKey, context.previousData);
      }
      alert(err.response?.data?.detail || "Failed to update alert status.");
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.alerts.all });
      queryClient.invalidateQueries({ queryKey: queryKeys.reports.summary });
    },
  });

  const columns: ColumnDef<Alert, any>[] = [
    {
      accessorKey: "id",
      header: "Alert ID",
      cell: ({ row }) => (
        <span className="font-mono text-muted-foreground text-[11px]">#{row.original.id}</span>
      ),
    },
    {
      accessorKey: "created_at",
      header: "Triggered At",
      cell: ({ row }) => (
        <span className="font-mono text-[11px] text-muted-foreground">
          {new Date(row.original.created_at).toLocaleString()}
        </span>
      ),
    },
    {
      accessorKey: "detection",
      header: "Associated Detection",
      cell: ({ row }) => (
        <Link
          to={`/detections/${row.original.detection}`}
          className="font-mono text-teal-400 hover:underline flex items-center gap-1"
        >
          <span>Detection #{row.original.detection}</span>
          <ExternalLink className="h-3 w-3" />
        </Link>
      ),
    },
    {
      accessorKey: "status",
      header: "Triage Status",
      cell: ({ row }) => {
        const currentStatus = row.original.status;
        return (
          <div className="flex items-center gap-2">
            <Select
              disabled={statusMutation.isPending || isViewer}
              value={currentStatus}
              onValueChange={(val: AlertStatus | null) => {
                if (val) {
                  statusMutation.mutate({ id: row.original.id, nextStatus: val });
                }
              }}
            >
              <SelectTrigger className="h-7 w-32 text-xs font-mono border-border bg-card">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="text-xs font-mono">
                <SelectItem value="open" className="text-severity-critical">
                  ● OPEN
                </SelectItem>
                <SelectItem value="investigating" className="text-severity-high">
                  ● INVESTIGATING
                </SelectItem>
                <SelectItem value="resolved" className="text-teal-400">
                  ● RESOLVED
                </SelectItem>
              </SelectContent>
            </Select>

            {statusMutation.isPending && statusMutation.variables?.id === row.original.id && (
              <Loader2 className="h-3 w-3 animate-spin text-teal-400" />
            )}
          </div>
        );
      },
    },
    {
      accessorKey: "resolved_at",
      header: "Resolved At",
      cell: ({ row }) => (
        <span className="font-mono text-[11px] text-muted-foreground">
          {row.original.resolved_at
            ? new Date(row.original.resolved_at).toLocaleTimeString()
            : "—"}
        </span>
      ),
    },
    {
      id: "actions",
      header: "Action",
      cell: ({ row }) => (
        <Link to={`/detections/${row.original.detection}`}>
          <Button variant="outline" size="sm" className="h-7 text-xs font-mono">
            Investigate
          </Button>
        </Link>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <Filter className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-xs text-muted-foreground font-medium">Status Filter:</span>
          <div className="flex items-center gap-1">
            {[
              { label: "ALL", val: "" },
              { label: "OPEN", val: "open" },
              { label: "INVESTIGATING", val: "investigating" },
              { label: "RESOLVED", val: "resolved" },
            ].map(({ label, val }) => (
              <Button
                key={label}
                size="sm"
                variant={statusFilter === val ? "secondary" : "ghost"}
                onClick={() => {
                  setStatusFilter(val);
                  setPage(1);
                }}
                className={`h-7 px-2.5 text-xs font-mono ${
                  statusFilter === val
                    ? "bg-teal-500/10 text-teal-400 border border-teal-500/20 font-bold"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {label}
              </Button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground font-medium">Severity:</span>
          <div className="flex items-center gap-1">
            {["", "critical", "high"].map((sev) => (
              <Button
                key={sev || "all"}
                size="sm"
                variant={severityFilter === sev ? "secondary" : "ghost"}
                onClick={() => {
                  setSeverityFilter(sev);
                  setPage(1);
                }}
                className={`h-7 px-2 text-xs font-mono uppercase ${
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

      {/* Alerts Table */}
      <DataTable
        columns={columns}
        data={data?.results ?? []}
        isLoading={isLoading}
        isError={isError}
        errorMessage={(error as any)?.message || "Failed to load alerts queue."}
        onRetry={refetch}
        totalCount={data?.count ?? 0}
        currentPage={page}
        pageSize={pageSize}
        onPageChange={setPage}
        onPageSizeChange={setPageSize}
        emptyState={
          <EmptyState
            icon={BellRing}
            title="Alert Queue Clear"
            description="No active alerts match the selected status filter."
          />
        }
      />
    </div>
  );
}
