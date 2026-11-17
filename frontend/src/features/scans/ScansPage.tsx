import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import {
  ScanSearch,
  Plus,
  Loader2,
  ExternalLink,
  Target,
  Clock,
  CheckCircle2,
  XCircle,
  AlertCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { DataTable } from "@/components/shared/DataTable";
import { EmptyState } from "@/components/shared/EmptyState";
import { listScans, createScan, getScan } from "@/api/security";
import { queryKeys } from "@/api/queryKeys";
import { useAuth } from "@/hooks/useAuth";
import type { Scan } from "@/api/schemas";

export function ScansPage() {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const isViewer = user?.role === "viewer";

  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(10);
  const [isCreateOpen, setIsCreateOpen] = React.useState(false);
  const [targetInput, setTargetInput] = React.useState("");
  const [createError, setCreateError] = React.useState<string | null>(null);

  // Detail Modal state
  const [selectedScanId, setSelectedScanId] = React.useState<number | null>(null);

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: queryKeys.scans.all,
    queryFn: () => listScans({ page, page_size: pageSize }),
  });

  // Query selected scan detail
  const { data: scanDetail, isLoading: isDetailLoading } = useQuery({
    queryKey: queryKeys.scans.detail(selectedScanId ?? 0),
    queryFn: () => getScan(selectedScanId!),
    enabled: !!selectedScanId,
  });

  // Create scan mutation
  const createMutation = useMutation({
    mutationFn: (target: string) => createScan({ target }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.scans.all });
      setIsCreateOpen(false);
      setTargetInput("");
      setCreateError(null);
    },
    onError: (err: any) => {
      setCreateError(err.response?.data?.detail || "Failed to create security scan.");
    },
  });

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "completed":
        return (
          <span className="inline-flex items-center gap-1 rounded bg-teal-500/10 text-teal-400 px-2 py-0.5 text-xs font-mono font-medium border border-teal-500/20">
            <CheckCircle2 className="h-3 w-3" /> COMPLETED
          </span>
        );
      case "running":
        return (
          <span className="inline-flex items-center gap-1 rounded bg-amber-500/10 text-amber-400 px-2 py-0.5 text-xs font-mono font-medium border border-amber-500/20">
            <Loader2 className="h-3 w-3 animate-spin" /> RUNNING
          </span>
        );
      case "failed":
        return (
          <span className="inline-flex items-center gap-1 rounded bg-severity-critical/10 text-severity-critical px-2 py-0.5 text-xs font-mono font-medium border border-severity-critical/20">
            <XCircle className="h-3 w-3" /> FAILED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 rounded bg-muted text-muted-foreground px-2 py-0.5 text-xs font-mono font-medium border border-border">
            <Clock className="h-3 w-3" /> PENDING
          </span>
        );
    }
  };

  const columns: ColumnDef<Scan, any>[] = [
    {
      accessorKey: "id",
      header: "Scan ID",
      cell: ({ row }) => (
        <span className="font-mono text-muted-foreground text-[11px]">#{row.original.id}</span>
      ),
    },
    {
      accessorKey: "target",
      header: "Target Host / Subnet",
      cell: ({ row }) => (
        <span className="font-mono text-foreground font-semibold flex items-center gap-1.5">
          <Target className="h-3.5 w-3.5 text-teal-400" />
          {row.original.target}
        </span>
      ),
    },
    {
      accessorKey: "status",
      header: "Execution Status",
      cell: ({ row }) => getStatusBadge(row.original.status),
    },
    {
      accessorKey: "requested_by",
      header: "Operator ID",
      cell: ({ row }) => (
        <span className="font-mono text-[11px] text-muted-foreground">
          User #{row.original.requested_by}
        </span>
      ),
    },
    {
      accessorKey: "created_at",
      header: "Created",
      cell: ({ row }) => (
        <span className="font-mono text-[11px] text-muted-foreground">
          {new Date(row.original.created_at).toLocaleString()}
        </span>
      ),
    },
    {
      id: "actions",
      header: "Details",
      cell: ({ row }) => (
        <Button
          size="sm"
          variant="outline"
          onClick={() => setSelectedScanId(row.original.id)}
          className="h-7 text-xs font-mono gap-1"
        >
          <span>Inspect</span>
          <ExternalLink className="h-3 w-3" />
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      {/* Header action */}
      <div className="flex items-center justify-between">
        <div className="text-xs text-muted-foreground">
          Target host vulnerability scanning and perimeter tracking
        </div>

        <Button
          size="sm"
          disabled={isViewer}
          title={isViewer ? "Viewer accounts cannot initiate scans" : "Queue new vulnerability scan"}
          onClick={() => setIsCreateOpen(true)}
          className="h-8 bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium gap-1.5"
        >
          <Plus className="h-3.5 w-3.5" />
          <span>Launch Scan</span>
        </Button>
      </div>

      {/* Scans Table */}
      <DataTable
        columns={columns}
        data={data?.results ?? []}
        isLoading={isLoading}
        isError={isError}
        errorMessage={(error as any)?.message || "Failed to load scan records."}
        onRetry={refetch}
        totalCount={data?.count ?? 0}
        currentPage={page}
        pageSize={pageSize}
        onPageChange={setPage}
        onPageSizeChange={setPageSize}
        emptyState={
          <EmptyState
            icon={ScanSearch}
            title="No Scans Executed"
            description="No vulnerability scans have been created in this environment yet."
            actionLabel={isViewer ? undefined : "Initiate Asset Scan"}
            onAction={isViewer ? undefined : () => setIsCreateOpen(true)}
          />
        }
      />

      {/* Launch Scan Dialog */}
      <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
        <DialogContent className="sm:max-w-md bg-card border-border text-xs">
          <DialogHeader>
            <DialogTitle className="text-sm font-bold tracking-tight">Queue Security Scan</DialogTitle>
            <DialogDescription className="text-xs text-muted-foreground">
              Provide the hostname, IP address, or CIDR target range for vulnerability assessment.
            </DialogDescription>
          </DialogHeader>

          {createError && (
            <div className="my-2 flex items-center gap-2 rounded border border-severity-critical/20 bg-severity-critical/10 p-2 text-xs text-severity-critical">
              <AlertCircle className="h-4 w-4 shrink-0" />
              <span>{createError}</span>
            </div>
          )}

          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (targetInput.trim()) createMutation.mutate(targetInput.trim());
            }}
            className="space-y-3 py-2"
          >
            <div className="space-y-1.5">
              <Label className="text-xs">Scan Target</Label>
              <Input
                placeholder="e.g. 192.168.1.0/24 or api.enterprise.internal"
                value={targetInput}
                onChange={(e) => setTargetInput(e.target.value)}
                className="h-8 text-xs font-mono border-border bg-muted/20"
                required
              />
            </div>

            <DialogFooter className="pt-3">
              <Button
                type="button"
                variant="ghost"
                onClick={() => setIsCreateOpen(false)}
                className="h-8 text-xs"
              >
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={createMutation.isPending || !targetInput.trim()}
                className="h-8 bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium gap-1.5"
              >
                {createMutation.isPending ? (
                  <>
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    <span>Queueing...</span>
                  </>
                ) : (
                  <span>Initiate Scan</span>
                )}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Scan Detail Dialog */}
      <Dialog
        open={!!selectedScanId}
        onOpenChange={(open) => !open && setSelectedScanId(null)}
      >
        <DialogContent className="sm:max-w-md bg-card border-border text-xs font-mono">
          <DialogHeader>
            <DialogTitle className="text-sm font-bold tracking-tight font-sans">
              Scan Record Details
            </DialogTitle>
            <DialogDescription className="text-xs text-muted-foreground font-mono">
              Scan ID #{selectedScanId}
            </DialogDescription>
          </DialogHeader>

          {isDetailLoading ? (
            <div className="space-y-2 py-4">
              <div className="h-4 bg-muted/40 rounded animate-pulse" />
              <div className="h-4 bg-muted/40 rounded animate-pulse" />
              <div className="h-4 bg-muted/40 rounded animate-pulse" />
            </div>
          ) : scanDetail ? (
            <div className="space-y-3 py-2 text-xs">
              <div className="flex justify-between py-1 border-b border-border">
                <span className="text-muted-foreground">Target:</span>
                <span className="text-foreground font-bold">{scanDetail.target}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-border">
                <span className="text-muted-foreground">Status:</span>
                <div>{getStatusBadge(scanDetail.status)}</div>
              </div>
              <div className="flex justify-between py-1 border-b border-border">
                <span className="text-muted-foreground">Requested By:</span>
                <span className="text-foreground">Operator #{scanDetail.requested_by}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-border">
                <span className="text-muted-foreground">Created:</span>
                <span className="text-foreground">{new Date(scanDetail.created_at).toLocaleString()}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-border">
                <span className="text-muted-foreground">Started:</span>
                <span className="text-foreground">
                  {scanDetail.started_at ? new Date(scanDetail.started_at).toLocaleString() : "Not started"}
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-muted-foreground">Completed:</span>
                <span className="text-foreground">
                  {scanDetail.completed_at ? new Date(scanDetail.completed_at).toLocaleString() : "Pending"}
                </span>
              </div>
            </div>
          ) : null}

          <DialogFooter>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setSelectedScanId(null)}
              className="h-8 text-xs font-sans"
            >
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
