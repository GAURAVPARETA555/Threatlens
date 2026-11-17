import * as React from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import {
  Radio,
  Plus,
  Search,
  Play,
  Loader2,
  AlertCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
  SheetFooter,
} from "@/components/ui/sheet";
import { DataTable } from "@/components/shared/DataTable";
import { EmptyState } from "@/components/shared/EmptyState";
import { listEvents, createEvent, analyzeDetection } from "@/api/security";
import { queryKeys } from "@/api/queryKeys";
import { useAuth } from "@/hooks/useAuth";
import type { SecurityEvent } from "@/api/schemas";

export function EventsPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const isViewer = user?.role === "viewer";

  // Filter & Pagination state
  const [sourceIpFilter, setSourceIpFilter] = React.useState("");
  const [endpointFilter, setEndpointFilter] = React.useState("");
  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(10);
  const [isSheetOpen, setIsSheetOpen] = React.useState(false);

  // Ingest form state
  const [formData, setFormData] = React.useState({
    source_ip: "192.168.1.105",
    endpoint: "/admin/login",
    request_rate: 65.0,
    failed_login_count: 12,
    special_char_count: 8,
    raw_payload: '{\n  "user_agent": "Mozilla/5.0",\n  "param": "\' OR \'1\'=\'1"\n}',
  });
  const [formError, setFormError] = React.useState<string | null>(null);

  // Query events
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: queryKeys.events.list({
      source_ip: sourceIpFilter || undefined,
      endpoint: endpointFilter || undefined,
      page,
      page_size: pageSize,
    }),
    queryFn: () =>
      listEvents({
        source_ip: sourceIpFilter || undefined,
        endpoint: endpointFilter || undefined,
        page,
        page_size: pageSize,
      }),
  });

  // Analyze mutation
  const analyzeMutation = useMutation({
    mutationFn: (eventId: number) => analyzeDetection(eventId),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.detections.all });
      queryClient.invalidateQueries({ queryKey: queryKeys.alerts.all });
      navigate(`/detections/${result.id}`);
    },
    onError: (err: any) => {
      alert(err.response?.data?.detail || "Failed to trigger analysis.");
    },
  });

  // Create event mutation
  const createMutation = useMutation({
    mutationFn: async (payload: typeof formData) => {
      let parsedPayload = {};
      try {
        if (payload.raw_payload.trim()) {
          parsedPayload = JSON.parse(payload.raw_payload);
        }
      } catch {
        throw new Error("Raw payload must be valid JSON syntax.");
      }

      return createEvent({
        source_ip: payload.source_ip,
        endpoint: payload.endpoint,
        request_rate: Number(payload.request_rate),
        failed_login_count: Number(payload.failed_login_count),
        special_char_count: Number(payload.special_char_count),
        raw_payload: parsedPayload,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.events.all });
      setIsSheetOpen(false);
      setFormError(null);
    },
    onError: (err: any) => {
      setFormError(err.message || err.response?.data?.detail || "Failed to ingest event.");
    },
  });

  const columns: ColumnDef<SecurityEvent, any>[] = [
    {
      accessorKey: "id",
      header: "ID",
      cell: ({ row }) => (
        <span className="font-mono text-muted-foreground text-[11px]">#{row.original.id}</span>
      ),
    },
    {
      accessorKey: "timestamp",
      header: "Timestamp",
      cell: ({ row }) => (
        <span className="font-mono text-[11px] text-muted-foreground">
          {new Date(row.original.timestamp).toLocaleString()}
        </span>
      ),
    },
    {
      accessorKey: "source_ip",
      header: "Source IP",
      cell: ({ row }) => (
        <span className="font-mono text-foreground font-medium">{row.original.source_ip}</span>
      ),
    },
    {
      accessorKey: "endpoint",
      header: "Target Endpoint",
      cell: ({ row }) => (
        <span className="font-mono text-xs text-teal-400 bg-muted/30 px-1.5 py-0.5 rounded border border-border">
          {row.original.endpoint}
        </span>
      ),
    },
    {
      accessorKey: "request_rate",
      header: "Req Rate",
      cell: ({ row }) => (
        <span className="font-mono text-[11px] text-foreground">
          {row.original.request_rate.toFixed(1)}/s
        </span>
      ),
    },
    {
      accessorKey: "failed_login_count",
      header: "Failed Logins",
      cell: ({ row }) => (
        <span
          className={`font-mono text-[11px] ${
            row.original.failed_login_count > 5
              ? "text-severity-critical font-bold"
              : "text-muted-foreground"
          }`}
        >
          {row.original.failed_login_count}
        </span>
      ),
    },
    {
      accessorKey: "special_char_count",
      header: "Special Chars",
      cell: ({ row }) => (
        <span
          className={`font-mono text-[11px] ${
            row.original.special_char_count > 3
              ? "text-severity-high font-bold"
              : "text-muted-foreground"
          }`}
        >
          {row.original.special_char_count}
        </span>
      ),
    },
    {
      id: "actions",
      header: "Action",
      cell: ({ row }) => (
        <Button
          size="sm"
          variant="outline"
          disabled={analyzeMutation.isPending || isViewer}
          title={isViewer ? "Viewer accounts cannot trigger detection analysis" : "Run hybrid detection"}
          onClick={(e) => {
            e.stopPropagation();
            analyzeMutation.mutate(row.original.id);
          }}
          className="h-7 text-xs font-mono text-teal-400 hover:text-teal-300 border-teal-500/30 bg-teal-500/5 hover:bg-teal-500/10 gap-1"
        >
          {analyzeMutation.isPending && analyzeMutation.variables === row.original.id ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : (
            <Play className="h-3 w-3" />
          )}
          <span>Analyze</span>
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      {/* Header controls & Ingest action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        {/* Filters */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="relative w-48">
            <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              placeholder="Filter by Source IP..."
              value={sourceIpFilter}
              onChange={(e) => {
                setSourceIpFilter(e.target.value);
                setPage(1);
              }}
              className="h-8 pl-8 text-xs font-mono border-border bg-card"
            />
          </div>

          <div className="relative w-48">
            <Input
              placeholder="Filter endpoint..."
              value={endpointFilter}
              onChange={(e) => {
                setEndpointFilter(e.target.value);
                setPage(1);
              }}
              className="h-8 px-2.5 text-xs font-mono border-border bg-card"
            />
          </div>

          {(sourceIpFilter || endpointFilter) && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setSourceIpFilter("");
                setEndpointFilter("");
                setPage(1);
              }}
              className="h-8 text-xs text-muted-foreground"
            >
              Clear
            </Button>
          )}
        </div>

        {/* Ingest event Sheet trigger */}
        <Sheet open={isSheetOpen} onOpenChange={setIsSheetOpen}>
          <SheetTrigger
            render={
              <Button
                size="sm"
                disabled={isViewer}
                title={isViewer ? "Viewers cannot ingest events" : "Ingest telemetry event"}
                className="h-8 bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium gap-1.5"
              />
            }
          >
            <Plus className="h-3.5 w-3.5" />
            <span>Ingest Event</span>
          </SheetTrigger>
          <SheetContent className="sm:max-w-md bg-card border-border overflow-y-auto">
            <SheetHeader className="pb-3 border-b border-border">
              <SheetTitle className="text-sm font-bold tracking-tight">Ingest Security Event</SheetTitle>
              <SheetDescription className="text-xs text-muted-foreground">
                Submit raw telemetry for rule detection evaluation and ML classification.
              </SheetDescription>
            </SheetHeader>

            {formError && (
              <div className="my-3 flex items-center gap-2 rounded border border-severity-critical/20 bg-severity-critical/10 p-2.5 text-xs text-severity-critical">
                <AlertCircle className="h-4 w-4 shrink-0" />
                <span>{formError}</span>
              </div>
            )}

            <form
              onSubmit={(e) => {
                e.preventDefault();
                createMutation.mutate(formData);
              }}
              className="space-y-3 py-4"
            >
              <div className="space-y-1">
                <Label className="text-xs">Source IP Address</Label>
                <Input
                  value={formData.source_ip}
                  onChange={(e) => setFormData({ ...formData, source_ip: e.target.value })}
                  placeholder="192.168.1.100"
                  className="h-8 text-xs font-mono border-border bg-muted/20"
                  required
                />
              </div>

              <div className="space-y-1">
                <Label className="text-xs">Endpoint URI</Label>
                <Input
                  value={formData.endpoint}
                  onChange={(e) => setFormData({ ...formData, endpoint: e.target.value })}
                  placeholder="/api/v1/auth"
                  className="h-8 text-xs font-mono border-border bg-muted/20"
                  required
                />
              </div>

              <div className="grid grid-cols-3 gap-2">
                <div className="space-y-1">
                  <Label className="text-[11px]">Req Rate (/s)</Label>
                  <Input
                    type="number"
                    step="0.1"
                    value={formData.request_rate}
                    onChange={(e) => setFormData({ ...formData, request_rate: Number(e.target.value) })}
                    className="h-8 text-xs font-mono border-border bg-muted/20"
                    required
                  />
                </div>
                <div className="space-y-1">
                  <Label className="text-[11px]">Failed Logins</Label>
                  <Input
                    type="number"
                    value={formData.failed_login_count}
                    onChange={(e) =>
                      setFormData({ ...formData, failed_login_count: Number(e.target.value) })
                    }
                    className="h-8 text-xs font-mono border-border bg-muted/20"
                    required
                  />
                </div>
                <div className="space-y-1">
                  <Label className="text-[11px]">Special Chars</Label>
                  <Input
                    type="number"
                    value={formData.special_char_count}
                    onChange={(e) =>
                      setFormData({ ...formData, special_char_count: Number(e.target.value) })
                    }
                    className="h-8 text-xs font-mono border-border bg-muted/20"
                    required
                  />
                </div>
              </div>

              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <Label className="text-xs">Raw JSON Payload</Label>
                  <span className="text-[10px] font-mono text-muted-foreground">JSON Object</span>
                </div>
                <Textarea
                  value={formData.raw_payload}
                  onChange={(e) => setFormData({ ...formData, raw_payload: e.target.value })}
                  placeholder='{"param": "value"}'
                  rows={5}
                  className="text-xs font-mono border-border bg-muted/20 resize-y"
                />
              </div>

              <SheetFooter className="pt-4 border-t border-border">
                <Button
                  type="submit"
                  disabled={createMutation.isPending}
                  className="w-full h-8 bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium gap-1.5"
                >
                  {createMutation.isPending ? (
                    <>
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      <span>Ingesting...</span>
                    </>
                  ) : (
                    <span>Submit Telemetry Event</span>
                  )}
                </Button>
              </SheetFooter>
            </form>
          </SheetContent>
        </Sheet>
      </div>

      {/* Events Data Table */}
      <DataTable
        columns={columns}
        data={data?.results ?? []}
        isLoading={isLoading}
        isError={isError}
        errorMessage={(error as any)?.message || "Failed to load events telemetry."}
        onRetry={refetch}
        totalCount={data?.count ?? 0}
        currentPage={page}
        pageSize={pageSize}
        onPageChange={setPage}
        onPageSizeChange={setPageSize}
        emptyState={
          <EmptyState
            icon={Radio}
            title="No Telemetry Events"
            description="No events match the current filter criteria or none have been ingested yet."
            actionLabel={isViewer ? undefined : "Ingest First Event"}
            onAction={isViewer ? undefined : () => setIsSheetOpen(true)}
          />
        }
      />
    </div>
  );
}
