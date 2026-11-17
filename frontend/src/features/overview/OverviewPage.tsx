import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  Radio,
  Crosshair,
  BellRing,
  ArrowRight,
  Flame,
} from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  PieChart,
  Pie,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { getReportSummary } from "@/api/insights";
import { listAlerts, listEvents } from "@/api/security";
import { queryKeys } from "@/api/queryKeys";

export function OverviewPage() {
  const {
    data: summaryReport,
    isLoading: isSummaryLoading,
  } = useQuery({
    queryKey: queryKeys.reports.summary,
    queryFn: getReportSummary,
    staleTime: 30000,
  });

  const { data: recentAlertsData, isLoading: isAlertsLoading } = useQuery({
    queryKey: queryKeys.alerts.list({ page_size: 5 }),
    queryFn: () => listAlerts({ page_size: 5 }),
  });

  const { data: recentEventsData } = useQuery({
    queryKey: queryKeys.events.list({ page_size: 5 }),
    queryFn: () => listEvents({ page_size: 5 }),
  });

  // Extract metrics from summary_json
  const summary = (summaryReport?.summary_json ?? {}) as Record<string, any>;
  const totalEvents = summary.total_security_events ?? 0;
  const totalDetections = summary.total_detections ?? 0;
  const alertSummary = summary.alert_summary ?? { open: 0, investigating: 0, resolved: 0 };
  const openAlerts = alertSummary.open ?? 0;
  const severityDist = summary.severity_distribution ?? { critical: 0, high: 0, medium: 0, low: 0 };
  const criticalCount = severityDist.critical ?? 0;
  const avgRiskScore = summary.average_risk_score ?? 0;

  // Attack types distribution data
  const attackDistRaw: Array<{ attack__name: string | null; count: number }> =
    summary.attack_distribution ?? [];
  const attackChartData = attackDistRaw.slice(0, 6).map((item) => ({
    name: item.attack__name || "Unknown",
    count: item.count,
  }));

  // Severity chart data
  const severityChartData = [
    { name: "Critical", count: severityDist.critical ?? 0, color: "var(--severity-critical)" },
    { name: "High", count: severityDist.high ?? 0, color: "var(--severity-high)" },
    { name: "Medium", count: severityDist.medium ?? 0, color: "var(--severity-medium)" },
    { name: "Low", count: severityDist.low ?? 0, color: "var(--severity-low)" },
  ];

  // Derive top source IPs from recent events
  const topIPsMap = (recentEventsData?.results ?? []).reduce((acc: Record<string, number>, ev) => {
    acc[ev.source_ip] = (acc[ev.source_ip] || 0) + 1;
    return acc;
  }, {});
  const topIPs = Object.entries(topIPsMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  return (
    <div className="space-y-5">
      {/* KPI Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Total Ingested Events */}
        <Card className="border-border bg-card">
          <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
            <span className="text-xs font-medium text-muted-foreground">Total Ingested Events</span>
            <Radio className="h-4 w-4 text-teal-400" />
          </CardHeader>
          <CardContent>
            {isSummaryLoading ? (
              <Skeleton className="h-7 w-20" />
            ) : (
              <div className="font-mono text-2xl font-bold tracking-tight text-foreground">
                {totalEvents.toLocaleString()}
              </div>
            )}
            <p className="text-[11px] font-mono text-muted-foreground mt-1">
              Raw telemetry in buffer
            </p>
          </CardContent>
        </Card>

        {/* Total Detections */}
        <Card className="border-border bg-card">
          <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
            <span className="text-xs font-medium text-muted-foreground">Total Detections</span>
            <Crosshair className="h-4 w-4 text-teal-400" />
          </CardHeader>
          <CardContent>
            {isSummaryLoading ? (
              <Skeleton className="h-7 w-20" />
            ) : (
              <div className="font-mono text-2xl font-bold tracking-tight text-foreground">
                {totalDetections.toLocaleString()}
              </div>
            )}
            <p className="text-[11px] font-mono text-muted-foreground mt-1">
              Rule + ML analyzed incidents
            </p>
          </CardContent>
        </Card>

        {/* Open Alerts */}
        <Card className="border-border bg-card">
          <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
            <span className="text-xs font-medium text-muted-foreground">Active Open Alerts</span>
            <BellRing className="h-4 w-4 text-severity-high" />
          </CardHeader>
          <CardContent>
            {isSummaryLoading ? (
              <Skeleton className="h-7 w-20" />
            ) : (
              <div className="font-mono text-2xl font-bold tracking-tight text-severity-high">
                {openAlerts}
              </div>
            )}
            <p className="text-[11px] font-mono text-muted-foreground mt-1">
              Pending analyst triage
            </p>
          </CardContent>
        </Card>

        {/* Critical Severity Threats */}
        <Card className="border-border bg-card">
          <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
            <span className="text-xs font-medium text-muted-foreground">Critical Severity</span>
            <Flame className="h-4 w-4 text-severity-critical" />
          </CardHeader>
          <CardContent>
            {isSummaryLoading ? (
              <Skeleton className="h-7 w-20" />
            ) : (
              <div className="font-mono text-2xl font-bold tracking-tight text-severity-critical">
                {criticalCount}
              </div>
            )}
            <div className="flex items-center gap-2 mt-1 text-[11px] font-mono text-muted-foreground">
              <span>Avg Risk:</span>
              <span className="font-semibold text-foreground">{avgRiskScore}</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Analytics Visualizations */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Severity Distribution */}
        <Card className="border-border bg-card lg:col-span-1">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
              Severity Stratification
            </CardTitle>
            <CardDescription className="text-xs text-muted-foreground">
              Incidents classified by dynamic risk engine
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-52 w-full flex items-center justify-center">
              {isSummaryLoading ? (
                <Skeleton className="h-44 w-44 rounded-full" />
              ) : totalDetections === 0 ? (
                <div className="text-xs text-muted-foreground text-center">
                  No telemetry detections yet.
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityChartData}
                      cx="50%"
                      cy="50%"
                      innerRadius={48}
                      outerRadius={70}
                      paddingAngle={3}
                      dataKey="count"
                    >
                      {severityChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "var(--surface-1)",
                        borderColor: "var(--border-color)",
                        fontSize: "11px",
                        fontFamily: "monospace",
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>

            {/* Severity Legend */}
            <div className="grid grid-cols-2 gap-2 pt-2 border-t border-border text-xs font-mono">
              {severityChartData.map((item) => (
                <div key={item.name} className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <span
                      className="h-2 w-2 rounded-full"
                      style={{ backgroundColor: item.color }}
                    />
                    <span className="text-muted-foreground text-[11px]">{item.name}</span>
                  </div>
                  <span className="font-semibold text-foreground">{item.count}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Top Attack Vectors */}
        <Card className="border-border bg-card lg:col-span-2">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <div>
              <CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                Attack Type Breakdown
              </CardTitle>
              <CardDescription className="text-xs text-muted-foreground">
                Most frequent OWASP & MITRE signature categorizations
              </CardDescription>
            </div>
            <Link to="/detections">
              <Button variant="ghost" size="sm" className="h-7 text-xs text-teal-400 gap-1 px-2">
                All Detections <ArrowRight className="h-3 w-3" />
              </Button>
            </Link>
          </CardHeader>
          <CardContent>
            <div className="h-60 w-full">
              {isSummaryLoading ? (
                <Skeleton className="h-full w-full" />
              ) : attackChartData.length === 0 ? (
                <div className="h-full flex items-center justify-center text-xs text-muted-foreground">
                  No attack vectors identified in detections.
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={attackChartData} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                    <XAxis
                      dataKey="name"
                      stroke="var(--fg-muted)"
                      fontSize={11}
                      tickLine={false}
                      interval={0}
                      angle={-15}
                      textAnchor="end"
                    />
                    <YAxis
                      stroke="var(--fg-muted)"
                      fontSize={11}
                      tickLine={false}
                      allowDecimals={false}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "var(--surface-1)",
                        borderColor: "var(--border-color)",
                        fontSize: "11px",
                        fontFamily: "monospace",
                      }}
                    />
                    <Bar dataKey="count" fill="var(--color-primary)" radius={[2, 2, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Triage Strip: Top Source IPs & Recent Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Top Source IPs */}
        <Card className="border-border bg-card lg:col-span-1">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
              Active Ingest Origin IPs
            </CardTitle>
            <CardDescription className="text-xs text-muted-foreground">
              Most frequent telemetry origin addresses
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {topIPs.length === 0 ? (
              <div className="text-xs text-muted-foreground py-4 text-center">
                No recent IP activity recorded.
              </div>
            ) : (
              topIPs.map(([ip, count]) => (
                <div
                  key={ip}
                  className="flex items-center justify-between p-2 rounded border border-border bg-muted/20 text-xs font-mono"
                >
                  <span className="text-foreground">{ip}</span>
                  <span className="text-muted-foreground text-[11px]">{count} events</span>
                </div>
              ))
            )}
            <div className="pt-2">
              <Link to="/events">
                <Button variant="outline" size="sm" className="w-full h-7 text-xs font-mono text-muted-foreground">
                  Browse Event Stream
                </Button>
              </Link>
            </div>
          </CardContent>
        </Card>

        {/* Recent Alerts Table */}
        <Card className="border-border bg-card lg:col-span-2">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <div>
              <CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                Priority Alerts Requiring Action
              </CardTitle>
              <CardDescription className="text-xs text-muted-foreground">
                High & Critical detections auto-escalated to triage
              </CardDescription>
            </div>
            <Link to="/alerts">
              <Button variant="ghost" size="sm" className="h-7 text-xs text-teal-400 gap-1 px-2">
                Triage Queue <ArrowRight className="h-3 w-3" />
              </Button>
            </Link>
          </CardHeader>
          <CardContent>
            {isAlertsLoading ? (
              <div className="space-y-2">
                <Skeleton className="h-9 w-full" />
                <Skeleton className="h-9 w-full" />
                <Skeleton className="h-9 w-full" />
              </div>
            ) : !recentAlertsData?.results?.length ? (
              <div className="py-8 text-center text-xs text-muted-foreground border border-dashed border-border rounded">
                No active alerts in queue. System posture nominal.
              </div>
            ) : (
              <div className="divide-y divide-border border border-border rounded overflow-hidden">
                {recentAlertsData.results.map((alert) => (
                  <div
                    key={alert.id}
                    className="flex items-center justify-between px-3 py-2 text-xs hover:bg-muted/30 transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-muted-foreground text-[11px]">
                        #{alert.id}
                      </span>
                      <span className="font-mono text-foreground font-medium">
                        Detection #{alert.detection}
                      </span>
                      <span
                        className={`text-[10px] font-mono px-1.5 py-0.5 rounded uppercase font-medium ${
                          alert.status === "open"
                            ? "bg-severity-critical/10 text-severity-critical"
                            : alert.status === "investigating"
                            ? "bg-severity-high/10 text-severity-high"
                            : "bg-teal-500/10 text-teal-400"
                        }`}
                      >
                        {alert.status}
                      </span>
                    </div>

                    <div className="flex items-center gap-3">
                      <span className="text-[11px] font-mono text-muted-foreground">
                        {new Date(alert.created_at).toLocaleTimeString()}
                      </span>
                      <Link to={`/detections/${alert.detection}`}>
                        <Button variant="outline" size="sm" className="h-6 text-[10px] px-2 font-mono">
                          Inspect
                        </Button>
                      </Link>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
