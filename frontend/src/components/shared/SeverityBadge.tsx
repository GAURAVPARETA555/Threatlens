import { cn } from "@/lib/utils";
import type { Severity } from "@/api/schemas";

const severityConfig: Record<
  Severity,
  { label: string; className: string; dotClassName: string }
> = {
  critical: {
    label: "Critical",
    className:
      "bg-severity-critical/10 text-severity-critical border-severity-critical/20",
    dotClassName: "bg-severity-critical",
  },
  high: {
    label: "High",
    className:
      "bg-severity-high/10 text-severity-high border-severity-high/20",
    dotClassName: "bg-severity-high",
  },
  medium: {
    label: "Medium",
    className:
      "bg-severity-medium/10 text-severity-medium border-severity-medium/20",
    dotClassName: "bg-severity-medium",
  },
  low: {
    label: "Low",
    className:
      "bg-severity-low/10 text-severity-low border-severity-low/20",
    dotClassName: "bg-severity-low",
  },
};

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const config = severityConfig[severity];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-xs font-medium border",
        config.className,
        className,
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", config.dotClassName)} />
      {config.label}
    </span>
  );
}
