import { cn } from "@/lib/utils";

interface RiskGaugeProps {
  score: number;
  className?: string;
  showDetails?: boolean;
}

export function RiskGauge({ score, className, showDetails = true }: RiskGaugeProps) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));

  const getSeverityColor = (val: number) => {
    if (val >= 85) return "text-severity-critical bg-severity-critical";
    if (val >= 65) return "text-severity-high bg-severity-high";
    if (val >= 40) return "text-severity-medium bg-severity-medium";
    return "text-severity-low bg-severity-low";
  };

  const getSeverityLabel = (val: number) => {
    if (val >= 85) return "Critical";
    if (val >= 65) return "High";
    if (val >= 40) return "Medium";
    return "Low";
  };

  // 10 segments for the segmented gauge
  const segments = Array.from({ length: 10 }, (_, i) => (i + 1) * 10);

  return (
    <div className={cn("flex flex-col gap-1.5", className)}>
      <div className="flex items-baseline justify-between gap-2">
        <span className="font-mono text-xl font-bold tracking-tight text-foreground">
          {score.toFixed(1)}
          <span className="text-xs font-normal text-muted-foreground ml-1">/ 100</span>
        </span>
        {showDetails && (
          <span className={cn("text-xs font-medium font-mono uppercase", getSeverityColor(clamped).split(" ")[0])}>
            {getSeverityLabel(clamped)}
          </span>
        )}
      </div>

      {/* Segmented bar */}
      <div className="flex h-2 w-full gap-1 items-center">
        {segments.map((val) => {
          const isActive = clamped >= val - 5;
          let activeColor = "bg-severity-low";
          if (val > 80) activeColor = "bg-severity-critical";
          else if (val > 60) activeColor = "bg-severity-high";
          else if (val > 30) activeColor = "bg-severity-medium";

          return (
            <div
              key={val}
              className={cn(
                "h-full flex-1 rounded-sm transition-all duration-300",
                isActive ? activeColor : "bg-muted/40",
              )}
            />
          );
        })}
      </div>
    </div>
  );
}
