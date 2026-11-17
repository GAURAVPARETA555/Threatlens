import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  Radio,
  Crosshair,
  BellRing,
  ScanSearch,
  FileText,
  Shield,
} from "lucide-react";
import { cn } from "@/lib/utils";

const navigation = [
  { name: "Overview", href: "/", icon: LayoutDashboard },
  { name: "Events", href: "/events", icon: Radio },
  { name: "Detections", href: "/detections", icon: Crosshair },
  { name: "Alerts", href: "/alerts", icon: BellRing },
  { name: "Scans", href: "/scans", icon: ScanSearch },
  { name: "Reports", href: "/reports", icon: FileText },
];

export function Sidebar() {
  return (
    <aside className="w-56 shrink-0 border-r border-border bg-card flex flex-col h-screen select-none">
      {/* Brand Header */}
      <div className="h-13 px-4 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="flex h-7 w-7 items-center justify-center rounded bg-teal-500/10 text-teal-400 border border-teal-500/20">
            <Shield className="h-4 w-4 text-teal-400" />
          </div>
          <div>
            <span className="text-xs font-bold tracking-tight text-foreground block">
              ThreatLens
            </span>
            <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider block -mt-0.5">
              SOC CONSOLE
            </span>
          </div>
        </div>
      </div>

      {/* Navigation items */}
      <nav className="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto">
        <div className="px-2 pb-1.5 text-[10px] font-mono uppercase text-muted-foreground tracking-wider">
          Telemetry & Triage
        </div>
        {navigation.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.name}
              to={item.href}
              end={item.href === "/"}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2.5 px-2.5 py-1.5 rounded text-xs font-medium transition-colors",
                  isActive
                    ? "bg-teal-500/10 text-teal-400 border border-teal-500/20 font-semibold"
                    : "text-muted-foreground hover:bg-muted/50 hover:text-foreground",
                )
              }
            >
              <Icon className="h-4 w-4 shrink-0" />
              <span>{item.name}</span>
            </NavLink>
          );
        })}
      </nav>

      {/* Engine Status Footer */}
      <div className="p-3 border-t border-border bg-muted/20">
        <div className="flex items-center justify-between text-[11px] font-mono text-muted-foreground">
          <div className="flex items-center gap-1.5">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-teal-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-teal-500"></span>
            </span>
            <span>HYBRID ENGINE</span>
          </div>
          <span className="text-teal-400 font-medium">ONLINE</span>
        </div>
        <div className="mt-1 text-[10px] font-mono text-muted-foreground truncate">
          Rule + ML (50/50) Risk
        </div>
      </div>
    </aside>
  );
}
