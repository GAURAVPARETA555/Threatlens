import * as React from "react";
import { useLocation } from "react-router-dom";
import {
  Search,
  Moon,
  Sun,
  LogOut,
  UserCheck,
  Shield,
  Eye,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAuth } from "@/hooks/useAuth";
import { cn } from "@/lib/utils";

const pageTitles: Record<string, { title: string; subtitle: string }> = {
  "/": { title: "Overview", subtitle: "Security Posture & Operations KPI" },
  "/events": { title: "Security Events", subtitle: "Telemetry Ingestion & Raw Payload Inspection" },
  "/detections": { title: "Detections", subtitle: "Hybrid Rule & ML Attack Analysis" },
  "/alerts": { title: "Alerts Queue", subtitle: "Incident Triage & State Management" },
  "/scans": { title: "Vulnerability Scans", subtitle: "Asset Scanning & Target Tracking" },
  "/reports": { title: "Security Reports", subtitle: "Automated Metrics & LLM Executive Intelligence" },
};

interface TopBarProps {
  onOpenCommand: () => void;
}

export function TopBar({ onOpenCommand }: TopBarProps) {
  const location = useLocation();
  const { user, logout } = useAuth();
  const [theme, setTheme] = React.useState<"dark" | "light">(() => {
    return document.documentElement.classList.contains("dark") ? "dark" : "light";
  });

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    if (next === "dark") {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }
  };

  // Find current matching title
  const currentPath = location.pathname;
  let pageInfo = pageTitles[currentPath];
  if (!pageInfo && currentPath.startsWith("/detections/")) {
    pageInfo = {
      title: "Detection Incident",
      subtitle: "Deterministic Rule Analysis & ML Confidence Deep-Dive",
    };
  } else if (!pageInfo) {
    pageInfo = { title: "Console", subtitle: "ThreatLens Security Operations" };
  }

  const roleBadgeStyle = {
    admin: "bg-red-500/10 text-red-400 border-red-500/20",
    analyst: "bg-teal-500/10 text-teal-400 border-teal-500/20",
    viewer: "bg-slate-500/10 text-slate-400 border-slate-500/20",
  }[user?.role || "viewer"];

  const roleIcon = {
    admin: <Shield className="h-3 w-3 text-red-400" />,
    analyst: <UserCheck className="h-3 w-3 text-teal-400" />,
    viewer: <Eye className="h-3 w-3 text-slate-400" />,
  }[user?.role || "viewer"];

  return (
    <header className="h-13 border-b border-border bg-card px-4 flex items-center justify-between shrink-0">
      {/* Title & context */}
      <div className="flex items-center gap-3">
        <div>
          <h1 className="text-xs font-bold text-foreground tracking-tight leading-none">
            {pageInfo.title}
          </h1>
          <span className="text-[11px] font-mono text-muted-foreground hidden sm:inline-block leading-tight mt-0.5">
            {pageInfo.subtitle}
          </span>
        </div>
      </div>

      {/* Global Actions */}
      <div className="flex items-center gap-2">
        {/* Cmd+K Quick search button */}
        <Button
          variant="outline"
          size="sm"
          onClick={onOpenCommand}
          className="h-8 px-2.5 text-xs text-muted-foreground font-mono bg-muted/30 border-border hover:text-foreground hidden sm:flex items-center gap-2"
        >
          <Search className="h-3.5 w-3.5" />
          <span className="text-[11px]">Search or jump to...</span>
          <kbd className="pointer-events-none inline-flex h-4 select-none items-center gap-1 rounded bg-muted px-1.5 font-mono text-[9px] font-medium text-muted-foreground">
            ⌘K
          </kbd>
        </Button>

        {/* Theme toggle */}
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8 text-muted-foreground hover:text-foreground"
          onClick={toggleTheme}
          title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
        >
          {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </Button>

        {/* User profile dropdown */}
        <DropdownMenu>
          <DropdownMenuTrigger
            render={
              <Button
                variant="outline"
                size="sm"
                className="h-8 px-2 text-xs flex items-center gap-2 border-border bg-muted/20"
              />
            }
          >
            <div className="h-5 w-5 rounded-full bg-teal-500/20 text-teal-400 flex items-center justify-center font-mono text-[10px] font-bold">
              {user?.username?.charAt(0).toUpperCase() || "U"}
            </div>
            <span className="font-medium text-foreground max-w-24 truncate text-xs">
              {user?.username || "Guest"}
            </span>
            <span
              className={cn(
                "inline-flex items-center gap-1 rounded px-1.5 py-0.2 text-[10px] font-mono uppercase border",
                roleBadgeStyle,
              )}
            >
              {roleIcon}
              {user?.role || "viewer"}
            </span>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56 text-xs">
            <DropdownMenuLabel>
              <div className="font-semibold text-foreground">{user?.username}</div>
              <div className="text-[11px] font-mono text-muted-foreground truncate">
                {user?.email || "No email"}
              </div>
              <div className="mt-1 flex items-center gap-1.5 text-[10px] font-mono text-muted-foreground">
                <span>Access Level:</span>
                <span className="text-teal-400 uppercase font-semibold">{user?.role}</span>
              </div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={logout} className="text-destructive cursor-pointer gap-2">
              <LogOut className="h-3.5 w-3.5" />
              <span>Log out</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
