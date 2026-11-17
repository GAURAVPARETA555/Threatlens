import * as React from "react";
import { useNavigate } from "react-router-dom";
import {
  LayoutDashboard,
  Radio,
  Crosshair,
  BellRing,
  ScanSearch,
  FileText,
  PlusCircle,
  FileSearch,
} from "lucide-react";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";

interface CommandMenuProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onOpenIngestModal?: () => void;
  onOpenScanModal?: () => void;
}

export function CommandMenu({
  open,
  onOpenChange,
  onOpenIngestModal,
  onOpenScanModal,
}: CommandMenuProps) {
  const navigate = useNavigate();

  React.useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        onOpenChange(!open);
      }
    };
    document.addEventListener("keydown", down);
    return () => document.removeEventListener("keydown", down);
  }, [open, onOpenChange]);

  const runCommand = React.useCallback(
    (command: () => void) => {
      onOpenChange(false);
      command();
    },
    [onOpenChange],
  );

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange}>
      <CommandInput placeholder="Type a command or search..." className="text-xs font-mono" />
      <CommandList className="text-xs">
        <CommandEmpty>No results found.</CommandEmpty>
        
        <CommandGroup heading="Navigation">
          <CommandItem onSelect={() => runCommand(() => navigate("/"))}>
            <LayoutDashboard className="mr-2 h-4 w-4" />
            <span>Overview Dashboard</span>
          </CommandItem>
          <CommandItem onSelect={() => runCommand(() => navigate("/events"))}>
            <Radio className="mr-2 h-4 w-4" />
            <span>Security Events Telemetry</span>
          </CommandItem>
          <CommandItem onSelect={() => runCommand(() => navigate("/detections"))}>
            <Crosshair className="mr-2 h-4 w-4" />
            <span>Threat Detections</span>
          </CommandItem>
          <CommandItem onSelect={() => runCommand(() => navigate("/alerts"))}>
            <BellRing className="mr-2 h-4 w-4" />
            <span>Alerts Triage Queue</span>
          </CommandItem>
          <CommandItem onSelect={() => runCommand(() => navigate("/scans"))}>
            <ScanSearch className="mr-2 h-4 w-4" />
            <span>Vulnerability Scans</span>
          </CommandItem>
          <CommandItem onSelect={() => runCommand(() => navigate("/reports"))}>
            <FileText className="mr-2 h-4 w-4" />
            <span>Executive & AI Reports</span>
          </CommandItem>
        </CommandGroup>

        <CommandGroup heading="Actions">
          <CommandItem
            onSelect={() =>
              runCommand(() => {
                if (onOpenIngestModal) onOpenIngestModal();
                else navigate("/events");
              })
            }
          >
            <PlusCircle className="mr-2 h-4 w-4 text-teal-400" />
            <span>Ingest Telemetry Event...</span>
          </CommandItem>
          <CommandItem
            onSelect={() =>
              runCommand(() => {
                if (onOpenScanModal) onOpenScanModal();
                else navigate("/scans");
              })
            }
          >
            <FileSearch className="mr-2 h-4 w-4 text-teal-400" />
            <span>Initiate Asset Scan...</span>
          </CommandItem>
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  );
}
