import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface CodeBlockProps {
  code: string | object;
  className?: string;
  maxHeight?: string;
  title?: string;
}

export function CodeBlock({ code, className, maxHeight = "max-h-96", title }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  const formatted =
    typeof code === "string"
      ? code
      : JSON.stringify(code, null, 2);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(formatted);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
    }
  };

  return (
    <div className={cn("relative rounded-md border border-border bg-card overflow-hidden", className)}>
      {title && (
        <div className="flex items-center justify-between border-b border-border px-3 py-1.5 bg-muted/30">
          <span className="text-xs font-mono font-medium text-muted-foreground">{title}</span>
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6 text-muted-foreground hover:text-foreground"
            onClick={handleCopy}
            title="Copy code"
          >
            {copied ? <Check className="h-3 w-3 text-teal-500" /> : <Copy className="h-3 w-3" />}
          </Button>
        </div>
      )}
      {!title && (
        <Button
          variant="ghost"
          size="icon"
          className="absolute right-2 top-2 h-6 w-6 text-muted-foreground hover:text-foreground z-10 bg-card/80 backdrop-blur-xs"
          onClick={handleCopy}
          title="Copy code"
        >
          {copied ? <Check className="h-3 w-3 text-teal-500" /> : <Copy className="h-3 w-3" />}
        </Button>
      )}
      <pre
        className={cn(
          "overflow-x-auto p-3 text-xs font-mono leading-relaxed text-foreground select-text",
          maxHeight,
        )}
      >
        <code>{formatted}</code>
      </pre>
    </div>
  );
}
