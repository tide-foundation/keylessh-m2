import { Button } from "@/components/ui/button";
import { RefreshCw } from "lucide-react";

export function RefreshButton({
  onClick,
  isRefreshing,
  secondsRemaining,
  disabled,
  "data-testid": dataTestId,
  title,
}: {
  onClick: () => void;
  isRefreshing: boolean;
  secondsRemaining: number | null;
  disabled?: boolean;
  "data-testid"?: string;
  title?: string;
}) {
  const label = isRefreshing ? "Refreshing..." : "Refresh";
  const subtitle = secondsRemaining !== null ? `Auto refresh in ${secondsRemaining}s` : null;

  return (
    <Button
      variant="outline"
      onClick={onClick}
      disabled={disabled || isRefreshing}
      data-testid={dataTestId}
      title={title || (subtitle ? `${label}. ${subtitle}` : label)}
      className="gap-2"
    >
      <RefreshCw className={`h-4 w-4 ${isRefreshing ? "animate-spin" : ""}`} />
      <span className="flex items-baseline gap-2">
        <span>{label}</span>
        {subtitle && (
          <span className="hidden sm:inline text-xs text-muted-foreground">
            {subtitle}
          </span>
        )}
      </span>
    </Button>
  );
}

