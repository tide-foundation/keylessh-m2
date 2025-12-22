import { Component, type ReactNode } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

/**
 * Error boundary that catches React errors and provides recovery options.
 * Specifically handles auth/storage corruption by offering to clear state.
 */
export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error("ErrorBoundary caught error:", error, errorInfo);
  }

  handleClearAndReload = () => {
    // Clear all potentially corrupted state
    try {
      localStorage.removeItem("access_token");
      sessionStorage.clear();
    } catch (e) {
      console.error("Failed to clear storage:", e);
    }
    window.location.href = "/login";
  };

  handleReload = () => {
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-background flex items-center justify-center p-4">
          <div className="max-w-md w-full space-y-6 text-center">
            <div className="mx-auto h-16 w-16 rounded-full bg-destructive/10 flex items-center justify-center">
              <AlertTriangle className="h-8 w-8 text-destructive" />
            </div>

            <div className="space-y-2">
              <h1 className="text-2xl font-semibold">Something went wrong</h1>
              <p className="text-muted-foreground">
                The application encountered an error during initialization.
                This is often caused by stale authentication data.
              </p>
            </div>

            <div className="flex flex-col gap-3">
              <Button onClick={this.handleClearAndReload} className="w-full">
                <RefreshCw className="mr-2 h-4 w-4" />
                Clear session and restart
              </Button>
              <Button variant="outline" onClick={this.handleReload} className="w-full">
                Try again
              </Button>
            </div>

            {this.state.error && (
              <details className="text-left text-xs text-muted-foreground bg-muted p-3 rounded-md">
                <summary className="cursor-pointer">Technical details</summary>
                <pre className="mt-2 whitespace-pre-wrap overflow-auto max-h-32">
                  {this.state.error.message}
                  {"\n"}
                  {this.state.error.stack}
                </pre>
              </details>
            )}
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
