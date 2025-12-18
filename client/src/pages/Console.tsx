import { useEffect, useRef, useState, useCallback } from "react";
import { useParams, useSearch } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { io, Socket } from "socket.io-client";
import "@xterm/xterm/css/xterm.css";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import {
  ArrowLeft,
  RefreshCw,
  Power,
  Copy,
  Maximize,
  Minimize,
  Wifi,
  WifiOff,
  Loader2,
} from "lucide-react";
import { Link } from "wouter";
import type { ServerWithAccess, ConnectionStatus } from "@shared/schema";

const statusConfig: Record<ConnectionStatus, { label: string; color: string; icon: typeof Wifi }> = {
  connecting: { label: "Connecting...", color: "bg-chart-4", icon: Loader2 },
  connected: { label: "Connected", color: "bg-chart-2", icon: Wifi },
  disconnected: { label: "Disconnected", color: "bg-muted-foreground", icon: WifiOff },
  error: { label: "Connection Error", color: "bg-destructive", icon: WifiOff },
};

export default function Console() {
  const params = useParams<{ serverId: string }>();
  const search = useSearch();
  const searchParams = new URLSearchParams(search);
  const sshUser = searchParams.get("user") || "root";

  const { toast } = useToast();

  const terminalRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<XTerm | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const socketRef = useRef<Socket | null>(null);

  const [status, setStatus] = useState<ConnectionStatus>("disconnected");
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [sshStatus, setSshStatus] = useState<string>("");

  const { data: server, isLoading: serverLoading } = useQuery<ServerWithAccess>({
    queryKey: ["/api/servers", params.serverId],
  });

  const connectToKeyleSSH = useCallback(() => {
    if (socketRef.current?.connected) {
      socketRef.current.disconnect();
    }

    setStatus("connecting");

    // Connect to KeyleSSH via Socket.IO (proxied through /ssh)
    const socket = io({
      path: "/ssh/socket.io",
      withCredentials: true,
      transports: ["websocket", "polling"],
    });

    socketRef.current = socket;

    // KeyleSSH Socket.IO events
    socket.on("connect", () => {
      setStatus("connected");
      xtermRef.current?.focus();
      // Send initial terminal geometry
      const dims = fitAddonRef.current?.proposeDimensions();
      if (dims) {
        socket.emit("geometry", dims.cols, dims.rows);
      }
    });

    socket.on("data", (data: string) => {
      xtermRef.current?.write(data);
    });

    socket.on("ssherror", (error: string) => {
      setStatus("error");
      toast({
        title: "SSH Error",
        description: error,
        variant: "destructive",
      });
    });

    socket.on("status", (statusMsg: string) => {
      setSshStatus(statusMsg);
    });

    socket.on("menu", () => {
      // KeyleSSH sends this when ready
      console.log("KeyleSSH menu ready");
    });

    socket.on("title", (title: string) => {
      document.title = title;
    });

    socket.on("reauth", () => {
      toast({
        title: "Authentication Required",
        description: "Please re-authenticate to continue",
        variant: "destructive",
      });
      setStatus("error");
    });

    socket.on("disconnect", (reason) => {
      console.log("Socket.IO disconnected:", reason);
      if (status === "connected") {
        setStatus("disconnected");
      }
    });

    socket.on("connect_error", (error) => {
      console.error("Socket.IO connection error:", error);
      setStatus("error");
      toast({
        title: "Connection error",
        description: "Failed to connect to KeyleSSH",
        variant: "destructive",
      });
    });
  }, [status, toast]);

  // Initialize KeyleSSH session with server credentials
  const initKeyleSSHSession = useCallback(async () => {
    if (!server) return;

    try {
      // Make a request to /ssh/ to set up the KeyleSSH session
      // This sets session.ssh with host/port and gets credentials
      const response = await fetch(`/ssh/?port=${server.port}`, {
        credentials: "include",
        headers: {
          // KeyleSSH uses basic auth or session-based auth
          // The host is configured in KeyleSSH's config.json
        },
      });

      if (response.ok) {
        // Session is set up, now connect via Socket.IO
        connectToKeyleSSH();
      } else {
        toast({
          title: "Session setup failed",
          description: "Failed to initialize SSH session",
          variant: "destructive",
        });
        setStatus("error");
      }
    } catch (error) {
      console.error("Failed to initialize KeyleSSH session:", error);
      toast({
        title: "Connection failed",
        description: "Failed to connect to KeyleSSH",
        variant: "destructive",
      });
      setStatus("error");
    }
  }, [server, connectToKeyleSSH, toast]);

  const handleReconnect = useCallback(() => {
    initKeyleSSHSession();
  }, [initKeyleSSHSession]);

  const handleDisconnect = useCallback(() => {
    socketRef.current?.disconnect();
    setStatus("disconnected");
  }, []);

  const handleCopy = useCallback(() => {
    const selection = xtermRef.current?.getSelection();
    if (selection) {
      navigator.clipboard.writeText(selection);
      toast({ title: "Copied to clipboard" });
    }
  }, [toast]);

  const toggleFullscreen = useCallback(() => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen();
      setIsFullscreen(true);
    } else {
      document.exitFullscreen();
      setIsFullscreen(false);
    }
  }, []);

  useEffect(() => {
    if (!terminalRef.current || xtermRef.current) return;

    const term = new XTerm({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
      theme: {
        background: "#0c0c0c",
        foreground: "#d4d4d4",
        cursor: "#d4d4d4",
        cursorAccent: "#0c0c0c",
        selectionBackground: "#264f78",
        black: "#0c0c0c",
        red: "#cd3131",
        green: "#0dbc79",
        yellow: "#e5e510",
        blue: "#2472c8",
        magenta: "#bc3fbc",
        cyan: "#11a8cd",
        white: "#e5e5e5",
        brightBlack: "#666666",
        brightRed: "#f14c4c",
        brightGreen: "#23d18b",
        brightYellow: "#f5f543",
        brightBlue: "#3b8eea",
        brightMagenta: "#d670d6",
        brightCyan: "#29b8db",
        brightWhite: "#e5e5e5",
      },
      allowProposedApi: true,
    });

    const fitAddon = new FitAddon();
    const webLinksAddon = new WebLinksAddon();

    term.loadAddon(fitAddon);
    term.loadAddon(webLinksAddon);

    term.open(terminalRef.current);
    fitAddon.fit();

    xtermRef.current = term;
    fitAddonRef.current = fitAddon;

    // Send terminal input to KeyleSSH via Socket.IO
    term.onData((data) => {
      if (socketRef.current?.connected) {
        socketRef.current.emit("data", data);
      }
    });

    const handleResize = () => {
      fitAddon.fit();
      // Send resize event to KeyleSSH
      if (socketRef.current?.connected) {
        const dims = fitAddon.proposeDimensions();
        if (dims) {
          socketRef.current.emit("resize", { rows: dims.rows, cols: dims.cols });
        }
      }
    };

    const resizeObserver = new ResizeObserver(handleResize);
    resizeObserver.observe(terminalRef.current);
    window.addEventListener("resize", handleResize);

    return () => {
      resizeObserver.disconnect();
      window.removeEventListener("resize", handleResize);
      term.dispose();
      xtermRef.current = null;
      socketRef.current?.disconnect();
    };
  }, []);

  // Auto-connect when server data is loaded
  useEffect(() => {
    if (server && status === "disconnected") {
      // Initialize KeyleSSH session first, then connect
      initKeyleSSHSession();
    }
  }, [server, status, initKeyleSSHSession]);

  const StatusIcon = statusConfig[status].icon;

  if (serverLoading) {
    return (
      <div className="h-full flex flex-col">
        <div className="h-12 px-4 flex items-center justify-between border-b border-border">
          <div className="flex items-center gap-4">
            <Skeleton className="h-8 w-8" />
            <Skeleton className="h-4 w-48" />
          </div>
          <Skeleton className="h-6 w-24" />
        </div>
        <div className="flex-1 bg-[#0c0c0c] flex items-center justify-center">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <div className="h-12 px-4 flex items-center justify-between border-b border-border bg-background shrink-0">
        <div className="flex items-center gap-4">
          <Link href="/app">
            <Button size="icon" variant="ghost" data-testid="back-button">
              <ArrowLeft className="h-4 w-4" />
            </Button>
          </Link>
          <div className="flex items-center gap-2">
            <span className="font-medium">{server?.name}</span>
            <span className="text-muted-foreground font-mono text-sm">
              {sshUser}@{server?.host}:{server?.port}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Badge
            variant={status === "connected" ? "default" : "secondary"}
            className="gap-1.5"
            data-testid="connection-status"
          >
            <StatusIcon className={`h-3 w-3 ${status === "connecting" ? "animate-spin" : ""}`} />
            {statusConfig[status].label}
          </Badge>

          <div className="flex items-center gap-1 ml-2">
            <Button
              size="icon"
              variant="ghost"
              onClick={handleCopy}
              title="Copy selection"
              data-testid="copy-button"
            >
              <Copy className="h-4 w-4" />
            </Button>
            <Button
              size="icon"
              variant="ghost"
              onClick={toggleFullscreen}
              title={isFullscreen ? "Exit fullscreen" : "Fullscreen"}
              data-testid="fullscreen-button"
            >
              {isFullscreen ? <Minimize className="h-4 w-4" /> : <Maximize className="h-4 w-4" />}
            </Button>
            {status !== "connected" && (
              <Button
                size="icon"
                variant="ghost"
                onClick={handleReconnect}
                disabled={status === "connecting"}
                title="Reconnect"
                data-testid="reconnect-button"
              >
                <RefreshCw className={`h-4 w-4 ${status === "connecting" ? "animate-spin" : ""}`} />
              </Button>
            )}
            {status === "connected" && (
              <Button
                size="icon"
                variant="ghost"
                onClick={handleDisconnect}
                title="Disconnect"
                data-testid="disconnect-button"
              >
                <Power className="h-4 w-4" />
              </Button>
            )}
          </div>
        </div>
      </div>

      <div className="flex-1 bg-[#0c0c0c] overflow-hidden relative">
        <div ref={terminalRef} className="absolute inset-0" data-testid="terminal-container" />
        
        {status === "error" && (
          <div className="absolute inset-0 flex items-center justify-center bg-background/80">
            <div className="text-center space-y-4">
              <WifiOff className="h-12 w-12 text-destructive mx-auto" />
              <div>
                <h3 className="font-medium">Connection Failed</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Unable to connect to {server?.name}
                </p>
              </div>
              <Button onClick={handleReconnect} data-testid="retry-button">
                <RefreshCw className="h-4 w-4 mr-2" />
                Try Again
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
