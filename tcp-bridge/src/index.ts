import { createServer } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { Socket, connect } from "net";
import { createHmac } from "crypto";

const PORT = parseInt(process.env.PORT || "8080");
const BRIDGE_SECRET = process.env.BRIDGE_SECRET || "change-me-in-production";

// Session token structure (signed by main server)
interface SessionToken {
  host: string;
  port: number;
  serverId: string;
  userId: string;
  exp: number;
}

// Verify and decode session token
function verifySessionToken(token: string): SessionToken | null {
  try {
    const [payload, signature] = token.split(".");
    if (!payload || !signature) return null;

    // Verify signature
    const expectedSig = createHmac("sha256", BRIDGE_SECRET)
      .update(payload)
      .digest("base64url");

    if (signature !== expectedSig) {
      console.log("[Bridge] Invalid token signature");
      return null;
    }

    const decoded = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf-8")
    );

    // Check expiration
    if (decoded.exp < Date.now()) {
      console.log("[Bridge] Token expired");
      return null;
    }

    return decoded as SessionToken;
  } catch (err) {
    console.log("[Bridge] Token decode error:", err);
    return null;
  }
}

// Create HTTP server
const server = createServer((req, res) => {
  // Health check endpoint
  if (req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", connections: activeConnections }));
    return;
  }

  res.writeHead(404);
  res.end("Not found");
});

// Track active connections for metrics
let activeConnections = 0;

// WebSocket server
const wss = new WebSocketServer({ server });

wss.on("connection", (ws: WebSocket, req) => {
  const url = new URL(req.url || "/", `http://${req.headers.host}`);
  const token = url.searchParams.get("token");

  if (!token) {
    console.log("[Bridge] No token provided");
    ws.close(4001, "Missing token");
    return;
  }

  // Verify session token
  const session = verifySessionToken(token);
  if (!session) {
    ws.close(4002, "Invalid token");
    return;
  }

  console.log(
    `[Bridge] New connection: ${session.userId} -> ${session.host}:${session.port}`
  );
  activeConnections++;

  // Open TCP connection to SSH server
  const tcpSocket: Socket = connect({
    host: session.host,
    port: session.port,
  });

  let tcpConnected = false;

  tcpSocket.on("connect", () => {
    tcpConnected = true;
    console.log(`[Bridge] TCP connected to ${session.host}:${session.port}`);

    // Send connected confirmation
    ws.send(JSON.stringify({ type: "connected" }));
  });

  tcpSocket.on("data", (data: Buffer) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(data);
    }
  });

  tcpSocket.on("error", (err: Error) => {
    console.log(`[Bridge] TCP error: ${err.message}`);
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: "error", message: err.message }));
      ws.close(4003, "TCP error");
    }
  });

  tcpSocket.on("close", () => {
    console.log("[Bridge] TCP closed");
    if (ws.readyState === WebSocket.OPEN) {
      ws.close(1000, "TCP closed");
    }
  });

  // Handle WebSocket messages (forward to TCP)
  ws.on("message", (data: Buffer) => {
    if (tcpConnected && !tcpSocket.destroyed) {
      tcpSocket.write(data);
    }
  });

  ws.on("close", () => {
    console.log("[Bridge] WebSocket closed");
    activeConnections--;
    if (!tcpSocket.destroyed) {
      tcpSocket.destroy();
    }
  });

  ws.on("error", (err: Error) => {
    console.log(`[Bridge] WebSocket error: ${err.message}`);
    if (!tcpSocket.destroyed) {
      tcpSocket.destroy();
    }
  });
});

server.listen(PORT, () => {
  console.log(`[Bridge] TCP Bridge listening on port ${PORT}`);
  console.log(`[Bridge] Health check: http://localhost:${PORT}/health`);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("[Bridge] Shutting down...");
  wss.clients.forEach((client) => {
    client.close(1001, "Server shutting down");
  });
  server.close(() => {
    console.log("[Bridge] Shutdown complete");
    process.exit(0);
  });
});
