import { createServer } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { Socket, connect } from "net";
import { jwtVerify, createLocalJWKSet, JWTPayload } from "jose";
import { readFileSync } from "fs";
import { join } from "path";

const PORT = parseInt(process.env.PORT || "8080");
const CONFIG_PATH = process.env.TIDECLOAK_CONFIG_PATH || join(process.cwd(), "data", "tidecloak.json");
const CONFIG_B64 = process.env.TIDECLOAK_CONFIG_B64; // Base64-encoded config (for Azure deployment)

// Load TideCloak config with JWKS
interface TidecloakConfig {
  realm: string;
  "auth-server-url": string;
  resource: string;
  jwk: {
    keys: Array<{
      kid: string;
      kty: string;
      alg: string;
      use: string;
      crv: string;
      x: string;
    }>;
  };
}

let tcConfig: TidecloakConfig | null = null;
let JWKS: ReturnType<typeof createLocalJWKSet> | null = null;

function loadConfig(): boolean {
  try {
    let configData: string;

    // Try base64-encoded env var first (for Azure deployment)
    if (CONFIG_B64) {
      configData = Buffer.from(CONFIG_B64, "base64").toString("utf-8");
      console.log("[Bridge] Loading JWKS from TIDECLOAK_CONFIG_B64 env var");
    } else {
      // Fall back to file path
      configData = readFileSync(CONFIG_PATH, "utf-8");
      console.log(`[Bridge] Loading JWKS from ${CONFIG_PATH}`);
    }

    tcConfig = JSON.parse(configData) as TidecloakConfig;

    if (!tcConfig.jwk || !tcConfig.jwk.keys || tcConfig.jwk.keys.length === 0) {
      console.error("[Bridge] No JWKS keys found in config");
      return false;
    }

    JWKS = createLocalJWKSet(tcConfig.jwk);
    console.log("[Bridge] JWKS loaded successfully");
    return true;
  } catch (err) {
    console.error("[Bridge] Failed to load config:", err);
    return false;
  }
}

// Verify JWT against JWKS
async function verifyToken(token: string): Promise<JWTPayload | null> {
  if (!JWKS || !tcConfig) {
    console.error("[Bridge] JWKS not initialized");
    return null;
  }

  try {
    const issuer = tcConfig["auth-server-url"].endsWith("/")
      ? `${tcConfig["auth-server-url"]}realms/${tcConfig.realm}`
      : `${tcConfig["auth-server-url"]}/realms/${tcConfig.realm}`;

    const { payload } = await jwtVerify(token, JWKS, {
      issuer,
    });

    // Check azp (authorized party) matches our resource
    if (payload.azp !== tcConfig.resource) {
      console.log(`[Bridge] AZP mismatch: expected ${tcConfig.resource}, got ${payload.azp}`);
      return null;
    }

    return payload;
  } catch (err) {
    console.log("[Bridge] JWT verification failed:", err);
    return null;
  }
}

// Load config on startup
if (!loadConfig()) {
  console.error("[Bridge] Failed to load TideCloak config. Exiting.");
  process.exit(1);
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

wss.on("connection", async (ws: WebSocket, req) => {
  const url = new URL(req.url || "/", `http://${req.headers.host}`);
  const token = url.searchParams.get("token");
  const host = url.searchParams.get("host");
  const port = parseInt(url.searchParams.get("port") || "22", 10);
  const serverId = url.searchParams.get("serverId");

  if (!token) {
    console.log("[Bridge] No token provided");
    ws.close(4001, "Missing token");
    return;
  }

  if (!host || !serverId) {
    console.log("[Bridge] Missing host or serverId");
    ws.close(4000, "Missing required parameters");
    return;
  }

  // Verify JWT
  const payload = await verifyToken(token);
  if (!payload) {
    ws.close(4002, "Invalid token");
    return;
  }

  const userId = payload.sub || "unknown";

  console.log(
    `[Bridge] New connection: ${userId} -> ${host}:${port}`
  );
  activeConnections++;

  // Open TCP connection to SSH server
  const tcpSocket: Socket = connect({
    host,
    port,
  });

  let tcpConnected = false;

  tcpSocket.on("connect", () => {
    tcpConnected = true;
    console.log(`[Bridge] TCP connected to ${host}:${port}`);

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
