import { WebSocketServer, WebSocket } from "ws";
import { createConnection, Socket } from "net";
import type { Server, IncomingMessage } from "http";
import type { Duplex } from "stream";
import { log } from "./index";

interface ConnectionInfo {
  ws: WebSocket;
  tcp: Socket | null;
  host: string;
  port: number;
}

const connections = new Map<WebSocket, ConnectionInfo>();

// JWT payload interface
interface JWTPayload {
  sub: string;
  exp: number;
  allowed_servers?: string[];
  realm_access?: { roles: string[] };
  resource_access?: { [client: string]: { roles: string[] } };
}

// Decode JWT without verification (same as auth.ts)
function decodeJWT(token: string): JWTPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const payload = Buffer.from(parts[1], "base64url").toString("utf-8");
    return JSON.parse(payload);
  } catch {
    return null;
  }
}

// Extract token from request (Authorization header or query param)
function extractToken(req: IncomingMessage): string | null {
  // Try Authorization header
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Bearer ")) {
    return authHeader.substring(7);
  }

  // Try query parameter
  const url = new URL(req.url || "", `http://${req.headers.host}`);
  const token = url.searchParams.get("token");
  if (token) {
    return token;
  }

  return null;
}

// TideCloak role names - tide-realm-admin is a client role under realm-management
const ADMIN_ROLE = "tide-realm-admin";
const REALM_MANAGEMENT_CLIENT = "realm-management";

// Validate user access to server
function validateAccess(payload: JWTPayload, serverId: string): boolean {
  // Check expiration
  if (payload.exp * 1000 < Date.now()) {
    return false;
  }

  // Check for admin role in realm-management client roles or realm roles
  const clientRoles = payload.resource_access?.[REALM_MANAGEMENT_CLIENT]?.roles || [];
  const realmRoles = payload.realm_access?.roles || [];
  const isAdmin = clientRoles.includes(ADMIN_ROLE) || realmRoles.includes(ADMIN_ROLE);

  // Admins have access to all servers
  if (isAdmin) {
    return true;
  }

  // Check allowed servers
  const allowedServers = payload.allowed_servers || [];
  return allowedServers.includes(serverId);
}

export function setupWSBridge(httpServer: Server): WebSocketServer {
  const wss = new WebSocketServer({
    noServer: true,
  });

  // Handle upgrade requests only for /ws/tcp path
  httpServer.on("upgrade", (request: IncomingMessage, socket: Duplex, head: Buffer) => {
    const url = new URL(request.url || "", `http://${request.headers.host}`);

    // Only handle /ws/tcp path, let other WebSocket connections (like Vite HMR) pass through
    if (url.pathname === "/ws/tcp") {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit("connection", ws, request);
      });
    }
    // Don't close the socket for other paths - let Vite or other handlers deal with them
  });

  wss.on("connection", (ws: WebSocket, req: IncomingMessage) => {
    const url = new URL(req.url || "", `http://${req.headers.host}`);
    const host = url.searchParams.get("host");
    const port = parseInt(url.searchParams.get("port") || "22", 10);
    const serverId = url.searchParams.get("serverId");

    // Validate required parameters
    if (!host || !serverId) {
      log("WebSocket connection rejected: missing host or serverId");
      ws.close(4000, "Missing required parameters: host, serverId");
      return;
    }

    // Validate JWT token
    const token = extractToken(req);
    if (!token) {
      log("WebSocket connection rejected: no token");
      ws.close(4001, "Authentication required");
      return;
    }

    const payload = decodeJWT(token);
    if (!payload) {
      log("WebSocket connection rejected: invalid token");
      ws.close(4001, "Invalid token");
      return;
    }

    // Check access permissions
    if (!validateAccess(payload, serverId)) {
      log(`WebSocket connection rejected: access denied to server ${serverId}`);
      ws.close(4003, "Access denied to this server");
      return;
    }

    log(`WebSocket TCP bridge: connecting to ${host}:${port} for user ${payload.sub}`);

    // Create TCP connection to target
    const tcp = createConnection({ host, port }, () => {
      log(`TCP connected to ${host}:${port}`);
      // Notify client that TCP connection is established
      ws.send(JSON.stringify({ type: "connected" }));
    });

    // Store connection info
    connections.set(ws, { ws, tcp, host, port });

    // Handle TCP data -> WebSocket
    tcp.on("data", (data: Buffer) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(data);
      }
    });

    // Handle TCP errors
    tcp.on("error", (err: Error) => {
      log(`TCP error for ${host}:${port}: ${err.message}`);
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "error", message: err.message }));
        ws.close(4002, `TCP error: ${err.message}`);
      }
    });

    // Handle TCP close
    tcp.on("close", () => {
      log(`TCP closed for ${host}:${port}`);
      if (ws.readyState === WebSocket.OPEN) {
        ws.close(1000, "TCP connection closed");
      }
      connections.delete(ws);
    });

    // Handle WebSocket messages -> TCP
    ws.on("message", (data: Buffer | string) => {
      const conn = connections.get(ws);
      if (conn?.tcp && !conn.tcp.destroyed) {
        // Forward binary data to TCP
        if (Buffer.isBuffer(data)) {
          conn.tcp.write(data);
        } else if (typeof data === "string") {
          // Check if it's a control message (JSON)
          try {
            const msg = JSON.parse(data);
            // Handle control messages if needed
            if (msg.type === "ping") {
              ws.send(JSON.stringify({ type: "pong" }));
              return;
            }
          } catch {
            // Not JSON, treat as raw data
          }
          conn.tcp.write(data);
        }
      }
    });

    // Handle WebSocket close
    ws.on("close", () => {
      const conn = connections.get(ws);
      if (conn?.tcp) {
        conn.tcp.destroy();
      }
      connections.delete(ws);
      log(`WebSocket closed for ${host}:${port}`);
    });

    // Handle WebSocket errors
    ws.on("error", (err: Error) => {
      log(`WebSocket error for ${host}:${port}: ${err.message}`);
      const conn = connections.get(ws);
      if (conn?.tcp) {
        conn.tcp.destroy();
      }
      connections.delete(ws);
    });
  });

  log("WebSocket TCP bridge initialized on /ws/tcp");
  return wss;
}
