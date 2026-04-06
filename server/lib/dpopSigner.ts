/**
 * Server-side DPoP proof requester.
 *
 * Maintains WebSocket connections to browsers. When the server needs to call
 * TideCloak with DPoP, it asks the connected browser to sign a proof for the
 * specific URL + method, waits for the response, then uses it.
 *
 * Flow:
 *   Server needs proof → WS message to browser → browser signs → WS response → server uses proof
 */

import { WebSocketServer, WebSocket } from "ws";
import type { Server as HTTPServer } from "http";
import crypto from "crypto";
import { verifyTideCloakToken } from "./auth/tideJWT";

// Connected signers keyed by user ID
const signers = new Map<string, WebSocket>();

// Pending proof requests keyed by request ID
const pendingRequests = new Map<string, {
  resolve: (proof: string) => void;
  reject: (err: Error) => void;
  timer: NodeJS.Timeout;
}>();

/**
 * Set up the DPoP signer WebSocket endpoint.
 * Browsers connect here after login to act as signing oracles.
 */
export function setupDPoPSigner(httpServer: HTTPServer): void {
  const wss = new WebSocketServer({ server: httpServer, path: "/ws/dpop-signer" });

  wss.on("connection", (ws: WebSocket) => {
    let userId: string | null = null;
    let authenticated = false;

    // 10 second auth timeout
    const authTimeout = setTimeout(() => {
      if (!authenticated) {
        ws.close(4001, "Auth timeout");
      }
    }, 10000);

    ws.on("message", async (data) => {
      try {
        const msg = JSON.parse(data.toString());

        // First message must be auth
        if (!authenticated) {
          if (msg.type === "auth" && msg.token) {
            const payload = await verifyTideCloakToken(msg.token, []);
            if (!payload?.sub) {
              ws.close(4002, "Invalid token");
              return;
            }

            userId = payload.sub;
            authenticated = true;
            clearTimeout(authTimeout);

            // Close existing connection for this user
            const existing = signers.get(userId);
            if (existing && existing.readyState === WebSocket.OPEN) {
              existing.close(4003, "Replaced by new connection");
            }

            signers.set(userId, ws);
            console.log(`[DPoP-Signer] User ${payload.preferred_username || userId} connected`);
          } else {
            ws.close(4001, "Auth required");
          }
          return;
        }

        // Authenticated — handle proof responses
        if (msg.type === "dpop_proof" && msg.requestId && msg.proof) {
          const pending = pendingRequests.get(msg.requestId);
          if (pending) {
            clearTimeout(pending.timer);
            pendingRequests.delete(msg.requestId);
            pending.resolve(msg.proof);
          }
        } else if (msg.type === "dpop_error" && msg.requestId) {
          const pending = pendingRequests.get(msg.requestId);
          if (pending) {
            clearTimeout(pending.timer);
            pendingRequests.delete(msg.requestId);
            pending.reject(new Error(msg.error || "DPoP signing failed"));
          }
        }
      } catch {
        // Ignore malformed messages
      }
    });

    ws.on("close", () => {
      clearTimeout(authTimeout);
      if (userId && signers.get(userId) === ws) {
        signers.delete(userId);
        console.log(`[DPoP-Signer] User ${userId} disconnected`);
      }
    });

    ws.on("error", () => {
      if (userId && signers.get(userId) === ws) {
        signers.delete(userId);
      }
    });
  });
}

/**
 * Request a DPoP proof from the browser for a specific TideCloak URL.
 *
 * @param userId - The authenticated user's sub claim
 * @param url - TideCloak URL to sign for (htu)
 * @param method - HTTP method (htm)
 * @param timeoutMs - How long to wait for the proof (default 5s)
 * @returns The signed DPoP proof JWT, or undefined if signer unavailable
 */
export async function requestDPoPProof(
  userId: string,
  url: string,
  method: string,
  timeoutMs = 5000,
): Promise<string | undefined> {
  const ws = signers.get(userId);
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return undefined; // No signer connected — fallback to Bearer
  }

  const requestId = crypto.randomUUID();

  return new Promise<string | undefined>((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingRequests.delete(requestId);
      resolve(undefined); // Timeout — fallback to Bearer
    }, timeoutMs);

    pendingRequests.set(requestId, {
      resolve: (proof) => resolve(proof),
      reject,
      timer,
    });

    // Ask the browser to sign
    ws.send(JSON.stringify({
      type: "dpop_request",
      requestId,
      url,
      method: method.toUpperCase(),
    }));
  });
}

/**
 * Check if a DPoP signer is connected for a user.
 */
export function hasSignerConnected(userId: string): boolean {
  const ws = signers.get(userId);
  return !!ws && ws.readyState === WebSocket.OPEN;
}
