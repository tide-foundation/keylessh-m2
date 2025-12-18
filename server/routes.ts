import type { Express } from "express";
import type { Server } from "http";
import { storage } from "./storage";
import { log } from "./index";
import type { ServerWithAccess, ActiveSession } from "@shared/schema";
import { authenticate, requireAdmin, keycloakAdmin, type AuthenticatedRequest } from "./auth";

// SSH connections are now handled by KeyleSSH via Socket.IO proxy
// See server/index.ts for the proxy configuration

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  app.get("/api/servers", authenticate, async (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;

      let servers;
      if (user.role === "admin") {
        servers = await storage.getServers();
      } else {
        servers = await storage.getServersByIds(user.allowedServers || []);
      }

      const serversWithAccess: ServerWithAccess[] = servers.map((server) => ({
        ...server,
        allowedSshUsers: server.sshUsers || [],
      }));

      res.json(serversWithAccess);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch servers" });
    }
  });

  app.get("/api/servers/:id", authenticate, async (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;
      const server = await storage.getServer(req.params.id);

      if (!server) {
        res.status(404).json({ message: "Server not found" });
        return;
      }

      // Check if user has access to this server (admins have access to all)
      if (user.role !== "admin" && !user.allowedServers.includes(server.id)) {
        res.status(403).json({ message: "Access denied to this server" });
        return;
      }

      const serverWithAccess: ServerWithAccess = {
        ...server,
        allowedSshUsers: server.sshUsers || [],
      };

      res.json(serverWithAccess);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch server" });
    }
  });

  app.get("/api/sessions", authenticate, async (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;
      const sessions = await storage.getSessionsByUserId(user.id);
      const servers = await storage.getServers();

      const activeSessions: ActiveSession[] = sessions.map((session) => {
        const server = servers.find((s) => s.id === session.serverId);
        return {
          ...session,
          serverName: server?.name || "Unknown",
          serverHost: server?.host || "Unknown",
        };
      });

      res.json(activeSessions);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch sessions" });
    }
  });

  app.post("/api/sessions", authenticate, async (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;
      const { serverId, sshUser } = req.body;

      const server = await storage.getServer(serverId);
      if (!server) {
        res.status(404).json({ message: "Server not found" });
        return;
      }

      // Check if user has access to this server
      if (user.role !== "admin" && !user.allowedServers.includes(serverId)) {
        res.status(403).json({ message: "Access denied to this server" });
        return;
      }

      const session = await storage.createSession({
        userId: user.id,
        serverId,
        sshUser,
        status: "active",
      });

      res.json(session);
    } catch (error) {
      res.status(500).json({ message: "Failed to create session" });
    }
  });

  app.delete("/api/sessions/:id", authenticate, async (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;
      const session = await storage.getSession(req.params.id);

      // Only allow ending own sessions (unless admin)
      if (session && user.role !== "admin" && session.userId !== user.id) {
        res.status(403).json({ message: "Access denied" });
        return;
      }

      await storage.endSession(req.params.id);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ message: "Failed to end session" });
    }
  });

  app.get("/api/admin/servers", authenticate, requireAdmin, async (req: AuthenticatedRequest, res) => {
    try {
      const servers = await storage.getServers();
      res.json(servers);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch servers" });
    }
  });

  app.post("/api/admin/servers", authenticate, requireAdmin, async (req: AuthenticatedRequest, res) => {
    try {
      const server = await storage.createServer(req.body);
      res.json(server);
    } catch (error) {
      res.status(500).json({ message: "Failed to create server" });
    }
  });

  app.patch("/api/admin/servers/:id", authenticate, requireAdmin, async (req: AuthenticatedRequest, res) => {
    try {
      const server = await storage.updateServer(req.params.id, req.body);
      if (!server) {
        res.status(404).json({ message: "Server not found" });
        return;
      }
      res.json(server);
    } catch (error) {
      res.status(500).json({ message: "Failed to update server" });
    }
  });

  app.delete("/api/admin/servers/:id", authenticate, requireAdmin, async (req: AuthenticatedRequest, res) => {
    try {
      const success = await storage.deleteServer(req.params.id);
      if (!success) {
        res.status(404).json({ message: "Server not found" });
        return;
      }
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete server" });
    }
  });

  app.get("/api/admin/users", authenticate, requireAdmin, async (req: AuthenticatedRequest, res) => {
    try {
      // Fetch users from Keycloak Admin API
      const users = await keycloakAdmin.getUsers();
      res.json(users);
    } catch (error) {
      log(`Failed to fetch users from Keycloak: ${error}`);
      res.status(500).json({ message: "Failed to fetch users" });
    }
  });

  app.patch("/api/admin/users/:id", authenticate, requireAdmin, async (req: AuthenticatedRequest, res) => {
    try {
      const { role, allowedServers } = req.body;
      const userId = req.params.id;

      // Update user in Keycloak
      if (role !== undefined) {
        await keycloakAdmin.updateUserRole(userId, role);
      }

      if (allowedServers !== undefined) {
        await keycloakAdmin.updateUserAttributes(userId, allowedServers);
      }

      // Fetch updated user
      const user = await keycloakAdmin.getUser(userId);
      if (!user) {
        res.status(404).json({ message: "User not found" });
        return;
      }

      res.json(user);
    } catch (error) {
      log(`Failed to update user in Keycloak: ${error}`);
      res.status(500).json({ message: "Failed to update user" });
    }
  });

  app.get("/api/admin/sessions", authenticate, requireAdmin, async (req: AuthenticatedRequest, res) => {
    try {
      const sessions = await storage.getSessions();
      const servers = await storage.getServers();

      const activeSessions: ActiveSession[] = sessions.map((session) => {
        const server = servers.find((s) => s.id === session.serverId);
        return {
          ...session,
          serverName: server?.name || "Unknown",
          serverHost: server?.host || "Unknown",
        };
      });

      res.json(activeSessions);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch sessions" });
    }
  });

  return httpServer;
}
