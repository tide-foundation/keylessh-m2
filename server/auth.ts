import type { Request, Response, NextFunction } from "express";
import type { OIDCUser, UserRole } from "@shared/schema";

// TideCloak/Keycloak configuration
const KEYCLOAK_URL = process.env.KEYCLOAK_URL || "https://staging.dauth.me";
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM || "keylessh";

// Extended Request interface with user information
export interface AuthenticatedRequest extends Request {
  user?: OIDCUser;
  accessToken?: string;
}

// JWT payload structure from TideCloak/Keycloak
interface JWTPayload {
  sub: string;
  preferred_username?: string;
  name?: string;
  email?: string;
  realm_access?: {
    roles: string[];
  };
  resource_access?: {
    [client: string]: {
      roles: string[];
    };
  };
  allowed_servers?: string[];
  exp: number;
  iat: number;
}

// Decode JWT without verification (TideCloak handles verification on client)
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

// TideCloak role names - tide-realm-admin is a client role under realm-management
const ADMIN_ROLE = "tide-realm-admin";
const REALM_MANAGEMENT_CLIENT = "realm-management";

// Extract user from JWT payload
function extractUserFromPayload(payload: JWTPayload): OIDCUser {
  // Check for admin role in realm-management client roles
  const clientRoles = payload.resource_access?.[REALM_MANAGEMENT_CLIENT]?.roles || [];
  const realmRoles = payload.realm_access?.roles || [];

  // Check both locations for backwards compatibility
  const isAdmin = clientRoles.includes(ADMIN_ROLE) || realmRoles.includes(ADMIN_ROLE);

  return {
    id: payload.sub,
    username: payload.preferred_username || payload.name || "",
    email: payload.email || "",
    role: isAdmin ? "admin" : "user" as UserRole,
    allowedServers: payload.allowed_servers || [],
  };
}

// Middleware to authenticate requests using JWT
export function authenticate(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ message: "Authentication required" });
    return;
  }

  const token = authHeader.substring(7);
  const payload = decodeJWT(token);

  if (!payload) {
    res.status(401).json({ message: "Invalid token format" });
    return;
  }

  // Check token expiration
  if (payload.exp * 1000 < Date.now()) {
    res.status(401).json({ message: "Token expired" });
    return;
  }

  req.user = extractUserFromPayload(payload);
  req.accessToken = token;
  next();
}

// Middleware to require admin role
export function requireAdmin(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  if (!req.user) {
    res.status(401).json({ message: "Authentication required" });
    return;
  }

  if (req.user.role !== "admin") {
    res.status(403).json({ message: "Admin access required" });
    return;
  }

  next();
}

// Keycloak Admin API client - uses the logged-in user's token
export class KeycloakAdmin {
  private baseUrl: string;
  private realm: string;

  constructor() {
    this.baseUrl = KEYCLOAK_URL;
    this.realm = KEYCLOAK_REALM;
  }

  // Get all users from Keycloak using the user's token
  async getUsers(token: string): Promise<OIDCUser[]> {
    const url = `${this.baseUrl}/admin/realms/${this.realm}/users`;

    console.log(`[KeycloakAdmin] Fetching users from: ${url}`);
    console.log(`[KeycloakAdmin] Using user's access token (first 20 chars): ${token.substring(0, 20)}...`);

    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`[KeycloakAdmin] Failed to fetch users: ${response.status} - ${errorText}`);
      throw new Error(`Failed to fetch users: ${response.status} - ${errorText}`);
    }

    const keycloakUsers = await response.json();

    // Transform Keycloak users to our OIDCUser format
    const users: OIDCUser[] = await Promise.all(
      keycloakUsers.map(async (kcUser: any) => {
        const roles = await this.getUserRoles(token, kcUser.id);
        const attributes = kcUser.attributes || {};

        return {
          id: kcUser.id,
          username: kcUser.username || "",
          email: kcUser.email || "",
          role: roles.includes(ADMIN_ROLE) ? "admin" : "user" as UserRole,
          allowedServers: attributes.allowed_servers || [],
        };
      })
    );

    return users;
  }

  // Get a single user by ID
  async getUser(token: string, userId: string): Promise<OIDCUser | null> {
    const url = `${this.baseUrl}/admin/realms/${this.realm}/users/${userId}`;

    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (response.status === 404) {
      return null;
    }

    if (!response.ok) {
      throw new Error(`Failed to fetch user: ${response.status}`);
    }

    const kcUser = await response.json();
    const roles = await this.getUserRoles(token, userId);
    const attributes = kcUser.attributes || {};

    return {
      id: kcUser.id,
      username: kcUser.username || "",
      email: kcUser.email || "",
      role: roles.includes(ADMIN_ROLE) ? "admin" : "user" as UserRole,
      allowedServers: attributes.allowed_servers || [],
    };
  }

  // Get user's roles (both realm and client roles)
  private async getUserRoles(token: string, userId: string): Promise<string[]> {
    const allRoles: string[] = [];

    // Get realm roles
    const realmRolesUrl = `${this.baseUrl}/admin/realms/${this.realm}/users/${userId}/role-mappings/realm`;
    const realmResponse = await fetch(realmRolesUrl, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (realmResponse.ok) {
      const realmRoles = await realmResponse.json();
      allRoles.push(...realmRoles.map((r: any) => r.name));
    }

    // Get client roles from realm-management
    // First, get the realm-management client ID
    const clientsUrl = `${this.baseUrl}/admin/realms/${this.realm}/clients?clientId=realm-management`;
    const clientsResponse = await fetch(clientsUrl, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (clientsResponse.ok) {
      const clients = await clientsResponse.json();
      if (clients.length > 0) {
        const realmManagementId = clients[0].id;
        const clientRolesUrl = `${this.baseUrl}/admin/realms/${this.realm}/users/${userId}/role-mappings/clients/${realmManagementId}`;
        const clientRolesResponse = await fetch(clientRolesUrl, {
          headers: { Authorization: `Bearer ${token}` },
        });

        if (clientRolesResponse.ok) {
          const clientRoles = await clientRolesResponse.json();
          allRoles.push(...clientRoles.map((r: any) => r.name));
        }
      }
    }

    return allRoles;
  }

  // Update user attributes (allowedServers)
  async updateUserAttributes(token: string, userId: string, allowedServers: string[]): Promise<void> {
    const url = `${this.baseUrl}/admin/realms/${this.realm}/users/${userId}`;

    const response = await fetch(url, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        attributes: {
          allowed_servers: allowedServers,
        },
      }),
    });

    if (!response.ok) {
      throw new Error(`Failed to update user attributes: ${response.status}`);
    }
  }

  // Update user role (admin/user)
  async updateUserRole(token: string, userId: string, role: UserRole): Promise<void> {
    // Get available realm roles
    const rolesUrl = `${this.baseUrl}/admin/realms/${this.realm}/roles`;
    const rolesResponse = await fetch(rolesUrl, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!rolesResponse.ok) {
      throw new Error(`Failed to fetch roles: ${rolesResponse.status}`);
    }

    const availableRoles = await rolesResponse.json();
    const adminRole = availableRoles.find((r: any) => r.name === ADMIN_ROLE);

    if (!adminRole) {
      throw new Error(`Admin role '${ADMIN_ROLE}' not found in realm`);
    }

    const userRolesUrl = `${this.baseUrl}/admin/realms/${this.realm}/users/${userId}/role-mappings/realm`;

    if (role === "admin") {
      // Add admin role
      await fetch(userRolesUrl, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify([adminRole]),
      });
    } else {
      // Remove admin role
      await fetch(userRolesUrl, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify([adminRole]),
      });
    }
  }
}

export const keycloakAdmin = new KeycloakAdmin();
