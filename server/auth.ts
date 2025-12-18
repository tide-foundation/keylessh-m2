import type { Request, Response, NextFunction } from "express";
import type { OIDCUser, UserRole } from "@shared/schema";

// TideCloak/Keycloak configuration
const KEYCLOAK_URL = process.env.KEYCLOAK_URL || "https://staging.dauth.me";
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM || "keylessh";
const KEYCLOAK_CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID || "keylessh";
const KEYCLOAK_CLIENT_SECRET = process.env.KEYCLOAK_CLIENT_SECRET || "";

// Extended Request interface with user information
export interface AuthenticatedRequest extends Request {
  user?: OIDCUser;
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

// TideCloak role names
const ADMIN_ROLE = "tide-realm-admin";

// Extract user from JWT payload
function extractUserFromPayload(payload: JWTPayload): OIDCUser {
  const roles = payload.realm_access?.roles || [];
  const isAdmin = roles.includes(ADMIN_ROLE);

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

// Keycloak Admin API client
export class KeycloakAdmin {
  private baseUrl: string;
  private realm: string;
  private clientId: string;
  private clientSecret: string;
  private accessToken: string | null = null;
  private tokenExpiry: number = 0;

  constructor() {
    this.baseUrl = KEYCLOAK_URL;
    this.realm = KEYCLOAK_REALM;
    this.clientId = KEYCLOAK_CLIENT_ID;
    this.clientSecret = KEYCLOAK_CLIENT_SECRET;
  }

  // Get admin access token using client credentials
  private async getAdminToken(): Promise<string> {
    if (this.accessToken && this.tokenExpiry > Date.now()) {
      return this.accessToken;
    }

    const tokenUrl = `${this.baseUrl}/realms/${this.realm}/protocol/openid-connect/token`;

    const params = new URLSearchParams();
    params.append("grant_type", "client_credentials");
    params.append("client_id", this.clientId);
    params.append("client_secret", this.clientSecret);

    const response = await fetch(tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params.toString(),
    });

    if (!response.ok) {
      throw new Error(`Failed to get admin token: ${response.status}`);
    }

    const data = await response.json();
    this.accessToken = data.access_token;
    this.tokenExpiry = Date.now() + (data.expires_in - 60) * 1000;

    return this.accessToken!;
  }

  // Get all users from Keycloak
  async getUsers(): Promise<OIDCUser[]> {
    const token = await this.getAdminToken();
    const url = `${this.baseUrl}/admin/realms/${this.realm}/users`;

    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch users: ${response.status}`);
    }

    const keycloakUsers = await response.json();

    // Transform Keycloak users to our OIDCUser format
    const users: OIDCUser[] = await Promise.all(
      keycloakUsers.map(async (kcUser: any) => {
        const roles = await this.getUserRoles(kcUser.id);
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
  async getUser(userId: string): Promise<OIDCUser | null> {
    const token = await this.getAdminToken();
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
    const roles = await this.getUserRoles(userId);
    const attributes = kcUser.attributes || {};

    return {
      id: kcUser.id,
      username: kcUser.username || "",
      email: kcUser.email || "",
      role: roles.includes(ADMIN_ROLE) ? "admin" : "user" as UserRole,
      allowedServers: attributes.allowed_servers || [],
    };
  }

  // Get user's realm roles
  private async getUserRoles(userId: string): Promise<string[]> {
    const token = await this.getAdminToken();
    const url = `${this.baseUrl}/admin/realms/${this.realm}/users/${userId}/role-mappings/realm`;

    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      return [];
    }

    const roles = await response.json();
    return roles.map((r: any) => r.name);
  }

  // Update user attributes (allowedServers)
  async updateUserAttributes(userId: string, allowedServers: string[]): Promise<void> {
    const token = await this.getAdminToken();
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
  async updateUserRole(userId: string, role: UserRole): Promise<void> {
    const token = await this.getAdminToken();

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
