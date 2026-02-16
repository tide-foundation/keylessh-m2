/**
 * Organization-Scoped Role Management
 *
 * Provides role management for freemium organizations in the shared TideCloak realm.
 * Uses master admin credentials to manage roles, allowing org-admins (who don't have
 * TideCloak realm-level permissions) to manage roles within their organization.
 */

import { log } from "../logger";
import { getAuthOverrideUrl, getRealm, getResource } from "./auth/tidecloakConfig";
import { RoleRepresentation } from "./auth/keycloakTypes";

interface OrgRole {
  id: string;
  name: string;
  description?: string;
  composite?: boolean;
  clientRole?: boolean;
}

/**
 * Get admin token from TideCloak master realm using password grant.
 */
async function getMasterAdminToken(): Promise<string> {
  const authServerUrl = getAuthOverrideUrl();
  const kcUser = process.env.KC_USER;
  const kcPassword = process.env.KC_PASSWORD;

  if (!kcUser || !kcPassword) {
    throw new Error("KC_USER and KC_PASSWORD must be set for org role management");
  }

  const response = await fetch(`${authServerUrl}/realms/master/protocol/openid-connect/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      username: kcUser,
      password: kcPassword,
      grant_type: "password",
      client_id: "admin-cli",
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to get master admin token: ${response.status} - ${errorText}`);
  }

  const data = await response.json();
  return data.access_token;
}

/**
 * Get the client UUID for the KeyleSSH client
 */
async function getClientUuid(token: string): Promise<string> {
  const authServerUrl = getAuthOverrideUrl();
  const realmName = getRealm();
  const clientId = getResource();

  const response = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/clients?clientId=${clientId}`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );

  if (!response.ok) {
    throw new Error(`Failed to get client: ${response.status}`);
  }

  const clients = await response.json();
  if (!clients.length) {
    throw new Error(`Client ${clientId} not found`);
  }

  return clients[0].id;
}

/**
 * Get all client roles (SSH roles) from TideCloak
 */
export async function getOrgRoles(): Promise<OrgRole[]> {
  const authServerUrl = getAuthOverrideUrl();
  const realmName = getRealm();
  const token = await getMasterAdminToken();
  const clientUuid = await getClientUuid(token);

  const response = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/clients/${clientUuid}/roles`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Failed to get roles: ${response.status} ${text}`);
  }

  const roles: RoleRepresentation[] = await response.json();

  return roles.map((r) => ({
    id: r.id!,
    name: r.name!,
    description: r.description,
    composite: r.composite,
    clientRole: r.clientRole,
  }));
}

/**
 * Get a specific role by name
 */
export async function getOrgRole(roleName: string): Promise<OrgRole | null> {
  const authServerUrl = getAuthOverrideUrl();
  const realmName = getRealm();
  const token = await getMasterAdminToken();
  const clientUuid = await getClientUuid(token);

  const response = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/clients/${clientUuid}/roles/${encodeURIComponent(roleName)}`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );

  if (response.status === 404) {
    return null;
  }

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Failed to get role: ${response.status} ${text}`);
  }

  const role: RoleRepresentation = await response.json();

  return {
    id: role.id!,
    name: role.name!,
    description: role.description,
    composite: role.composite,
    clientRole: role.clientRole,
  };
}

/**
 * Create a new client role
 */
export async function createOrgRole(name: string, description?: string): Promise<OrgRole> {
  const authServerUrl = getAuthOverrideUrl();
  const realmName = getRealm();
  const token = await getMasterAdminToken();
  const clientUuid = await getClientUuid(token);

  const roleRep: RoleRepresentation = {
    name,
    description: description || "",
    clientRole: true,
  };

  const response = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/clients/${clientUuid}/roles`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(roleRep),
    }
  );

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Failed to create role: ${response.status} ${text}`);
  }

  log(`Created org role: ${name}`);

  // Fetch the created role to get its ID
  const createdRole = await getOrgRole(name);
  if (!createdRole) {
    throw new Error("Role was created but could not be retrieved");
  }

  return createdRole;
}

/**
 * Update a role's description
 */
export async function updateOrgRole(
  roleName: string,
  updates: { description?: string }
): Promise<OrgRole> {
  const authServerUrl = getAuthOverrideUrl();
  const realmName = getRealm();
  const token = await getMasterAdminToken();
  const clientUuid = await getClientUuid(token);

  // Get current role
  const currentRole = await getOrgRole(roleName);
  if (!currentRole) {
    throw new Error(`Role ${roleName} not found`);
  }

  const roleRep: RoleRepresentation = {
    id: currentRole.id,
    name: roleName,
    description: updates.description ?? currentRole.description,
    clientRole: true,
  };

  const response = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/clients/${clientUuid}/roles/${encodeURIComponent(roleName)}`,
    {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(roleRep),
    }
  );

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Failed to update role: ${response.status} ${text}`);
  }

  log(`Updated org role: ${roleName}`);

  return {
    ...currentRole,
    description: updates.description ?? currentRole.description,
  };
}

/**
 * Delete a role
 */
export async function deleteOrgRole(roleName: string): Promise<void> {
  const authServerUrl = getAuthOverrideUrl();
  const realmName = getRealm();
  const token = await getMasterAdminToken();
  const clientUuid = await getClientUuid(token);

  const response = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/clients/${clientUuid}/roles/${encodeURIComponent(roleName)}`,
    {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Failed to delete role: ${response.status} ${text}`);
  }

  log(`Deleted org role: ${roleName}`);
}

/**
 * Grant a role to a user
 */
export async function grantOrgRoleToUser(userId: string, roleName: string): Promise<void> {
  const authServerUrl = getAuthOverrideUrl();
  const realmName = getRealm();
  const token = await getMasterAdminToken();
  const clientUuid = await getClientUuid(token);

  // Get the role
  const role = await getOrgRole(roleName);
  if (!role) {
    throw new Error(`Role ${roleName} not found`);
  }

  const response = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/users/${userId}/role-mappings/clients/${clientUuid}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify([{ id: role.id, name: role.name }]),
    }
  );

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Failed to grant role to user: ${response.status} ${text}`);
  }

  log(`Granted role ${roleName} to user ${userId}`);
}

/**
 * Remove a role from a user
 */
export async function removeOrgRoleFromUser(userId: string, roleName: string): Promise<void> {
  const authServerUrl = getAuthOverrideUrl();
  const realmName = getRealm();
  const token = await getMasterAdminToken();
  const clientUuid = await getClientUuid(token);

  // Get the role
  const role = await getOrgRole(roleName);
  if (!role) {
    throw new Error(`Role ${roleName} not found`);
  }

  const response = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/users/${userId}/role-mappings/clients/${clientUuid}`,
    {
      method: "DELETE",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify([{ id: role.id, name: role.name }]),
    }
  );

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Failed to remove role from user: ${response.status} ${text}`);
  }

  log(`Removed role ${roleName} from user ${userId}`);
}

/**
 * Get all roles assigned to a user (client roles only)
 */
export async function getUserOrgRoles(userId: string): Promise<OrgRole[]> {
  const authServerUrl = getAuthOverrideUrl();
  const realmName = getRealm();
  const token = await getMasterAdminToken();
  const clientUuid = await getClientUuid(token);

  const response = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/users/${userId}/role-mappings/clients/${clientUuid}`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Failed to get user roles: ${response.status} ${text}`);
  }

  const roles: RoleRepresentation[] = await response.json();

  return roles.map((r) => ({
    id: r.id!,
    name: r.name!,
    description: r.description,
    composite: r.composite,
    clientRole: r.clientRole,
  }));
}
