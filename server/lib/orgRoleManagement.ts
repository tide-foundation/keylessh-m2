/**
 * Organization-Scoped Role Management
 *
 * Provides role management for freemium organizations in the shared TideCloak realm.
 * Uses master admin credentials to manage roles, allowing org-admins (who don't have
 * TideCloak realm-level permissions) to manage roles within their organization.
 */

import { log } from "../logger";
import { getAuthOverrideUrl, getRealm, getResource } from "./auth/tidecloakConfig";
import { RoleRepresentation, ChangeSetRequest } from "./auth/keycloakTypes";
import {
  AddApprovalToChangeRequest,
  CommitChangeRequest,
  GetUserChangeRequests,
  GetRoleChangeRequests,
} from "./tidecloakApi";

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
 * Auto-approve and commit any pending TideCloak change-sets after an admin API call.
 *
 * TideCloak intercepts standard Keycloak admin API calls and creates draft
 * change-sets that must be approved and committed before taking effect.
 *
 * Strategy:
 * 1. Try to parse change-set info from the response body
 * 2. If nothing found, query pending user & role change requests as fallback
 */
async function autoApproveAndCommit(response: Response, token: string, operation: string): Promise<void> {
  const changeSets: ChangeSetRequest[] = [];

  // Strategy 1: Parse the response body for change-set info
  try {
    const responseBody = await response.text();
    if (responseBody) {
      const csResponse = JSON.parse(responseBody);

      // Format A: changeSetRequests as a JSON string
      if (csResponse.changeSetRequests) {
        const parsed = JSON.parse(csResponse.changeSetRequests);
        if (Array.isArray(parsed)) {
          for (const cs of parsed) {
            changeSets.push({
              changeSetId: cs.draftRecordId || cs.changeSetId,
              changeSetType: cs.changeSetType,
              actionType: cs.actionType,
            });
          }
        }
      }

      // Format B: top-level draftRecordId
      if (changeSets.length === 0 && csResponse.draftRecordId) {
        changeSets.push({
          changeSetId: csResponse.draftRecordId,
          changeSetType: csResponse.changeSetType,
          actionType: csResponse.actionType,
        });
      }
    }
  } catch {
    // Response might be empty or not JSON — fall through to strategy 2
  }

  // Strategy 2: Query pending change requests if response didn't yield any
  if (changeSets.length === 0) {
    try {
      const [userRequests, roleRequests] = await Promise.all([
        GetUserChangeRequests(token).catch(() => []),
        GetRoleChangeRequests(token).catch(() => []),
      ]);

      for (const req of [...userRequests, ...roleRequests]) {
        if (req.retrievalInfo?.changeSetId) {
          changeSets.push(req.retrievalInfo);
        }
      }
    } catch (queryError) {
      log(`Could not query pending change-sets for ${operation}: ${queryError}`);
    }
  }

  // Approve and commit each change-set
  for (const changeSet of changeSets) {
    try {
      log(`Auto-approving change-set for ${operation}: ${changeSet.changeSetId}`);
      await AddApprovalToChangeRequest(changeSet, token);

      log(`Auto-committing change-set for ${operation}: ${changeSet.changeSetId}`);
      await CommitChangeRequest(changeSet, token);
    } catch (err) {
      log(`Failed to auto-approve/commit change-set ${changeSet.changeSetId} for ${operation}: ${err}`);
    }
  }
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

  // Auto-approve and commit the change-set so the role reaches the IAM
  await autoApproveAndCommit(response, token, `role creation: ${name}`);

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

  await autoApproveAndCommit(response, token, `role update: ${roleName}`);

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

  await autoApproveAndCommit(response, token, `role deletion: ${roleName}`);

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

  await autoApproveAndCommit(response, token, `grant role ${roleName} to user ${userId}`);

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

  await autoApproveAndCommit(response, token, `remove role ${roleName} from user ${userId}`);

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
