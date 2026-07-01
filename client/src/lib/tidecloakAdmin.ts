/**
 * Client-side TideCloak Admin API — calls TideCloak directly from the browser
 * using appFetch (DPoP-secured).
 *
 * Requires TideCloak CORS to allow the app origin.
 */
import { IAMService } from "@tidecloak/js";
import { appFetch } from "./appFetch";

// Lazy-loaded config from /api/auth/config
let _config: { realm: string; "auth-server-url": string; resource: string } | null = null;

async function getConfig() {
  if (!_config) {
    const res = await fetch("/api/auth/config");
    _config = await res.json();
  }
  return _config!;
}

async function getTcUrl() {
  const cfg = await getConfig();
  return `${cfg["auth-server-url"].replace(/\/+$/, "")}/admin/realms/${cfg.realm}`;
}

async function getClientId() {
  const cfg = await getConfig();
  return cfg.resource;
}

/**
 * Fetch wrapper for TideCloak admin API calls from the browser.
 * Uses appFetch which handles DPoP proof generation.
 */
async function tcFetch<T = any>(path: string, options: RequestInit = {}): Promise<T> {
  const base = await getTcUrl();
  const url = `${base}${path}`;

  // secureFetch only adds DPoP when it sees Authorization: Bearer <our token>
  const token = await IAMService.getToken();
  const response = await appFetch(url, {
    ...options,
    headers: {
      accept: "application/json",
      Authorization: `Bearer ${token}`,
      ...((options.headers as Record<string, string>) || {}),
    },
  });

  if (!response.ok) {
    const errorBody = await response.text().catch(() => response.statusText);
    console.error(`[tcFetch] ${options.method || "GET"} ${url} → ${response.status}:`, errorBody);
    throw new Error(`TideCloak API error: ${response.status} ${errorBody}`);
  }

  // Some endpoints return no body (204, or empty 200)
  const text = await response.text();
  if (!text) return undefined as T;

  try {
    return JSON.parse(text) as T;
  } catch {
    return text as T;
  }
}

// ============================================
// Types (match Keycloak representations)
// ============================================

interface UserRepresentation {
  id?: string;
  username?: string;
  firstName?: string;
  lastName?: string;
  email?: string;
  enabled?: boolean;
  attributes?: Record<string, string[]>;
  [key: string]: any;
}

interface RoleRepresentation {
  id?: string;
  name?: string;
  description?: string;
  composite?: boolean;
  composites?: { client?: Record<string, string[]> };
  attributes?: Record<string, string[]>;
  [key: string]: any;
}

interface ClientRepresentation {
  id?: string;
  clientId?: string;
  [key: string]: any;
}

interface MappingsRepresentation {
  clientMappings?: Record<string, { mappings: RoleRepresentation[] }>;
  realmMappings?: RoleRepresentation[];
  [key: string]: any;
}

interface ChangeSetRequest {
  changeSetId: string;
  changeSetType: string;
  actionType: string;
}

interface KeycloakEvent {
  id: string;
  time: number;
  type: string;
  clientId?: string;
  userId?: string;
  ipAddress?: string;
  details?: Record<string, any>;
}

// ============================================
// Client lookup helpers
// ============================================

let _clientCache = new Map<string, ClientRepresentation>();

async function getClientByClientId(clientId: string): Promise<ClientRepresentation | null> {
  const cached = _clientCache.get(clientId);
  if (cached) return cached;

  const clients = await tcFetch<ClientRepresentation[]>(`/clients?clientId=${clientId}`);
  if (clients.length > 0) {
    _clientCache.set(clientId, clients[0]);
    return clients[0];
  }
  return null;
}

const REALM_MGMT = "realm-management";
const ADMIN_ROLE = "tide-realm-admin";

// ============================================
// Caching + concurrency helpers
// ============================================

interface CacheEntry<T> { data: T; expiry: number; }

const _usersCache: { entry?: CacheEntry<UserRepresentation[]> } = {};
const _usersWithRolesCache: { entry?: CacheEntry<any[]> } = {};
const _rolesCache: { entry?: CacheEntry<RoleRepresentation[]> } = {};
const CACHE_TTL = 30_000; // 30 seconds

/** Run async tasks with a concurrency limit */
async function limitedAll<T>(tasks: (() => Promise<T>)[], limit: number): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  let idx = 0;
  async function worker() {
    while (idx < tasks.length) {
      const i = idx++;
      results[i] = await tasks[i]();
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, () => worker()));
  return results;
}

/** Invalidate user/role caches (call after mutations) */
export function invalidateUsersCache(): void { _usersCache.entry = undefined; _usersWithRolesCache.entry = undefined; }
export function invalidateRolesCache(): void { _rolesCache.entry = undefined; }

/** Fire-and-forget prefetch of users+roles right after login so caches are warm */
export function prefetchAdminData(): void {
  // These run in parallel, populate caches, errors are silently ignored
  getUsers().catch(() => {});
  getClientRoles().catch(() => {});
}

// ============================================
// User Management
// ============================================

export async function getUsers(): Promise<UserRepresentation[]> {
  if (_usersCache.entry && Date.now() < _usersCache.entry.expiry) {
    return _usersCache.entry.data;
  }
  const users = await tcFetch<UserRepresentation[]>("/users?briefRepresentation=false");
  _usersCache.entry = { data: users, expiry: Date.now() + CACHE_TTL };
  return users;
}

/**
 * Fetch all users with their roles using a role-centric approach.
 * Maximizes parallelism: fires users, client lookups, role list, and admin
 * members all concurrently. Only 2 sequential rounds:
 *   Round 1: users + both client lookups + role list (all parallel)
 *   Round 2: role-member fetches (all parallel)
 */
export async function getUsersWithRoles(
  users?: UserRepresentation[]
): Promise<(UserRepresentation & { clientRoles: string[] })[]> {
  // Return cached if fresh
  if (_usersWithRolesCache.entry && Date.now() < _usersWithRolesCache.entry.expiry) {
    return _usersWithRolesCache.entry.data;
  }

  // --- Round 1: fetch users + realm-management client in parallel ---
  const usersP = users ? Promise.resolve(users) : getUsers();
  const rmClientP = getClientByClientId(REALM_MGMT);
  const [allUsers, rmClient] = await Promise.all([usersP, rmClientP]);

  // --- Round 2: fetch admin members only (no per-role member listing needed) ---
  const adminUsers = rmClient?.id
    ? await tcFetch<UserRepresentation[]>(
        `/clients/${rmClient.id}/roles/${encodeURIComponent(ADMIN_ROLE)}/users`
      ).catch(() => [] as UserRepresentation[])
    : [] as UserRepresentation[];

  const adminSet = new Set(adminUsers.map(u => u.id!));

  const result = allUsers.map(u => ({
    ...u,
    clientRoles: adminSet.has(u.id!) ? [ADMIN_ROLE] : [],
  }));

  _usersWithRolesCache.entry = { data: result, expiry: Date.now() + CACHE_TTL };
  return result;
}

export async function getUserByVuid(vuid: string): Promise<UserRepresentation[]> {
  return tcFetch<UserRepresentation[]>(`/users?q=vuid:${vuid}`);
}

export async function addUser(userRep: { username: string; firstName: string; lastName: string; email: string }): Promise<void> {
  await tcFetch("/users", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(userRep),
  });
  invalidateUsersCache();
}

export async function updateUser(userId: string, data: { firstName: string; lastName: string; email: string }): Promise<void> {
  const user = await tcFetch<UserRepresentation>(`/users/${userId}`);
  const updated = { ...user, ...data };
  await tcFetch(`/users/${userId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(updated),
  });
  invalidateUsersCache();
}

export async function deleteUser(userId: string): Promise<void> {
  await tcFetch(`/users/${userId}`, { method: "DELETE" });
  invalidateUsersCache();
}

export async function setUserEnabled(userId: string, enabled: boolean): Promise<void> {
  const user = await tcFetch<UserRepresentation>(`/users/${userId}`);
  const updated = { ...user, enabled };
  await tcFetch(`/users/${userId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(updated),
  });
  invalidateUsersCache();
}

export async function getUserRoleMappings(userId: string): Promise<MappingsRepresentation> {
  return tcFetch<MappingsRepresentation>(`/users/${userId}/role-mappings`);
}

export async function getUserClientRoleMappings(userId: string): Promise<RoleRepresentation[]> {
  const clientId = await getClientId();
  const client = await getClientByClientId(clientId);
  if (!client?.id) return [];
  return tcFetch<RoleRepresentation[]>(`/users/${userId}/role-mappings/clients/${client.id}`);
}

export async function getUserRealmManagementRoleMappings(userId: string): Promise<RoleRepresentation[]> {
  const client = await getClientByClientId(REALM_MGMT);
  if (!client?.id) return [];
  return tcFetch<RoleRepresentation[]>(`/users/${userId}/role-mappings/clients/${client.id}`).catch(() => []);
}

export async function getTideLinkUrl(userId: string, redirectUri: string): Promise<string> {
  const clientId = await getClientId();
  return tcFetch<string>(
    `/tideAdminResources/get-required-action-link?userId=${userId}&lifespan=43200&redirect_uri=${redirectUri}&client_id=${clientId}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(["link-tide-account-action"]),
    }
  );
}

// ============================================
// Role Management
// ============================================

export async function getClientRoles(): Promise<RoleRepresentation[]> {
  // Return cached if fresh
  if (_rolesCache.entry && Date.now() < _rolesCache.entry.expiry) {
    return _rolesCache.entry.data;
  }

  const clientId = await getClientId();
  const client = await getClientByClientId(clientId);
  if (!client) return [];

  // The list endpoint already returns id, name, description, clientRole, containerId
  // No need to re-fetch each role by ID
  const roles = await tcFetch<RoleRepresentation[]>(`/clients/${client.id}/roles`);

  _rolesCache.entry = { data: roles, expiry: Date.now() + CACHE_TTL };
  return roles;
}

export async function getTideRealmAdminRole(): Promise<RoleRepresentation> {
  const client = await getClientByClientId(REALM_MGMT);
  if (!client) throw new Error("No client found: " + REALM_MGMT);

  const roles = await tcFetch<RoleRepresentation[]>(`/clients/${client.id}/roles?search=${ADMIN_ROLE}`);
  return roles[0];
}

export async function getAllRoles(): Promise<RoleRepresentation[]> {
  const clientRoles = await getClientRoles();

  try {
    const adminRole = await getTideRealmAdminRole();
    return [...clientRoles, adminRole];
  } catch {
    return clientRoles;
  }
}

export async function createRole(data: { name: string; description?: string }): Promise<void> {
  const clientIdStr = await getClientId();
  const client = await getClientByClientId(clientIdStr);
  if (!client) throw new Error(`Client '${clientIdStr}' not found`);

  await tcFetch(`/clients/${client.id}/roles`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  invalidateRolesCache();
}

export async function updateRole(roleRep: { name: string; description?: string }): Promise<void> {
  const clientIdStr = await getClientId();
  const client = await getClientByClientId(clientIdStr);
  if (!client) throw new Error(`Client '${clientIdStr}' not found`);

  await tcFetch(`/clients/${client.id}/roles/${roleRep.name}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(roleRep),
  });
  invalidateRolesCache();
}

export async function deleteRole(roleName: string): Promise<{ approvalCreated: boolean; message?: string }> {
  const clientIdStr = await getClientId();
  const client = await getClientByClientId(clientIdStr);
  if (!client) throw new Error(`Client '${clientIdStr}' not found`);

  // Use role ID for deletion (role name with colons/slashes breaks URL path)
  const role = await findRoleByName(client.id, roleName);
  await tcFetch(`/roles-by-id/${role.id}`, { method: "DELETE" });
  invalidateRolesCache();

  // Check if role still exists (approval created instead of immediate delete)
  try {
    await findRoleByName(client.id, roleName);
    return { approvalCreated: true, message: "Approval request created" };
  } catch {
    return { approvalCreated: false };
  }
}

/** Determine which TideCloak client a role belongs to. */
async function getClientIdForRole(roleName: string): Promise<string> {
  if (roleName === ADMIN_ROLE) return REALM_MGMT;
  return await getClientId();
}

/// Look up a role by name without putting the name in the URL path.
/// Keycloak's GET /roles/{name} breaks on colons/slashes in role names.
/// Uses the cached roles list from getClientRoles().
async function findRoleByName(_clientUuid: string, roleName: string): Promise<RoleRepresentation> {
  let roles = await getClientRoles();
  let role = roles.find((r) => r.name === roleName);
  if (!role) {
    // Cache miss — invalidate and retry
    invalidateRolesCache();
    roles = await getClientRoles();
    role = roles.find((r) => r.name === roleName);
    if (!role) throw new Error(`Role '${roleName}' not found`);
  }
  return role;
}

export async function grantUserRole(userId: string, roleName: string): Promise<void> {
  const isAdmin = roleName === ADMIN_ROLE;
  const targetClientId = await getClientIdForRole(roleName);
  const client = await getClientByClientId(targetClientId);

  if (!client?.id) throw new Error(`Client '${targetClientId}' not found`);

  const role = isAdmin
    ? await getTideRealmAdminRole()
    : await findRoleByName(client.id, roleName);

  await tcFetch(`/users/${userId}/role-mappings/clients/${client.id}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify([role]),
  });
  invalidateUsersCache();
}

export async function removeUserRole(userId: string, roleName: string): Promise<void> {
  const isAdmin = roleName === ADMIN_ROLE;
  const targetClientId = await getClientIdForRole(roleName);
  const client = await getClientByClientId(targetClientId);

  if (!client?.id) throw new Error(`Client '${targetClientId}' not found`);

  const role = isAdmin
    ? await getTideRealmAdminRole()
    : await findRoleByName(client.id, roleName);

  await tcFetch(`/users/${userId}/role-mappings/clients/${client.id}`, {
    method: "DELETE",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify([{ id: role.id, name: role.name }]),
  });
  invalidateUsersCache();
}

// ============================================
// Events / Logs
// ============================================

export async function getClientEvents(first: number = 0, max: number = 100): Promise<KeycloakEvent[]> {
  const clientId = await getClientId();
  const params = new URLSearchParams({ first: String(first), max: String(max), client: clientId });
  return tcFetch<KeycloakEvent[]>(`/events?${params.toString()}`);
}

// ============================================
// Change Set / Approval Operations
// ============================================

// Repointed to the consolidated iga-core surface (the old /tide-admin/change-set/*
// + /tideAdminResources/add-review|add-rejection endpoints were removed). This is
// the LIVE admin-UI CR path (AdminApprovals.tsx -> api.ts -> here), running
// client-direct over the DPoP-bound admin token via tcFetch (NO mTLS/delegation).
// The /iga/* admin endpoints require a manage-realm-capable token, which the
// admin-console user's token carries. The enclave-sign round-trip shape
// (getRawChangeSetRequest -> sign -> addApprovalWithSignedRequest) is preserved.

// GET /iga/change-requests?status=PENDING returns a flat list for ALL entity
// types; filter by entityType here. Field renames vs the old surface:
//   draftRecordId -> id ; changeSetType -> entityType ; state -> status.
// The api.ts list mappers read item.data.draftRecordId, so we alias id ->
// draftRecordId on the `data` object to keep them working unchanged.
async function getPendingChangeRequests(): Promise<any[]> {
  return tcFetch<any[]>("/iga/change-requests?status=PENDING");
}

// Lookups the display mappers need to turn the new `rows` (which carry only
// UUIDs for GRANT_ROLES) back into human-readable User / Role / Client values.
interface CrLookups {
  usersById: Map<string, UserRepresentation>;
  rolesById: Map<string, RoleRepresentation>;
  clientIdByUuid: Map<string, string>;
}

async function buildCrLookups(): Promise<CrLookups> {
  const [users, roles, appClientId] = await Promise.all([
    getUsers().catch(() => [] as UserRepresentation[]),
    getAllRoles().catch(() => [] as RoleRepresentation[]),
    getClientId(),
  ]);
  const usersById = new Map<string, UserRepresentation>();
  for (const u of users) if (u.id) usersById.set(u.id, u);
  const rolesById = new Map<string, RoleRepresentation>();
  for (const r of roles) if (r.id) rolesById.set(r.id, r);

  // Map a role's container (client) UUID to its clientId string so a
  // resolved role can name its client. Only the two clients we ever touch
  // (the app client + realm-management) need resolving.
  const clientIdByUuid = new Map<string, string>();
  const [appClient, rmClient] = await Promise.all([
    getClientByClientId(appClientId).catch(() => null),
    getClientByClientId(REALM_MGMT).catch(() => null),
  ]);
  if (appClient?.id) clientIdByUuid.set(appClient.id, appClient.clientId || appClientId);
  if (rmClient?.id) clientIdByUuid.set(rmClient.id, rmClient.clientId || REALM_MGMT);
  return { usersById, rolesById, clientIdByUuid };
}

// Pull display-friendly User / Role / Client out of the new iga-core CR `rows`.
// `rows` is DB-row shaped with UPPERCASE column names that vary by actionType:
//   GRANT_ROLES : [{ USER_ID, ROLE_ID }]              (UUIDs only, resolve to names)
//   CREATE_USER : [{ ID, USERNAME, REP_JSON, ... }]   (USERNAME present)
//   CREATE_ROLE : [{ ID, NAME, CLIENT_ID, ... }]      (NAME + CLIENT_ID present)
function extractCrDisplay(d: any, lk: CrLookups): {
  userRecord: { username: string }[];
  role: string;
  compositeRole: string | undefined;
  clientId: string;
} {
  const rows: any[] = Array.isArray(d.rows) ? d.rows : [];
  const row = rows[0] || {};
  let username: string | undefined;
  let role: string | undefined;
  let compositeRole: string | undefined;
  let clientId: string | undefined;

  // User: prefer an explicit USERNAME (CREATE_USER), else resolve USER_ID.
  const userId = row.USER_ID || row.ID || d.entityId;
  username = row.USERNAME || (userId ? lk.usersById.get(userId)?.username : undefined);

  // Role: prefer an explicit NAME (CREATE_ROLE), else resolve ROLE_ID.
  const roleId = row.ROLE_ID || (d.entityType === "ROLE" ? row.ID || d.entityId : undefined);
  const resolvedRole = roleId ? lk.rolesById.get(roleId) : undefined;
  role = row.NAME || resolvedRole?.name;
  compositeRole = resolvedRole?.composite ? resolvedRole?.name : undefined;

  // Client: explicit CLIENT_ID (CREATE_ROLE), else the resolved role's container.
  const containerUuid = row.CLIENT_UUID || resolvedRole?.containerId;
  clientId = row.CLIENT_ID || (containerUuid ? lk.clientIdByUuid.get(containerUuid) : undefined);

  return {
    userRecord: username ? [{ username }] : [],
    role: role || "Unknown",
    compositeRole,
    clientId: clientId || "Unknown",
  };
}

function toRetrieval(d: any, lk: CrLookups) {
  const display = extractCrDisplay(d, lk);
  return {
    // Preserve the legacy `data` field names the api.ts mappers read
    // (draftRecordId / changeSetType), aliased from the new rep. Also inject
    // the display fields (userRecord / role / compositeRole / clientId) the
    // api.ts list mappers pull out of the OLD payload shape, recomputed from
    // the new `rows`/`entityType`.
    data: {
      ...d,
      draftRecordId: d.id,
      changeSetType: d.entityType,
      userRecord: display.userRecord,
      role: display.role,
      compositeRole: display.compositeRole,
      clientId: display.clientId,
    },
    retrievalInfo: {
      changeSetId: d.id,
      changeSetType: d.entityType,
      actionType: d.actionType,
    } as ChangeSetRequest,
  };
}

export async function getUserChangeRequests(): Promise<any[]> {
  const all = await getPendingChangeRequests();
  const userCrs = all.filter(d => d.entityType === "USER");
  if (userCrs.length === 0) return [];
  const lk = await buildCrLookups();
  return userCrs.map(d => toRetrieval(d, lk));
}

export async function getRoleChangeRequests(): Promise<any[]> {
  const all = await getPendingChangeRequests();
  const roleCrs = all.filter(d => d.entityType === "ROLE");
  if (roleCrs.length === 0) return [];
  const lk = await buildCrLookups();
  return roleCrs.map(d => toRetrieval(d, lk));
}

// Phase-1 /approve with empty body. multiAdmin returns
// {mode:"needs-approval", requestModel,...}; firstAdmin/simple records AND
// auto-commits in one call. Replaces the old add-review no-signature approve.
export async function addApprovalToChangeRequest(changeSet: ChangeSetRequest): Promise<void> {
  await tcFetch(`/iga/change-requests/${changeSet.changeSetId}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
}

// REJECT maps to /deny on the new surface (the old add-rejection is gone).
export async function addRejectionToChangeRequest(changeSet: ChangeSetRequest): Promise<void> {
  await tcFetch(`/iga/change-requests/${changeSet.changeSetId}/deny`, {
    method: "POST",
  });
}

// Apply-only. Usually unnecessary (/approve auto-commits at quorum). id in path,
// empty body. Replaces the removed /tide-admin/change-set/commit.
export async function commitChangeRequest(changeSet: ChangeSetRequest): Promise<void> {
  await tcFetch(`/iga/change-requests/${changeSet.changeSetId}/commit`, {
    method: "POST",
  });
}

// CANCEL maps to /deny on the new surface (the old change-set/cancel is gone).
export async function cancelChangeRequest(changeSet: ChangeSetRequest): Promise<void> {
  await tcFetch(`/iga/change-requests/${changeSet.changeSetId}/deny`, {
    method: "POST",
  });
}

// "Get raw request to sign" is now PHASE 1 of /approve: the empty-body call
// returns the requestModel (multiAdmin) that the enclave signs. We adapt it into
// the legacy [{changesetId, changeSetDraftRequests, requiresApprovalPopup}] shape
// that AdminApprovals.tsx already consumes. If mode !== "needs-approval"
// (firstAdmin/simple realms) the CR was already recorded/committed and there is
// nothing to sign; return [] so the caller treats it as "no popup required".
export async function getRawChangeSetRequest(changeSet: ChangeSetRequest): Promise<any[]> {
  const phase1 = await tcFetch<any>(`/iga/change-requests/${changeSet.changeSetId}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  const needsApproval = phase1?.mode === "needs-approval" && !!phase1?.requestModel;
  if (!needsApproval) {
    return [];
  }
  return [
    {
      changesetId: phase1.changeRequestId ?? changeSet.changeSetId,
      changeSetDraftRequests: phase1.requestModel as string,
      requiresApprovalPopup: true,
    },
  ];
}

// PHASE 2: submit the enclave-signed doken toward the CR's threshold via
// /approve {requestModel:<signed>}. Auto-commits at quorum. Replaces the old
// multipart add-review with a `requests` form field.
export async function addApprovalWithSignedRequest(
  changeSet: ChangeSetRequest,
  signedRequest: string
): Promise<void> {
  await tcFetch(`/iga/change-requests/${changeSet.changeSetId}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ requestModel: signedRequest }),
  });
}

// ============================================
// Admin policy (for policy-commit ORK PreSign)
// ============================================

// Fetch the tide-realm-admin authorization policy (base64) that the ORK PreSign
// requires attached to a policy-commit sign-model. This uses the CLIENT-DIRECT
// DPoP path (tcFetch -> IAMService.getToken() DPoP token + appFetch DPoP proof,
// against {authServerUrl}/admin/realms/{realm}), the SAME mechanism the CR ops
// (getUserChangeRequests / addApprovalWithSignedRequest / commitChangeRequest)
// use to reach iga-core. The server-relay Bearer path 401s at iga-core because
// the forwarded token carries no DPoP proof; this DPoP-authenticated request is
// what iga-core's admin surface accepts. The role-policies READ is
// authenticated-only (less privileged than the /iga/change-requests endpoints
// the CR path already hits), so the same DPoP token satisfies it. Returns the
// base64 `.policy` field of the IgaRolePolicyRepresentation.
export async function getAdminPolicy(): Promise<string> {
  const rep = await tcFetch<{ policy?: string }>(
    "/iga/role-policies/name/tide-realm-admin"
  );
  return rep?.policy ?? "";
}

// ============================================
// SSH Policy Sync (still goes through server)
// ============================================

// Repointed to the consolidated iga-core role-policies / forseti-contracts
// surface (the old PUT /tide-admin/ssh-policies was removed). Two writes over
// the same DPoP-bound admin token (NO mTLS/delegation):
//   1. POST /iga/forseti-contracts {contractCode, name} -> {id}
//   2. POST /iga/role-policies {name, policy, policySig, contractId, ...}
// policySig is the detached 64-byte Ed25519 signature (Base64, <=512 chars) the
// server returns in syncData — the same signature keylessh already produced via
// the enclave/ORK sign. iga-core keys policies by NAME; keylessh uses the role
// name (roleId). Note: the reserved name `tide-realm-admin` is rejected (400).
export async function syncPolicyToTideCloak(policy: {
  roleId: string;
  contractCode?: string;
  approvalType: string;
  executionType: string;
  threshold: number;
  policyData: string;
  policySig: string;
}): Promise<void> {
  // Step 1: upsert the Forseti contract (if supplied) to obtain a contractId.
  let contractId: string | undefined;
  if (policy.contractCode) {
    const contract = await tcFetch<{ id?: string }>("/iga/forseti-contracts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ contractCode: policy.contractCode, name: policy.roleId }),
    });
    contractId = contract?.id;
  }

  // Step 2: upsert the role policy keyed by the role NAME.
  await tcFetch("/iga/role-policies", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name: policy.roleId,
      contractId,
      approvalType: policy.approvalType,
      executionType: policy.executionType,
      threshold: policy.threshold,
      // policy = combined signed blob (uncapped TEXT). policySig = detached
      // 64-byte Ed25519 sig Base64 (~88 chars, under the VARCHAR(512) cap).
      policy: policy.policyData,
      policySig: policy.policySig,
      policyData: policy.policyData,
    }),
  });
}
