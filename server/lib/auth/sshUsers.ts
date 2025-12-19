import type { TokenPayload } from "./tideJWT";
import { SSH_USERS_CLAIM_NAMES } from "@shared/config/claims";

function getAllRoleNames(payload: TokenPayload): string[] {
  const realmRoles = payload.realm_access?.roles || [];
  const clientRoles = Object.values(payload.resource_access || {}).flatMap((access) => access.roles || []);
  return [...realmRoles, ...clientRoles];
}

function parseStringArrayClaim(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value
      .filter((v): v is string => typeof v === "string")
      .map((v) => v.trim())
      .filter(Boolean);
  }

  if (typeof value === "string") {
    return value
      .split(",")
      .map((v) => v.trim())
      .filter(Boolean);
  }

  return [];
}

function parseSshUsersFromRoles(payload: TokenPayload): string[] {
  const roles = getAllRoleNames(payload);
  const extracted: string[] = [];

  for (const role of roles) {
    if (typeof role !== "string") continue;

    // Supported patterns:
    // - ssh:root
    // - ssh-root
    const match = role.match(/^ssh[:\-](.+)$/i);
    if (!match) continue;

    const user = match[1].trim();
    if (!user) continue;
    extracted.push(user);
  }

  return extracted;
}

export function getAllowedSshUsersFromToken(payload: TokenPayload | undefined | null): string[] {
  if (!payload) return [];

  const fromClaims: string[] = [];
  for (const claimName of SSH_USERS_CLAIM_NAMES) {
    fromClaims.push(...parseStringArrayClaim(payload[claimName]));
  }

  const fromRoles = parseSshUsersFromRoles(payload);
  return Array.from(new Set([...fromClaims, ...fromRoles]));
}
