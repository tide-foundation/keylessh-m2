import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import { eq, desc, inArray, and, lt } from "drizzle-orm";
import { randomUUID } from "crypto";
import {
  users,
  servers,
  sessions,
  fileOperations,
  subscriptions,
  billingHistory,
  bridges,
  organizations,
  organizationUsers,
  enterpriseLeads,
  policyTemplates,
  subscriptionTiers,
  type User,
  type InsertUser,
  type Server,
  type InsertServer,
  type Session,
  type InsertSession,
  type FileOperation,
  type FileOperationType,
  type FileOperationMode,
  type FileOperationStatus,
  type PolicyTemplate,
  type InsertPolicyTemplate,
  type TemplateParameter,
  type Subscription,
  type InsertSubscription,
  type BillingHistory,
  type Bridge,
  type InsertBridge,
  type Organization,
  type OrganizationUser,
  type EnterpriseLead,
  type InsertEnterpriseLead,
  type SubscriptionTier,
  type LicenseInfo,
  type LimitCheck,
  type OrgRole,
} from "@shared/schema";
import { getAdminPolicy } from "./lib/tidecloakApi";
import { isStripeConfigured } from "./lib/stripe";
import { DEFAULT_ORG_ID, DEFAULT_ORG_NAME, DEFAULT_ORG_SLUG } from "./config";
import { createRequire } from "module";

// Use createRequire for heimdall-tide (CJS module with broken ESM exports)
const require = createRequire(
  typeof __filename !== "undefined" ? __filename : import.meta.url
);
const { PolicySignRequest } = require("heimdall-tide");

// Base64 conversion helpers for Tide request handling
function base64ToBytes(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, "base64"));
}

function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  getUsers(): Promise<User[]>;
  updateUser(id: string, data: Partial<User>): Promise<User | undefined>;

  getServers(orgId: string): Promise<Server[]>;
  getServer(id: string): Promise<Server | undefined>;
  getServersByIds(ids: string[]): Promise<Server[]>;
  createServer(orgId: string, server: InsertServer): Promise<Server>;
  updateServer(id: string, data: Partial<Server>): Promise<Server | undefined>;
  deleteServer(id: string): Promise<boolean>;

  getSessions(orgId: string): Promise<Session[]>;
  getSession(id: string): Promise<Session | undefined>;
  getSessionsByUserId(userId: string): Promise<Session[]>;
  createSession(orgId: string, session: InsertSession): Promise<Session>;
  updateSession(id: string, data: Partial<Session>): Promise<Session | undefined>;
  endSession(id: string): Promise<boolean>;
}

// PostgreSQL connection pool and Drizzle instance
let pool: pg.Pool;
let db: ReturnType<typeof drizzle>;

export async function initDatabase() {
  const connectionString = process.env.DATABASE_URL || "postgresql://localhost:5432/keylessh";

  pool = new pg.Pool({
    connectionString,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
    ssl: connectionString.includes('azure') ? { rejectUnauthorized: false } : undefined,
  });

  pool.on("error", (err: Error) => {
    console.error("Unexpected PG pool error:", err);
  });

  db = drizzle(pool);

  // Seed: Create default organization if it doesn't exist
  try {
    const [existingOrg] = await db.select({ id: organizations.id })
      .from(organizations)
      .where(eq(organizations.id, DEFAULT_ORG_ID))
      .limit(1);

    if (!existingOrg) {
      await db.insert(organizations).values({
        id: DEFAULT_ORG_ID,
        name: DEFAULT_ORG_NAME,
        slug: DEFAULT_ORG_SLUG,
        createdAt: new Date(),
      });
      console.log(`[Storage] Created default organization: ${DEFAULT_ORG_NAME}`);
    }
  } catch (err) {
    console.error(`[Storage] Failed to seed default organization: ${err}`);
  }

  // Seed: Create default bridge from BRIDGE_URL env var if no bridges exist
  try {
    const bridgeUrl = process.env.BRIDGE_URL;
    if (bridgeUrl) {
      const { rows } = await pool.query(`SELECT COUNT(*) as count FROM bridges`);
      if (parseInt(rows[0].count) === 0) {
        const id = randomUUID();
        await db.insert(bridges).values({
          id,
          name: "Default Bridge",
          url: bridgeUrl,
          description: "Auto-created from BRIDGE_URL environment variable",
          enabled: true,
          isDefault: true,
          createdAt: new Date(),
          organizationId: DEFAULT_ORG_ID,
        });
        console.log(`[Storage] Created default bridge from BRIDGE_URL: ${bridgeUrl}`);
      }
    }
  } catch (err) {
    console.error(`[Storage] Failed to seed default bridge: ${err}`);
  }

  // Seed or update default SSH template
  await seedDefaultTemplate();
}

export async function closeDatabase() {
  if (pool) {
    await pool.end();
  }
}

// Default SSH policy template
const DEFAULT_SSH_TEMPLATE = {
  name: "SSH Access Policy",
  description:
    "Standard SSH access policy with role-based authorization. Uses [PolicyParam] attributes and DecisionBuilder for clean, declarative policy logic.",
  csCode: `using Ork.Forseti.Sdk;
using System;
using System.Collections.Generic;
using System.Text;

/// <summary>
/// SSH Challenge Signing Policy for Keyle-SSH.
/// Uses [PolicyParam] attributes for automatic parameter binding and
/// DecisionBuilder for composable policy validation.
/// </summary>
public class Contract : IAccessPolicy
{
    [PolicyParam(Required = true, Description = "Role required for SSH access.")]
    public string Role { get; set; }

    [PolicyParam(Required = true, Description = "Resource identifier for role check.")]
    public string Resource { get; set; }

    /// <summary>
    /// Validate the request data. Always called.
    /// This validates ctx.Data is an SSHv2 publickey authentication "to-be-signed" payload:
    /// string session_id || byte 50 || string user || string "ssh-connection" || string "publickey" || bool TRUE
    /// || string alg || string key_blob
    /// </summary>
    public PolicyDecision ValidateData(DataContext ctx)
    {
        if (string.IsNullOrWhiteSpace(Role))
            return PolicyDecision.Deny("Role is missing.");

        var parts = Role.Split(':', 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2 || parts[1].Length == 0)
            return PolicyDecision.Deny("Role must be in the form 'prefix:role'.");

        var userRole = parts[1];

        if (ctx == null || ctx.Data == null || ctx.Data.Length == 0)
            return PolicyDecision.Deny("No data provided for SSH challenge validation");

        if (ctx.Data.Length < 24)
            return PolicyDecision.Deny($"Data too short to be an SSH publickey challenge: {ctx.Data.Length} bytes");

        if (ctx.Data.Length > 8192)
            return PolicyDecision.Deny($"Data too large for SSH challenge: {ctx.Data.Length} bytes (maximum 8192)");

        if (!SshPublicKeyChallenge.TryParse(ctx.Data, out var parsed, out var err))
            return PolicyDecision.Deny(err);

        if (parsed.PublicKeyAlgorithm != "ssh-ed25519")
            return PolicyDecision.Deny("Only ssh-ed25519 allowed");

        if(parsed.Username != userRole) {
            return PolicyDecision.Deny("Not allowed to log in as " + parsed.Username);
        }

        return PolicyDecision.Allow();
    }

    public PolicyDecision ValidateApprovers(ApproversContext ctx)
    {
        var approvers = DokenDto.WrapAll(ctx.Dokens);
        return Decision
            .Require(approvers != null && approvers.Count > 0, "No approver dokens provided")
            .RequireAnyWithRole(approvers, Resource, Role);
    }

    public PolicyDecision ValidateExecutor(ExecutorContext ctx)
    {
        var executor = new DokenDto(ctx.Doken);
        return Decision
            .RequireNotExpired(executor)
            .RequireRole(executor, Resource, Role);
    }

    internal static class SshPublicKeyChallenge
    {
        internal sealed class Parsed
        {
            public int SessionIdLength { get; set; }
            public string Username { get; set; }
            public string Service { get; set; }
            public string Method { get; set; }
            public string PublicKeyAlgorithm { get; set; }
            public string PublicKeyBlobType { get; set; }
            public int PublicKeyBlobLength { get; set; }
        }

        public static bool TryParse(byte[] buf, out Parsed parsed, out string error)
        {
            parsed = null;
            error = "";

            int off = 0;

            // session_id (ssh string)
            if (!TryReadSshString(buf, ref off, out var sessionId))
            {
                error = "Invalid SSH string for session_id";
                return false;
            }

            // Common session_id lengths: 20/32/48/64
            if (!(sessionId.Length == 20 || sessionId.Length == 32 || sessionId.Length == 48 || sessionId.Length == 64))
            {
                error = $"Unexpected session_id length: {sessionId.Length}";
                return false;
            }

            // message type
            if (!TryReadByte(buf, ref off, out byte msg))
            {
                error = "Missing SSH message type";
                return false;
            }

            if (msg != 50) // SSH_MSG_USERAUTH_REQUEST
            {
                error = $"Not SSH userauth request (expected msg 50, got {msg})";
                return false;
            }

            // username, service, method
            if (!TryReadSshAscii(buf, ref off, 256, out var username, out error)) return false;
            if (!TryReadSshAscii(buf, ref off, 64, out var service, out error)) return false;
            if (!TryReadSshAscii(buf, ref off, 64, out var method, out error)) return false;

            if (!string.Equals(service, "ssh-connection", StringComparison.Ordinal))
            {
                error = $"Unexpected SSH service: {service}";
                return false;
            }

            if (!string.Equals(method, "publickey", StringComparison.Ordinal))
            {
                error = $"Unexpected SSH auth method: {method}";
                return false;
            }

            // boolean TRUE
            if (!TryReadByte(buf, ref off, out byte hasSig))
            {
                error = "Missing publickey boolean";
                return false;
            }

            if (hasSig != 1)
            {
                error = "Expected publickey boolean TRUE (1)";
                return false;
            }

            // algorithm
            if (!TryReadSshAscii(buf, ref off, 128, out var alg, out error)) return false;

            // Allowlist
            var allowed = new HashSet<string>(StringComparer.Ordinal)
            {
                "ssh-ed25519",
                "rsa-sha2-256",
                "rsa-sha2-512",
                "ecdsa-sha2-nistp256",
                "ecdsa-sha2-nistp384",
                "ecdsa-sha2-nistp521",
            };

            if (!allowed.Contains(alg))
            {
                error = $"Disallowed/unknown SSH public key algorithm: {alg}";
                return false;
            }

            // key blob
            if (!TryReadSshString(buf, ref off, out var keyBlob))
            {
                error = "Invalid SSH string for publickey blob";
                return false;
            }

            if (keyBlob.Length < 8)
            {
                error = "Publickey blob too short";
                return false;
            }

            // key blob begins with ssh string key type
            int kbOff = 0;
            if (!TryReadSshString(keyBlob, ref kbOff, out var keyTypeBytes))
            {
                error = "Invalid publickey blob (missing key type string)";
                return false;
            }

            var keyType = AsciiString(keyTypeBytes, 64);
            if (keyType == null)
            {
                error = "Invalid publickey blob key type (non-ASCII or too long)";
                return false;
            }

            if (!IsAlgConsistentWithKeyType(alg, keyType))
            {
                error = $"Algorithm/key type mismatch: alg={alg}, keyType={keyType}";
                return false;
            }

            // Strict: no trailing bytes
            if (off != buf.Length)
            {
                error = $"Unexpected trailing data: {buf.Length - off} bytes";
                return false;
            }

            parsed = new Parsed
            {
                SessionIdLength = sessionId.Length,
                Username = username,
                Service = service,
                Method = method,
                PublicKeyAlgorithm = alg,
                PublicKeyBlobType = keyType,
                PublicKeyBlobLength = keyBlob.Length
            };

            return true;
        }

        private static bool IsAlgConsistentWithKeyType(string alg, string keyType)
        {
            if (alg == "ssh-ed25519") return keyType == "ssh-ed25519";
            if (alg == "rsa-sha2-256" || alg == "rsa-sha2-512") return keyType == "ssh-rsa";
            if (alg.StartsWith("ecdsa-sha2-nistp", StringComparison.Ordinal)) return keyType == alg;
            return false;
        }

        private static bool TryReadByte(byte[] buf, ref int off, out byte b)
        {
            b = 0;
            if (off >= buf.Length) return false;
            b = buf[off++];
            return true;
        }

        private static bool TryReadU32(byte[] buf, ref int off, out uint v)
        {
            v = 0;
            if (off + 4 > buf.Length) return false;
            v = (uint)(buf[off] << 24 | buf[off + 1] << 16 | buf[off + 2] << 8 | buf[off + 3]);
            off += 4;
            return true;
        }

        // SSH "string" = uint32 len + len bytes
        private static bool TryReadSshString(byte[] buf, ref int off, out byte[] s)
        {
            s = null;
            if (!TryReadU32(buf, ref off, out var len)) return false;
            if (len > (uint)(buf.Length - off)) return false;

            s = new byte[(int)len];
            Buffer.BlockCopy(buf, off, s, 0, (int)len);
            off += (int)len;
            return true;
        }

        private static bool TryReadSshAscii(byte[] buf, ref int off, int maxLen, out string value, out string error)
        {
            value = "";
            error = "";

            if (!TryReadSshString(buf, ref off, out var bytes))
            {
                error = "Invalid SSH string field";
                return false;
            }

            if (bytes.Length == 0 || bytes.Length > maxLen)
            {
                error = $"Invalid field length: {bytes.Length} (max {maxLen})";
                return false;
            }

            var s = AsciiString(bytes, maxLen);
            if (s == null)
            {
                error = "Field contains non-ASCII or control characters";
                return false;
            }

            value = s;
            return true;
        }

        private static string AsciiString(byte[] bytes, int maxLen)
        {
            if (bytes.Length == 0 || bytes.Length > maxLen) return null;

            for (int i = 0; i < bytes.Length; i++)
            {
                byte c = bytes[i];
                if (c < 0x20 || c > 0x7E) return null;
            }

            return Encoding.ASCII.GetString(bytes);
        }
    }
}`,
  parameters: [] as TemplateParameter[],
  createdBy: "system",
};

async function seedDefaultTemplate() {
  try {
    const { rows } = await pool.query(
      `SELECT id, cs_code FROM policy_templates WHERE name = $1 AND created_by = 'system'`,
      [DEFAULT_SSH_TEMPLATE.name]
    );

    if (rows.length === 0) {
      const id = randomUUID();
      await db.insert(policyTemplates).values({
        id,
        name: DEFAULT_SSH_TEMPLATE.name,
        description: DEFAULT_SSH_TEMPLATE.description,
        csCode: DEFAULT_SSH_TEMPLATE.csCode,
        parameters: DEFAULT_SSH_TEMPLATE.parameters,
        createdBy: DEFAULT_SSH_TEMPLATE.createdBy,
        createdAt: new Date(),
        organizationId: DEFAULT_ORG_ID,
      });
    } else if (rows[0].cs_code !== DEFAULT_SSH_TEMPLATE.csCode) {
      await pool.query(
        `UPDATE policy_templates SET cs_code = $1, description = $2, parameters = $3, updated_at = NOW() WHERE id = $4`,
        [DEFAULT_SSH_TEMPLATE.csCode, DEFAULT_SSH_TEMPLATE.description, JSON.stringify(DEFAULT_SSH_TEMPLATE.parameters), rows[0].id]
      );
    }
  } catch {
    // Ignore seeding errors
  }
}

export class SQLiteStorage implements IStorage {
  async getUser(id: string): Promise<User | undefined> {
    const [result] = await db.select().from(users).where(eq(users.id, id)).limit(1);
    return result;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [result] = await db.select().from(users).where(eq(users.username, username)).limit(1);
    return result;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = randomUUID();
    const user: User = {
      id,
      username: insertUser.username,
      email: insertUser.email,
      role: insertUser.role ?? "user",
      allowedServers: (insertUser.allowedServers ?? []) as string[],
    };
    await db.insert(users).values(user);
    return user;
  }

  async getUsers(): Promise<User[]> {
    return await db.select().from(users);
  }

  async updateUser(id: string, data: Partial<User>): Promise<User | undefined> {
    const existing = await this.getUser(id);
    if (!existing) return undefined;

    const updated = { ...existing, ...data, id };
    await db.update(users).set(updated).where(eq(users.id, id));
    return updated;
  }

  async getServers(orgId: string): Promise<Server[]> {
    return await db.select().from(servers).where(eq(servers.organizationId, orgId));
  }

  async getServer(id: string): Promise<Server | undefined> {
    const [result] = await db.select().from(servers).where(eq(servers.id, id)).limit(1);
    return result;
  }

  async getServersByIds(ids: string[]): Promise<Server[]> {
    if (ids.length === 0) return [];
    return await db.select().from(servers).where(inArray(servers.id, ids));
  }

  async createServer(orgId: string, insertServer: InsertServer): Promise<Server> {
    const id = randomUUID();
    const server: Server = {
      id,
      name: insertServer.name,
      host: insertServer.host,
      port: insertServer.port ?? 22,
      environment: insertServer.environment ?? "production",
      tags: (insertServer.tags ?? []) as string[],
      enabled: insertServer.enabled ?? true,
      sshUsers: (insertServer.sshUsers ?? []) as string[],
      recordingEnabled: insertServer.recordingEnabled ?? false,
      recordedUsers: (insertServer.recordedUsers ?? []) as string[],
      bridgeId: insertServer.bridgeId ?? null,
      organizationId: orgId,
    };
    await db.insert(servers).values(server);
    return server;
  }

  async updateServer(id: string, data: Partial<Server>): Promise<Server | undefined> {
    const existing = await this.getServer(id);
    if (!existing) return undefined;

    const updated = { ...existing, ...data, id };
    await db.update(servers).set(updated).where(eq(servers.id, id));
    return updated;
  }

  async deleteServer(id: string): Promise<boolean> {
    const result = await db.delete(servers).where(eq(servers.id, id)).returning({ id: servers.id });
    return result.length > 0;
  }

  async getSessions(orgId: string): Promise<Session[]> {
    return await db.select().from(sessions).where(eq(sessions.organizationId, orgId)).orderBy(desc(sessions.startedAt));
  }

  async getSession(id: string): Promise<Session | undefined> {
    const [result] = await db.select().from(sessions).where(eq(sessions.id, id)).limit(1);
    return result;
  }

  async getSessionsByUserId(userId: string): Promise<Session[]> {
    return await db
      .select()
      .from(sessions)
      .where(eq(sessions.userId, userId))
      .orderBy(desc(sessions.startedAt));
  }

  async createSession(orgId: string, insertSession: InsertSession): Promise<Session> {
    const id = randomUUID();
    const session: Session = {
      id,
      userId: insertSession.userId,
      userUsername: insertSession.userUsername ?? null,
      userEmail: insertSession.userEmail ?? null,
      serverId: insertSession.serverId,
      sshUser: insertSession.sshUser,
      status: insertSession.status ?? "active",
      startedAt: new Date(),
      endedAt: null,
      recordingId: insertSession.recordingId ?? null,
      organizationId: orgId,
    };
    await db.insert(sessions).values(session);
    return session;
  }

  async updateSession(id: string, data: Partial<Session>): Promise<Session | undefined> {
    const existing = await this.getSession(id);
    if (!existing) return undefined;

    const updated = { ...existing, ...data, id };
    await db.update(sessions).set(updated).where(eq(sessions.id, id));
    return updated;
  }

  async endSession(id: string): Promise<boolean> {
    const result = await db
      .update(sessions)
      .set({ status: "completed", endedAt: new Date() })
      .where(eq(sessions.id, id))
      .returning({ id: sessions.id });
    return result.length > 0;
  }

  async cleanupStaleSessions(maxAgeMs: number = 24 * 60 * 60 * 1000): Promise<number> {
    const cutoff = new Date(Date.now() - maxAgeMs);
    const result = await db
      .update(sessions)
      .set({ status: "completed", endedAt: new Date() })
      .where(and(eq(sessions.status, "active"), lt(sessions.startedAt, cutoff)))
      .returning({ id: sessions.id });
    return result.length;
  }
}

// Approval types
export type ApprovalType = 'user_create' | 'user_update' | 'user_delete' | 'role_assign' | 'role_remove';
export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'committed' | 'cancelled';

export interface PendingApproval {
  id: string;
  type: ApprovalType;
  requestedBy: string;
  targetUserId?: string;
  targetUserEmail?: string;
  data: string;
  status: ApprovalStatus;
  createdAt: number;
  updatedAt?: number;
  approvedBy?: string[];
  deniedBy?: string[];
}

export interface ApprovalDecision {
  id: number;
  approvalId: string;
  userVuid: string;
  userEmail: string;
  decision: number;
  createdAt: number;
}

export interface AccessChangeLog {
  id: number;
  timestamp: number;
  type: string;
  approvalId: string;
  userEmail: string;
  targetUser?: string;
  details?: string;
}

// Approval storage class
export class ApprovalStorage {
  async getPendingApprovals(orgId: string): Promise<PendingApproval[]> {
    const { rows } = await pool.query(
      `SELECT * FROM pending_approvals WHERE status = 'pending' AND organization_id = $1 ORDER BY created_at DESC`,
      [orgId]
    );

    return Promise.all(rows.map(async (row: any) => {
      const approversResult = await pool.query(
        `SELECT user_vuid FROM approval_decisions WHERE approval_id = $1 AND decision = 1`,
        [row.id]
      );
      const deniersResult = await pool.query(
        `SELECT user_vuid FROM approval_decisions WHERE approval_id = $1 AND decision = 0`,
        [row.id]
      );

      return {
        id: row.id,
        type: row.type as ApprovalType,
        requestedBy: row.requested_by,
        targetUserId: row.target_user_id,
        targetUserEmail: row.target_user_email,
        data: row.data,
        status: row.status as ApprovalStatus,
        createdAt: Math.floor(new Date(row.created_at).getTime() / 1000),
        updatedAt: row.updated_at ? Math.floor(new Date(row.updated_at).getTime() / 1000) : undefined,
        approvedBy: approversResult.rows.map((a: any) => a.user_vuid),
        deniedBy: deniersResult.rows.map((d: any) => d.user_vuid),
      };
    }));
  }

  async createApproval(
    orgId: string,
    type: ApprovalType,
    requestedBy: string,
    data: any,
    targetUserId?: string,
    targetUserEmail?: string
  ): Promise<string> {
    const id = randomUUID();
    await pool.query(
      `INSERT INTO pending_approvals (id, type, requested_by, target_user_id, target_user_email, data, status, organization_id)
       VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7)`,
      [id, type, requestedBy, targetUserId, targetUserEmail, JSON.stringify(data), orgId]
    );

    await this.addAccessChangeLog('created', id, requestedBy, targetUserEmail, JSON.stringify(data));
    return id;
  }

  async addDecision(
    approvalId: string,
    userVuid: string,
    userEmail: string,
    approved: boolean
  ): Promise<boolean> {
    try {
      await pool.query(
        `INSERT INTO approval_decisions (approval_id, user_vuid, user_email, decision)
         VALUES ($1, $2, $3, $4)`,
        [approvalId, userVuid, userEmail, approved ? 1 : 0]
      );

      await this.addAccessChangeLog(
        approved ? 'approved' : 'denied',
        approvalId,
        userEmail,
        undefined,
        undefined
      );

      return true;
    } catch (error) {
      console.error('Error adding decision:', error);
      return false;
    }
  }

  async removeDecision(approvalId: string, userVuid: string): Promise<boolean> {
    const result = await pool.query(
      `DELETE FROM approval_decisions WHERE approval_id = $1 AND user_vuid = $2`,
      [approvalId, userVuid]
    );
    return (result.rowCount ?? 0) > 0;
  }

  async commitApproval(id: string, userEmail: string): Promise<boolean> {
    const result = await pool.query(
      `UPDATE pending_approvals SET status = 'committed', updated_at = NOW()
       WHERE id = $1 AND status = 'pending'`,
      [id]
    );

    if ((result.rowCount ?? 0) > 0) {
      await this.addAccessChangeLog('committed', id, userEmail);
    }

    return (result.rowCount ?? 0) > 0;
  }

  async cancelApproval(id: string, userEmail: string): Promise<boolean> {
    const result = await pool.query(
      `UPDATE pending_approvals SET status = 'cancelled', updated_at = NOW()
       WHERE id = $1 AND status = 'pending'`,
      [id]
    );

    if ((result.rowCount ?? 0) > 0) {
      await this.addAccessChangeLog('cancelled', id, userEmail);
    }

    return (result.rowCount ?? 0) > 0;
  }

  async deleteApproval(id: string, userEmail: string): Promise<boolean> {
    const approvalResult = await pool.query(
      `SELECT target_user_email FROM pending_approvals WHERE id = $1`,
      [id]
    );
    const approval = approvalResult.rows[0];

    const result = await pool.query(
      `DELETE FROM pending_approvals WHERE id = $1`,
      [id]
    );

    if ((result.rowCount ?? 0) > 0) {
      await this.addAccessChangeLog('deleted', id, userEmail, approval?.target_user_email);
    }

    return (result.rowCount ?? 0) > 0;
  }

  async getApproval(id: string): Promise<PendingApproval | undefined> {
    const { rows } = await pool.query(
      `SELECT * FROM pending_approvals WHERE id = $1`,
      [id]
    );

    if (rows.length === 0) return undefined;
    const row = rows[0];

    const approversResult = await pool.query(
      `SELECT user_vuid FROM approval_decisions WHERE approval_id = $1 AND decision = 1`,
      [id]
    );
    const deniersResult = await pool.query(
      `SELECT user_vuid FROM approval_decisions WHERE approval_id = $1 AND decision = 0`,
      [id]
    );

    return {
      id: row.id,
      type: row.type as ApprovalType,
      requestedBy: row.requested_by,
      targetUserId: row.target_user_id,
      targetUserEmail: row.target_user_email,
      data: row.data,
      status: row.status as ApprovalStatus,
      createdAt: Math.floor(new Date(row.created_at).getTime() / 1000),
      updatedAt: row.updated_at ? Math.floor(new Date(row.updated_at).getTime() / 1000) : undefined,
      approvedBy: approversResult.rows.map((a: any) => a.user_vuid),
      deniedBy: deniersResult.rows.map((d: any) => d.user_vuid),
    };
  }

  async addAccessChangeLog(
    type: string,
    approvalId: string,
    userEmail: string,
    targetUser?: string,
    details?: string
  ): Promise<void> {
    await pool.query(
      `INSERT INTO access_change_logs (type, approval_id, user_email, target_user, details)
       VALUES ($1, $2, $3, $4, $5)`,
      [type, approvalId, userEmail, targetUser, details]
    );
  }

  async getAccessChangeLogs(limit: number = 100, offset: number = 0): Promise<AccessChangeLog[]> {
    const { rows } = await pool.query(
      `SELECT * FROM access_change_logs ORDER BY timestamp DESC LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    return rows.map((row: any) => ({
      id: row.id,
      timestamp: Math.floor(new Date(row.timestamp).getTime() / 1000),
      type: row.type,
      approvalId: row.approval_id,
      userEmail: row.user_email,
      targetUser: row.target_user,
      details: row.details,
    }));
  }
}

// SSH Policy types
export interface SshPolicy {
  roleId: string;
  contractType: string;
  approvalType: "implicit" | "explicit";
  executionType: "public" | "private";
  threshold: number;
  policyData?: string;
  createdAt: number;
  updatedAt?: number;
}

export interface InsertSshPolicy {
  roleId: string;
  contractType: string;
  approvalType: "implicit" | "explicit";
  executionType: "public" | "private";
  threshold: number;
  policyData?: string;
}

// SSH Policy storage class
export class PolicyStorage {
  async upsertPolicy(policy: InsertSshPolicy): Promise<SshPolicy> {
    const existing = await this.getPolicy(policy.roleId);

    if (existing) {
      await pool.query(
        `UPDATE ssh_policies
         SET contract_type = $1, approval_type = $2, execution_type = $3, threshold = $4, policy_data = $5, updated_at = NOW()
         WHERE role_id = $6`,
        [policy.contractType, policy.approvalType, policy.executionType, policy.threshold, policy.policyData || null, policy.roleId]
      );

      return {
        ...policy,
        createdAt: existing.createdAt,
        updatedAt: Math.floor(Date.now() / 1000),
      };
    } else {
      await pool.query(
        `INSERT INTO ssh_policies (role_id, contract_type, approval_type, execution_type, threshold, policy_data)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [policy.roleId, policy.contractType, policy.approvalType, policy.executionType, policy.threshold, policy.policyData || null]
      );

      return {
        ...policy,
        createdAt: Math.floor(Date.now() / 1000),
      };
    }
  }

  async getPolicy(roleId: string): Promise<SshPolicy | undefined> {
    const { rows } = await pool.query(
      `SELECT * FROM ssh_policies WHERE role_id = $1`,
      [roleId]
    );

    if (rows.length === 0) return undefined;
    const row = rows[0];

    return {
      roleId: row.role_id,
      contractType: row.contract_type,
      approvalType: row.approval_type as "implicit" | "explicit",
      executionType: row.execution_type as "public" | "private",
      threshold: row.threshold,
      policyData: row.policy_data || undefined,
      createdAt: Math.floor(new Date(row.created_at).getTime() / 1000),
      updatedAt: row.updated_at ? Math.floor(new Date(row.updated_at).getTime() / 1000) : undefined,
    };
  }

  async getAllPolicies(orgId: string): Promise<SshPolicy[]> {
    const { rows } = await pool.query(
      `SELECT * FROM ssh_policies WHERE organization_id = $1 ORDER BY created_at DESC`,
      [orgId]
    );

    return rows.map((row: any) => ({
      roleId: row.role_id,
      contractType: row.contract_type,
      approvalType: row.approval_type as "implicit" | "explicit",
      executionType: row.execution_type as "public" | "private",
      threshold: row.threshold,
      policyData: row.policy_data || undefined,
      createdAt: Math.floor(new Date(row.created_at).getTime() / 1000),
      updatedAt: row.updated_at ? Math.floor(new Date(row.updated_at).getTime() / 1000) : undefined,
    }));
  }

  async deletePolicy(roleId: string): Promise<boolean> {
    const result = await pool.query(
      `DELETE FROM ssh_policies WHERE role_id = $1`,
      [roleId]
    );
    return (result.rowCount ?? 0) > 0;
  }
}

// Pending SSH Policy types
export interface PendingSshPolicy {
  id: string;
  roleId: string;
  requestedBy: string;
  requestedByEmail?: string;
  policyRequestData: string;
  contractCode?: string;
  status: "pending" | "approved" | "committed" | "cancelled";
  threshold: number;
  createdAt: number;
  updatedAt?: number;
  approvalCount?: number;
  rejectionCount?: number;
  approvedBy?: string[];
  deniedBy?: string[];
  commitReady?: boolean;
}

export interface InsertPendingSshPolicy {
  id: string;
  roleId: string;
  requestedBy: string;
  requestedByEmail?: string;
  policyRequestData: string;
  contractCode?: string;
  threshold?: number;
}

export interface SshPolicyDecision {
  policyRequestId: string;
  userVuid: string;
  userEmail: string;
  decision: 0 | 1;
  createdAt: number;
}

// Pending SSH Policy storage class
export class PendingPolicyStorage {
  async createPendingPolicy(policy: InsertPendingSshPolicy): Promise<PendingSshPolicy> {
    await pool.query(
      `INSERT INTO pending_ssh_policies (id, role_id, requested_by, requested_by_email, policy_request_data, contract_code, threshold)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [policy.id, policy.roleId, policy.requestedBy, policy.requestedByEmail || null, policy.policyRequestData, policy.contractCode || null, policy.threshold || 1]
    );

    const threshold = policy.threshold || 1;
    await pool.query(
      `INSERT INTO ssh_policy_logs (type, policy_request_id, user_email, role_id, details, status, approval_count, threshold)
       VALUES ('created', $1, $2, $3, $4, 'pending', 0, $5)`,
      [policy.id, policy.requestedByEmail || policy.requestedBy, policy.roleId, JSON.stringify({ threshold }), threshold]
    );

    return {
      ...policy,
      status: "pending",
      threshold: policy.threshold || 1,
      createdAt: Math.floor(Date.now() / 1000),
    };
  }

  async getPendingPolicy(id: string): Promise<PendingSshPolicy | undefined> {
    const { rows } = await pool.query(
      `SELECT p.*,
        (SELECT COUNT(*) FROM ssh_policy_decisions d WHERE d.policy_request_id = p.id AND d.decision = 1) as approval_count,
        (SELECT COUNT(*) FROM ssh_policy_decisions d WHERE d.policy_request_id = p.id AND d.decision = 0) as rejection_count
       FROM pending_ssh_policies p WHERE p.id = $1`,
      [id]
    );

    if (rows.length === 0) return undefined;
    const row = rows[0];

    return {
      id: row.id,
      roleId: row.role_id,
      requestedBy: row.requested_by,
      requestedByEmail: row.requested_by_email,
      policyRequestData: row.policy_request_data,
      contractCode: row.contract_code,
      status: row.status as "pending" | "approved" | "committed" | "cancelled",
      threshold: row.threshold,
      createdAt: Math.floor(new Date(row.created_at).getTime() / 1000),
      updatedAt: row.updated_at ? Math.floor(new Date(row.updated_at).getTime() / 1000) : undefined,
      approvalCount: parseInt(row.approval_count),
      rejectionCount: parseInt(row.rejection_count),
    };
  }

  async getAllPendingPolicies(orgId: string): Promise<PendingSshPolicy[]> {
    const { rows } = await pool.query(
      `SELECT p.*,
        (SELECT COUNT(*) FROM ssh_policy_decisions d WHERE d.policy_request_id = p.id AND d.decision = 1) as approval_count,
        (SELECT COUNT(*) FROM ssh_policy_decisions d WHERE d.policy_request_id = p.id AND d.decision = 0) as rejection_count,
        (SELECT STRING_AGG(user_vuid, ',') FROM ssh_policy_decisions d WHERE d.policy_request_id = p.id AND d.decision = 1) as approved_by,
        (SELECT STRING_AGG(user_vuid, ',') FROM ssh_policy_decisions d WHERE d.policy_request_id = p.id AND d.decision = 0) as denied_by
       FROM pending_ssh_policies p
       WHERE p.status IN ('pending', 'approved') AND p.organization_id = $1
       ORDER BY p.created_at DESC`,
      [orgId]
    );

    let adminPolicyBytes: Uint8Array | null = null;
    try {
      const adminPolicyBase64 = await getAdminPolicy();
      adminPolicyBytes = base64ToBytes(adminPolicyBase64);
    } catch (error) {
      console.error("Failed to fetch admin policy:", error);
    }

    const policies = await Promise.all(rows.map(async (row: any) => {
      const approvalCount = parseInt(row.approval_count) || 0;
      const isCommitReady = approvalCount >= row.threshold;
      let policyRequestData = row.policy_request_data;

      if (isCommitReady && adminPolicyBytes) {
        try {
          const request = PolicySignRequest.decode(base64ToBytes(policyRequestData));
          request.addPolicy(adminPolicyBytes);
          const updatedData = bytesToBase64(request.encode());

          await pool.query(
            `UPDATE pending_ssh_policies SET policy_request_data = $1 WHERE id = $2`,
            [updatedData, row.id]
          );

          policyRequestData = updatedData;
        } catch (error) {
          console.error(`Failed to add admin policy to request ${row.id}:`, error);
        }
      }

      return {
        id: row.id,
        roleId: row.role_id,
        requestedBy: row.requested_by,
        requestedByEmail: row.requested_by_email,
        policyRequestData,
        contractCode: row.contract_code,
        status: row.status as "pending" | "approved" | "committed" | "cancelled",
        threshold: row.threshold,
        createdAt: Math.floor(new Date(row.created_at).getTime() / 1000),
        updatedAt: row.updated_at ? Math.floor(new Date(row.updated_at).getTime() / 1000) : undefined,
        approvalCount,
        rejectionCount: parseInt(row.rejection_count) || 0,
        approvedBy: row.approved_by ? row.approved_by.split(',') : [],
        deniedBy: row.denied_by ? row.denied_by.split(',') : [],
        commitReady: isCommitReady,
      };
    }));

    return policies;
  }

  async addDecision(decision: Omit<SshPolicyDecision, "createdAt">): Promise<void> {
    await pool.query(
      `INSERT INTO ssh_policy_decisions (policy_request_id, user_vuid, user_email, decision)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT(policy_request_id, user_vuid) DO UPDATE SET decision = EXCLUDED.decision, created_at = NOW()`,
      [decision.policyRequestId, decision.userVuid, decision.userEmail, decision.decision]
    );

    const policy = await this.getPendingPolicy(decision.policyRequestId);
    const logType = decision.decision === 1 ? "approved" : "denied";
    const approvalCount = policy?.approvalCount || 0;
    const threshold = policy?.threshold || 1;

    let statusAfterAction = "pending";
    if (decision.decision === 1 && approvalCount >= threshold) {
      statusAfterAction = "approved";
      await this.updateStatus(decision.policyRequestId, "approved");
    }

    await pool.query(
      `INSERT INTO ssh_policy_logs (type, policy_request_id, user_email, role_id, status, approval_count, threshold)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [logType, decision.policyRequestId, decision.userEmail, policy?.roleId || null, statusAfterAction, approvalCount, threshold]
    );
  }

  async updateStatus(id: string, status: "pending" | "approved" | "committed" | "cancelled"): Promise<void> {
    await pool.query(
      `UPDATE pending_ssh_policies SET status = $1, updated_at = NOW() WHERE id = $2`,
      [status, id]
    );
  }

  async getDecisions(policyRequestId: string): Promise<SshPolicyDecision[]> {
    const { rows } = await pool.query(
      `SELECT * FROM ssh_policy_decisions WHERE policy_request_id = $1 ORDER BY created_at DESC`,
      [policyRequestId]
    );

    return rows.map((row: any) => ({
      policyRequestId: row.policy_request_id,
      userVuid: row.user_vuid,
      userEmail: row.user_email,
      decision: row.decision as 0 | 1,
      createdAt: Math.floor(new Date(row.created_at).getTime() / 1000),
    }));
  }

  async hasUserVoted(policyRequestId: string, userVuid: string): Promise<boolean> {
    const { rows } = await pool.query(
      `SELECT 1 FROM ssh_policy_decisions WHERE policy_request_id = $1 AND user_vuid = $2`,
      [policyRequestId, userVuid]
    );
    return rows.length > 0;
  }

  async getUserDecision(policyRequestId: string, userVuid: string): Promise<number | null> {
    const { rows } = await pool.query(
      `SELECT decision FROM ssh_policy_decisions WHERE policy_request_id = $1 AND user_vuid = $2`,
      [policyRequestId, userVuid]
    );
    return rows.length > 0 ? rows[0].decision : null;
  }

  async updatePolicyRequest(id: string, policyRequestData: string): Promise<void> {
    await pool.query(
      `UPDATE pending_ssh_policies SET policy_request_data = $1 WHERE id = $2`,
      [policyRequestData, id]
    );
  }

  async revokeDecision(policyRequestId: string, userVuid: string): Promise<boolean> {
    const result = await pool.query(
      `DELETE FROM ssh_policy_decisions WHERE policy_request_id = $1 AND user_vuid = $2`,
      [policyRequestId, userVuid]
    );
    return (result.rowCount ?? 0) > 0;
  }

  async commitPolicy(id: string, userEmail: string): Promise<void> {
    const policy = await this.getPendingPolicy(id);
    if (!policy) throw new Error("Policy not found");
    if (policy.status !== "approved") throw new Error("Policy not approved yet");

    await this.updateStatus(id, "committed");

    await pool.query(
      `INSERT INTO ssh_policy_logs (type, policy_request_id, user_email, role_id, status, approval_count, threshold)
       VALUES ('committed', $1, $2, $3, 'committed', $4, $5)`,
      [id, userEmail, policy.roleId, policy.approvalCount || 0, policy.threshold]
    );
  }

  async cancelPolicy(id: string, userEmail: string): Promise<void> {
    const policy = await this.getPendingPolicy(id);
    if (!policy) throw new Error("Policy not found");

    await this.updateStatus(id, "cancelled");

    await pool.query(
      `INSERT INTO ssh_policy_logs (type, policy_request_id, user_email, role_id, status, approval_count, threshold)
       VALUES ('cancelled', $1, $2, $3, 'cancelled', $4, $5)`,
      [id, userEmail, policy.roleId, policy.approvalCount || 0, policy.threshold]
    );
  }

  async getLogs(limit: number = 100, offset: number = 0): Promise<any[]> {
    const { rows } = await pool.query(
      `SELECT
        l.*,
        p.created_at as policy_created_at,
        p.requested_by_email as policy_requested_by
       FROM ssh_policy_logs l
       LEFT JOIN pending_ssh_policies p ON l.policy_request_id = p.id
       ORDER BY l.timestamp DESC
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    return rows.map((row: any) => ({
      id: row.id,
      timestamp: Math.floor(new Date(row.timestamp).getTime() / 1000),
      type: row.type,
      policyRequestId: row.policy_request_id,
      userEmail: row.user_email,
      roleId: row.role_id,
      details: row.details,
      policyStatus: row.status,
      policyThreshold: row.threshold,
      policyCreatedAt: row.policy_created_at ? Math.floor(new Date(row.policy_created_at).getTime() / 1000) : undefined,
      policyRequestedBy: row.policy_requested_by,
      approvalCount: row.approval_count || 0,
    }));
  }
}

// Policy Template storage class
export class TemplateStorage {
  async createTemplate(orgId: string, template: InsertPolicyTemplate): Promise<PolicyTemplate> {
    const id = randomUUID();
    const now = new Date();

    await db.insert(policyTemplates).values({
      id,
      name: template.name,
      description: template.description,
      csCode: template.csCode,
      parameters: template.parameters,
      createdBy: template.createdBy,
      createdAt: now,
      organizationId: orgId,
    });

    return {
      id,
      name: template.name,
      description: template.description,
      csCode: template.csCode,
      parameters: template.parameters,
      createdBy: template.createdBy,
      createdAt: now,
    };
  }

  async getTemplate(id: string): Promise<PolicyTemplate | undefined> {
    const { rows } = await pool.query(
      `SELECT * FROM policy_templates WHERE id = $1`,
      [id]
    );

    if (rows.length === 0) return undefined;
    const row = rows[0];

    return {
      id: row.id,
      name: row.name,
      description: row.description,
      csCode: row.cs_code,
      parameters: (typeof row.parameters === 'string' ? JSON.parse(row.parameters) : row.parameters) as TemplateParameter[],
      createdBy: row.created_by,
      createdAt: new Date(row.created_at),
      updatedAt: row.updated_at ? new Date(row.updated_at) : undefined,
    };
  }

  async getTemplateByName(name: string): Promise<PolicyTemplate | undefined> {
    const { rows } = await pool.query(
      `SELECT * FROM policy_templates WHERE name = $1`,
      [name]
    );

    if (rows.length === 0) return undefined;
    const row = rows[0];

    return {
      id: row.id,
      name: row.name,
      description: row.description,
      csCode: row.cs_code,
      parameters: (typeof row.parameters === 'string' ? JSON.parse(row.parameters) : row.parameters) as TemplateParameter[],
      createdBy: row.created_by,
      createdAt: new Date(row.created_at),
      updatedAt: row.updated_at ? new Date(row.updated_at) : undefined,
    };
  }

  async getAllTemplates(orgId: string): Promise<PolicyTemplate[]> {
    const { rows } = await pool.query(
      `SELECT * FROM policy_templates WHERE organization_id = $1 ORDER BY created_at DESC`,
      [orgId]
    );

    return rows.map((row: any) => ({
      id: row.id,
      name: row.name,
      description: row.description,
      csCode: row.cs_code,
      parameters: (typeof row.parameters === 'string' ? JSON.parse(row.parameters) : row.parameters) as TemplateParameter[],
      createdBy: row.created_by,
      createdAt: new Date(row.created_at),
      updatedAt: row.updated_at ? new Date(row.updated_at) : undefined,
    }));
  }

  async updateTemplate(id: string, data: Partial<InsertPolicyTemplate>): Promise<PolicyTemplate | undefined> {
    const existing = await this.getTemplate(id);
    if (!existing) return undefined;

    const updates: string[] = [];
    const values: any[] = [];
    let paramIndex = 1;

    if (data.name !== undefined) {
      updates.push(`name = $${paramIndex++}`);
      values.push(data.name);
    }
    if (data.description !== undefined) {
      updates.push(`description = $${paramIndex++}`);
      values.push(data.description);
    }
    if (data.csCode !== undefined) {
      updates.push(`cs_code = $${paramIndex++}`);
      values.push(data.csCode);
    }
    if (data.parameters !== undefined) {
      updates.push(`parameters = $${paramIndex++}`);
      values.push(JSON.stringify(data.parameters));
    }

    if (updates.length > 0) {
      updates.push(`updated_at = NOW()`);
      values.push(id);

      await pool.query(
        `UPDATE policy_templates SET ${updates.join(', ')} WHERE id = $${paramIndex}`,
        values
      );
    }

    return this.getTemplate(id);
  }

  async deleteTemplate(id: string): Promise<boolean> {
    const result = await pool.query(
      `DELETE FROM policy_templates WHERE id = $1`,
      [id]
    );
    return (result.rowCount ?? 0) > 0;
  }
}

// Subscription storage class for license management
export class SubscriptionStorage {
  async getSubscription(orgId: string): Promise<Subscription | null> {
    const [row] = await db.select().from(subscriptions)
      .where(eq(subscriptions.organizationId, orgId))
      .orderBy(desc(subscriptions.createdAt))
      .limit(1);

    if (!row) return null;
    return row;
  }

  async upsertSubscription(orgId: string, data: Partial<InsertSubscription> & { tier?: SubscriptionTier }): Promise<Subscription> {
    const existing = await this.getSubscription(orgId);
    const now = new Date();

    if (existing) {
      const updates: string[] = [];
      const values: any[] = [];
      let paramIndex = 1;

      if (data.tier !== undefined) {
        updates.push(`tier = $${paramIndex++}`);
        values.push(data.tier);
      }
      if (data.stripeCustomerId !== undefined) {
        updates.push(`stripe_customer_id = $${paramIndex++}`);
        values.push(data.stripeCustomerId);
      }
      if (data.stripeSubscriptionId !== undefined) {
        updates.push(`stripe_subscription_id = $${paramIndex++}`);
        values.push(data.stripeSubscriptionId);
      }
      if (data.stripePriceId !== undefined) {
        updates.push(`stripe_price_id = $${paramIndex++}`);
        values.push(data.stripePriceId);
      }
      if (data.status !== undefined) {
        updates.push(`status = $${paramIndex++}`);
        values.push(data.status);
      }
      if (data.currentPeriodEnd !== undefined) {
        updates.push(`current_period_end = $${paramIndex++}`);
        values.push(data.currentPeriodEnd);
      }
      if (data.cancelAtPeriodEnd !== undefined) {
        updates.push(`cancel_at_period_end = $${paramIndex++}`);
        values.push(data.cancelAtPeriodEnd);
      }

      if (updates.length > 0) {
        updates.push(`updated_at = NOW()`);
        values.push(existing.id);

        await pool.query(
          `UPDATE subscriptions SET ${updates.join(', ')} WHERE id = $${paramIndex}`,
          values
        );
      }

      return (await this.getSubscription(orgId))!;
    } else {
      const id = randomUUID();
      await db.insert(subscriptions).values({
        id,
        tier: data.tier || 'free',
        stripeCustomerId: data.stripeCustomerId || null,
        stripeSubscriptionId: data.stripeSubscriptionId || null,
        stripePriceId: data.stripePriceId || null,
        status: data.status || 'active',
        currentPeriodEnd: data.currentPeriodEnd || null,
        cancelAtPeriodEnd: data.cancelAtPeriodEnd || false,
        createdAt: now,
        organizationId: orgId,
      });

      return (await this.getSubscription(orgId))!;
    }
  }

  async getUsageCounts(orgId: string): Promise<{ users: number; servers: number }> {
    const { rows } = await pool.query(
      `SELECT COUNT(*) as count FROM servers WHERE organization_id = $1`,
      [orgId]
    );

    return {
      users: 0,
      servers: parseInt(rows[0].count),
    };
  }

  async getServerCount(orgId: string): Promise<number> {
    const { rows } = await pool.query(
      `SELECT COUNT(*) as count FROM servers WHERE organization_id = $1`,
      [orgId]
    );
    return parseInt(rows[0].count);
  }

  async getEnabledServerCount(orgId: string): Promise<number> {
    const { rows } = await pool.query(
      `SELECT COUNT(*) as count FROM servers WHERE enabled = true AND organization_id = $1`,
      [orgId]
    );
    return parseInt(rows[0].count);
  }

  async getServerCounts(orgId: string): Promise<{ total: number; enabled: number }> {
    const { rows } = await pool.query(
      `SELECT
        COUNT(*) as total,
        SUM(CASE WHEN enabled = true THEN 1 ELSE 0 END) as enabled
       FROM servers WHERE organization_id = $1`,
      [orgId]
    );
    return { total: parseInt(rows[0].total), enabled: parseInt(rows[0].enabled) || 0 };
  }

  async checkCanAdd(orgId: string, resource: 'user' | 'server', currentCount: number): Promise<LimitCheck> {
    if (!isStripeConfigured()) {
      return {
        allowed: true,
        current: currentCount,
        limit: Infinity,
        tier: 'enterprise',
        tierName: 'Unlimited',
      };
    }

    const subscription = await this.getSubscription(orgId);
    const tier: SubscriptionTier = (subscription?.tier as SubscriptionTier) || 'free';
    const tierConfig = subscriptionTiers[tier];
    const limit = resource === 'user' ? tierConfig.maxUsers : tierConfig.maxServers;

    const allowed = limit === -1 || currentCount < limit;

    return {
      allowed,
      current: currentCount,
      limit: limit === -1 ? Infinity : limit,
      tier,
      tierName: tierConfig.name,
    };
  }

  async getLicenseInfo(
    orgId: string,
    userCounts: { total: number; enabled: number }
  ): Promise<LicenseInfo> {
    const serverCounts = await this.getServerCounts(orgId);

    if (!isStripeConfigured()) {
      return {
        subscription: null,
        usage: { users: userCounts.total, servers: serverCounts.total },
        limits: {
          maxUsers: Infinity,
          maxServers: Infinity,
        },
        tier: 'enterprise',
        tierName: 'Unlimited',
        overLimit: {
          users: {
            isOverLimit: false,
            enabled: userCounts.enabled,
            total: userCounts.total,
            limit: -1,
            overBy: 0,
          },
          servers: {
            isOverLimit: false,
            enabled: serverCounts.enabled,
            total: serverCounts.total,
            limit: -1,
            overBy: 0,
          },
        },
      };
    }

    const subscription = await this.getSubscription(orgId);
    const tier: SubscriptionTier = (subscription?.tier as SubscriptionTier) || 'free';
    const tierConfig = subscriptionTiers[tier];

    const userLimit = tierConfig.maxUsers === -1 ? Infinity : tierConfig.maxUsers;
    const serverLimit = tierConfig.maxServers === -1 ? Infinity : tierConfig.maxServers;

    const userOverBy = userLimit === Infinity ? 0 : Math.max(0, userCounts.enabled - userLimit);
    const serverOverBy = serverLimit === Infinity ? 0 : Math.max(0, serverCounts.enabled - serverLimit);

    return {
      subscription,
      usage: { users: userCounts.total, servers: serverCounts.total },
      limits: {
        maxUsers: userLimit,
        maxServers: serverLimit,
      },
      tier,
      tierName: tierConfig.name,
      overLimit: {
        users: {
          isOverLimit: userOverBy > 0,
          enabled: userCounts.enabled,
          total: userCounts.total,
          limit: userLimit === Infinity ? -1 : userLimit,
          overBy: userOverBy,
        },
        servers: {
          isOverLimit: serverOverBy > 0,
          enabled: serverCounts.enabled,
          total: serverCounts.total,
          limit: serverLimit === Infinity ? -1 : serverLimit,
          overBy: serverOverBy,
        },
      },
    };
  }

  async updateOverLimitStatus(orgId: string, usersOverLimit: boolean, serversOverLimit: boolean): Promise<void> {
    const subscription = await this.getSubscription(orgId);
    if (!subscription) return;

    await pool.query(
      `UPDATE subscriptions SET users_over_limit = $1, servers_over_limit = $2 WHERE id = $3`,
      [usersOverLimit, serversOverLimit, subscription.id]
    );
  }

  async isSshBlocked(orgId: string): Promise<{ blocked: boolean; reason?: string }> {
    if (!isStripeConfigured()) {
      return { blocked: false };
    }

    const subscription = await this.getSubscription(orgId);
    if (!subscription) {
      return { blocked: false };
    }

    const tier: SubscriptionTier = (subscription.tier as SubscriptionTier) || 'free';
    const tierConfig = subscriptionTiers[tier];
    const serverLimit = tierConfig.maxServers;

    const serverCounts = await this.getServerCounts(orgId);
    const serversOverLimit = serverLimit !== -1 && serverCounts.enabled > serverLimit;

    const { rows } = await pool.query(
      `SELECT users_over_limit FROM subscriptions WHERE id = $1`,
      [subscription.id]
    );

    const usersOverLimit = rows[0]?.users_over_limit === true;

    if (usersOverLimit && serversOverLimit) {
      return {
        blocked: true,
        reason: "Your organization has exceeded both user and server limits. Please contact an administrator to enable SSH access.",
      };
    }

    if (usersOverLimit) {
      return {
        blocked: true,
        reason: "Your organization has exceeded the user limit for the current plan. Please contact an administrator to enable SSH access.",
      };
    }

    if (serversOverLimit) {
      return {
        blocked: true,
        reason: "Your organization has exceeded the server limit for the current plan. Please contact an administrator to enable SSH access.",
      };
    }

    return { blocked: false };
  }

  async addBillingRecord(orgId: string, data: {
    stripeInvoiceId?: string;
    amount: number;
    currency?: string;
    status: string;
    invoicePdf?: string;
    description?: string;
  }): Promise<void> {
    const subscription = await this.getSubscription(orgId);
    if (!subscription) return;

    const id = randomUUID();
    await db.insert(billingHistory).values({
      id,
      subscriptionId: subscription.id,
      stripeInvoiceId: data.stripeInvoiceId || null,
      amount: data.amount,
      currency: data.currency || 'usd',
      status: data.status,
      invoicePdf: data.invoicePdf || null,
      description: data.description || null,
      createdAt: new Date(),
      organizationId: orgId,
    });
  }

  async getBillingHistory(orgId: string, limit: number = 50): Promise<BillingHistory[]> {
    return await db.select().from(billingHistory)
      .where(eq(billingHistory.organizationId, orgId))
      .orderBy(desc(billingHistory.createdAt))
      .limit(limit);
  }
}

// Recording types
export interface Recording {
  id: string;
  sessionId: string;
  serverId: string;
  serverName: string;
  userId: string;
  userEmail: string;
  sshUser: string;
  startedAt: Date;
  endedAt?: Date | null;
  duration?: number | null;
  terminalWidth: number;
  terminalHeight: number;
  data: string;
  textContent: string;
  fileSize: number;
}

export interface InsertRecording {
  sessionId: string;
  serverId: string;
  serverName: string;
  userId: string;
  userEmail: string;
  sshUser: string;
  terminalWidth?: number;
  terminalHeight?: number;
}

// Recording storage class for session recordings
export class RecordingStorage {
  async createRecording(data: InsertRecording): Promise<Recording> {
    const id = randomUUID();
    const now = new Date();

    await pool.query(
      `INSERT INTO recordings (id, session_id, server_id, server_name, user_id, user_email, ssh_user, started_at, terminal_width, terminal_height)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [id, data.sessionId, data.serverId, data.serverName, data.userId, data.userEmail, data.sshUser, now, data.terminalWidth || 80, data.terminalHeight || 24]
    );

    return {
      id,
      sessionId: data.sessionId,
      serverId: data.serverId,
      serverName: data.serverName,
      userId: data.userId,
      userEmail: data.userEmail,
      sshUser: data.sshUser,
      startedAt: now,
      endedAt: null,
      duration: null,
      terminalWidth: data.terminalWidth || 80,
      terminalHeight: data.terminalHeight || 24,
      data: "",
      textContent: "",
      fileSize: 0,
    };
  }

  async appendData(id: string, eventData: string): Promise<void> {
    await pool.query(
      `UPDATE recordings SET data = data || $1, file_size = file_size + $2 WHERE id = $3`,
      [eventData, Buffer.byteLength(eventData, 'utf8'), id]
    );
  }

  async appendTextContent(id: string, text: string): Promise<void> {
    await pool.query(
      `UPDATE recordings SET text_content = text_content || $1 WHERE id = $2`,
      [text, id]
    );
  }

  async finalizeRecording(id: string): Promise<void> {
    const now = new Date();

    const { rows } = await pool.query(
      `SELECT started_at FROM recordings WHERE id = $1`,
      [id]
    );

    if (rows.length > 0) {
      const startedAt = new Date(rows[0].started_at);
      const duration = Math.floor((now.getTime() - startedAt.getTime()) / 1000);
      await pool.query(
        `UPDATE recordings SET ended_at = $1, duration = $2 WHERE id = $3`,
        [now, duration, id]
      );
    }
  }

  async getRecording(id: string): Promise<Recording | undefined> {
    const { rows } = await pool.query(
      `SELECT * FROM recordings WHERE id = $1`,
      [id]
    );

    if (rows.length === 0) return undefined;
    return this.mapRow(rows[0]);
  }

  async getRecordingBySessionId(sessionId: string): Promise<Recording | undefined> {
    const { rows } = await pool.query(
      `SELECT * FROM recordings WHERE session_id = $1`,
      [sessionId]
    );

    if (rows.length === 0) return undefined;
    return this.mapRow(rows[0]);
  }

  async getRecordings(orgId: string, limit: number = 50, offset: number = 0): Promise<Recording[]> {
    const { rows } = await pool.query(
      `SELECT * FROM recordings WHERE organization_id = $1 ORDER BY started_at DESC LIMIT $2 OFFSET $3`,
      [orgId, limit, offset]
    );
    return rows.map((row: any) => this.mapRow(row));
  }

  async getRecordingsByServer(serverId: string, limit: number = 50): Promise<Recording[]> {
    const { rows } = await pool.query(
      `SELECT * FROM recordings WHERE server_id = $1 ORDER BY started_at DESC LIMIT $2`,
      [serverId, limit]
    );
    return rows.map((row: any) => this.mapRow(row));
  }

  async getRecordingsByUser(userId: string, limit: number = 50): Promise<Recording[]> {
    const { rows } = await pool.query(
      `SELECT * FROM recordings WHERE user_id = $1 ORDER BY started_at DESC LIMIT $2`,
      [userId, limit]
    );
    return rows.map((row: any) => this.mapRow(row));
  }

  async searchRecordings(orgId: string, query: string, limit: number = 50): Promise<Recording[]> {
    const { rows } = await pool.query(
      `SELECT * FROM recordings WHERE organization_id = $1 AND text_content LIKE $2 ORDER BY started_at DESC LIMIT $3`,
      [orgId, `%${query}%`, limit]
    );
    return rows.map((row: any) => this.mapRow(row));
  }

  async getRecordingCount(): Promise<number> {
    const { rows } = await pool.query(`SELECT COUNT(*) as count FROM recordings`);
    return parseInt(rows[0].count);
  }

  async getTotalStorageBytes(): Promise<number> {
    const { rows } = await pool.query(`SELECT SUM(file_size) as total FROM recordings`);
    return parseInt(rows[0].total) || 0;
  }

  async deleteRecording(id: string): Promise<boolean> {
    const result = await pool.query(
      `DELETE FROM recordings WHERE id = $1`,
      [id]
    );
    return (result.rowCount ?? 0) > 0;
  }

  async deleteRecordingsOlderThan(date: Date): Promise<number> {
    const result = await pool.query(
      `DELETE FROM recordings WHERE started_at < $1`,
      [date]
    );
    return result.rowCount ?? 0;
  }

  private mapRow(row: any): Recording {
    return {
      id: row.id,
      sessionId: row.session_id,
      serverId: row.server_id,
      serverName: row.server_name,
      userId: row.user_id,
      userEmail: row.user_email,
      sshUser: row.ssh_user,
      startedAt: new Date(row.started_at),
      endedAt: row.ended_at ? new Date(row.ended_at) : null,
      duration: row.duration,
      terminalWidth: row.terminal_width,
      terminalHeight: row.terminal_height,
      data: row.data,
      textContent: row.text_content,
      fileSize: row.file_size,
    };
  }
}

// File operation storage class
export interface InsertFileOperation {
  sessionId: string;
  serverId: string;
  userId: string;
  userEmail?: string;
  sshUser: string;
  operation: FileOperationType;
  path: string;
  targetPath?: string;
  fileSize?: number;
  mode: FileOperationMode;
  status: FileOperationStatus;
  errorMessage?: string;
}

export class FileOperationStorage {
  async logOperation(orgId: string, data: InsertFileOperation): Promise<FileOperation> {
    const id = randomUUID();
    const now = new Date();

    await db.insert(fileOperations).values({
      id,
      sessionId: data.sessionId,
      serverId: data.serverId,
      userId: data.userId,
      userEmail: data.userEmail || null,
      sshUser: data.sshUser,
      operation: data.operation,
      path: data.path,
      targetPath: data.targetPath || null,
      fileSize: data.fileSize || null,
      mode: data.mode,
      status: data.status,
      errorMessage: data.errorMessage || null,
      timestamp: now,
      organizationId: orgId,
    });

    return {
      id,
      sessionId: data.sessionId,
      serverId: data.serverId,
      userId: data.userId,
      userEmail: data.userEmail || null,
      sshUser: data.sshUser,
      operation: data.operation,
      path: data.path,
      targetPath: data.targetPath || null,
      fileSize: data.fileSize || null,
      mode: data.mode,
      status: data.status,
      errorMessage: data.errorMessage || null,
      timestamp: now,
      organizationId: orgId,
    };
  }

  async getOperationsBySession(sessionId: string): Promise<FileOperation[]> {
    return await db.select().from(fileOperations)
      .where(eq(fileOperations.sessionId, sessionId))
      .orderBy(desc(fileOperations.timestamp));
  }

  async getOperationsByServer(serverId: string, limit: number = 100): Promise<FileOperation[]> {
    return await db.select().from(fileOperations)
      .where(eq(fileOperations.serverId, serverId))
      .orderBy(desc(fileOperations.timestamp))
      .limit(limit);
  }

  async getOperationsByUser(userId: string, limit: number = 100): Promise<FileOperation[]> {
    return await db.select().from(fileOperations)
      .where(eq(fileOperations.userId, userId))
      .orderBy(desc(fileOperations.timestamp))
      .limit(limit);
  }

  async getOperations(orgId: string, limit: number = 100, offset: number = 0): Promise<FileOperation[]> {
    return await db.select().from(fileOperations)
      .where(eq(fileOperations.organizationId, orgId))
      .orderBy(desc(fileOperations.timestamp))
      .limit(limit)
      .offset(offset);
  }

  async getOperationCount(): Promise<number> {
    const { rows } = await pool.query(`SELECT COUNT(*) as count FROM file_operations`);
    return parseInt(rows[0].count);
  }

  async deleteOperationsOlderThan(date: Date): Promise<number> {
    const result = await db.delete(fileOperations)
      .where(lt(fileOperations.timestamp, date))
      .returning({ id: fileOperations.id });
    return result.length;
  }
}

// Bridge storage class for SSH bridge/relay endpoints
export class BridgeStorage {
  async createBridge(orgId: string, data: InsertBridge): Promise<Bridge> {
    const id = randomUUID();
    const now = new Date();

    if (data.isDefault) {
      await pool.query(`UPDATE bridges SET is_default = false WHERE organization_id = $1`, [orgId]);
    }

    await db.insert(bridges).values({
      id,
      name: data.name,
      url: data.url,
      description: data.description || null,
      enabled: data.enabled !== false,
      isDefault: data.isDefault || false,
      createdAt: now,
      organizationId: orgId,
    });

    return {
      id,
      name: data.name,
      url: data.url,
      description: data.description || null,
      enabled: data.enabled !== false,
      isDefault: data.isDefault || false,
      createdAt: now,
      organizationId: orgId,
    };
  }

  async getBridge(id: string): Promise<Bridge | undefined> {
    const [result] = await db.select().from(bridges).where(eq(bridges.id, id)).limit(1);
    return result;
  }

  async getDefaultBridge(orgId?: string): Promise<Bridge | undefined> {
    if (orgId) {
      const [result] = await db.select().from(bridges)
        .where(and(eq(bridges.isDefault, true), eq(bridges.enabled, true), eq(bridges.organizationId, orgId)))
        .limit(1);
      return result;
    } else {
      const [result] = await db.select().from(bridges)
        .where(and(eq(bridges.isDefault, true), eq(bridges.enabled, true)))
        .limit(1);
      return result;
    }
  }

  async getBridges(orgId: string): Promise<Bridge[]> {
    return await db.select().from(bridges)
      .where(eq(bridges.organizationId, orgId))
      .orderBy(desc(bridges.isDefault));
  }

  async getEnabledBridges(orgId: string): Promise<Bridge[]> {
    return await db.select().from(bridges)
      .where(and(eq(bridges.enabled, true), eq(bridges.organizationId, orgId)))
      .orderBy(desc(bridges.isDefault));
  }

  async updateBridge(id: string, data: Partial<InsertBridge>): Promise<Bridge | undefined> {
    const existing = await this.getBridge(id);
    if (!existing) return undefined;

    const updates: string[] = [];
    const values: any[] = [];
    let paramIndex = 1;

    if (data.name !== undefined) {
      updates.push(`name = $${paramIndex++}`);
      values.push(data.name);
    }
    if (data.url !== undefined) {
      updates.push(`url = $${paramIndex++}`);
      values.push(data.url);
    }
    if (data.description !== undefined) {
      updates.push(`description = $${paramIndex++}`);
      values.push(data.description || null);
    }
    if (data.enabled !== undefined) {
      updates.push(`enabled = $${paramIndex++}`);
      values.push(data.enabled);
    }
    if (data.isDefault !== undefined) {
      if (data.isDefault) {
        await pool.query(`UPDATE bridges SET is_default = false`);
      }
      updates.push(`is_default = $${paramIndex++}`);
      values.push(data.isDefault);
    }

    if (updates.length > 0) {
      values.push(id);
      await pool.query(
        `UPDATE bridges SET ${updates.join(', ')} WHERE id = $${paramIndex}`,
        values
      );
    }

    return this.getBridge(id);
  }

  async deleteBridge(id: string): Promise<boolean> {
    await pool.query(`UPDATE servers SET bridge_id = NULL WHERE bridge_id = $1`, [id]);

    const result = await pool.query(
      `DELETE FROM bridges WHERE id = $1`,
      [id]
    );
    return (result.rowCount ?? 0) > 0;
  }
}

// Organization storage for multi-tenancy
export class OrganizationStorage {
  async createOrganization(name: string, slug: string): Promise<Organization> {
    const id = randomUUID();
    const now = new Date();
    const org: Organization = { id, name, slug, createdAt: now, updatedAt: null };
    await db.insert(organizations).values(org);
    return org;
  }

  async getOrganization(id: string): Promise<Organization | undefined> {
    const [result] = await db.select().from(organizations).where(eq(organizations.id, id)).limit(1);
    return result;
  }

  async getOrganizationBySlug(slug: string): Promise<Organization | undefined> {
    const [result] = await db.select().from(organizations).where(eq(organizations.slug, slug)).limit(1);
    return result;
  }

  async listOrganizations(): Promise<Organization[]> {
    return await db.select().from(organizations);
  }

  async updateOrganization(id: string, data: Partial<Pick<Organization, "name" | "slug">>): Promise<Organization | undefined> {
    const existing = await this.getOrganization(id);
    if (!existing) return undefined;
    const updated = { ...existing, ...data, updatedAt: new Date() };
    await db.update(organizations).set(updated).where(eq(organizations.id, id));
    return updated;
  }

  async deleteOrganization(id: string): Promise<boolean> {
    const result = await db.delete(organizations).where(eq(organizations.id, id)).returning({ id: organizations.id });
    return result.length > 0;
  }

  async addUserToOrg(orgId: string, userId: string, role: OrgRole = "user"): Promise<OrganizationUser> {
    const id = randomUUID();
    const now = new Date();
    const membership: OrganizationUser = { id, organizationId: orgId, userId, role, joinedAt: now };
    await db.insert(organizationUsers).values(membership);
    return membership;
  }

  async removeUserFromOrg(orgId: string, userId: string): Promise<boolean> {
    const result = await db
      .delete(organizationUsers)
      .where(and(eq(organizationUsers.organizationId, orgId), eq(organizationUsers.userId, userId)))
      .returning({ id: organizationUsers.id });
    return result.length > 0;
  }

  async getOrgUsers(orgId: string): Promise<OrganizationUser[]> {
    return await db
      .select()
      .from(organizationUsers)
      .where(eq(organizationUsers.organizationId, orgId));
  }

  async getUserOrgs(userId: string): Promise<OrganizationUser[]> {
    return await db
      .select()
      .from(organizationUsers)
      .where(eq(organizationUsers.userId, userId));
  }

  async updateUserOrgRole(orgId: string, userId: string, role: OrgRole): Promise<OrganizationUser | undefined> {
    const [existing] = await db
      .select()
      .from(organizationUsers)
      .where(and(eq(organizationUsers.organizationId, orgId), eq(organizationUsers.userId, userId)))
      .limit(1);
    if (!existing) return undefined;
    const updated = { ...existing, role };
    await db.update(organizationUsers)
      .set({ role })
      .where(and(eq(organizationUsers.organizationId, orgId), eq(organizationUsers.userId, userId)));
    return updated;
  }
}

// Enterprise leads storage for contact form submissions
export class EnterpriseLeadStorage {
  async createLead(data: InsertEnterpriseLead): Promise<EnterpriseLead> {
    const id = randomUUID();
    const now = new Date();
    const lead: EnterpriseLead = {
      id,
      companyName: data.companyName,
      contactEmail: data.contactEmail,
      contactFirstName: data.contactFirstName,
      contactLastName: data.contactLastName,
      phone: data.phone ?? null,
      companySize: data.companySize,
      serverCount: data.serverCount ?? null,
      useCase: data.useCase ?? null,
      status: data.status || "new",
      notes: data.notes ?? null,
      createdAt: now,
      updatedAt: null,
    };
    await db.insert(enterpriseLeads).values(lead);
    return lead;
  }

  async getLead(id: string): Promise<EnterpriseLead | undefined> {
    const [result] = await db.select().from(enterpriseLeads).where(eq(enterpriseLeads.id, id)).limit(1);
    return result;
  }

  async listLeads(status?: string): Promise<EnterpriseLead[]> {
    if (status) {
      return await db.select().from(enterpriseLeads).where(eq(enterpriseLeads.status, status)).orderBy(desc(enterpriseLeads.createdAt));
    }
    return await db.select().from(enterpriseLeads).orderBy(desc(enterpriseLeads.createdAt));
  }

  async updateLead(id: string, data: Partial<Pick<EnterpriseLead, "status" | "notes">>): Promise<EnterpriseLead | undefined> {
    const existing = await this.getLead(id);
    if (!existing) return undefined;
    const updated = { ...existing, ...data, updatedAt: new Date() };
    await db.update(enterpriseLeads).set(updated).where(eq(enterpriseLeads.id, id));
    return updated;
  }

  async deleteLead(id: string): Promise<boolean> {
    const result = await db.delete(enterpriseLeads).where(eq(enterpriseLeads.id, id)).returning({ id: enterpriseLeads.id });
    return result.length > 0;
  }
}

export const storage = new SQLiteStorage();
export const approvalStorage = new ApprovalStorage();
export const policyStorage = new PolicyStorage();
export const pendingPolicyStorage = new PendingPolicyStorage();
export const templateStorage = new TemplateStorage();
export const subscriptionStorage = new SubscriptionStorage();
export const recordingStorage = new RecordingStorage();
export const fileOperationStorage = new FileOperationStorage();
export const bridgeStorage = new BridgeStorage();
export const organizationStorage = new OrganizationStorage();
export const enterpriseLeadStorage = new EnterpriseLeadStorage();
