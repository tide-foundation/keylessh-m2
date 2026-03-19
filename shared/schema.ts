import { pgTable, text, integer, boolean, timestamp, jsonb, serial, unique } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Organizations table
export const organizations = pgTable("organizations", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }),
});

// Organization membership (user ↔ org with role)
export const organizationUsers = pgTable("organization_users", {
  id: text("id").primaryKey(),
  organizationId: text("organization_id").notNull(),
  userId: text("user_id").notNull(),
  role: text("role").notNull().default("user"), // "global-admin" | "org-admin" | "user"
  joinedAt: timestamp("joined_at", { withTimezone: true }).notNull(),
}, (table) => [
  unique("uq_org_user").on(table.organizationId, table.userId),
]);

export const users = pgTable("users", {
  id: text("id").primaryKey(),
  username: text("username").notNull().unique(),
  email: text("email").notNull(),
  role: text("role").notNull().default("user"),
  allowedServers: jsonb("allowed_servers").$type<string[]>().notNull().default([]),
});

// SSH bridges - WebSocket-to-TCP relay endpoints
export const bridges = pgTable("bridges", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  url: text("url").notNull(), // WebSocket URL, e.g., wss://bridge.example.com/ws/tcp
  description: text("description"),
  enabled: boolean("enabled").notNull().default(true),
  isDefault: boolean("is_default").notNull().default(false),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  organizationId: text("organization_id").notNull().default("default"),
});

// Signal servers - P2P signaling + HTTP relay endpoints (gateway connections)
export const signalServers = pgTable("signal_servers", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  url: text("url").notNull(), // e.g. https://tidestun.codesyo.com:9090
  description: text("description"),
  enabled: boolean("enabled").notNull().default(true),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
});

export const servers = pgTable("servers", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  host: text("host").notNull(),
  port: integer("port").notNull().default(22),
  environment: text("environment").notNull().default("production"),
  tags: jsonb("tags").$type<string[]>().notNull().default([]),
  enabled: boolean("enabled").notNull().default(true),
  sshUsers: jsonb("ssh_users").$type<string[]>().notNull().default([]),
  // Session recording settings
  recordingEnabled: boolean("recording_enabled").notNull().default(false),
  recordedUsers: jsonb("recorded_users").$type<string[]>().notNull().default([]), // Empty = all users when enabled
  // Bridge association - null means use default/embedded bridge
  bridgeId: text("bridge_id"),
  organizationId: text("organization_id").notNull().default("default"),
});

export const sessions = pgTable("sessions", {
  id: text("id").primaryKey(),
  userId: text("user_id").notNull(),
  userUsername: text("user_username"),
  userEmail: text("user_email"),
  serverId: text("server_id").notNull(),
  sshUser: text("ssh_user").notNull(),
  status: text("status").notNull().default("active"),
  startedAt: timestamp("started_at", { withTimezone: true }).notNull(),
  endedAt: timestamp("ended_at", { withTimezone: true }),
  recordingId: text("recording_id"), // Link to recording if session was recorded
  organizationId: text("organization_id").notNull().default("default"),
});

// File operations log - tracks SFTP/SCP file transfers
export const fileOperations = pgTable("file_operations", {
  id: text("id").primaryKey(),
  sessionId: text("session_id").notNull(),
  serverId: text("server_id").notNull(),
  userId: text("user_id").notNull(),
  userEmail: text("user_email"),
  sshUser: text("ssh_user").notNull(),
  operation: text("operation").notNull(), // "upload" | "download" | "delete" | "mkdir" | "rename" | "chmod"
  path: text("path").notNull(),
  targetPath: text("target_path"), // For rename operations
  fileSize: integer("file_size"), // Size in bytes (for upload/download)
  mode: text("mode").notNull(), // "sftp" | "scp"
  status: text("status").notNull(), // "success" | "error"
  errorMessage: text("error_message"),
  timestamp: timestamp("timestamp", { withTimezone: true }).notNull(),
  organizationId: text("organization_id").notNull().default("default"),
});

// Session recordings table - stores terminal I/O for playback
export const recordings = pgTable("recordings", {
  id: text("id").primaryKey(),
  sessionId: text("session_id").notNull(),
  serverId: text("server_id").notNull(),
  serverName: text("server_name").notNull(),
  userId: text("user_id").notNull(),
  userEmail: text("user_email").notNull(),
  sshUser: text("ssh_user").notNull(),
  startedAt: timestamp("started_at", { withTimezone: true }).notNull(),
  endedAt: timestamp("ended_at", { withTimezone: true }),
  duration: integer("duration"), // Duration in seconds
  terminalWidth: integer("terminal_width").notNull().default(80),
  terminalHeight: integer("terminal_height").notNull().default(24),
  // Recording data in asciicast v2 format (JSON lines)
  data: text("data").notNull().default(""),
  // Searchable text content (all output concatenated)
  textContent: text("text_content").notNull().default(""),
  fileSize: integer("file_size").notNull().default(0), // Size in bytes
  organizationId: text("organization_id").notNull().default("default"),
});

// Subscription tier definitions
export const subscriptionTiers = {
  free: { name: 'Free', maxUsers: 5, maxServers: 2 },
  pro: { name: 'Pro', maxUsers: 25, maxServers: 10 },
  enterprise: { name: 'Enterprise', maxUsers: -1, maxServers: -1 }, // -1 = unlimited
} as const;

export type SubscriptionTier = keyof typeof subscriptionTiers;
export type SubscriptionStatus = 'active' | 'canceled' | 'past_due' | 'trialing';

// Organization subscription table
export const subscriptions = pgTable("subscriptions", {
  id: text("id").primaryKey(),
  tier: text("tier").notNull().default("free"),
  stripeCustomerId: text("stripe_customer_id"),
  stripeSubscriptionId: text("stripe_subscription_id"),
  stripePriceId: text("stripe_price_id"),
  status: text("status").notNull().default("active"),
  currentPeriodEnd: integer("current_period_end"),
  cancelAtPeriodEnd: boolean("cancel_at_period_end").default(false),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }),
  organizationId: text("organization_id").notNull().default("default"),
});

// Billing history table
export const billingHistory = pgTable("billing_history", {
  id: text("id").primaryKey(),
  subscriptionId: text("subscription_id").notNull(),
  stripeInvoiceId: text("stripe_invoice_id"),
  amount: integer("amount").notNull(), // cents
  currency: text("currency").notNull().default("usd"),
  status: text("status").notNull(), // paid, open, void
  invoicePdf: text("invoice_pdf"),
  description: text("description"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  organizationId: text("organization_id").notNull().default("default"),
});

// Enterprise leads - contact form submissions for enterprise inquiries
export const enterpriseLeads = pgTable("enterprise_leads", {
  id: text("id").primaryKey(),
  companyName: text("company_name").notNull(),
  contactEmail: text("contact_email").notNull(),
  contactFirstName: text("contact_first_name").notNull(),
  contactLastName: text("contact_last_name").notNull(),
  phone: text("phone"),
  companySize: text("company_size").notNull(), // "1-10", "11-50", etc.
  serverCount: text("server_count"), // "1-10", "11-50", etc.
  useCase: text("use_case"),
  status: text("status").notNull().default("new"), // "new", "contacted", "qualified", "converted", "closed"
  notes: text("notes"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }),
});

// ============================================
// Approval & Policy tables (previously raw SQL)
// ============================================

// Pending approvals for user/role changes
export const pendingApprovals = pgTable("pending_approvals", {
  id: text("id").primaryKey(),
  type: text("type").notNull(), // 'user_create', 'user_update', 'user_delete', 'role_assign', 'role_remove'
  requestedBy: text("requested_by").notNull(),
  targetUserId: text("target_user_id"),
  targetUserEmail: text("target_user_email"),
  data: text("data").notNull(),
  status: text("status").notNull().default("pending"), // 'pending', 'approved', 'denied', 'committed', 'cancelled'
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }),
  organizationId: text("organization_id").notNull().default("default"),
});

// Approval decisions (votes)
export const approvalDecisions = pgTable("approval_decisions", {
  id: serial("id").primaryKey(),
  approvalId: text("approval_id").notNull(),
  userVuid: text("user_vuid").notNull(),
  userEmail: text("user_email").notNull(),
  decision: integer("decision").notNull(), // 0 = deny, 1 = approve
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  organizationId: text("organization_id").notNull().default("default"),
}, (table) => [
  unique("uq_approval_decision").on(table.approvalId, table.userVuid),
]);

// Access change audit logs
export const accessChangeLogs = pgTable("access_change_logs", {
  id: serial("id").primaryKey(),
  timestamp: timestamp("timestamp", { withTimezone: true }).notNull().defaultNow(),
  type: text("type").notNull(), // 'created', 'approved', 'denied', 'deleted', 'committed', 'cancelled'
  approvalId: text("approval_id").notNull(),
  userEmail: text("user_email").notNull(),
  targetUser: text("target_user"),
  details: text("details"),
  organizationId: text("organization_id").notNull().default("default"),
});

// SSH signing policies for roles (committed policies)
export const sshPolicies = pgTable("ssh_policies", {
  roleId: text("role_id").primaryKey(),
  contractType: text("contract_type").notNull(),
  approvalType: text("approval_type").notNull(), // 'implicit', 'explicit'
  executionType: text("execution_type").notNull(), // 'public', 'private'
  threshold: integer("threshold").notNull().default(1),
  policyData: text("policy_data"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }),
  organizationId: text("organization_id").notNull().default("default"),
});

// Pending SSH policy requests (awaiting approval)
export const pendingSshPolicies = pgTable("pending_ssh_policies", {
  id: text("id").primaryKey(),
  roleId: text("role_id").notNull(),
  requestedBy: text("requested_by").notNull(),
  requestedByEmail: text("requested_by_email"),
  policyRequestData: text("policy_request_data").notNull(),
  contractCode: text("contract_code"),
  status: text("status").notNull().default("pending"), // 'pending', 'approved', 'committed', 'cancelled'
  threshold: integer("threshold").notNull().default(1),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }),
  organizationId: text("organization_id").notNull().default("default"),
});

// SSH policy approval decisions
export const sshPolicyDecisions = pgTable("ssh_policy_decisions", {
  id: serial("id").primaryKey(),
  policyRequestId: text("policy_request_id").notNull(),
  userVuid: text("user_vuid").notNull(),
  userEmail: text("user_email").notNull(),
  decision: integer("decision").notNull(), // 0 = deny, 1 = approve
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  organizationId: text("organization_id").notNull().default("default"),
}, (table) => [
  unique("uq_policy_decision").on(table.policyRequestId, table.userVuid),
]);

// SSH policy change logs
export const sshPolicyLogs = pgTable("ssh_policy_logs", {
  id: serial("id").primaryKey(),
  timestamp: timestamp("timestamp", { withTimezone: true }).notNull().defaultNow(),
  type: text("type").notNull(), // 'created', 'approved', 'denied', 'committed', 'cancelled'
  policyRequestId: text("policy_request_id").notNull(),
  userEmail: text("user_email").notNull(),
  roleId: text("role_id"),
  details: text("details"),
  status: text("status").notNull().default("pending"), // 'pending', 'approved', 'committed', 'cancelled'
  approvalCount: integer("approval_count").notNull().default(0),
  threshold: integer("threshold").notNull().default(1),
  organizationId: text("organization_id").notNull().default("default"),
});

// Policy templates for reusable Forseti contracts
export const policyTemplates = pgTable("policy_templates", {
  id: text("id").primaryKey(),
  name: text("name").notNull().unique(),
  description: text("description").notNull(),
  csCode: text("cs_code").notNull(),
  parameters: jsonb("parameters").$type<TemplateParameter[]>().notNull().default([]),
  createdBy: text("created_by").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }),
  organizationId: text("organization_id").notNull().default("default"),
});

// ============================================
// Insert schemas and type exports
// ============================================

export const insertUserSchema = createInsertSchema(users).omit({ id: true });
export const insertServerSchema = createInsertSchema(servers).omit({ id: true });
export const insertSessionSchema = createInsertSchema(sessions).omit({ id: true, startedAt: true, endedAt: true });
export const insertSubscriptionSchema = createInsertSchema(subscriptions).omit({ id: true, createdAt: true, updatedAt: true });
export const insertBillingHistorySchema = createInsertSchema(billingHistory).omit({ id: true, createdAt: true });
export const insertBridgeSchema = createInsertSchema(bridges).omit({ id: true, createdAt: true });
export const insertSignalServerSchema = createInsertSchema(signalServers).omit({ id: true, createdAt: true });
export const insertOrganizationSchema = createInsertSchema(organizations).omit({ id: true, createdAt: true, updatedAt: true });
export const insertOrganizationUserSchema = createInsertSchema(organizationUsers).omit({ id: true, joinedAt: true });
export const insertEnterpriseLeadSchema = createInsertSchema(enterpriseLeads).omit({ id: true, createdAt: true, updatedAt: true });

export type InsertUser = z.infer<typeof insertUserSchema>;
export type InsertServer = z.infer<typeof insertServerSchema>;
export type InsertSession = z.infer<typeof insertSessionSchema>;
export type InsertSubscription = z.infer<typeof insertSubscriptionSchema>;
export type InsertBillingHistory = z.infer<typeof insertBillingHistorySchema>;
export type InsertBridge = z.infer<typeof insertBridgeSchema>;
export type InsertSignalServer = z.infer<typeof insertSignalServerSchema>;
export type InsertOrganization = z.infer<typeof insertOrganizationSchema>;
export type InsertOrganizationUser = z.infer<typeof insertOrganizationUserSchema>;
export type InsertEnterpriseLead = z.infer<typeof insertEnterpriseLeadSchema>;

export type User = typeof users.$inferSelect;
export type Server = typeof servers.$inferSelect;
export type Session = typeof sessions.$inferSelect;
export type FileOperation = typeof fileOperations.$inferSelect;
export type Subscription = typeof subscriptions.$inferSelect;
export type BillingHistory = typeof billingHistory.$inferSelect;
export type Bridge = typeof bridges.$inferSelect;
export type SignalServer = typeof signalServers.$inferSelect;
export type Organization = typeof organizations.$inferSelect;
export type OrganizationUser = typeof organizationUsers.$inferSelect;
export type EnterpriseLead = typeof enterpriseLeads.$inferSelect;

// File operation types for API
export type FileOperationType = "upload" | "download" | "delete" | "mkdir" | "rename" | "chmod";
export type FileOperationMode = "sftp" | "scp";
export type FileOperationStatus = "success" | "error";

// Over-limit status for resources
export interface OverLimitStatus {
  users: {
    isOverLimit: boolean;
    enabled: number;
    total: number;
    limit: number;
    overBy: number;
  };
  servers: {
    isOverLimit: boolean;
    enabled: number;
    total: number;
    limit: number;
    overBy: number;
  };
}

// License info response for API
export interface LicenseInfo {
  subscription: Subscription | null;
  usage: { users: number; servers: number };
  limits: { maxUsers: number; maxServers: number };
  tier: SubscriptionTier;
  tierName: string;
  overLimit?: OverLimitStatus;
}

// Limit check response
export interface LimitCheck {
  allowed: boolean;
  current: number;
  limit: number;
  tier: SubscriptionTier;
  tierName: string;
}

export type UserRole = "user" | "admin";
export type OrgRole = "global-admin" | "org-admin" | "user";

export interface OIDCUser {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  allowedServers: string[];
  organizationId: string;
  orgRole: OrgRole;
}

export interface AuthState {
  user: OIDCUser | null;
  accessToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  organizationId: string | null;
  orgRole: OrgRole | null;
}

export type ServerStatus = "online" | "offline" | "unknown";

export interface ServerWithAccess extends Server {
  allowedSshUsers: string[];
  status: ServerStatus;  // Actual health status from health check
}

export interface ActiveSession extends Session {
  serverName: string;
  serverHost: string;
}

export type ConnectionStatus = "connecting" | "connected" | "disconnected" | "error";

// Admin User type (TideCloak Admin API shape)
export interface AdminUser {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  username?: string;
  role: string[];  // Array of role names
  linked: boolean; // Tide account link status
  enabled: boolean; // Whether the user account is enabled
  isAdmin: boolean; // Whether the user is an administrator
}

// Admin User Update type
export interface AdminUserUpdate extends AdminUser {
  rolesToAdd?: string[];
  rolesToRemove?: string[];
}

// Admin Role type (TideCloak Admin API shape)
export interface AdminRole {
  id: string;
  name: string;
  description?: string;
  clientRole?: boolean;
  clientId?: string;
}

// Policy Template parameter definition
export interface TemplateParameter {
  name: string;
  type: "string" | "number" | "boolean" | "select";
  helpText: string;
  required: boolean;
  defaultValue?: string | number | boolean;
  options?: string[];  // For "select" type
}

// Policy Template entity
export interface PolicyTemplate {
  id: string;
  name: string;
  description: string;
  csCode: string;
  parameters: TemplateParameter[];
  createdBy: string;
  createdAt: Date;
  updatedAt?: Date;
}

export interface InsertPolicyTemplate {
  name: string;
  description: string;
  csCode: string;
  parameters: TemplateParameter[];
  createdBy: string;
}
