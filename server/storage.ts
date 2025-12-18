import { drizzle } from "drizzle-orm/better-sqlite3";
import Database from "better-sqlite3";
import { eq, desc, inArray } from "drizzle-orm";
import { randomUUID } from "crypto";
import { mkdirSync, existsSync } from "fs";
import { dirname } from "path";
import {
  users,
  servers,
  sessions,
  type User,
  type InsertUser,
  type Server,
  type InsertServer,
  type Session,
  type InsertSession,
} from "@shared/schema";

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  getUsers(): Promise<User[]>;
  updateUser(id: string, data: Partial<User>): Promise<User | undefined>;

  getServers(): Promise<Server[]>;
  getServer(id: string): Promise<Server | undefined>;
  getServersByIds(ids: string[]): Promise<Server[]>;
  createServer(server: InsertServer): Promise<Server>;
  updateServer(id: string, data: Partial<Server>): Promise<Server | undefined>;
  deleteServer(id: string): Promise<boolean>;

  getSessions(): Promise<Session[]>;
  getSession(id: string): Promise<Session | undefined>;
  getSessionsByUserId(userId: string): Promise<Session[]>;
  createSession(session: InsertSession): Promise<Session>;
  updateSession(id: string, data: Partial<Session>): Promise<Session | undefined>;
  endSession(id: string): Promise<boolean>;
}

// Database path
const DB_PATH = process.env.DATABASE_URL || "./data/keylessh.db";

// Ensure data directory exists
const dbDir = dirname(DB_PATH);
if (!existsSync(dbDir)) {
  mkdirSync(dbDir, { recursive: true });
}

// Initialize SQLite database
const sqlite = new Database(DB_PATH);
sqlite.pragma("journal_mode = WAL");

// Initialize Drizzle
const db = drizzle(sqlite);

// Create tables if they don't exist
sqlite.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    allowed_servers TEXT NOT NULL DEFAULT '[]'
  );

  CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 22,
    environment TEXT NOT NULL DEFAULT 'production',
    tags TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1,
    ssh_users TEXT NOT NULL DEFAULT '[]'
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    server_id TEXT NOT NULL,
    ssh_user TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    started_at INTEGER NOT NULL,
    ended_at INTEGER
  );
`);

export class SQLiteStorage implements IStorage {
  async getUser(id: string): Promise<User | undefined> {
    const result = db.select().from(users).where(eq(users.id, id)).get();
    return result;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const result = db.select().from(users).where(eq(users.username, username)).get();
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
    db.insert(users).values(user).run();
    return user;
  }

  async getUsers(): Promise<User[]> {
    return db.select().from(users).all();
  }

  async updateUser(id: string, data: Partial<User>): Promise<User | undefined> {
    const existing = await this.getUser(id);
    if (!existing) return undefined;

    const updated = { ...existing, ...data, id };
    db.update(users).set(updated).where(eq(users.id, id)).run();
    return updated;
  }

  async getServers(): Promise<Server[]> {
    return db.select().from(servers).all();
  }

  async getServer(id: string): Promise<Server | undefined> {
    const result = db.select().from(servers).where(eq(servers.id, id)).get();
    return result;
  }

  async getServersByIds(ids: string[]): Promise<Server[]> {
    if (ids.length === 0) return [];
    return db.select().from(servers).where(inArray(servers.id, ids)).all();
  }

  async createServer(insertServer: InsertServer): Promise<Server> {
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
    };
    db.insert(servers).values(server).run();
    return server;
  }

  async updateServer(id: string, data: Partial<Server>): Promise<Server | undefined> {
    const existing = await this.getServer(id);
    if (!existing) return undefined;

    const updated = { ...existing, ...data, id };
    db.update(servers).set(updated).where(eq(servers.id, id)).run();
    return updated;
  }

  async deleteServer(id: string): Promise<boolean> {
    const result = db.delete(servers).where(eq(servers.id, id)).run();
    return result.changes > 0;
  }

  async getSessions(): Promise<Session[]> {
    return db.select().from(sessions).orderBy(desc(sessions.startedAt)).all();
  }

  async getSession(id: string): Promise<Session | undefined> {
    const result = db.select().from(sessions).where(eq(sessions.id, id)).get();
    return result;
  }

  async getSessionsByUserId(userId: string): Promise<Session[]> {
    return db
      .select()
      .from(sessions)
      .where(eq(sessions.userId, userId))
      .orderBy(desc(sessions.startedAt))
      .all();
  }

  async createSession(insertSession: InsertSession): Promise<Session> {
    const id = randomUUID();
    const session: Session = {
      id,
      userId: insertSession.userId,
      serverId: insertSession.serverId,
      sshUser: insertSession.sshUser,
      status: insertSession.status ?? "active",
      startedAt: new Date(),
      endedAt: null,
    };
    db.insert(sessions).values(session).run();
    return session;
  }

  async updateSession(id: string, data: Partial<Session>): Promise<Session | undefined> {
    const existing = await this.getSession(id);
    if (!existing) return undefined;

    const updated = { ...existing, ...data, id };
    db.update(sessions).set(updated).where(eq(sessions.id, id)).run();
    return updated;
  }

  async endSession(id: string): Promise<boolean> {
    const result = db
      .update(sessions)
      .set({ status: "completed", endedAt: new Date() })
      .where(eq(sessions.id, id))
      .run();
    return result.changes > 0;
  }
}

export const storage = new SQLiteStorage();
