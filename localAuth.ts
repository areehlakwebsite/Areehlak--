import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { eq, and, gt } from "drizzle-orm";
import { getDb } from "./db";
import { sessions, users } from "../drizzle/schema";
import { ENV } from "./_core/env";

const scrypt = promisify(scryptCallback);
export const LOCAL_COOKIE_NAME = "areehlak_session";
const SESSION_DAYS = 30;
const PIN_MAX_ATTEMPTS = 5;
const PIN_LOCK_MINUTES = 15;

function digest(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

export async function hashSecret(value: string) {
  const salt = randomBytes(16).toString("hex");
  const derived = (await scrypt(value, salt, 64)) as Buffer;
  return `${salt}:${derived.toString("hex")}`;
}

export async function verifySecret(value: string, stored: string) {
  const [salt, expectedHex] = stored.split(":");
  if (!salt || !expectedHex) return false;
  const derived = (await scrypt(value, salt, 64)) as Buffer;
  const expected = Buffer.from(expectedHex, "hex");
  return expected.length === derived.length && timingSafeEqual(expected, derived);
}

export function normalizePhone(phone: string) {
  const normalized = phone.replace(/[\s-]/g, "").replace(/^\+20/, "0");
  return normalized;
}

export function isEgyptianPhone(phone: string) {
  return /^01[0125][0-9]{8}$/.test(normalizePhone(phone));
}

function cookieOptions() {
  return { httpOnly: true, secure: true, sameSite: "none" as const, path: "/", maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000 };
}

export async function createSession(userId: number, res: { cookie: (name: string, value: string, options: Record<string, unknown>) => void }) {
  const rawToken = randomBytes(32).toString("hex");
  const db = await getDb();
  if (!db) throw new Error("قاعدة البيانات غير متاحة حاليًا");
  await db.insert(sessions).values({ userId, tokenHash: digest(rawToken), expiresAt: new Date(Date.now() + SESSION_DAYS * 86400000) });
  res.cookie(LOCAL_COOKIE_NAME, rawToken, cookieOptions());
}

export async function clearSession(req: { cookies?: Record<string, string> }, res: { clearCookie: (name: string, options: Record<string, unknown>) => void }) {
  const rawToken = req.cookies?.[LOCAL_COOKIE_NAME];
  const db = await getDb();
  if (rawToken && db) await db.delete(sessions).where(eq(sessions.tokenHash, digest(rawToken)));
  res.clearCookie(LOCAL_COOKIE_NAME, { ...cookieOptions(), maxAge: -1 });
}

export async function userFromRequest(req: { cookies?: Record<string, string> }) {
  const rawToken = req.cookies?.[LOCAL_COOKIE_NAME];
  if (!rawToken) return null;
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select({ user: users }).from(sessions).innerJoin(users, eq(sessions.userId, users.id)).where(and(eq(sessions.tokenHash, digest(rawToken)), gt(sessions.expiresAt, new Date()), eq(users.isBlocked, false))).limit(1);
  return rows[0]?.user ?? null;
}

export async function ensureAdminAccount() {
  const db = await getDb();
  if (!db || !isEgyptianPhone(ENV.adminPhone)) return;
  const existing = await db.select().from(users).where(eq(users.phone, ENV.adminPhone)).limit(1);
  const passwordHash = await hashSecret(ENV.adminPassword);
  const pinHash = await hashSecret(ENV.adminSecurityPin);
  if (!existing[0]) {
    await db.insert(users).values({ openId: `local-${ENV.adminPhone}`, phone: ENV.adminPhone, passwordHash, securityPinHash: pinHash, role: "admin", name: "مدير أريحلك", loginMethod: "local" });
  } else if (existing[0].role !== "admin") {
    await db.update(users).set({ role: "admin", passwordHash, securityPinHash: pinHash }).where(eq(users.id, existing[0].id));
  }
}

export const PIN_LIMITS = { maxAttempts: PIN_MAX_ATTEMPTS, lockMinutes: PIN_LOCK_MINUTES };
