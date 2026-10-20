/**
 * Admin-only record of sign-in attempts.
 * Stores the result, the method, and the network. Does not store private keys,
 * signatures, MACs, challenges, session cookies, or public key bytes.
 */
import { clientIp, type AuthEnv } from "./auth";

export const LOGIN_ATTEMPT_TTL_SECONDS = 60 * 60 * 24 * 30;

export type LoginFamily = "device" | "pqc" | "ecdhe" | "kem" | "lab";
export type LoginPhase = "register" | "challenge" | "login";

export type LoginAttempt = {
  at: string;
  ip: string;
  family: LoginFamily;
  phase: LoginPhase;
  suite: string;
  result: "accepted" | "rejected";
  code: string;
  accountPrefix: string;
  detail: string;
};

const FAMILIES = new Set<LoginFamily>(["device", "pqc", "ecdhe", "kem", "lab"]);
const PHASES = new Set<LoginPhase>(["register", "challenge", "login"]);

function familyLabel(family: LoginFamily): string {
  if (family === "device") return "Device key";
  if (family === "pqc") return "Post-quantum signature";
  if (family === "ecdhe") return "ECDHE key agreement";
  if (family === "kem") return "Post-quantum key agreement";
  return "Key lab";
}

function attemptDetail(family: LoginFamily, phase: LoginPhase, result: LoginAttempt["result"], code: string): string {
  const step = phase === "register" ? "registration" : phase === "challenge" ? "challenge" : "sign-in";
  if (result === "accepted") {
    return `${familyLabel(family)} ${step} was accepted. The private key was not stored.`;
  }
  return `${familyLabel(family)} ${step} was rejected (${code}). The private key was not stored.`;
}

function cleanCode(value: string): string {
  return /^[a-z0-9_]{1,40}$/.test(value) ? value : "other";
}

function cleanSuite(value: string): string {
  return /^[A-Za-z0-9-]{1,40}$/.test(value) ? value : "";
}

function accountPrefix(value: string): string {
  const hex = value.replace(/[\s:]/g, "").toLowerCase();
  return /^[a-f0-9]{8,64}$/.test(hex) ? hex.slice(0, 8) : "";
}

function asAttempt(value: unknown): LoginAttempt | null {
  if (!value || typeof value !== "object") return null;
  const row = value as Record<string, unknown>;
  const family = row.family;
  const phase = row.phase;
  const result = row.result;
  if (typeof family !== "string" || !FAMILIES.has(family as LoginFamily)) return null;
  if (typeof phase !== "string" || !PHASES.has(phase as LoginPhase)) return null;
  if (result !== "accepted" && result !== "rejected") return null;
  const code = typeof row.code === "string" ? cleanCode(row.code) : "other";
  const suite = typeof row.suite === "string" ? cleanSuite(row.suite) : "";
  const prefix = typeof row.accountPrefix === "string" ? accountPrefix(row.accountPrefix) : "";
  const at = typeof row.at === "string" && /^\d{4}-\d{2}-\d{2}T/.test(row.at) ? row.at.slice(0, 40) : "";
  const ipRaw = typeof row.ip === "string" ? row.ip.trim().slice(0, 64) : "";
  const ip = ipRaw === "unknown" || /^[0-9a-fA-F:.]+$/.test(ipRaw) ? ipRaw : "";
  if (!at || !ip) return null;
  const knownFamily = family as LoginFamily;
  const knownPhase = phase as LoginPhase;
  return {
    at,
    ip,
    family: knownFamily,
    phase: knownPhase,
    suite,
    result,
    code,
    accountPrefix: prefix,
    detail: attemptDetail(knownFamily, knownPhase, result, code),
  };
}

export async function logAuthResponse(
  request: Request,
  env: AuthEnv,
  family: LoginFamily,
  phase: LoginPhase,
  response: Response,
): Promise<Response> {
  if (!env.BILLING_KV) return response;
  try {
    let code = response.ok ? "ok" : "rejected";
    let suite = "";
    let prefix = "";
    let storedFamily = family;
    const data = (await response.clone().json()) as Record<string, unknown>;
    if (typeof data.error === "string") code = cleanCode(data.error);
    else if (response.ok) code = "ok";
    if (typeof data.suite === "string") suite = cleanSuite(data.suite);
    if (data.family === "ecdhe" || data.family === "kem") storedFamily = data.family;
    if (typeof data.fingerprint === "string") prefix = accountPrefix(data.fingerprint);
    const user = data.user;
    if (!prefix && user && typeof user === "object" && typeof (user as { fingerprint?: unknown }).fingerprint === "string") {
      prefix = accountPrefix((user as { fingerprint: string }).fingerprint);
    }
    const result = response.ok ? "accepted" : "rejected";
    const entry: LoginAttempt = {
      at: new Date().toISOString(),
      ip: clientIp(request),
      family: storedFamily,
      phase,
      suite,
      result,
      code,
      accountPrefix: prefix,
      detail: attemptDetail(storedFamily, phase, result, code),
    };
    const stamp = String(9_999_999_999_999 - Date.now()).padStart(13, "0");
    const noise = crypto.getRandomValues(new Uint8Array(4));
    const tail = [...noise].map((b) => b.toString(16).padStart(2, "0")).join("");
    await env.BILLING_KV.put(`auth:attempt:${stamp}_${tail}`, JSON.stringify(entry), {
      expirationTtl: LOGIN_ATTEMPT_TTL_SECONDS,
    });
  } catch {
    // The sign-in response still returns when the log cannot be written.
  }
  return response;
}

export async function listLoginAttempts(env: AuthEnv): Promise<LoginAttempt[]> {
  if (!env.BILLING_KV) return [];
  const listed = await env.BILLING_KV.list({ prefix: "auth:attempt:", limit: 80 });
  const entries: LoginAttempt[] = [];
  for (const key of listed.keys) {
    const raw = await env.BILLING_KV.get(key.name);
    if (!raw) continue;
    try {
      const parsed = asAttempt(JSON.parse(raw));
      if (parsed) entries.push(parsed);
    } catch {
      // Skip a damaged row.
    }
  }
  entries.sort((a, b) => b.at.localeCompare(a.at));
  return entries.slice(0, 40);
}
