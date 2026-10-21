/**
 * Admin-only record of sign-in attempts.
 * Stores SHAKE256 digests of the network and account, a record hash, and a
 * hash chain. Does not store the raw network, account, private keys,
 * signatures, MACs, challenges, session cookies, or public key bytes.
 * The digest is unsalted. A leaked log can still be matched against a guessed IPv4.
 */
import { clientIp, type AuthEnv } from "./auth";
import { noteAuthFailure } from "./authBan";
import {
  PQC_LOG_ALG,
  accountHash,
  chainHash,
  isPqcLogHash,
  loginRecordHash,
  networkHash,
  type LoginSealFields,
} from "./pqcLogHash";

export const LOGIN_ATTEMPT_TTL_SECONDS = 60 * 60 * 24 * 30;
const ATTEMPT_CHAIN_KEY = "auth:log-chain:attempt";

export type LoginFamily = "device" | "pqc" | "ecdhe" | "kem" | "lab";
export type LoginPhase = "register" | "challenge" | "login";

export type PublicLoginAttempt = {
  at: string;
  family: LoginFamily;
  phase: LoginPhase;
  suite: string;
  result: "accepted" | "rejected";
  code: string;
  detail: string;
  networkHash: string;
  accountHash: string;
  recordHash: string;
  prevHash: string;
  chain: string;
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

function attemptDetail(family: LoginFamily, phase: LoginPhase, result: PublicLoginAttempt["result"], code: string): string {
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

function hashOrEmpty(value: unknown): string {
  return typeof value === "string" && isPqcLogHash(value) ? value : "";
}

function usableIp(value: string): string {
  const ip = value.trim().slice(0, 64);
  if (ip === "unknown") return ip;
  return /^[0-9a-fA-F:.]+$/.test(ip) ? ip : "";
}

function asAttempt(value: unknown): PublicLoginAttempt | null {
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
  const at = typeof row.at === "string" && /^\d{4}-\d{2}-\d{2}T/.test(row.at) ? row.at.slice(0, 40) : "";
  if (!at) return null;
  let network = hashOrEmpty(row.networkHash);
  if (!network && typeof row.ip === "string") {
    const ip = usableIp(row.ip);
    if (ip) network = networkHash(ip);
  }
  if (!network) return null;
  let account = hashOrEmpty(row.accountHash);
  if (!account && typeof row.accountPrefix === "string") account = accountHash(row.accountPrefix);
  const knownFamily = family as LoginFamily;
  const knownPhase = phase as LoginPhase;
  return {
    at,
    family: knownFamily,
    phase: knownPhase,
    suite,
    result,
    code,
    detail: attemptDetail(knownFamily, knownPhase, result, code),
    networkHash: network,
    accountHash: account,
    recordHash: hashOrEmpty(row.recordHash),
    prevHash: hashOrEmpty(row.prevHash),
    chain: hashOrEmpty(row.chain),
  };
}

async function readTip(env: AuthEnv): Promise<string> {
  if (!env.BILLING_KV) return "";
  const raw = await env.BILLING_KV.get(ATTEMPT_CHAIN_KEY);
  return raw && isPqcLogHash(raw) ? raw : "";
}

export async function readLoginChainTip(env: AuthEnv): Promise<string> {
  return readTip(env);
}

export async function logAuthResponse(
  request: Request,
  env: AuthEnv,
  family: LoginFamily,
  phase: LoginPhase,
  response: Response,
): Promise<Response> {
  const ip = clientIp(request);
  let code = response.ok ? "ok" : "rejected";
  let suite = "";
  let storedFamily = family;
  let account = "";
  try {
    const data = (await response.clone().json()) as Record<string, unknown>;
    if (typeof data.error === "string") code = cleanCode(data.error);
    else if (response.ok) code = "ok";
    if (typeof data.suite === "string") suite = cleanSuite(data.suite);
    if (data.family === "ecdhe" || data.family === "kem") storedFamily = data.family;
    if (typeof data.fingerprint === "string") account = accountHash(data.fingerprint);
    const user = data.user;
    if (!account && user && typeof user === "object" && typeof (user as { fingerprint?: unknown }).fingerprint === "string") {
      account = accountHash((user as { fingerprint: string }).fingerprint);
    }
  } catch {
    // A body that is not JSON still counts as a rejection when the status is not OK.
  }
  try {
    if (env.BILLING_KV) {
      const result = response.ok ? "accepted" : "rejected";
      const at = new Date().toISOString();
      const fields: LoginSealFields = {
        at,
        family: storedFamily,
        phase,
        suite,
        result,
        code,
        networkHash: networkHash(ip),
        accountHash: account,
      };
      const recordHash = loginRecordHash(fields);
      const prevHash = await readTip(env);
      const chain = chainHash(prevHash, recordHash);
      const stamp = String(9_999_999_999_999 - Date.now()).padStart(13, "0");
      const noise = crypto.getRandomValues(new Uint8Array(4));
      const tail = [...noise].map((b) => b.toString(16).padStart(2, "0")).join("");
      await env.BILLING_KV.put(
        `auth:attempt:${stamp}_${tail}`,
        JSON.stringify({
          v: 1,
          alg: PQC_LOG_ALG,
          ...fields,
          detail: attemptDetail(storedFamily, phase, result, code),
          recordHash,
          prevHash,
          chain,
        }),
        { expirationTtl: LOGIN_ATTEMPT_TTL_SECONDS },
      );
      await env.BILLING_KV.put(ATTEMPT_CHAIN_KEY, chain);
    }
  } catch {
    // The sign-in response still returns when the log cannot be written.
  }
  if (!response.ok) {
    try {
      await noteAuthFailure(env, ip, code);
    } catch {
      // Pause bookkeeping must not change the sign-in response.
    }
  }
  return response;
}

export async function listLoginAttempts(env: AuthEnv, take = 40): Promise<PublicLoginAttempt[]> {
  if (!env.BILLING_KV) return [];
  const scan = Math.min(Math.max(take, 1), 100) + 40;
  const listed = await env.BILLING_KV.list({ prefix: "auth:attempt:", limit: Math.min(scan, 200) });
  const entries: PublicLoginAttempt[] = [];
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
  return entries.slice(0, Math.min(Math.max(take, 1), 100));
}
