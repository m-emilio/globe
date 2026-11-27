import { parseReconAddress } from "../reconAddress";
/**
 * Admin API — defense in depth (not “isAdmin flag on the client”).
 *
 * Threat model:
 * - Client-reported isAdmin is UI only; every /api/admin/* call re-checks server env.
 * - Session alone is NOT enough for grant/revoke/claim (stolen token risk).
 * - Mutating actions require ALL of:
 *     1) Logged-in session (ADMIN_FINGERPRINTS or ADMIN_USER_IDS)
 *     2) Short-lived elevation token from a fresh device-key signature (proves key still held)
 *     3) Last check: that key's fingerprint is an exact ADMIN_FINGERPRINTS member
 * - A shared action secret is not accepted. The public fingerprint is not a bearer token.
 * - A user-id allowlist entry can open the admin session and cannot approve mutations.
 * - Read-only lookup, audit, and the sign-in list need (1) only.
 * - The security-log export needs the full mutation gate.
 * - Empty ADMIN_FINGERPRINTS + ADMIN_USER_IDS ⇒ no admins (fail closed).
 */

import * as openpgp from "openpgp";
import {
  assertNoPrivateKeyMaterial,
  authSessionStorageKey,
  sessionCookie,
  sessionRecordsForAccount,
  clientIp,
  getSessionUser,
  hasUnexpiredTimestamp,
  readJsonBody,
  bodyTooLargeResponse,
  getUserByFingerprint,
  getUserById,
  deleteUserAccount,
  ADMIN_KV_MAX_ENTRIES,
  bootstrapAdminFingerprintCount,
  bootstrapAdminUserIdCount,
  findKvAdmin,
  forgetKvAdminCache,
  isAdminUserWithKv,
  isAllowlistedAdminFingerprint,
  isAllowlistedAdminFingerprintWithKv,
  kvAdminDigest,
  kvAdminPepperAvailable,
  loadKvAdmins,
  maskFingerprint,
  normalizeFingerprint,
  parseAndValidatePublicKey,
  saveKvAdmins,
  type KvAdminEntry,
  rateLimitDurable,
  setUserTransitPaid,
  setUserUnlimitedKeys,
  unlimitedKeySealMatches,
  type AuthEnv,
  type UserRecord,
} from "./auth";
import { claimPaidCheckoutSessions, grantPaidToUser, readUserEntitlement, type BillingEnv } from "./billing";
import {
  b64ToFixedBytes,
  decodeStoredPublicKey,
  PQC_SIG_SUITES,
  verifyPqcSignature,
} from "./pqcVerify";
import { AUTH_BAN_SECONDS, AUTH_FAIL_LIMIT, AUTH_FAIL_WINDOW_SECONDS } from "./authBan";
import { listLoginAttempts, readLoginChainTip } from "./loginLog";
import { BodyLimitError, readBoundedRequestText, readBoundedText } from "./boundedBody";
import { CANARY_PATH, purpleTeamDirectory, purpleTeamHost, type PurpleTeamBindings } from "./purpleTeamDirectory";
import { lookupPublicRecon, normalizeReconDomain, RECON_CERTIFICATE_PATH } from "./purpleTeamRecon";
import { lookupIpRecon } from "./reconIp";
import { getCloudflareClientIp, readConnectionMetadata } from "./connectionMetadata";
import { inspectMailPolicies, normalizeDkimSelector } from "./purpleTeamMail";
import { reconCertificatePage, reconPage, type ReconPageData } from "./purpleTeamReconPage";
import { globeHeaderFindings } from "./globeHeaderFindings";
import type { ToolFinding, ToolResult } from "./purpleTeamTools";
import { operationsPage, type OperationsPageData } from "./securityOperationsPage";
import { runFeedIsolationDrill, runSessionContainmentDrill } from "./securityOperationsDrills";
import { detectOperationsAlerts, OPERATIONS_PATH, RECENT_AUDIT_LIMIT, RECENT_LOGIN_LIMIT } from "./securityOperationsModel";
import { validSessionReference } from "./sessionContainment";
import {
  PQC_LOG_ALG,
  PQC_LOG_BYTES,
  PQC_LOG_DOMAIN,
  accountHash,
  auditRecordHash,
  chainHash,
  isPqcLogHash,
  networkHash,
  privilegeSeal,
  readLogPepper,
  userSeal,
  type AuditSealFields,
} from "./pqcLogHash";

export type AdminEnv = AuthEnv &
  BillingEnv & {
    ADMIN_FINGERPRINTS?: string;
    ADMIN_USER_IDS?: string;
    /** Legacy binding. This module does not compare it. */
    ADMIN_ACTION_SECRET?: string;
  };

type SecurityHeadersFn = (headers: Headers) => void;

type AuditEntry = {
  at: string;
  adminUserId: string;
  adminFingerprint: string;
  action: string;
  targetUserId?: string | null;
  targetFingerprint?: string | null;
  /** Precomputed 64-hex target digest (used when the raw fingerprint is not stored). */
  targetHash?: string | null;
  detail?: string;
  ip: string;
  ok?: boolean;
};

type ElevChallenge = {
  v?: number;
  adminHash?: string;
  userHash?: string;
  nonce?: string;
  expiresAtMs?: number;
  createdAt: string;
  expiresAt: string;
  /** Present only on challenges created before the seal. */
  userId?: string;
  fingerprint?: string;
  message?: string;
};

type ElevToken = {
  v?: number;
  adminHash?: string;
  userHash?: string;
  createdAt: string;
  expiresAt: string;
  /** Present only on tokens created before the seal. */
  userId?: string;
  fingerprint?: string;
};

const ELEV_CHALLENGE_TTL_SEC = 120; // 2 minutes
const ELEV_TOKEN_TTL_SEC = 10 * 60; // 10 minutes
const ADMIN_PROTOCOL = "globe-admin-elevate:v1";
const MAX_SIGNATURE_CHARS = 16_000;

function json(
  data: unknown,
  init?: ResponseInit,
  applySecurityHeaders?: SecurityHeadersFn,
) {
  const headers = new Headers(init?.headers);
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  applySecurityHeaders?.(headers);
  return new Response(JSON.stringify(data), { ...init, headers });
}

function randomHex(bytes = 32): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return [...arr].map((b) => b.toString(16).padStart(2, "0")).join("");
}

type AccessOrigin = "stripe" | "admin" | "unrecorded";

function storedOrigin(
  active: boolean,
  source: "stripe" | "admin" | undefined,
): AccessOrigin | null {
  if (!active) return null;
  if (source === "stripe" || source === "admin") return source;
  return "unrecorded";
}

function publicUser(u: UserRecord) {
  const unlimitedKeys = unlimitedKeySealMatches(u);
  return {
    id: u.id,
    fingerprint: u.fingerprint,
    primaryUserId: u.primaryUserId,
    transitPaid: Boolean(u.transitPaid),
    transitOrigin: storedOrigin(Boolean(u.transitPaid), u.transitSource),
    unlimitedKeys,
    unlimitedKeyOrigin: storedOrigin(unlimitedKeys, u.unlimitedKeySource),
    createdAt: u.createdAt,
  };
}

/** Older flags have no source field. A stored Stripe receipt still counts as payment. */
async function withReceiptOrigin(env: AdminEnv, user: UserRecord) {
  const view = publicUser(user);
  if (view.transitOrigin !== "unrecorded" && view.unlimitedKeyOrigin !== "unrecorded") {
    return view;
  }
  const receipt = await readUserEntitlement(env, user.id);
  if (!receipt) return view;
  if (view.transitOrigin === "unrecorded" && receipt.kind === "transit") {
    view.transitOrigin = "stripe";
  }
  if (view.unlimitedKeyOrigin === "unrecorded" && receipt.kind === "unlimited_keys") {
    view.unlimitedKeyOrigin = "stripe";
  }
  return view;
}

function elevChallengeKey(id: string) {
  return `admin:elev-chal:${id}`;
}

function elevTokenKey(token: string) {
  return `admin:elev:${token}`;
}

/**
 * Verify elevation token matches this admin session.
 */
async function requireElevation(
  request: Request,
  env: AdminEnv,
  user: UserRecord,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<{ ok: true } | { ok: false; response: Response }> {
  const elev =
    request.headers.get("x-admin-elevation")?.trim() ||
    request.headers.get("x-admin-elevation-token")?.trim() ||
    "";
  if (!elev || !/^[a-f0-9]{32,128}$/i.test(elev) || !env.BILLING_KV) {
    return {
      ok: false,
      response: json(
        {
          error: "elevation_required",
          message:
            "Privileged actions need a fresh device-key step-up. Call /api/admin/elevate-challenge then /api/admin/elevate.",
        },
        { status: 403 },
        applySecurityHeaders,
      ),
    };
  }

  const elevRaw = await env.BILLING_KV.get(elevTokenKey(elev));
  if (!elevRaw) {
    return {
      ok: false,
      response: json(
        {
          error: "elevation_expired",
          message: "Elevation expired or invalid. Unlock admin privileges again.",
        },
        { status: 403 },
        applySecurityHeaders,
      ),
    };
  }

  let elevRec: ElevToken;
  try {
    elevRec = JSON.parse(elevRaw) as ElevToken;
  } catch {
    await env.BILLING_KV.delete(elevTokenKey(elev));
    return {
      ok: false,
      response: json(
        { error: "elevation_invalid" },
        { status: 403 },
        applySecurityHeaders,
      ),
    };
  }

  const sealedToSession =
    Boolean(elevRec?.adminHash && elevRec.userHash) &&
    elevRec.adminHash === privilegeSeal("unlock", user.fingerprint) &&
    elevRec.userHash === userSeal(user.id);
  const legacySession =
    !elevRec?.adminHash &&
    elevRec?.userId === user.id &&
    elevRec.fingerprint === user.fingerprint;
  if (
    (!sealedToSession && !legacySession) ||
    !hasUnexpiredTimestamp(elevRec?.expiresAt)
  ) {
    await env.BILLING_KV.delete(elevTokenKey(elev));
    return {
      ok: false,
      response: json(
        {
          error: "elevation_expired",
          message: "Elevation expired or does not match this session.",
        },
        { status: 403 },
        applySecurityHeaders,
      ),
    };
  }

  return { ok: true };
}

const AUDIT_CHAIN_KEY = "auth:log-chain:audit";
const AUDIT_TTL_SECONDS = 60 * 60 * 24 * 180;

function cleanAction(value: string): string {
  return /^[a-z0-9_]{1,64}$/.test(value) ? value : "other";
}

function cleanDetail(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f]/g, "").slice(0, 200);
}

function hashOrEmpty(value: unknown): string {
  return typeof value === "string" && isPqcLogHash(value) ? value : "";
}

function usableIp(value: string): string {
  const ip = value.trim().slice(0, 64);
  if (ip === "unknown") return ip;
  return /^[0-9a-fA-F:.]+$/.test(ip) ? ip : "";
}

export type PublicAudit = {
  at: string;
  action: string;
  ok: boolean;
  detail: string;
  adminHash: string;
  targetHash: string;
  networkHash: string;
  recordHash: string;
  prevHash: string;
  chain: string;
};

function asPublicAudit(value: unknown, pepper: string): PublicAudit | null {
  if (!value || typeof value !== "object") return null;
  const row = value as Record<string, unknown>;
  const at = typeof row.at === "string" && /^\d{4}-\d{2}-\d{2}T/.test(row.at) ? row.at.slice(0, 40) : "";
  const action = typeof row.action === "string" ? cleanAction(row.action) : "";
  if (!at || !action) return null;
  let admin = hashOrEmpty(row.adminHash);
  let target = hashOrEmpty(row.targetHash);
  let network = hashOrEmpty(row.networkHash);
  if (!admin && typeof row.adminFingerprint === "string") admin = accountHash(row.adminFingerprint, pepper);
  if (!target && typeof row.targetFingerprint === "string") target = accountHash(row.targetFingerprint, pepper);
  if (!network && typeof row.ip === "string") {
    const ip = usableIp(row.ip);
    if (ip) network = networkHash(ip, pepper);
  }
  return {
    at,
    action,
    ok: row.ok !== false,
    detail: typeof row.detail === "string" ? cleanDetail(row.detail) : "",
    adminHash: admin,
    targetHash: target,
    networkHash: network,
    recordHash: hashOrEmpty(row.recordHash),
    prevHash: hashOrEmpty(row.prevHash),
    chain: hashOrEmpty(row.chain),
  };
}

async function readAuditChainTip(env: AdminEnv): Promise<string> {
  if (!env.BILLING_KV) return "";
  const raw = await env.BILLING_KV.get(AUDIT_CHAIN_KEY);
  return raw && isPqcLogHash(raw) ? raw : "";
}

async function listPrefixedKeys(env: AdminEnv, prefix: string): Promise<string[]> {
  if (!env.BILLING_KV) return [];
  const names: string[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < 4; page++) {
    const listed = await env.BILLING_KV.list({ prefix, limit: 1000, cursor });
    for (const key of listed.keys) names.push(key.name);
    if (listed.list_complete || !listed.cursor) break;
    cursor = listed.cursor;
  }
  return names;
}

async function listPublicAudits(env: AdminEnv, take = 40, includeLegacy = true): Promise<PublicAudit[]> {
  if (!env.BILLING_KV) return [];
  const scan = Math.min(Math.max(take, 1), 100);
  const pepper = readLogPepper(env);
  const sealed = includeLegacy ? (await listPrefixedKeys(env, "admin:seal:")).slice(0, scan)
    : (await env.BILLING_KV.list({ prefix: "admin:seal:", limit: scan })).keys.map(key => key.name);
  const legacy = includeLegacy ? await listPrefixedKeys(env, "admin:audit:") : [];
  const names = [...sealed, ...legacy.slice(-scan)];
  const entries: PublicAudit[] = [];
  for (const name of names) {
    const raw = await env.BILLING_KV.get(name);
    if (!raw) continue;
    try {
      const parsed = asPublicAudit(JSON.parse(raw), pepper);
      if (parsed) entries.push(parsed);
    } catch {
      // skip a damaged row
    }
  }
  entries.sort((a, b) => b.at.localeCompare(a.at));
  return entries.slice(0, scan);
}

async function writeAudit(env: AdminEnv, entry: AuditEntry) {
  if (!env.BILLING_KV) return;
  try {
    const at = /^\d{4}-\d{2}-\d{2}T/.test(entry.at) ? entry.at.slice(0, 40) : new Date().toISOString();
    const pepper = readLogPepper(env);
    const fields: AuditSealFields = {
      at,
      action: cleanAction(entry.action),
      ok: entry.ok !== false,
      detail: cleanDetail(entry.detail || ""),
      adminHash: accountHash(entry.adminFingerprint, pepper),
      targetHash: entry.targetFingerprint
        ? accountHash(entry.targetFingerprint, pepper)
        : entry.targetHash && isPqcLogHash(entry.targetHash)
          ? entry.targetHash
          : "",
      networkHash: networkHash(entry.ip, pepper),
    };
    const recordHash = auditRecordHash(fields);
    const prevHash = await readAuditChainTip(env);
    const chain = chainHash(prevHash, recordHash);
    const stamp = String(9_999_999_999_999 - Date.now()).padStart(13, "0");
    const key = `admin:seal:${stamp}_${randomHex(4)}`;
    await env.BILLING_KV.put(
      key,
      JSON.stringify({
        v: 1,
        alg: PQC_LOG_ALG,
        ...fields,
        recordHash,
        prevHash,
        chain,
      }),
      { expirationTtl: AUDIT_TTL_SECONDS },
    );
    await env.BILLING_KV.put(AUDIT_CHAIN_KEY, chain);
    return key;
  } catch {
    // Skip the write rather than store a raw network or account.
  }
}

type AdminGate =
  | { ok: true; user: UserRecord; sessionId: string }
  | { ok: false; response: Response };
type RecordAudit = (entry: AuditEntry) => Promise<unknown>;

async function authorizeAdminSession(
  request: Request,
  env: AdminEnv,
  session: Awaited<ReturnType<typeof getSessionUser>>,
  applySecurityHeaders?: SecurityHeadersFn,
  audit: RecordAudit = (entry) => writeAudit(env, entry),
): Promise<AdminGate> {
  if (!session) {
    return {
      ok: false,
      response: json(
        { error: "login_required", message: "Sign in as an admin." },
        { status: 401 },
        applySecurityHeaders,
      ),
    };
  }

  if (!(await isAdminUserWithKv(session.user, env, request))) {
    await audit({
      at: new Date().toISOString(),
      adminUserId: session.user.id,
      adminFingerprint: session.user.fingerprint,
      action: "admin_denied",
      detail: "not_on_allowlist",
      ip: clientIp(request),
      ok: false,
    });
    return {
      ok: false,
      response: json(
        { error: "forbidden", message: "Admin access required." },
        { status: 403 },
        applySecurityHeaders,
      ),
    };
  }

  return { ok: true, user: session.user, sessionId: session.sessionId };
}

// The session and request rate limit both come from the normal Worker path.
async function requireAdminSession(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<AdminGate> {
  const limited = await rateLimitDurable(
    env, `admin:${clientIp(request)}`, 30, 60_000, applySecurityHeaders,
  );
  if (limited) return { ok: false, response: limited };
  return authorizeAdminSession(request, env, await getSessionUser(request, env), applySecurityHeaders);
}

/**
 * Last check for privileged actions: the signed session key is an exact
 * ADMIN_FINGERPRINTS member. The header value is never treated as proof.
 */
async function rejectUnlessAllowlistedFingerprint(
  request: Request,
  env: AdminEnv,
  user: UserRecord,
  applySecurityHeaders?: SecurityHeadersFn,
  audit: RecordAudit = (entry) => writeAudit(env, entry),
): Promise<Response | null> {
  if (await isAllowlistedAdminFingerprintWithKv(user.fingerprint, env, request)) return null;
  await audit({
    at: new Date().toISOString(),
    adminUserId: user.id,
    adminFingerprint: user.fingerprint,
    action: "admin_fingerprint_denied",
    detail: "not_on_fingerprint_allowlist",
    ip: clientIp(request),
    ok: false,
  });
  return json(
    {
      error: "admin_fingerprint_required",
      message:
        "Privileged actions need a signature from a key on ADMIN_FINGERPRINTS. A user-id entry is not enough, and no shared action secret is accepted.",
    },
    { status: 403 },
    applySecurityHeaders,
  );
}

async function requirePurpleTeamSession(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
) {
  const gate = await requireAdminSession(request, env, applySecurityHeaders);
  if (!gate.ok) return gate;
  const denied = await rejectUnlessAllowlistedFingerprint(request, env, gate.user, applySecurityHeaders);
  return denied ? { ok: false as const, response: denied } : gate;
}

export async function adminPurpleTeamRecon(
  request: Request,
  env: AdminEnv & PurpleTeamBindings,
  applySecurityHeaders: SecurityHeadersFn,
): Promise<Response> {
  const gate = await requirePurpleTeamSession(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;

  const url = new URL(request.url);
  if (url.pathname === RECON_CERTIFICATE_PATH || url.pathname === RECON_CERTIFICATE_PATH + "/") {
    return reconCertificatePage((url.searchParams.get("name") ?? "").slice(0, 254), applySecurityHeaders);
  }
  const ownConnection = {
    ...readConnectionMetadata(request),
    address: parseReconAddress(getCloudflareClientIp(request) ?? ""),
  };
  const render = (page: ReconPageData) => reconPage({ ...page, ownConnection }, applySecurityHeaders);
  const store = (domain: string) => purpleTeamHost(env, "recon:" + domain);
  if (request.method !== "POST") {
    const input = url.searchParams.get("t") ?? "";
    const address = parseReconAddress(input);
    if (address) return render({ domain: address.value });
    const domain = normalizeReconDomain(input) ?? "";
    if (!domain) {
      try {
        const savedDomains = await purpleTeamDirectory(env).recentReconHosts();
        return render({ domain, savedDomains });
      } catch {
        return render({ domain, notice: "The saved domain list is unavailable." });
      }
    }
    const id = url.searchParams.get("snapshot") ?? undefined;
    const download = url.searchParams.get("download") === "1";
    if (id && !/^\d{13}-[0-9a-f-]{36}$/.test(id)) {
      return render({ domain, notice: "Saved snapshot unavailable.", status: 404 });
    }
    try {
      const history = await store(domain).reconHistory(id);
      if ((id || download) && !history.selected) {
        return render({ domain, notice: "Saved snapshot unavailable.", status: 404 });
      }
      return render({
        domain, snapshot: history.selected ?? undefined, results: history.selected?.results,
        previous: history.previous, entries: history.entries, download,
      });
    } catch {
      return render({ domain, notice: "Snapshot history is unavailable.", status: 503 });
    }
  }
  if (request.headers.get("origin") !== url.origin) {
    return json({ error: "same_origin_required" }, { status: 403 }, applySecurityHeaders);
  }
  if (!/^application\/x-www-form-urlencoded(?:\s*;|$)/i.test(request.headers.get("content-type") ?? "")) {
    return json({ error: "form_required" }, { status: 415 }, applySecurityHeaders);
  }
  let fields: URLSearchParams;
  try {
    fields = new URLSearchParams(await readBoundedRequestText(request, 1024));
  } catch (error) {
    return error instanceof BodyLimitError ? bodyTooLargeResponse(applySecurityHeaders)
      : json({ error: "invalid_form" }, { status: 400 }, applySecurityHeaders);
  }
  const input = fields.get("domain") ?? "";
  const address = parseReconAddress(input);
  if (address) {
    const limited = await rateLimitDurable(env, "purple:recon:" + gate.user.id, 6, 60_000, applySecurityHeaders);
    if (limited) return limited;
    const ipResults = await lookupIpRecon(address);
    const unavailable = address.isPublic && !ipResults.routing && ipResults.names === null;
    return render({ domain: address.value, ipResults, status: unavailable ? 503 : 200 });
  }
  const domain = normalizeReconDomain(input);
  if (!domain) {
    return render({ domain: "", notice: "Enter a public domain or an IPv4 or IPv6 address.", status: 400 });
  }
  const selectorInput = fields.get("selector")?.trim() ?? "";
  const selector = selectorInput ? normalizeDkimSelector(selectorInput) : undefined;
  if (selectorInput && (!selector || (selector + "._domainkey." + domain).length > 253)) {
    return render({ domain, notice: "Enter one DKIM selector label, such as selector1.", status: 400 });
  }
  const limited = await rateLimitDurable(env, "purple:recon:" + gate.user.id, 6, 60_000, applySecurityHeaders);
  if (limited) return limited;

  const results = await lookupPublicRecon(domain);
  if (fields.get("mail") === "1" || selector) {
    results.mail = await inspectMailPolicies(domain, results.dns, selector ?? undefined);
  }
  const unavailable = !results.certificates && results.dns.every(record => record.values === null);
  if (unavailable) return render({
    domain, results, notice: "Public sources are unavailable. Retry to collect a snapshot.", status: 503,
  });
  try {
    if (fields.get("save") === "1") {
      const actor = accountHash(gate.user.fingerprint, readLogPepper(env)) || userSeal(gate.user.id);
      const history = await store(domain).saveRecon(results, actor);
      if (!history) return render({ domain, results, notice: "The snapshot is too large to save." });
      let notice: string | undefined;
      if (history.selected) {
        try {
          await purpleTeamDirectory(env).noteReconSnapshot(domain, Date.parse(history.selected.at));
        } catch {
          notice = "Snapshot saved. The saved domain list could not be updated.";
        }
      }
      return render({
        domain, results, notice, snapshot: history.selected ?? undefined, previous: history.previous, entries: history.entries,
      });
    }
    const history = await store(domain).reconHistory();
    return render({ domain, results, previous: history.selected, entries: history.entries });
  } catch {
    return render({ domain, results, notice: "Snapshot history is unavailable." });
  }
}

async function confirmDrillAudit(
  env: AdminEnv,
  user: UserRecord,
  request: Request,
  detail: string,
  ok: boolean,
): Promise<boolean> {
  const key = await writeAudit(env, {
    at: new Date().toISOString(), adminUserId: user.id, adminFingerprint: user.fingerprint,
    action: "purple_team_drill", detail, ip: clientIp(request), ok,
  });
  if (!key || !env.BILLING_KV) return false;
  try {
    const raw = await env.BILLING_KV.get(key);
    const record = raw ? asPublicAudit(JSON.parse(raw), readLogPepper(env)) : null;
    return record?.action === "purple_team_drill" && record.detail === detail;
  } catch {
    return false;
  }
}

async function runCanaryDrill(
  request: Request,
  env: AdminEnv & PurpleTeamBindings,
  operator: UserRecord,
  dispatch: (request: Request) => Promise<Response>,
): Promise<ToolResult> {
  const runId = crypto.randomUUID();
  const directory = purpleTeamDirectory(env);
  await directory.armCanary(runId);
  const response = await dispatch(new Request(new URL(CANARY_PATH + runId, request.url)));
  await response.body?.cancel();
  const receipt = await directory.canaryReceipt(runId);
  const hit = receipt?.hit ?? null;
  const observed = hit !== null && response.status === 404;
  const elapsed = receipt && hit !== null ? (hit - receipt.armed) + " ms" : "unknown";
  const auditVisible = await confirmDrillAudit(
    env, operator, request, runId + " canary " + response.status + " " + elapsed, observed,
  );
  return {
    title: "Canary drill", runId, findings: [
      { check: "Canary request", status: observed ? "pass" : "review",
        evidence: "HTTP " + response.status + " · Durable Object receipt " + (hit === null ? "missing" : "recorded in " + elapsed) + "." },
      { check: "Globe audit event", status: auditVisible ? "pass" : "unknown",
        evidence: auditVisible ? "The matching event was confirmed in the sealed admin audit log."
          : "The matching audit event was unavailable on readback." },
    ],
  };
}

type OperationsEnv = AdminEnv & PurpleTeamBindings & Pick<Env, "Globe">;
const globeRoom = (env: OperationsEnv, name: string) => env.Globe.get(env.Globe.idFromName(name));

export async function adminSecurityOperations(
  request: Request,
  env: OperationsEnv,
  applySecurityHeaders: SecurityHeadersFn,
  dispatch: (request: Request) => Promise<Response>,
): Promise<Response> {
  const gate = await requirePurpleTeamSession(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;
  const directory = purpleTeamDirectory(env);
  const url = new URL(request.url);
  const render = async (details: Partial<OperationsPageData> = {}) => {
    const [room, inbox] = await Promise.allSettled([
      globeRoom(env, "default").operationsStatus(),
      directory.operationsAlerts(),
    ]);
    return operationsPage({
      checkedAt: new Date().toISOString(),
      edge: String(request.cf?.colo ?? "").slice(0, 8),
      room: room.status === "fulfilled" ? room.value : null,
      inbox: inbox.status === "fulfilled" ? inbox.value : null,
      ...details,
    }, applySecurityHeaders);
  };
  if (request.method !== "POST") {
    const host = url.searchParams.get("host");
    if (!host) return render();
    try {
      if (host.length <= 253 && await directory.hasHost(host)) {
        const archive = await purpleTeamHost(env, host).view(url.searchParams.get("report") || undefined);
        if (archive.state?.hostname === host) return await render({ archive });
      }
      return render({ notice: "Saved website report unavailable.", status: 404 });
    } catch {
      return render({ notice: "Saved website reports are temporarily unavailable.", status: 503 });
    }
  }
  if (request.headers.get("origin") !== url.origin) {
    return json({ error: "same_origin_required" }, { status: 403 }, applySecurityHeaders);
  }
  if (!/^application\/x-www-form-urlencoded(?:\s*;|$)/i.test(request.headers.get("content-type") ?? "")) {
    return json({ error: "form_required" }, { status: 415 }, applySecurityHeaders);
  }
  let fields: URLSearchParams;
  try {
    fields = new URLSearchParams(await readBoundedText(request.body, 2048));
  } catch (error) {
    return error instanceof BodyLimitError ? bodyTooLargeResponse(applySecurityHeaders)
      : json({ error: "invalid_form" }, { status: 400 }, applySecurityHeaders);
  }
  const limited = await rateLimitDurable(env, "purple:operations:" + gate.user.id, 8, 60_000, applySecurityHeaders);
  if (limited) return limited;
  const tool = fields.get("tool");
  const runId = crypto.randomUUID();
  const result = async (title: string, findings: ToolFinding[]) => {
    const passed = findings.every(finding => finding.status === "pass");
    const receipt = await confirmDrillAudit(env, gate.user, request, runId + " " + tool, passed);
    return render({
      result: { title, runId, findings: [...findings, {
        check: "Exercise audit receipt", status: receipt ? "pass" : "unknown",
        evidence: receipt ? "Confirmed in the sealed admin audit log." : "The audit entry could not be confirmed.",
      }] },
    });
  };

  try {
    if (tool === "drills") {
      const [session, feed] = await Promise.all([runSessionContainmentDrill(), runFeedIsolationDrill()]);
      return await result("Local session and Live Feed drills", [...session, ...feed]);
    }
    if (tool === "evaluate") {
      const [logins, audits] = await Promise.all([
        listLoginAttempts(env, RECENT_LOGIN_LIMIT, 0),
        listPublicAudits(env, RECENT_AUDIT_LIMIT, false),
      ]);
      const alerts = detectOperationsAlerts(logins, audits, Date.now());
      await directory.recordOperationsAlerts(alerts);
      return await render({ notice: "Evaluated " + logins.length + " sign-in records and " + audits.length +
        " audit records. Matched " + alerts.length + " detections." });
    }
    if (tool === "alert_state") {
      const id = fields.get("alert") ?? "";
      const state = fields.get("state");
      if (!/^[a-z0-9:-]{4,256}$/.test(id) || (state !== "acknowledged" && state !== "resolved" && state !== "open")) {
        return json({ error: "invalid_alert_update" }, { status: 400 }, applySecurityHeaders);
      }
      const actor = accountHash(gate.user.fingerprint, readLogPepper(env)) || userSeal(gate.user.id);
      const changed = await directory.setOperationsAlertState(id, state, actor);
      const auditRecorded = changed ? Boolean(await writeAudit(env, {
        at: new Date().toISOString(), adminUserId: gate.user.id, adminFingerprint: gate.user.fingerprint,
        action: "operations_alert_state", detail: state + " " + id.slice(0, 140), ip: clientIp(request), ok: true,
      })) : false;
      const notice = changed ? "Alert updated." + (auditRecorded ? "" : " Audit receipt unavailable.")
        : "The alert state is already current or the alert has expired.";
      return await render({ notice });
    }
    if (tool === "checks" || tool === "health") {
      const checks = [
        { path: "/", check: "Globe shell", expected: 200 },
        { path: "/api/auth/me", check: "Session endpoint", expected: 200 },
        { path: "/api/live-feed/connection", check: "Live Feed connection endpoint", expected: 200 },
        { path: OPERATIONS_PATH, check: "Purple Team signed-out gate", expected: 401 },
      ];
      const findings: ToolFinding[] = [];
      for (const spec of checks) {
        const started = Date.now();
        try {
          const response = await dispatch(new Request(new URL(spec.path, url), { method: "HEAD" }));
          await response.body?.cancel();
          findings.push({
            check: spec.check,
            status: response.status === 429 ? "unknown" : response.status === spec.expected ? "pass" : "review",
            evidence: "Expected HTTP " + spec.expected + " · Observed HTTP " + response.status +
              " · " + (Date.now() - started) + " ms inside the Worker.",
          });
          if (spec.path === "/" && response.ok) {
            findings.push(...globeHeaderFindings(response.headers, sessionCookie("fixture", request)));
          }
        } catch {
          findings.push({ check: spec.check, status: "unknown", evidence: "The Worker did not return a response." });
        }
      }
      let canaryId: string | undefined;
      try {
        const canary = await runCanaryDrill(request, env, gate.user, dispatch);
        canaryId = canary.runId;
        findings.push(...canary.findings);
      } catch {
        findings.push({ check: "Canary", status: "unknown", evidence: "The canary receipt could not be checked." });
      }
      return await render({ result: { title: "Globe checks", runId: canaryId, findings } });
    }
  } catch {
    return render({ notice: "An operations service was unavailable. Refresh its state before retrying.", status: 503 });
  }
  return json({ error: "invalid_tool" }, { status: 400 }, applySecurityHeaders);
}

export async function retiredPurpleTeamRoute(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders: SecurityHeadersFn,
  page: boolean,
): Promise<Response> {
  const gate = await requirePurpleTeamSession(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;
  if (page && (request.method === "GET" || request.method === "HEAD")) {
    const headers = new Headers({ location: OPERATIONS_PATH, "cache-control": "private, no-store" });
    applySecurityHeaders(headers);
    return new Response(null, { status: 303, headers });
  }
  return json({ error: "purple_team_tool_retired" }, { status: 410 }, applySecurityHeaders);
}

export async function adminSessionContainment(
  request: Request,
  env: OperationsEnv,
  applySecurityHeaders: SecurityHeadersFn,
): Promise<Response> {
  const send = (body: unknown, status = 200) => json(body, { status }, applySecurityHeaders);
  if (request.headers.get("origin") !== new URL(request.url).origin) return send({ error: "same_origin_required" }, 403);
  const gate = await requireAdminMutation(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;
  const limited = await rateLimitDurable(env, "purple:containment:" + gate.user.id, 12, 60_000, applySecurityHeaders);
  if (limited) return limited;
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get("content-type") ?? "")) {
    return send({ error: "json_required" }, 415);
  }
  let body: { action?: unknown; account?: unknown; reference?: unknown; paused?: unknown };
  try {
    body = await readJsonBody(request, 2048) as typeof body;
  } catch (error) {
    return error instanceof BodyLimitError ? bodyTooLargeResponse(applySecurityHeaders)
      : send({ error: "invalid_json" }, 400);
  }
  const directory = purpleTeamDirectory(env);
  const audit = async (action: string, detail: string, targetFingerprint?: string) => Boolean(await writeAudit(env, {
    at: new Date().toISOString(), adminUserId: gate.user.id, adminFingerprint: gate.user.fingerprint,
    action, detail, targetFingerprint, ip: clientIp(request), ok: true,
  }));
  try {
    if (body?.action === "status") return send({ paused: await directory.peerRequestsPaused() });
    if (body?.action === "pause" && typeof body.paused === "boolean") {
      await directory.setPeerRequestsPaused(body.paused);
      const auditRecorded = await audit("operations_peer_pause", body.paused ? "paused" : "resumed");
      return send({ paused: await directory.peerRequestsPaused(), auditRecorded });
    }
    if ((body?.action === "retest" || body?.action === "finish_disconnect") && validSessionReference(body.reference)) {
      const reference = body.reference;
      const revoked = await directory.isSessionRevoked(reference);
      if (!revoked) return send({ error: "revocation_unavailable" }, 404);
      const rooms = new Set(["default", ...await directory.sessionRooms(reference)]);
      if (body.action === "finish_disconnect") {
        const results = await Promise.allSettled([...rooms].map(room => globeRoom(env, room).disconnectSession(reference)));
        await audit("operations_session_disconnect",
          "session " + reference.slice(0, 12) + " · unconfirmed rooms " + results.filter(row => row.status === "rejected").length);
      }
      const counts = await Promise.allSettled([...rooms].map(room => globeRoom(env, room).sessionSocketCount(reference)));
      const open = counts.reduce((sum, row) => sum + (row.status === "fulfilled" ? row.value : 0), 0);
      return send({ revoked, open, unknownRooms: counts.filter(row => row.status === "rejected").length });
    }
    if (body?.action !== "sessions" && body?.action !== "revoke") return send({ error: "invalid_action" }, 400);
    const lookup = typeof body.account === "string" ? body.account.trim() : "";
    if (!lookup || lookup.length > 128) return send({ error: "invalid_account", message: "Enter an exact account ID or fingerprint." }, 400);
    const fingerprint = normalizeFingerprint(lookup);
    const user = await getUserById(env, lookup) ??
      (fingerprint && /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(fingerprint) ? await getUserByFingerprint(env, fingerprint) : null);
    if (!user) return send({ error: "account_not_found", message: "Account not found." }, 404);
    const sessions = await sessionRecordsForAccount(env, user.id);
    if (body.action === "sessions") return send({
      account: user.id,
      fingerprint: maskFingerprint(user.fingerprint),
      sessions: await Promise.all(sessions.map(async entry => ({
        reference: entry.reference, createdAt: entry.createdAt, expiresAt: entry.expiresAt,
        current: entry.sessionId === gate.sessionId,
        revoked: await directory.isSessionRevoked(entry.reference),
      }))),
    });
    if (!validSessionReference(body.reference)) return send({ error: "invalid_session_reference" }, 400);
    const selected = sessions.find(entry => entry.reference === body.reference);
    if (!selected) return send({ error: "session_unavailable", message: "Reload the account’s sessions." }, 404);
    if (selected.sessionId === gate.sessionId) return send({ error: "current_session", message: "Use Sign out to end this session." }, 409);
    await directory.revokeSession(selected.reference, Date.parse(selected.expiresAt));
    const rooms = new Set(["default", ...await directory.sessionRooms(selected.reference)]);
    const results = await Promise.allSettled([...rooms].map(room => globeRoom(env, room).disconnectSession(selected.reference)));
    const disconnected = results.reduce((sum, row) => sum + (row.status === "fulfilled" ? row.value : 0), 0);
    const unknownRooms = results.filter(row => row.status === "rejected").length;
    const kvRemoved = await env.BILLING_KV?.delete(authSessionStorageKey(selected.sessionId)).then(() => true, () => false) ?? false;
    const auditRecorded = await audit("operations_session_revoke",
      "session " + selected.reference.slice(0, 12) + " · disconnected " + disconnected + " · unconfirmed rooms " + unknownRooms,
      user.fingerprint);
    return send({ revoked: true, reference: selected.reference, disconnected, unknownRooms, kvRemoved, auditRecorded });
  } catch {
    return send({ error: "operations_unavailable", message: "The operations service is unavailable. Check its state before retrying." }, 503);
  }
}

/**
 * Mutating admin actions: session, device-key elevation, then fingerprint allowlist.
 * Fail closed when ADMIN_FINGERPRINTS is empty or the signed key is absent.
 */
async function requireAdminMutation(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<
  | { ok: true; user: UserRecord; sessionId: string }
  | { ok: false; response: Response }
> {
  const gate = await requireAdminSession(request, env, applySecurityHeaders);
  if (!gate.ok) return gate;

  const elevGate = await requireElevation(
    request,
    env,
    gate.user,
    applySecurityHeaders,
  );
  if (!elevGate.ok) return elevGate;

  const fingerprintDenied = await rejectUnlessAllowlistedFingerprint(
    request,
    env,
    gate.user,
    applySecurityHeaders,
  );
  if (fingerprintDenied) return { ok: false, response: fingerprintDenied };

  return gate;
}

export async function adminStatus(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const gate = await requireAdminSession(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;

  return json(
    {
      ok: true,
      admin: publicUser(gate.user),
      actionSecretRequired: false,
      actionSecretConfigured: false,
      elevationTtlSeconds: ELEV_TOKEN_TTL_SEC,
      security: {
        mutationsRequire: [
          "allowlisted_session",
          "device_key_elevation",
          "admin_fingerprint_allowlist",
        ],
        note: "Client isAdmin is UI only. The last check is the signed key's exact ADMIN_FINGERPRINTS match. A shared action secret is not accepted.",
      },
      capabilities: {
        read: ["lookup_user", "list_recent_audit", "elevate"],
        /** list_users is elevated — device-key signature plus fingerprint allowlist. */
        elevatedRead: ["list_users"],
        mutate: [
          "grant_transit",
          "revoke_transit",
          "grant_unlimited_keys",
          "revoke_unlimited_keys",
          "claim_session",
          "delete_user",
        ],
      },
    },
    { status: 200 },
    applySecurityHeaders,
  );
}

/**
 * Issue a short-lived message the admin private key must sign.
 * Session must already be an allowlisted admin.
 */
const UNLIMITED_KEY_PROTOCOL = "globe-unlimited-keys:v1";

function elevationMessage(request: Request, user: UserRecord, challenge: ElevChallenge): string | null {
  if (!hasUnexpiredTimestamp(challenge?.expiresAt)) return null;
  if (challenge.message && challenge.userId && challenge.fingerprint) {
    if (challenge.userId !== user.id || challenge.fingerprint !== user.fingerprint) return null;
    return challenge.message;
  }
  if (
    !challenge.nonce ||
    typeof challenge.expiresAtMs !== "number" ||
    !challenge.adminHash ||
    !challenge.userHash ||
    !/^[a-f0-9]{16,64}$/.test(challenge.nonce)
  ) {
    return null;
  }
  if (!Number.isFinite(challenge.expiresAtMs) || challenge.expiresAtMs <= Date.now()) return null;
  if (challenge.adminHash !== privilegeSeal("unlock", user.fingerprint)) return null;
  if (challenge.userHash !== userSeal(user.id)) return null;
  return [
    ADMIN_PROTOCOL,
    new URL(request.url).origin,
    user.id,
    user.fingerprint,
    challenge.nonce,
    String(challenge.expiresAtMs),
  ].join("|");
}

async function verifyHeldKey(
  user: UserRecord,
  message: string,
  pqcSignature: string,
  signatureArmored: string,
): Promise<boolean> {
  try {
    const storedPqc = decodeStoredPublicKey(user.publicKeyArmored);
    if (storedPqc) {
      if (!pqcSignature || pqcSignature.length > 70_000) return false;
      const signature = b64ToFixedBytes(pqcSignature, PQC_SIG_SUITES[storedPqc.suite].signature);
      return verifyPqcSignature(storedPqc.suite, signature, message, storedPqc.publicKey);
    }
    if (!signatureArmored || signatureArmored.length > MAX_SIGNATURE_CHARS) return false;
    if (/BEGIN PGP PRIVATE KEY BLOCK/i.test(signatureArmored)) return false;
    const publicKey = await openpgp.readKey({ armoredKey: user.publicKeyArmored });
    const signed = await openpgp.createMessage({ text: message });
    const signature = await openpgp.readSignature({ armoredSignature: signatureArmored });
    const result = await openpgp.verify({
      message: signed,
      signature,
      verificationKeys: publicKey,
    });
    const sig = result.signatures[0];
    if (!sig) return false;
    await sig.verified;
    return true;
  } catch {
    return false;
  }
}

function unlimitedKeyPrivilegeMessage(
  action: "grant" | "revoke",
  targetFingerprint: string,
  adminFingerprint: string,
): string {
  return `${UNLIMITED_KEY_PROTOCOL}|${action}|${targetFingerprint}|${adminFingerprint}`;
}

export async function adminElevateChallenge(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const gate = await requireAdminSession(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;

  if (!env.BILLING_KV) {
    return json(
      { error: "kv_missing" },
      { status: 503 },
      applySecurityHeaders,
    );
  }

  const fingerprintDenied = await rejectUnlessAllowlistedFingerprint(
    request,
    env,
    gate.user,
    applySecurityHeaders,
  );
  if (fingerprintDenied) return fingerprintDenied;

  const challengeId = randomHex(16);
  const nonce = randomHex(16);
  const expiresAtMs = Date.now() + ELEV_CHALLENGE_TTL_SEC * 1000;
  const expiresAt = new Date(expiresAtMs).toISOString();
  const origin = new URL(request.url).origin;
  const adminHash = privilegeSeal("unlock", gate.user.fingerprint);
  const sessionUserHash = userSeal(gate.user.id);
  if (!adminHash || !sessionUserHash) {
    return json(
      { error: "admin_misconfigured", message: "This admin key has no fingerprint seal." },
      { status: 503 },
      applySecurityHeaders,
    );
  }
  const message = [
    ADMIN_PROTOCOL,
    origin,
    gate.user.id,
    gate.user.fingerprint,
    nonce,
    String(expiresAtMs),
  ].join("|");

  const record: ElevChallenge = {
    v: 1,
    adminHash,
    userHash: sessionUserHash,
    nonce,
    expiresAtMs,
    createdAt: new Date().toISOString(),
    expiresAt,
  };

  await env.BILLING_KV.put(
    elevChallengeKey(challengeId),
    JSON.stringify(record),
    { expirationTtl: ELEV_CHALLENGE_TTL_SEC },
  );

  return json(
    {
      challengeId,
      message,
      expiresAt,
      fingerprint: gate.user.fingerprint,
      instructions:
        "Sign message with your device private key (never upload the key). POST signature to /api/admin/elevate.",
    },
    { status: 200 },
    applySecurityHeaders,
  );
}

/**
 * Verify PGP signature over elevate challenge → short-lived elevation token.
 */
export async function adminElevate(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const gate = await requireAdminSession(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;

  if (!env.BILLING_KV) {
    return json(
      { error: "kv_missing" },
      { status: 503 },
      applySecurityHeaders,
    );
  }

  const limited = await rateLimitDurable(
    env,
    `admin:elevate:${gate.user.id}`,
    8,
    60_000,
    applySecurityHeaders,
  );
  if (limited) return limited;

  let body: { challengeId?: string; signatureArmored?: string; pqcSignature?: string } = {};
  try {
    body = (await readJsonBody(request)) as typeof body;
    assertNoPrivateKeyMaterial(body);
  } catch (error) {
    if (error instanceof BodyLimitError) return bodyTooLargeResponse(applySecurityHeaders);
    if (error instanceof Error && error.message === "private_key_rejected") {
      return json(
        {
          error: "private_key_rejected",
          message: "Send a detached signature only — never a private key.",
        },
        { status: 400 },
        applySecurityHeaders,
      );
    }
    return json(
      { error: "invalid_json" },
      { status: 400 },
      applySecurityHeaders,
    );
  }

  const challengeId = body.challengeId?.trim() || "";
  const signatureArmored = body.signatureArmored?.trim() || "";
  const pqcSignature = body.pqcSignature?.trim() || "";
  if (!challengeId || !/^[a-f0-9]{16,128}$/i.test(challengeId)) {
    return json(
      {
        error: "invalid_elevate",
        message: "challengeId and a device signature are required.",
      },
      { status: 400 },
      applySecurityHeaders,
    );
  }

  if (/BEGIN PGP PRIVATE KEY BLOCK/i.test(signatureArmored) || /BEGIN PGP PRIVATE KEY BLOCK/i.test(pqcSignature)) {
    return json(
      { error: "private_key_rejected" },
      { status: 400 },
      applySecurityHeaders,
    );
  }

  // Single-use challenge consume
  const chalKey = elevChallengeKey(challengeId);
  const chalRaw = await env.BILLING_KV.get(chalKey);
  if (chalRaw) await env.BILLING_KV.delete(chalKey);

  if (!chalRaw) {
    return json(
      {
        error: "invalid_challenge",
        message: "Elevation challenge expired or already used.",
      },
      { status: 401 },
      applySecurityHeaders,
    );
  }

  let challenge: ElevChallenge;
  try {
    challenge = JSON.parse(chalRaw) as ElevChallenge;
  } catch {
    return json(
      { error: "invalid_challenge" },
      { status: 401 },
      applySecurityHeaders,
    );
  }

  const signedMessage = elevationMessage(request, gate.user, challenge);
  if (!signedMessage) {
    return json(
      {
        error: "invalid_challenge",
        message: "Elevation challenge does not match this admin session.",
      },
      { status: 401 },
      applySecurityHeaders,
    );
  }

  const signatureOk = await verifyHeldKey(gate.user, signedMessage, pqcSignature, signatureArmored);
  if (!signatureOk) {
    await writeAudit(env, {
      at: new Date().toISOString(),
      adminUserId: gate.user.id,
      adminFingerprint: gate.user.fingerprint,
      action: "elevate_failed",
      detail: "bad_signature",
      ip: clientIp(request),
      ok: false,
    });
    return json(
      {
        error: "auth_failed",
        message: "Could not verify elevation signature.",
      },
      { status: 401 },
      applySecurityHeaders,
    );
  }

  const fingerprintDenied = await rejectUnlessAllowlistedFingerprint(
    request,
    env,
    gate.user,
    applySecurityHeaders,
  );
  if (fingerprintDenied) return fingerprintDenied;

  const elevationToken = randomHex(32);
  const expiresAt = new Date(
    Date.now() + ELEV_TOKEN_TTL_SEC * 1000,
  ).toISOString();
  const elevRec: ElevToken = {
    v: 1,
    adminHash: privilegeSeal("unlock", gate.user.fingerprint),
    userHash: userSeal(gate.user.id),
    createdAt: new Date().toISOString(),
    expiresAt,
  };
  await env.BILLING_KV.put(elevTokenKey(elevationToken), JSON.stringify(elevRec), {
    expirationTtl: ELEV_TOKEN_TTL_SEC,
  });

  await writeAudit(env, {
    at: new Date().toISOString(),
    adminUserId: gate.user.id,
    adminFingerprint: gate.user.fingerprint,
    action: "elevate_ok",
    detail: `ttl=${ELEV_TOKEN_TTL_SEC}s`,
    ip: clientIp(request),
    ok: true,
  });

  return json(
    {
      elevationToken,
      expiresAt,
      ttlSeconds: ELEV_TOKEN_TTL_SEC,
      message:
        "Privileged window open for about 10 minutes. Grant unlimited keys to this account is ready.",
    },
    { status: 200 },
    applySecurityHeaders,
  );
}

export async function adminLookupUser(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const gate = await requireAdminSession(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;

  const url = new URL(request.url);
  const q = (url.searchParams.get("q") || "").trim();
  if (!q || q.length < 6) {
    return json(
      {
        error: "query_required",
        message: "Pass ?q=<userId|fingerprint> (min 6 chars).",
      },
      { status: 400 },
      applySecurityHeaders,
    );
  }

  let user: UserRecord | null = null;
  // Prefer full fingerprint match when 40/64 hex
  const asFp = normalizeFingerprint(q);
  if (asFp) {
    user = await getUserByFingerprint(env, asFp);
  }
  if (!user && /^[a-f0-9]{16,64}$/i.test(q)) {
    user = await getUserById(env, q.toLowerCase());
  }
  if (!user) {
    user = await getUserByFingerprint(env, q);
  }

  if (!user) {
    return json(
      { found: false, user: null },
      { status: 200 },
      applySecurityHeaders,
    );
  }

  await writeAudit(env, {
    at: new Date().toISOString(),
    adminUserId: gate.user.id,
    adminFingerprint: gate.user.fingerprint,
    action: "lookup_user",
    targetUserId: user.id,
    targetFingerprint: user.fingerprint,
    ip: clientIp(request),
    ok: true,
  });

  return json(
    { found: true, user: await withReceiptOrigin(env, user) },
    { status: 200 },
    applySecurityHeaders,
  );
}

export async function adminGrantTransit(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const gate = await requireAdminMutation(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;

  let body: { userId?: string; fingerprint?: string; note?: string } = {};
  try {
    body = (await readJsonBody(request)) as typeof body;
    assertNoPrivateKeyMaterial(body);
  } catch (error) {
    if (error instanceof BodyLimitError) return bodyTooLargeResponse(applySecurityHeaders);
    body = {};
  }

  let user: UserRecord | null = null;
  if (body.userId?.trim()) {
    user = await getUserById(env, body.userId.trim());
  }
  if (!user && body.fingerprint?.trim()) {
    user = await getUserByFingerprint(env, body.fingerprint.trim());
  }
  if (!user) {
    return json(
      {
        error: "user_not_found",
        message: "Provide a valid userId or fingerprint.",
      },
      { status: 404 },
      applySecurityHeaders,
    );
  }

  const updated = await setUserTransitPaid(env, user.id, true, "admin");
  if (!updated) {
    return json(
      { error: "update_failed" },
      { status: 500 },
      applySecurityHeaders,
    );
  }

  await writeAudit(env, {
    at: new Date().toISOString(),
    adminUserId: gate.user.id,
    adminFingerprint: gate.user.fingerprint,
    action: "grant_transit",
    targetUserId: user.id,
    targetFingerprint: user.fingerprint,
    detail: body.note?.slice(0, 200) || "manual grant",
    ip: clientIp(request),
    ok: true,
  });

  return json(
    {
      ok: true,
      user: publicUser(updated),
      message: "Transit access granted.",
    },
    { status: 200 },
    applySecurityHeaders,
  );
}

export async function adminRevokeTransit(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const gate = await requireAdminMutation(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;

  let body: { userId?: string; fingerprint?: string; note?: string } = {};
  try {
    body = (await readJsonBody(request)) as typeof body;
    assertNoPrivateKeyMaterial(body);
  } catch (error) {
    if (error instanceof BodyLimitError) return bodyTooLargeResponse(applySecurityHeaders);
    body = {};
  }

  let user: UserRecord | null = null;
  if (body.userId?.trim()) {
    user = await getUserById(env, body.userId.trim());
  }
  if (!user && body.fingerprint?.trim()) {
    user = await getUserByFingerprint(env, body.fingerprint.trim());
  }
  if (!user) {
    return json(
      { error: "user_not_found" },
      { status: 404 },
      applySecurityHeaders,
    );
  }

  const updated = await setUserTransitPaid(env, user.id, false);
  if (!updated) {
    return json(
      { error: "update_failed" },
      { status: 500 },
      applySecurityHeaders,
    );
  }

  await writeAudit(env, {
    at: new Date().toISOString(),
    adminUserId: gate.user.id,
    adminFingerprint: gate.user.fingerprint,
    action: "revoke_transit",
    targetUserId: user.id,
    targetFingerprint: user.fingerprint,
    detail: body.note?.slice(0, 200) || "manual revoke",
    ip: clientIp(request),
    ok: true,
  });

  return json(
    {
      ok: true,
      user: publicUser(updated),
      message: "Transit access revoked.",
    },
    { status: 200 },
    applySecurityHeaders,
  );
}

async function mutateUnlimitedKeys(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders: SecurityHeadersFn | undefined,
  grant: boolean,
): Promise<Response> {
  const gate = await requireAdminMutation(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;

  let body: {
    userId?: string;
    fingerprint?: string;
    note?: string;
    pqcSignature?: string;
    signatureArmored?: string;
  } = {};
  try {
    body = (await readJsonBody(request)) as typeof body;
    assertNoPrivateKeyMaterial(body);
  } catch (error) {
    if (error instanceof BodyLimitError) return bodyTooLargeResponse(applySecurityHeaders);
    if (error instanceof Error && error.message === "private_key_rejected") {
      return json(
        { error: "private_key_rejected", message: "Send a detached signature only — never a private key." },
        { status: 400 },
        applySecurityHeaders,
      );
    }
    return json({ error: "invalid_json" }, { status: 400 }, applySecurityHeaders);
  }

  const target = normalizeFingerprint(body.fingerprint || "");
  const adminFingerprint = normalizeFingerprint(gate.user.fingerprint);
  if (!target || !adminFingerprint) {
    return json(
      {
        error: "fingerprint_required",
        message: "Enter the account fingerprint. Unlimited keys follow that key.",
      },
      { status: 400 },
      applySecurityHeaders,
    );
  }

  const action = grant ? "grant" : "revoke";
  const signed = await verifyHeldKey(
    gate.user,
    unlimitedKeyPrivilegeMessage(action, target, adminFingerprint),
    body.pqcSignature?.trim() || "",
    body.signatureArmored?.trim() || "",
  );
  if (!signed) {
    await writeAudit(env, {
      at: new Date().toISOString(),
      adminUserId: gate.user.id,
      adminFingerprint: gate.user.fingerprint,
      action: grant ? "grant_unlimited_keys" : "revoke_unlimited_keys",
      detail: "bad_privilege_signature",
      ip: clientIp(request),
      ok: false,
    });
    return json(
      {
        error: "privilege_signature_required",
        message: "The admin key must sign this account fingerprint. A swapped account id is rejected.",
      },
      { status: 401 },
      applySecurityHeaders,
    );
  }

  const user = await getUserByFingerprint(env, target);
  if (!user) {
    return json(
      { error: "user_not_found", message: "No account is registered for that fingerprint." },
      { status: 404 },
      applySecurityHeaders,
    );
  }
  if (body.userId?.trim() && body.userId.trim().toLowerCase() !== user.id.toLowerCase()) {
    return json(
      {
        error: "fingerprint_mismatch",
        message: "The account id does not match the signed fingerprint.",
      },
      { status: 409 },
      applySecurityHeaders,
    );
  }

  const updated = await setUserUnlimitedKeys(env, user.id, grant, grant ? "admin" : undefined);
  if (!updated) {
    return json({ error: "update_failed" }, { status: 500 }, applySecurityHeaders);
  }

  await writeAudit(env, {
    at: new Date().toISOString(),
    adminUserId: gate.user.id,
    adminFingerprint: gate.user.fingerprint,
    action: grant ? "grant_unlimited_keys" : "revoke_unlimited_keys",
    targetUserId: user.id,
    targetFingerprint: user.fingerprint,
    detail: body.note?.slice(0, 200) || (grant ? "manual grant" : "manual revoke"),
    ip: clientIp(request),
    ok: true,
  });

  return json(
    {
      ok: true,
      user: publicUser(updated),
      message: grant
        ? "Unlimited sign-in keys granted for this key. The seal is a SHAKE256 digest of its fingerprint."
        : "Unlimited sign-in keys revoked for this key. Networks that only held this key return to 3 keys.",
    },
    { status: 200 },
    applySecurityHeaders,
  );
}

export async function adminGrantUnlimitedKeys(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  return mutateUnlimitedKeys(request, env, applySecurityHeaders, true);
}

export async function adminRevokeUnlimitedKeys(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  return mutateUnlimitedKeys(request, env, applySecurityHeaders, false);
}

/**
 * Admin claims one real Stripe Checkout session.
 * The session's client_reference_id must be that Globe account.
 * Requires the full mutation gate. Orphan sessions are not attached.
 */
export async function adminClaimSession(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const gate = await requireAdminMutation(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;

  let body: { session_id?: string; userId?: string; fingerprint?: string } =
    {};
  try {
    body = (await readJsonBody(request)) as typeof body;
    assertNoPrivateKeyMaterial(body);
  } catch (error) {
    if (error instanceof BodyLimitError) return bodyTooLargeResponse(applySecurityHeaders);
    body = {};
  }

  const sessionId = body.session_id?.trim();
  if (!sessionId || !/^cs_(test_|live_)?[a-zA-Z0-9]{8,200}$/.test(sessionId)) {
    return json(
      { error: "session_id_required" },
      { status: 400 },
      applySecurityHeaders,
    );
  }

  const secret = env.STRIPE_SECRET_KEY?.trim();
  if (!secret) {
    return json(
      { error: "stripe_not_configured" },
      { status: 503 },
      applySecurityHeaders,
    );
  }

  try {
    const Stripe = (await import("stripe")).default;
    const stripe = new Stripe(secret, {
      httpClient: Stripe.createFetchHttpClient(),
    } as ConstructorParameters<typeof Stripe>[1]);
    const checkout = await stripe.checkout.sessions.retrieve(sessionId);
    const ref =
      typeof checkout.client_reference_id === "string"
        ? checkout.client_reference_id.trim()
        : "";
    if (!/^[a-f0-9]{16,64}$/i.test(ref)) {
      return json(
        {
          error: "session_user_mismatch",
          message:
            "This checkout has no Globe account id. A real claim only unlocks the account named on the Stripe session.",
        },
        { status: 403 },
        applySecurityHeaders,
      );
    }

    const named = await getUserById(env, ref);
    if (!named) {
      return json(
        {
          error: "user_not_found",
          message: "The account named on this Stripe session is not registered.",
        },
        { status: 404 },
        applySecurityHeaders,
      );
    }

    const requestedId = body.userId?.trim() || "";
    if (requestedId && requestedId !== named.id) {
      return json(
        {
          error: "session_user_mismatch",
          message: "That account is not the one named on this Stripe session.",
        },
        { status: 403 },
        applySecurityHeaders,
      );
    }
    if (body.fingerprint?.trim()) {
      const byFingerprint = await getUserByFingerprint(env, body.fingerprint.trim());
      if (!byFingerprint || byFingerprint.id !== named.id) {
        return json(
          {
            error: "session_user_mismatch",
            message: "That key is not the account named on this Stripe session.",
          },
          { status: 403 },
          applySecurityHeaders,
        );
      }
    }

    const target = named;
    const record = await grantPaidToUser(env, {
      userId: target.id,
      sessionId: checkout.id,
      customerId:
        typeof checkout.customer === "string"
          ? checkout.customer
          : checkout.customer?.id ?? null,
      customerEmail:
        checkout.customer_details?.email ?? checkout.customer_email ?? null,
      paymentStatus: checkout.payment_status,
      amountTotal: checkout.amount_total,
      currency: checkout.currency,
      source: "claim",
    });

    if (!record) {
      await writeAudit(env, {
        at: new Date().toISOString(),
        adminUserId: gate.user.id,
        adminFingerprint: gate.user.fingerprint,
        action: "admin_claim_session",
        targetUserId: target.id,
        targetFingerprint: target.fingerprint,
        detail: `failed session ${sessionId}`,
        ip: clientIp(request),
        ok: false,
      });
      return json(
        {
          error: "claim_failed",
          message:
            "Could not grant access (payment incomplete, amount too low, or user missing).",
        },
        { status: 402 },
        applySecurityHeaders,
      );
    }

    const updated = await getUserById(env, target.id);
    await writeAudit(env, {
      at: new Date().toISOString(),
      adminUserId: gate.user.id,
      adminFingerprint: gate.user.fingerprint,
      action: "admin_claim_session",
      targetUserId: target.id,
      targetFingerprint: target.fingerprint,
      detail: `stripe session ${sessionId}`,
      ip: clientIp(request),
      ok: true,
    });

    return json(
      {
        ok: true,
        user: updated ? publicUser(updated) : publicUser(target),
        sessionId,
        paymentStatus: checkout.payment_status,
        kind: record.kind,
      },
      { status: 200 },
      applySecurityHeaders,
    );
  } catch {
    return json(
      {
        error: "claim_failed",
        message: "Could not claim checkout session.",
      },
      { status: 502 },
      applySecurityHeaders,
    );
  }
}

/**
 * Scan recent completed Stripe Checkout sessions and claim each one whose
 * client_reference_id is a registered Globe account. One elevation covers the scan.
 */
export async function adminClaimStripeUsers(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const gate = await requireAdminMutation(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;
  const limited = await rateLimitDurable(
    env,
    "admin:claim-stripe-all",
    3,
    10 * 60_000,
    applySecurityHeaders,
  );
  if (limited) return limited;
  if (!env.STRIPE_SECRET_KEY?.trim() || !env.BILLING_KV) {
    return json(
      { error: "stripe_not_configured", message: "Stripe is not configured on this deployment." },
      { status: 503 },
      applySecurityHeaders,
    );
  }
  try {
    const summary = await claimPaidCheckoutSessions(env);
    await writeAudit(env, {
      at: new Date().toISOString(),
      adminUserId: gate.user.id,
      adminFingerprint: gate.user.fingerprint,
      action: "admin_claim_stripe_all",
      targetUserId: "",
      targetFingerprint: "",
      detail: `claimed=${summary.claimed} already=${summary.already} skipped=${summary.skipped} unmatched=${summary.unmatched} scanned=${summary.scanned}`,
      ip: clientIp(request),
      ok: true,
    });
    return json(
      {
        ok: true,
        ...summary,
        message: `Claimed ${summary.claimed} paid session${summary.claimed === 1 ? "" : "s"}. ${summary.already} already matched. ${summary.skipped} skipped. ${summary.unmatched} had no Globe account.`,
      },
      { status: 200 },
      applySecurityHeaders,
    );
  } catch {
    return json(
      {
        error: "claim_failed",
        message: "Could not scan Stripe sessions.",
      },
      { status: 502 },
      applySecurityHeaders,
    );
  }
}

export async function adminListAudit(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const gate = await requireAdminSession(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;
  const entries = await listPublicAudits(env, 40);
  return json({ entries }, { status: 200 }, applySecurityHeaders);
}

/** Recent sign-in attempts. Same admin session gate as the audit list. No key material. */
export async function adminListLoginAttempts(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const gate = await requireAdminSession(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;
  const attempts = await listLoginAttempts(env, 40);
  return json(
    {
      attempts,
      retentionDays: 30,
      keyLimitPerIp: 3,
      alg: PQC_LOG_ALG,
      stored:
        "SHAKE256 digests of the network and account, mixed with a Worker secret pepper, plus a record hash and hash chain. Raw network addresses and account ids are not returned. Private keys, signatures, MACs, challenges, and session cookies are not stored.",
    },
    { status: 200 },
    applySecurityHeaders,
  );
}

/** Downloadable copy of the hashed sign-in attempts and admin audits. Needs elevation. */
export async function adminExportSecurityLog(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const gate = await requireAdminMutation(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;
  if (!readLogPepper(env)) {
    return json(
      {
        error: "log_pepper_missing",
        message: "The log pepper secret is not configured.",
      },
      { status: 503 },
      applySecurityHeaders,
    );
  }
  const [attempts, audits, attemptTip, auditTip] = await Promise.all([
    listLoginAttempts(env, 100),
    listPublicAudits(env, 100),
    readLoginChainTip(env),
    readAuditChainTip(env),
  ]);
  return json(
    {
      alg: PQC_LOG_ALG,
      dkLen: PQC_LOG_BYTES,
      domain: PQC_LOG_DOMAIN,
      generatedAt: new Date().toISOString(),
      loginRecordFields: ["at", "family", "phase", "suite", "result", "code", "networkHash", "accountHash"],
      auditRecordFields: ["at", "action", "ok", "detail", "adminHash", "targetHash", "networkHash"],
      okEncoding: "1 when the action succeeded, 0 otherwise",
      digestInput: `${PQC_LOG_DOMAIN}:label:<pepper>:<value> for network and account. The pepper is a Worker secret and is not in this file.`,
      chainInput: "prevHash|recordHash under the chain label. An empty prevHash is the first link.",
      peppered:
        "New network and account digests include a secret pepper. Rows written before that pepper stay as stored digests. Privilege seals are separate and are not in this file.",
      elevation: "This export requires the 10-minute device-key elevation.",
      pause: {
        countedFailures: AUTH_FAIL_LIMIT,
        windowSeconds: AUTH_FAIL_WINDOW_SECONDS,
        pauseSeconds: AUTH_BAN_SECONDS,
      },
      chainTips: { attempt: attemptTip, audit: auditTip },
      attempts,
      audits,
    },
    {
      status: 200,
      headers: { "content-disposition": 'attachment; filename="globe-security-log.json"' },
    },
    applySecurityHeaders,
  );
}

/**
 * List all registered users (public fields only — never public keys).
 * Requires full elevation: session, device-key step-up, then fingerprint allowlist.
 * Accepts GET or POST (POST preferred — avoids intermediary GET quirks with admin headers).
 * Paginated via KV cursor; filters scan additional pages when needed.
 */
export async function adminListUsers(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const gate = await requireAdminMutation(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;

  if (!env.BILLING_KV) {
    return json(
      { error: "kv_missing", users: [], cursor: null, complete: true },
      { status: 503 },
      applySecurityHeaders,
    );
  }

  const limited = await rateLimitDurable(
    env,
    `admin:list-users:${gate.user.id}`,
    40,
    60_000,
    applySecurityHeaders,
  );
  if (limited) return limited;

  const url = new URL(request.url);
  let body: {
    limit?: number;
    cursor?: string | null;
    paid?: boolean | string;
    locked?: boolean | string;
  } = {};
  if (request.method === "POST") {
    try {
      body = (await readJsonBody(request)) as typeof body;
    } catch (error) {
      if (error instanceof BodyLimitError) return bodyTooLargeResponse(applySecurityHeaders);
      body = {};
    }
  }

  const rawLimit = Number(
    body.limit ?? (url.searchParams.get("limit") || "100"),
  );
  const limit = Math.min(
    200,
    Math.max(1, Number.isFinite(rawLimit) ? Math.floor(rawLimit) : 100),
  );
  let cursorParam =
    (typeof body.cursor === "string" ? body.cursor.trim() : "") ||
    url.searchParams.get("cursor")?.trim() ||
    undefined;
  const paidOnly =
    body.paid === true ||
    body.paid === "1" ||
    url.searchParams.get("paid") === "1";
  const lockedOnly =
    body.locked === true ||
    body.locked === "1" ||
    url.searchParams.get("locked") === "1";

  try {
    const users: ReturnType<typeof publicUser>[] = [];
    const seenIds = new Set<string>();
    let complete = true;
    let nextCursor: string | null = null;
    // When filtering, scan up to a few KV pages so the first response isn't empty.
    const maxPages = paidOnly || lockedOnly ? 8 : 1;
    let filledEarly = false;

    for (let page = 0; page < maxPages; page++) {
      const listed = await env.BILLING_KV.list({
        prefix: "auth:user:",
        limit: Math.min(200, Math.max(limit, 50)),
        ...(cursorParam ? { cursor: cursorParam } : {}),
      });

      for (const key of listed.keys) {
        // Only accept expected user record keys (defense-in-depth against odd prefixes)
        if (!/^auth:user:[a-f0-9]{16,64}$/i.test(key.name)) continue;
        const raw = await env.BILLING_KV.get(key.name);
        if (!raw) continue;
        try {
          const rec = JSON.parse(raw) as UserRecord;
          if (!rec?.id || !rec?.fingerprint) continue;
          // Never include private key material even if a corrupt record had extra fields
          const pub = await withReceiptOrigin(env, rec);
          if (paidOnly && !pub.transitPaid) continue;
          if (lockedOnly && pub.transitPaid) continue;
          if (seenIds.has(pub.id)) continue;
          seenIds.add(pub.id);
          users.push(pub);
          if (users.length >= limit) {
            filledEarly = true;
            break;
          }
        } catch {
          // skip corrupt records
        }
      }

      complete = listed.list_complete;
      nextCursor = listed.list_complete ? null : listed.cursor || null;
      cursorParam = nextCursor || undefined;

      if (users.length >= limit || listed.list_complete) break;
    }

    // If we stopped because the page filled mid-scan, more KV keys may remain
    // even when list_complete is false; keep cursor for Load more. Client dedupes.
    if (filledEarly && !complete && !nextCursor) {
      // should not happen if KV returns cursor when incomplete; fail closed to complete
      complete = true;
    }

    users.sort((a, b) => {
      const ca = a.createdAt || "";
      const cb = b.createdAt || "";
      return cb.localeCompare(ca);
    });

    // Trim to requested limit after multi-page filter fill
    const trimmed = users.slice(0, limit);

    try {
      await writeAudit(env, {
        at: new Date().toISOString(),
        adminUserId: gate.user.id,
        adminFingerprint: gate.user.fingerprint,
        action: "list_users",
        detail: `count=${trimmed.length} complete=${complete}`,
        ip: clientIp(request),
        ok: true,
      });
    } catch {
      // listing still succeeds if audit write fails
    }

    return json(
      {
        ok: true,
        users: trimmed,
        count: trimmed.length,
        cursor: complete ? null : nextCursor,
        complete,
      },
      { status: 200 },
      applySecurityHeaders,
    );
  } catch (error) {
    const detail = error instanceof Error ? error.message : "list_failed";
    return json(
      {
        error: "list_failed",
        message: `Could not list users from storage (${detail}).`,
        users: [],
        cursor: null,
        complete: true,
      },
      { status: 500 },
      applySecurityHeaders,
    );
  }
}

/**
 * Permanently delete a user account (KV identity + sessions + entitlement index).
 * Requires full elevation. Cannot delete your own admin session account.
 */
export async function adminDeleteUser(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const gate = await requireAdminMutation(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;

  const limited = await rateLimitDurable(
    env,
    `admin:delete-user:${gate.user.id}`,
    20,
    60_000,
    applySecurityHeaders,
  );
  if (limited) return limited;

  let body: { userId?: string; fingerprint?: string; confirm?: string } = {};
  try {
    body = (await readJsonBody(request)) as typeof body;
    assertNoPrivateKeyMaterial(body);
  } catch (error) {
    if (error instanceof BodyLimitError) return bodyTooLargeResponse(applySecurityHeaders);
    if (error instanceof Error && error.message === "private_key_rejected") {
      return json(
        { error: "private_key_rejected" },
        { status: 400 },
        applySecurityHeaders,
      );
    }
    body = {};
  }

  // Require explicit confirm token to avoid mis-clicks.
  // Allowlisted admin accounts need a second confirm so one click cannot wipe them.
  const confirm = (body.confirm || "").trim().toUpperCase();
  if (confirm !== "DELETE" && confirm !== "DELETE ADMIN") {
    return json(
      {
        error: "confirm_required",
        message: 'Send confirm: "DELETE" to permanently remove a user.',
      },
      { status: 400 },
      applySecurityHeaders,
    );
  }

  let user: UserRecord | null = null;
  if (body.userId?.trim()) {
    user = await getUserById(env, body.userId.trim());
  }
  if (!user && body.fingerprint?.trim()) {
    user = await getUserByFingerprint(env, body.fingerprint.trim());
  }
  if (!user) {
    return json(
      {
        error: "user_not_found",
        message: "Provide a valid userId or fingerprint.",
      },
      { status: 404 },
      applySecurityHeaders,
    );
  }

  // Allowlisted accounts stay protected from a single click, including the
  // signed-in admin. A second confirm deletes the database record only.
  // ADMIN_FINGERPRINTS is not changed, so that key can register again as admin.
  const targetIsAdmin = await isAdminUserWithKv(user, env, request);
  if (targetIsAdmin && confirm !== "DELETE ADMIN") {
    const self = user.id === gate.user.id;
    return json(
      {
        error: "admin_delete_confirm",
        message: self
          ? "This is the admin account you are signed in as. Confirm again to delete it from the database. This ends your session. The allowlist is unchanged, so this key can register again and will still be an admin."
          : "This account is on the admin allowlist. Confirm again to delete it from the database. The allowlist is unchanged, so this key can register again and will still be an admin.",
      },
      { status: 409 },
      applySecurityHeaders,
    );
  }

  const removed = await deleteUserAccount(env, user.id);
  if (!removed) {
    return json(
      { error: "delete_failed", message: "Could not delete user." },
      { status: 500 },
      applySecurityHeaders,
    );
  }

  await writeAudit(env, {
    at: new Date().toISOString(),
    adminUserId: gate.user.id,
    adminFingerprint: gate.user.fingerprint,
    action: "delete_user",
    targetUserId: removed.id,
    targetFingerprint: removed.fingerprint,
    detail: `sessions_revoked=${removed.sessionsRevoked}${targetIsAdmin ? " allowlisted_admin" : ""}`,
    ip: clientIp(request),
    ok: true,
  });

  return json(
    {
      ok: true,
      deleted: removed,
      message: `User ${removed.id.slice(0, 12)}… permanently removed (${removed.sessionsRevoked} sessions revoked).`,
    },
    { status: 200 },
    applySecurityHeaders,
  );
}

/* ------------------------------------------------------------------------ *
 * Manage admins (UI-managed allowlist in BILLING_KV)
 *
 * Bootstrap admins (ADMIN_FINGERPRINT_SECRET, ADMIN_FINGERPRINTS_EXTRA,
 * ADMIN_FINGERPRINTS, ADMIN_USER_IDS) are permanent Worker secrets/vars and
 * cannot be listed by value or removed here. UI-managed admins are stored as a
 * digest + masked display form only (see auth.ts KvAdminEntry).
 * Every route needs the full mutation gate: admin session, fresh device-key
 * elevation, and an allowlisted signing fingerprint.
 * ------------------------------------------------------------------------ */

const ADMIN_ENTRY_ID_RE = /^[a-f0-9]{8,32}$/;

/** Reject cross-site callers. Elevation is header-only, so this is defense in depth. */
function manageAdminsOriginOk(request: Request): boolean {
  let expected: string;
  try {
    expected = new URL(request.url).origin;
  } catch {
    return false;
  }
  const origin = request.headers.get("origin");
  if (origin) {
    if (origin === "null") return false;
    try {
      if (new URL(origin).origin !== expected) return false;
    } catch {
      return false;
    }
  }
  const site = request.headers.get("sec-fetch-site");
  if (site && site !== "same-origin" && site !== "none") return false;
  return true;
}

function manageAdminsCrossSite(applySecurityHeaders?: SecurityHeadersFn): Response {
  return json(
    { error: "cross_site_rejected", message: "Admin management must come from this site." },
    { status: 403 },
    applySecurityHeaders,
  );
}

function cleanAdminLabel(value: unknown): string {
  if (typeof value !== "string") return "";
  return value
    .replace(/[\u0000-\u001f\u007f<>"'`\\]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 60);
}

function publicKvAdmin(entry: KvAdminEntry, selfId: string | null) {
  return {
    id: entry.id,
    masked: entry.masked,
    label: entry.label,
    addedAt: entry.addedAt,
    addedBy: entry.addedByMasked,
    isYou: selfId === entry.id,
    removable: true,
  };
}

async function manageAdminsGate(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<{ ok: true; user: UserRecord } | { ok: false; response: Response }> {
  if (!manageAdminsOriginOk(request)) {
    return { ok: false, response: manageAdminsCrossSite(applySecurityHeaders) };
  }
  const gate = await requireAdminMutation(request, env, applySecurityHeaders);
  if (!gate.ok) return gate;
  if (!env.BILLING_KV) {
    return { ok: false, response: json({ error: "kv_missing" }, { status: 503 }, applySecurityHeaders) };
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    const limited = await rateLimitDurable(
      env,
      `admin:manage-admins:${gate.user.id}`,
      20,
      60_000,
      applySecurityHeaders,
    );
    if (limited) return { ok: false, response: limited };
  }
  return { ok: true, user: gate.user };
}

/** GET /api/admin/admins — bootstrap counts plus masked UI-managed admins. */
export async function adminListAdmins(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const gate = await manageAdminsGate(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;
  const kv = await loadKvAdmins(env, request);
  const self = findKvAdmin(gate.user.fingerprint, kv, env);
  const bootstrapFingerprints = bootstrapAdminFingerprintCount(env);
  const bootstrapUserIds = bootstrapAdminUserIdCount(env);
  return json(
    {
      ok: true,
      bootstrap: {
        fingerprints: bootstrapFingerprints,
        userIds: bootstrapUserIds,
        removable: false,
        note: "permanent (Cloudflare secret)",
      },
      admins: kv.map((e) => publicKvAdmin(e, self?.id ?? null)),
      max: ADMIN_KV_MAX_ENTRIES,
      you: {
        masked: maskFingerprint(gate.user.fingerprint),
        bootstrap: isAllowlistedAdminFingerprint(gate.user.fingerprint, env),
        id: self?.id ?? null,
      },
      storage:
        "UI-managed admins are stored as a SHAKE256 digest of the fingerprint plus a masked form (first 4 + last 4). Bootstrap admins live in Worker secrets and are never shown.",
    },
    { status: 200 },
    applySecurityHeaders,
  );
}

/** POST /api/admin/admins — add by fingerprint or armored PUBLIC key. Idempotent. */
export async function adminAddAdmin(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const gate = await manageAdminsGate(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;

  let body: { fingerprint?: unknown; publicKey?: unknown; label?: unknown } = {};
  try {
    body = (await readJsonBody(request)) as typeof body;
    assertNoPrivateKeyMaterial(body);
  } catch (error) {
    if (error instanceof BodyLimitError) return bodyTooLargeResponse(applySecurityHeaders);
    if (error instanceof Error && error.message === "private_key_rejected") {
      return json(
        {
          error: "private_key_rejected",
          message: "That is a PRIVATE key. Paste the public key or the fingerprint only — never a private key.",
        },
        { status: 400 },
        applySecurityHeaders,
      );
    }
    return json({ error: "invalid_json" }, { status: 400 }, applySecurityHeaders);
  }
  if (!body || typeof body !== "object") {
    return json({ error: "invalid_json" }, { status: 400 }, applySecurityHeaders);
  }

  const publicKey = typeof body.publicKey === "string" ? body.publicKey.trim() : "";
  const rawFp = typeof body.fingerprint === "string" ? body.fingerprint.trim() : "";
  let fingerprint: string | null = null;
  let via: "public_key" | "fingerprint" = "fingerprint";
  if (publicKey) {
    via = "public_key";
    try {
      const parsed = await parseAndValidatePublicKey(publicKey);
      fingerprint = normalizeFingerprint(parsed.fingerprint);
    } catch (error) {
      const code = error instanceof Error ? error.message : "";
      if (code === "private_key_rejected") {
        return json(
          {
            error: "private_key_rejected",
            message: "That is a PRIVATE key. Paste the public key or the fingerprint only — never a private key.",
          },
          { status: 400 },
          applySecurityHeaders,
        );
      }
      return json(
        {
          error: "invalid_public_key",
          message:
            code === "key_not_usable"
              ? "That public key is expired or revoked."
              : "Could not read that public key. Paste the full armored PUBLIC KEY BLOCK, or the 40/64-hex fingerprint.",
        },
        { status: 400 },
        applySecurityHeaders,
      );
    }
  } else if (rawFp) {
    fingerprint = normalizeFingerprint(rawFp);
  }
  if (!fingerprint) {
    return json(
      {
        error: "invalid_fingerprint",
        message: "Enter a 40- or 64-character hex fingerprint (spaces/colons are fine), or paste a public key.",
      },
      { status: 400 },
      applySecurityHeaders,
    );
  }

  if (isAllowlistedAdminFingerprint(fingerprint, env)) {
    return json(
      {
        ok: true,
        already: true,
        bootstrap: true,
        message: "That key is already a permanent admin (Cloudflare secret).",
      },
      { status: 200 },
      applySecurityHeaders,
    );
  }

  const kv = await loadKvAdmins(env, request);
  const self = findKvAdmin(gate.user.fingerprint, kv, env);
  const existing = findKvAdmin(fingerprint, kv, env);
  if (existing) {
    return json(
      {
        ok: true,
        already: true,
        admin: publicKvAdmin(existing, self?.id ?? null),
        message: `Already an admin (${existing.masked}).`,
      },
      { status: 200 },
      applySecurityHeaders,
    );
  }
  if (kv.length >= ADMIN_KV_MAX_ENTRIES) {
    return json(
      { error: "too_many_admins", message: `At most ${ADMIN_KV_MAX_ENTRIES} UI-managed admins.` },
      { status: 409 },
      applySecurityHeaders,
    );
  }

  const peppered = kvAdminPepperAvailable(env);
  const digest = kvAdminDigest(fingerprint, env, peppered);
  if (!digest) {
    return json({ error: "digest_failed" }, { status: 500 }, applySecurityHeaders);
  }
  const entry: KvAdminEntry = {
    id: randomHex(8),
    digest,
    peppered,
    masked: maskFingerprint(fingerprint),
    label: cleanAdminLabel(body.label),
    addedByMasked: maskFingerprint(gate.user.fingerprint),
    addedAt: new Date().toISOString(),
  };
  try {
    await saveKvAdmins(env, [...kv, entry]);
  } catch {
    return json({ error: "save_failed", message: "Could not save the admin list." }, { status: 500 }, applySecurityHeaders);
  }
  forgetKvAdminCache(request);

  await writeAudit(env, {
    at: entry.addedAt,
    adminUserId: gate.user.id,
    adminFingerprint: gate.user.fingerprint,
    action: "admin_add",
    targetFingerprint: fingerprint,
    detail: `id=${entry.id} via=${via}`,
    ip: clientIp(request),
    ok: true,
  });

  return json(
    {
      ok: true,
      added: publicKvAdmin(entry, self?.id ?? null),
      message: `Added admin ${entry.masked}. They get admin access on their next request (allow up to a minute).`,
    },
    { status: 201 },
    applySecurityHeaders,
  );
}

/** DELETE /api/admin/admins/:id — remove a UI-managed admin. */
export async function adminRemoveAdmin(
  request: Request,
  env: AdminEnv,
  id: string,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const gate = await manageAdminsGate(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;

  if (id === "bootstrap") {
    return json(
      {
        error: "bootstrap_protected",
        message: "Permanent admins live in Cloudflare secrets and cannot be removed here.",
      },
      { status: 403 },
      applySecurityHeaders,
    );
  }
  if (!ADMIN_ENTRY_ID_RE.test(id)) {
    return json({ error: "invalid_id" }, { status: 400 }, applySecurityHeaders);
  }

  let confirmSelf = new URL(request.url).searchParams.get("confirmSelf") === "1";
  try {
    const body = (await readJsonBody(request, 4_096)) as { confirmSelf?: unknown };
    if (body?.confirmSelf === true) confirmSelf = true;
  } catch (error) {
    if (error instanceof BodyLimitError) return bodyTooLargeResponse(applySecurityHeaders);
    // The confirmation can also be supplied in the URL.
  }

  const kv = await loadKvAdmins(env, request);
  const target = kv.find((e) => e.id === id);
  if (!target) {
    return json(
      {
        error: "admin_not_found",
        message: "No UI-managed admin with that id. Permanent (Cloudflare secret) admins cannot be removed here.",
      },
      { status: 404 },
      applySecurityHeaders,
    );
  }

  // Keep at least one admin that can still sign privileged actions.
  const remainingSigners = bootstrapAdminFingerprintCount(env) + kv.length - 1;
  if (remainingSigners < 1) {
    return json(
      { error: "last_admin", message: "Cannot remove the last remaining admin." },
      { status: 409 },
      applySecurityHeaders,
    );
  }

  const self = findKvAdmin(gate.user.fingerprint, kv, env);
  const removingSelf = Boolean(self && self.id === target.id);
  if (removingSelf && !confirmSelf) {
    return json(
      {
        error: "self_remove_confirm",
        message: "This is your own admin entry. Confirm again to remove yourself; you will lose admin access.",
      },
      { status: 409 },
      applySecurityHeaders,
    );
  }

  try {
    await saveKvAdmins(env, kv.filter((e) => e.id !== target.id));
  } catch {
    return json({ error: "save_failed", message: "Could not save the admin list." }, { status: 500 }, applySecurityHeaders);
  }
  forgetKvAdminCache(request);

  await writeAudit(env, {
    at: new Date().toISOString(),
    adminUserId: gate.user.id,
    adminFingerprint: gate.user.fingerprint,
    action: "admin_remove",
    targetHash: target.peppered ? target.digest : "",
    detail: `id=${target.id}${removingSelf ? " self" : ""}`,
    ip: clientIp(request),
    ok: true,
  });

  return json(
    {
      ok: true,
      removed: { id: target.id, masked: target.masked, label: target.label },
      selfRemoved: removingSelf,
      message: `Removed admin ${target.masked}.`,
    },
    { status: 200 },
    applySecurityHeaders,
  );
}
