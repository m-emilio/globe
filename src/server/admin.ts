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
 * - Read-only lookup/audit need (1) only.
 * - Empty ADMIN_FINGERPRINTS + ADMIN_USER_IDS ⇒ no admins (fail closed).
 */

import * as openpgp from "openpgp";
import {
  assertNoPrivateKeyMaterial,
  clientIp,
  getSessionUser,
  getUserByFingerprint,
  getUserById,
  deleteUserAccount,
  isAdminUser,
  isAllowlistedAdminFingerprint,
  normalizeFingerprint,
  rateLimitDurable,
  setUserTransitPaid,
  setUserUnlimitedKeys,
  unlimitedKeySealMatches,
  type AuthEnv,
  type UserRecord,
} from "./auth";
import { grantPaidToUser, type BillingEnv } from "./billing";
import {
  b64ToFixedBytes,
  decodeStoredPublicKey,
  PQC_SIG_SUITES,
  verifyPqcSignature,
} from "./pqcVerify";
import { AUTH_BAN_SECONDS, AUTH_FAIL_LIMIT, AUTH_FAIL_WINDOW_SECONDS } from "./authBan";
import { listLoginAttempts, readLoginChainTip } from "./loginLog";
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

function publicUser(u: UserRecord) {
  return {
    id: u.id,
    fingerprint: u.fingerprint,
    primaryUserId: u.primaryUserId,
    transitPaid: Boolean(u.transitPaid),
    unlimitedKeys: unlimitedKeySealMatches(u),
    createdAt: u.createdAt,
  };
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
    Boolean(elevRec.adminHash && elevRec.userHash) &&
    elevRec.adminHash === privilegeSeal("unlock", user.fingerprint) &&
    elevRec.userHash === userSeal(user.id);
  const legacySession =
    !elevRec.adminHash &&
    elevRec.userId === user.id &&
    elevRec.fingerprint === user.fingerprint;
  if (
    (!sealedToSession && !legacySession) ||
    new Date(elevRec.expiresAt).getTime() <= Date.now()
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

function asPublicAudit(value: unknown): PublicAudit | null {
  if (!value || typeof value !== "object") return null;
  const row = value as Record<string, unknown>;
  const at = typeof row.at === "string" && /^\d{4}-\d{2}-\d{2}T/.test(row.at) ? row.at.slice(0, 40) : "";
  const action = typeof row.action === "string" ? cleanAction(row.action) : "";
  if (!at || !action) return null;
  let admin = hashOrEmpty(row.adminHash);
  let target = hashOrEmpty(row.targetHash);
  let network = hashOrEmpty(row.networkHash);
  if (!admin && typeof row.adminFingerprint === "string") admin = accountHash(row.adminFingerprint);
  if (!target && typeof row.targetFingerprint === "string") target = accountHash(row.targetFingerprint);
  if (!network && typeof row.ip === "string") {
    const ip = usableIp(row.ip);
    if (ip) network = networkHash(ip);
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

async function listPublicAudits(env: AdminEnv, take = 40): Promise<PublicAudit[]> {
  if (!env.BILLING_KV) return [];
  const scan = Math.min(Math.max(take, 1), 100);
  const sealed = (await listPrefixedKeys(env, "admin:seal:")).slice(0, scan);
  const legacy = await listPrefixedKeys(env, "admin:audit:");
  const names = [...sealed, ...legacy.slice(-scan)];
  const entries: PublicAudit[] = [];
  for (const name of names) {
    const raw = await env.BILLING_KV.get(name);
    if (!raw) continue;
    try {
      const parsed = asPublicAudit(JSON.parse(raw));
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
    const fields: AuditSealFields = {
      at,
      action: cleanAction(entry.action),
      ok: entry.ok !== false,
      detail: cleanDetail(entry.detail || ""),
      adminHash: accountHash(entry.adminFingerprint),
      targetHash: entry.targetFingerprint ? accountHash(entry.targetFingerprint) : "",
      networkHash: networkHash(entry.ip),
    };
    const recordHash = auditRecordHash(fields);
    const prevHash = await readAuditChainTip(env);
    const chain = chainHash(prevHash, recordHash);
    const stamp = String(9_999_999_999_999 - Date.now()).padStart(13, "0");
    await env.BILLING_KV.put(
      `admin:seal:${stamp}_${randomHex(4)}`,
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
  } catch {
    // Skip the write rather than store a raw network or account.
  }
}

/**
 * Session + allowlist only (read paths).
 * Does NOT authorize grant/revoke/claim.
 */
async function requireAdminSession(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<
  | { ok: true; user: UserRecord; sessionId: string }
  | { ok: false; response: Response }
> {
  const limited = await rateLimitDurable(
    env,
    `admin:${clientIp(request)}`,
    30,
    60_000,
    applySecurityHeaders,
  );
  if (limited) return { ok: false, response: limited };

  const session = await getSessionUser(request, env);
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

  if (!isAdminUser(session.user, env)) {
    await writeAudit(env, {
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

/**
 * Last check for privileged actions: the signed session key is an exact
 * ADMIN_FINGERPRINTS member. The header value is never treated as proof.
 */
async function rejectUnlessAllowlistedFingerprint(
  request: Request,
  env: AdminEnv,
  user: UserRecord,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response | null> {
  if (isAllowlistedAdminFingerprint(user.fingerprint, env)) return null;
  await writeAudit(env, {
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
  if (new Date(challenge.expiresAt).getTime() <= Date.now()) return null;
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
  if (challenge.expiresAtMs <= Date.now()) return null;
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
    body = (await request.json()) as typeof body;
    assertNoPrivateKeyMaterial(body);
  } catch (error) {
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
    { found: true, user: publicUser(user) },
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
    body = (await request.json()) as typeof body;
    assertNoPrivateKeyMaterial(body);
  } catch {
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

  const updated = await setUserTransitPaid(env, user.id, true);
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
    body = (await request.json()) as typeof body;
    assertNoPrivateKeyMaterial(body);
  } catch {
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
    body = (await request.json()) as typeof body;
    assertNoPrivateKeyMaterial(body);
  } catch (error) {
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

  const updated = await setUserUnlimitedKeys(env, user.id, grant);
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
 * Admin claims a paid Stripe Checkout session for a user.
 * Requires full mutation gate (secret + PGP elevation).
 * If client_reference_id is set, target must match it.
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
    body = (await request.json()) as typeof body;
    assertNoPrivateKeyMaterial(body);
  } catch {
    body = {};
  }

  const sessionId = body.session_id?.trim();
  if (!sessionId || !/^cs_[a-zA-Z0-9_]+$/.test(sessionId)) {
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
    if (
      checkout.payment_status !== "paid" &&
      checkout.payment_status !== "no_payment_required"
    ) {
      return json(
        {
          error: "payment_not_complete",
          paymentStatus: checkout.payment_status,
        },
        { status: 402 },
        applySecurityHeaders,
      );
    }

    const ref =
      typeof checkout.client_reference_id === "string"
        ? checkout.client_reference_id.trim()
        : "";

    let target: UserRecord | null = null;
    if (body.userId?.trim()) {
      target = await getUserById(env, body.userId.trim());
    }
    if (!target && body.fingerprint?.trim()) {
      target = await getUserByFingerprint(env, body.fingerprint.trim());
    }
    if (!target && ref) {
      target = await getUserById(env, ref);
    }

    if (!target) {
      return json(
        {
          error: "user_not_found",
          message:
            "Could not resolve user. Pass userId/fingerprint, or ensure client_reference_id is a known user id.",
          client_reference_id: ref || null,
        },
        { status: 404 },
        applySecurityHeaders,
      );
    }

    if (ref && ref !== target.id) {
      return json(
        {
          error: "session_user_mismatch",
          message:
            "Checkout client_reference_id does not match the target user.",
          client_reference_id: ref,
          targetUserId: target.id,
        },
        { status: 403 },
        applySecurityHeaders,
      );
    }

    // Route through grantPaidToUser so claim ledger + amount checks apply.
    // forceRebind allows admin recovery of orphan sessions.
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
      forceRebind: true,
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
      detail: ref
        ? `session ${sessionId}`
        : `session ${sessionId} (no client_reference_id; admin-attached)`,
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
        "SHAKE256 digests of the network and account, plus a record hash and hash chain. Raw network addresses and account ids are not returned. Private keys, signatures, MACs, challenges, and session cookies are not stored.",
    },
    { status: 200 },
    applySecurityHeaders,
  );
}

/** Downloadable copy of the hashed sign-in attempts and admin audits. Admin session only. */
export async function adminExportSecurityLog(
  request: Request,
  env: AdminEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const gate = await requireAdminSession(request, env, applySecurityHeaders);
  if (!gate.ok) return gate.response;
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
      digestInput: `${PQC_LOG_DOMAIN}:label:value`,
      chainInput: "prevHash|recordHash under the chain label. An empty prevHash is the first link.",
      unsalted:
        "SHAKE256 has no pepper. A leaked export can be matched against a guessed IPv4. IPv6 is not practical to guess.",
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
      body = (await request.json()) as typeof body;
    } catch {
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
          const pub = publicUser(rec);
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
    body = (await request.json()) as typeof body;
    assertNoPrivateKeyMaterial(body);
  } catch (error) {
    if (error instanceof Error && error.message === "private_key_rejected") {
      return json(
        { error: "private_key_rejected" },
        { status: 400 },
        applySecurityHeaders,
      );
    }
    body = {};
  }

  // Require explicit confirm token to avoid mis-clicks
  if ((body.confirm || "").trim().toUpperCase() !== "DELETE") {
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

  if (user.id === gate.user.id) {
    return json(
      {
        error: "cannot_delete_self",
        message: "You cannot delete the account for your own admin session.",
      },
      { status: 400 },
      applySecurityHeaders,
    );
  }

  // Do not allow elevated admins to wipe other allowlisted admin identities
  // (compromised support key should not delete co-admins).
  if (isAdminUser(user, env)) {
    await writeAudit(env, {
      at: new Date().toISOString(),
      adminUserId: gate.user.id,
      adminFingerprint: gate.user.fingerprint,
      action: "delete_user_denied",
      targetUserId: user.id,
      targetFingerprint: user.fingerprint,
      detail: "target_is_allowlisted_admin",
      ip: clientIp(request),
      ok: false,
    });
    return json(
      {
        error: "cannot_delete_admin",
        message:
          "Refusing to delete an allowlisted admin account. Remove them from ADMIN_FINGERPRINTS / ADMIN_USER_IDS first if intentional.",
      },
      { status: 403 },
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
    detail: `sessions_revoked=${removed.sessionsRevoked}`,
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
