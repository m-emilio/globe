/**
 * Admin API — defense in depth (not “isAdmin flag on the client”).
 *
 * Threat model:
 * - Client-reported isAdmin is UI only; every /api/admin/* call re-checks server env.
 * - Session alone is NOT enough for grant/revoke/claim (stolen token risk).
 * - Mutating actions require ALL of:
 *     1) Logged-in session whose fingerprint is in ADMIN_FINGERPRINTS (or id in ADMIN_USER_IDS)
 *     2) ADMIN_ACTION_SECRET Worker secret (mandatory — fail closed if unset; never store in KV)
 *     3) Short-lived elevation token from a fresh PGP signature (proves key still held)
 * - Admin UI may generate a candidate secret in browser memory only; operator must set it
 *   as a Cloudflare Worker secret (wrangler secret put / dashboard). Never KV, git, or logs.
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
  normalizeFingerprint,
  rateLimitDurable,
  setUserTransitPaid,
  type AuthEnv,
  type UserRecord,
} from "./auth";
import { grantPaidToUser, type BillingEnv } from "./billing";

export type AdminEnv = AuthEnv &
  BillingEnv & {
    ADMIN_FINGERPRINTS?: string;
    ADMIN_USER_IDS?: string;
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
  userId: string;
  fingerprint: string;
  message: string;
  createdAt: string;
  expiresAt: string;
};

type ElevToken = {
  userId: string;
  fingerprint: string;
  createdAt: string;
  expiresAt: string;
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

/** Constant-time string compare (equal length only). */
function timingSafeEqualString(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) {
    out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return out === 0;
}

function publicUser(u: UserRecord) {
  return {
    id: u.id,
    fingerprint: u.fingerprint,
    primaryUserId: u.primaryUserId,
    transitPaid: Boolean(u.transitPaid),
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
 * Action secret from Worker secret / .dev.vars only — never KV or client storage.
 * Rejects empty / placeholder values. Never log the value.
 */
function actionSecretConfigured(env: AdminEnv): string | null {
  const s = env.ADMIN_ACTION_SECRET?.trim() || "";
  if (!s || s.length < 16) return null;
  if (/^(change-me|secret|password|todo|placeholder)/i.test(s)) return null;
  return s;
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
            "Privileged actions need a fresh PGP step-up. Call /api/admin/elevate-challenge then /api/admin/elevate.",
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

  if (
    elevRec.userId !== user.id ||
    elevRec.fingerprint !== user.fingerprint ||
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

async function writeAudit(env: AdminEnv, entry: AuditEntry) {
  if (!env.BILLING_KV) return;
  const id = `${Date.now()}_${randomHex(4)}`;
  await env.BILLING_KV.put(`admin:audit:${id}`, JSON.stringify(entry), {
    expirationTtl: 60 * 60 * 24 * 180,
  });
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
 * Mutating admin actions: session allowlist + action secret + elevation token.
 * Fail closed if ADMIN_ACTION_SECRET Worker secret is missing/weak.
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

  const expectedSecret = actionSecretConfigured(env);
  if (!expectedSecret) {
    return {
      ok: false,
      response: json(
        {
          error: "admin_misconfigured",
          message:
            "ADMIN_ACTION_SECRET must be set as a Worker secret (≥16 chars) for grant/revoke/claim. Fail-closed. Never store in KV.",
        },
        { status: 503 },
        applySecurityHeaders,
      ),
    };
  }

  const provided = request.headers.get("x-admin-action-secret")?.trim() || "";
  if (!provided || !timingSafeEqualString(provided, expectedSecret)) {
    await writeAudit(env, {
      at: new Date().toISOString(),
      adminUserId: gate.user.id,
      adminFingerprint: gate.user.fingerprint,
      action: "admin_secret_failed",
      ip: clientIp(request),
      ok: false,
    });
    return {
      ok: false,
      response: json(
        {
          error: "admin_secret_required",
          message:
            "Valid x-admin-action-secret header required for privileged admin actions.",
        },
        { status: 403 },
        applySecurityHeaders,
      ),
    };
  }

  const elevGate = await requireElevation(
    request,
    env,
    gate.user,
    applySecurityHeaders,
  );
  if (!elevGate.ok) return elevGate;

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
      actionSecretRequired: true,
      actionSecretConfigured: Boolean(actionSecretConfigured(env)),
      elevationTtlSeconds: ELEV_TOKEN_TTL_SEC,
      security: {
        mutationsRequire: [
          "allowlisted_session",
          "admin_action_secret",
          "pgp_step_up_elevation",
        ],
        actionSecretStorage:
          "Cloudflare Worker secret ADMIN_ACTION_SECRET only. Never KV, git, or browser storage.",
        note: "Client isAdmin is UI only; mutations re-verify on the server.",
      },
      capabilities: {
        read: ["lookup_user", "list_recent_audit", "elevate"],
        /** list_users is elevated (PGP + action secret) — bulk directory, not open to session-only admin. */
        elevatedRead: ["list_users"],
        mutate: [
          "grant_transit",
          "revoke_transit",
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

  if (!actionSecretConfigured(env)) {
    return json(
      {
        error: "admin_misconfigured",
        message:
          "Set ADMIN_ACTION_SECRET (≥16 random chars) as a Cloudflare Worker secret before elevation. Never store it in KV.",
      },
      { status: 503 },
      applySecurityHeaders,
    );
  }

  const challengeId = randomHex(16);
  const nonce = randomHex(16);
  const expiresAtMs = Date.now() + ELEV_CHALLENGE_TTL_SEC * 1000;
  const expiresAt = new Date(expiresAtMs).toISOString();
  const origin = new URL(request.url).origin;
  const message = [
    ADMIN_PROTOCOL,
    origin,
    gate.user.id,
    gate.user.fingerprint,
    nonce,
    String(expiresAtMs),
  ].join("|");

  const record: ElevChallenge = {
    userId: gate.user.id,
    fingerprint: gate.user.fingerprint,
    message,
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

  let body: { challengeId?: string; signatureArmored?: string } = {};
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
  if (
    !challengeId ||
    !/^[a-f0-9]{16,128}$/i.test(challengeId) ||
    !signatureArmored ||
    signatureArmored.length > MAX_SIGNATURE_CHARS
  ) {
    return json(
      {
        error: "invalid_elevate",
        message: "challengeId and signatureArmored are required.",
      },
      { status: 400 },
      applySecurityHeaders,
    );
  }

  if (/BEGIN PGP PRIVATE KEY BLOCK/i.test(signatureArmored)) {
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

  if (
    challenge.userId !== gate.user.id ||
    challenge.fingerprint !== gate.user.fingerprint ||
    new Date(challenge.expiresAt).getTime() <= Date.now()
  ) {
    return json(
      {
        error: "invalid_challenge",
        message: "Elevation challenge does not match this admin session.",
      },
      { status: 401 },
      applySecurityHeaders,
    );
  }

  try {
    const publicKey = await openpgp.readKey({
      armoredKey: gate.user.publicKeyArmored,
    });
    const message = await openpgp.createMessage({ text: challenge.message });
    const signature = await openpgp.readSignature({
      armoredSignature: signatureArmored,
    });
    const result = await openpgp.verify({
      message,
      signature,
      verificationKeys: publicKey,
    });
    const sig = result.signatures[0];
    if (!sig) throw new Error("no_signature");
    await sig.verified;
  } catch {
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

  const elevationToken = randomHex(32);
  const expiresAt = new Date(
    Date.now() + ELEV_TOKEN_TTL_SEC * 1000,
  ).toISOString();
  const elevRec: ElevToken = {
    userId: gate.user.id,
    fingerprint: gate.user.fingerprint,
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
        "Privileged admin window open. Send x-admin-elevation + x-admin-action-secret on grant/revoke/claim.",
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

  if (!env.BILLING_KV) {
    return json({ entries: [] }, { status: 200 }, applySecurityHeaders);
  }

  const listed = await env.BILLING_KV.list({
    prefix: "admin:audit:",
    limit: 50,
  });
  const entries: AuditEntry[] = [];
  for (const key of listed.keys) {
    const raw = await env.BILLING_KV.get(key.name);
    if (!raw) continue;
    try {
      entries.push(JSON.parse(raw) as AuditEntry);
    } catch {
      // skip
    }
  }
  entries.sort((a, b) => b.at.localeCompare(a.at));

  return json(
    { entries: entries.slice(0, 40) },
    { status: 200 },
    applySecurityHeaders,
  );
}

/**
 * List all registered users (public fields only — never public keys).
 * Requires full elevation: allowlisted session + action secret + PGP step-up.
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
