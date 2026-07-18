/**
 * OpenPGP public-key auth for Cloudflare Workers (BILLING_KV).
 *
 * - Register: store validated **public** key only (fingerprint = primary identity)
 * - Login: client proves possession by signing a challenge with a **device-local**
 *   private key (never uploaded). Server only verifies the signature.
 * - No account password. Passphrase is only the OpenPGP key passphrase if the
 *   user encrypted their device key.
 * - Sessions: opaque **session token** (not a PGP key):
 *     · HttpOnly cookie `globe_session`
 *     · Authorization: Bearer <token>
 *     · x-session-token header
 *     · ?auth_token= query (URL handoff; adopt-token then strip)
 * - Private keys must never appear in request bodies (rejected if detected)
 */

import * as openpgp from "openpgp";

const SESSION_COOKIE = "globe_session";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days
const CHALLENGE_TTL_SECONDS = 180; // 3 minutes
const MAX_PUBLIC_KEY_CHARS = 32_000;
const MAX_SIGNATURE_CHARS = 16_000;
const AUTH_PROTOCOL = "globe-auth:v1";
const SESSION_TOKEN_RE = /^[a-f0-9]{32,128}$/i;
/** Cap concurrent sessions per user; oldest pruned on login */
const MAX_SESSIONS_PER_USER = 8;

export type AuthEnv = {
  BILLING_KV?: KVNamespace;
  /** When "1" / "true", transit also requires a paid entitlement on the user. */
  TRANSIT_REQUIRE_PAYMENT?: string;
  /** Comma-separated OpenPGP fingerprints allowed as admins (server-side only). */
  ADMIN_FINGERPRINTS?: string;
  /** Comma-separated user ids allowed as admins (server-side only). */
  ADMIN_USER_IDS?: string;
  /**
   * Optional second factor for destructive admin actions (grant/revoke).
   * Send as header x-admin-action-secret when set.
   */
  ADMIN_ACTION_SECRET?: string;
};

export type UserRecord = {
  id: string;
  fingerprint: string;
  publicKeyArmored: string;
  primaryUserId: string | null;
  createdAt: string;
  /** Future Stripe unlock; ignored when TRANSIT_REQUIRE_PAYMENT is off. */
  transitPaid?: boolean;
};

export type SessionRecord = {
  userId: string;
  createdAt: string;
  expiresAt: string;
};

type ChallengeRecord = {
  fingerprint: string;
  message: string;
  createdAt: string;
  expiresAt: string;
};

export type PublicUser = {
  id: string;
  fingerprint: string;
  primaryUserId: string | null;
  transitPaid: boolean;
};

function parseCsvList(raw?: string): string[] {
  return (raw || "")
    .split(/[,\s]+/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

/**
 * Fingerprint allowlists may use spaces/colons (gpg-style) or commas between
 * multiple entries. Do not split a single fingerprint on internal spaces.
 */
function parseFingerprintAllowlist(raw?: string): string[] {
  return (raw || "")
    .split(",")
    .map((s) => s.replace(/[\s:]/g, "").toLowerCase())
    .filter(Boolean);
}

/**
 * Admin = allowlisted fingerprint and/or user id from env (not client-asserted).
 * Empty allowlists ⇒ nobody is admin (fail closed).
 * Note: this only answers "is this identity allowlisted?" — mutative admin
 * APIs also require action secret + PGP step-up elevation (see admin.ts).
 */
export function isAdminUser(user: UserRecord, env: AuthEnv): boolean {
  const fps = parseFingerprintAllowlist(env.ADMIN_FINGERPRINTS);
  const ids = parseCsvList(env.ADMIN_USER_IDS);
  if (fps.length === 0 && ids.length === 0) return false;
  const fp = user.fingerprint.replace(/[\s:]/g, "").toLowerCase();
  return fps.includes(fp) || ids.includes(user.id.toLowerCase());
}

function adminFlags(user: UserRecord, env: AuthEnv) {
  return {
    isAdmin: isAdminUser(user, env),
    adminActionSecretRequired: Boolean(env.ADMIN_ACTION_SECRET?.trim()),
  };
}

export async function getUserById(
  env: AuthEnv,
  userId: string,
): Promise<UserRecord | null> {
  if (!env.BILLING_KV || !userId) return null;
  const raw = await env.BILLING_KV.get(userKey(userId));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as UserRecord;
  } catch {
    return null;
  }
}

export async function getUserByFingerprint(
  env: AuthEnv,
  fingerprint: string,
): Promise<UserRecord | null> {
  if (!env.BILLING_KV) return null;
  const fp = normalizeFingerprint(fingerprint);
  if (!fp) return null;
  const userId = await env.BILLING_KV.get(fingerprintKey(fp));
  if (!userId) return null;
  return getUserById(env, userId);
}

type SecurityHeadersFn = (headers: Headers) => void;

// Best-effort in-isolate rate limits (resets when isolate recycles).
const rateBuckets = new Map<string, { windowStart: number; count: number }>();

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

function userKey(userId: string) {
  return `auth:user:${userId}`;
}

function fingerprintKey(fingerprint: string) {
  return `auth:fp:${fingerprint}`;
}

function sessionKey(sessionId: string) {
  return `auth:session:${sessionId}`;
}

function userSessionsKey(userId: string) {
  return `auth:user-sessions:${userId}`;
}

function challengeKey(challengeId: string) {
  return `auth:challenge:${challengeId}`;
}

function challengeUsedKey(challengeId: string) {
  return `auth:challenge-used:${challengeId}`;
}

function bufferToHex(buf: ArrayBuffer | Uint8Array) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomId(bytes = 32): string {
  return bufferToHex(crypto.getRandomValues(new Uint8Array(bytes)));
}

export function normalizeFingerprint(input: string): string | null {
  const hex = input.replace(/[\s:]/g, "").toLowerCase();
  if (!/^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(hex)) return null;
  return hex;
}

function looksLikePrivateKey(armored: string): boolean {
  return /BEGIN PGP PRIVATE KEY BLOCK/i.test(armored);
}

function looksLikePublicKey(armored: string): boolean {
  return /BEGIN PGP PUBLIC KEY BLOCK/i.test(armored);
}

export function clientIp(request: Request): string {
  return (
    request.headers.get("cf-connecting-ip") ||
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    "unknown"
  );
}

/**
 * Sliding-window rate limit. Returns a 429 Response when exceeded, else null.
 */
export function rateLimitOrNull(
  key: string,
  limit: number,
  windowMs: number,
  applySecurityHeaders?: SecurityHeadersFn,
): Response | null {
  const now = Date.now();
  const bucket = rateBuckets.get(key);
  if (!bucket || now - bucket.windowStart >= windowMs) {
    rateBuckets.set(key, { windowStart: now, count: 1 });
    if (rateBuckets.size > 5_000) {
      for (const [k, v] of rateBuckets) {
        if (now - v.windowStart >= windowMs) rateBuckets.delete(k);
      }
    }
    return null;
  }
  bucket.count += 1;
  if (bucket.count > limit) {
    return json(
      {
        error: "rate_limited",
        message: "Too many requests. Try again shortly.",
      },
      {
        status: 429,
        headers: { "retry-after": String(Math.ceil(windowMs / 1000)) },
      },
      applySecurityHeaders,
    );
  }
  return null;
}

function sessionCookie(
  sessionId: string,
  request: Request,
  maxAge = SESSION_TTL_SECONDS,
) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `${SESSION_COOKIE}=${encodeURIComponent(sessionId)}; Path=/; Max-Age=${maxAge}; SameSite=Lax; HttpOnly${secure}`;
}

function clearSessionCookie(request: Request) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly${secure}`;
}

function parseSessionTokenCandidate(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const token = raw.trim();
  return SESSION_TOKEN_RE.test(token) ? token : null;
}

/**
 * Resolve session id. Prefer HttpOnly cookie (browser app).
 * Bearer / x-session-token for non-browser clients.
 * Query tokens only when allowQuery (adopt-token handoff).
 * This is a server-issued session id — never a PGP private key.
 */
export function readSessionId(
  request: Request,
  options?: { allowQuery?: boolean },
): string | null {
  // 1) HttpOnly cookie — primary path for the web client
  const cookie = request.headers.get("cookie") || "";
  const match = cookie.match(
    new RegExp(`(?:^|;\\s*)${SESSION_COOKIE}=([^;]+)`),
  );
  if (match?.[1]) {
    try {
      const fromCookie = parseSessionTokenCandidate(
        decodeURIComponent(match[1]),
      );
      if (fromCookie) return fromCookie;
    } catch {
      // ignore
    }
  }

  // 2) Explicit headers (optional API / legacy — not used by cookie-only client)
  const auth = request.headers.get("authorization") || "";
  const bearer = auth.match(/^Bearer\s+(\S+)/i)?.[1];
  const fromBearer = parseSessionTokenCandidate(bearer);
  if (fromBearer) return fromBearer;

  const fromHeader = parseSessionTokenCandidate(
    request.headers.get("x-session-token"),
  );
  if (fromHeader) return fromHeader;

  // 3) Query handoff — ONLY when explicitly allowed (adopt-token)
  if (options?.allowQuery) {
    try {
      const url = new URL(request.url);
      const fromQuery = parseSessionTokenCandidate(
        url.searchParams.get("auth_token") ||
          url.searchParams.get("session_token"),
      );
      if (fromQuery) return fromQuery;
    } catch {
      // ignore
    }
  }

  return null;
}

/** Reject any request payload that looks like it includes a private key. */
export function assertNoPrivateKeyMaterial(payload: unknown): void {
  const scan = (value: unknown, depth = 0): void => {
    if (depth > 6 || value == null) return;
    if (typeof value === "string") {
      if (/BEGIN PGP PRIVATE KEY BLOCK/i.test(value)) {
        throw new Error("private_key_rejected");
      }
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) scan(item, depth + 1);
      return;
    }
    if (typeof value === "object") {
      for (const v of Object.values(value as Record<string, unknown>)) {
        scan(v, depth + 1);
      }
    }
  };
  scan(payload);
}

function toPublicUser(user: UserRecord): PublicUser {
  return {
    id: user.id,
    fingerprint: user.fingerprint,
    primaryUserId: user.primaryUserId,
    transitPaid: Boolean(user.transitPaid),
  };
}

async function parseAndValidatePublicKey(armored: string): Promise<{
  fingerprint: string;
  publicKeyArmored: string;
  primaryUserId: string | null;
}> {
  if (!armored || armored.length > MAX_PUBLIC_KEY_CHARS) {
    throw new Error("invalid_public_key");
  }
  if (looksLikePrivateKey(armored)) {
    throw new Error("private_key_rejected");
  }
  if (!looksLikePublicKey(armored)) {
    throw new Error("invalid_public_key");
  }

  const key = await openpgp.readKey({
    armoredKey: armored.trim(),
    config: {
      // Reject weak RSA at parse/use boundary
      minRSABits: 2048,
    },
  });
  if (key.isPrivate()) {
    throw new Error("private_key_rejected");
  }

  // Reject expired primary keys when expiration is set
  const now = new Date();
  try {
    await key.verifyPrimaryKey(now);
  } catch {
    throw new Error("key_not_usable");
  }

  // Extra strength guard (RSA bit length / algorithm family)
  try {
    const algo = key.getAlgorithmInfo() as {
      algorithm?: string;
      bits?: number;
    };
    if (
      typeof algo.bits === "number" &&
      algo.bits > 0 &&
      algo.bits < 2048
    ) {
      throw new Error("weak_key");
    }
    const alg = (algo.algorithm || "").toLowerCase();
    if (alg.includes("dsa") || alg === "elgamal") {
      throw new Error("weak_key");
    }
  } catch (error) {
    if (error instanceof Error && error.message === "weak_key") throw error;
    // getAlgorithmInfo may throw on exotic keys — fall through to verify
  }

  const fingerprint = normalizeFingerprint(key.getFingerprint());
  if (!fingerprint) {
    throw new Error("invalid_fingerprint");
  }

  const userIds = key.getUserIDs();
  const primaryUserId =
    userIds.find((u) => typeof u === "string" && u.trim())?.trim() || null;

  // Re-armor from parsed key so we only store public material
  const publicKeyArmored = key.armor();

  return { fingerprint, publicKeyArmored, primaryUserId };
}

async function listUserSessions(
  env: AuthEnv,
  userId: string,
): Promise<string[]> {
  if (!env.BILLING_KV) return [];
  const raw = await env.BILLING_KV.get(userSessionsKey(userId));
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (s): s is string => typeof s === "string" && SESSION_TOKEN_RE.test(s),
    );
  } catch {
    return [];
  }
}

async function trackUserSession(
  env: AuthEnv,
  userId: string,
  sessionId: string,
): Promise<void> {
  if (!env.BILLING_KV) return;
  let sessions = await listUserSessions(env, userId);
  sessions = sessions.filter((s) => s !== sessionId);
  sessions.push(sessionId);
  // Prune oldest beyond cap
  while (sessions.length > MAX_SESSIONS_PER_USER) {
    const drop = sessions.shift();
    if (drop) {
      await env.BILLING_KV.delete(sessionKey(drop));
    }
  }
  await env.BILLING_KV.put(
    userSessionsKey(userId),
    JSON.stringify(sessions),
    { expirationTtl: SESSION_TTL_SECONDS },
  );
}

async function untrackUserSession(
  env: AuthEnv,
  userId: string,
  sessionId: string,
): Promise<void> {
  if (!env.BILLING_KV) return;
  const sessions = (await listUserSessions(env, userId)).filter(
    (s) => s !== sessionId,
  );
  if (sessions.length === 0) {
    await env.BILLING_KV.delete(userSessionsKey(userId));
  } else {
    await env.BILLING_KV.put(
      userSessionsKey(userId),
      JSON.stringify(sessions),
      { expirationTtl: SESSION_TTL_SECONDS },
    );
  }
}

async function createSession(
  env: AuthEnv,
  userId: string,
): Promise<string | null> {
  if (!env.BILLING_KV) return null;
  const sessionId = randomId(32);
  const now = new Date();
  const expires = new Date(now.getTime() + SESSION_TTL_SECONDS * 1000);
  const record: SessionRecord = {
    userId,
    createdAt: now.toISOString(),
    expiresAt: expires.toISOString(),
  };
  await env.BILLING_KV.put(sessionKey(sessionId), JSON.stringify(record), {
    expirationTtl: SESSION_TTL_SECONDS,
  });
  await trackUserSession(env, userId, sessionId);
  return sessionId;
}

/**
 * Browser clients get cookie only (no sessionToken in JSON).
 * Non-browser / explicit API clients may opt in with:
 *   x-session-token-response: 1
 */
function sessionResponse(
  request: Request,
  sessionId: string,
  body: Record<string, unknown>,
  status: number,
  applySecurityHeaders?: SecurityHeadersFn,
) {
  const headers = new Headers();
  headers.append("set-cookie", sessionCookie(sessionId, request));
  applySecurityHeaders?.(headers);
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  const includeToken =
    request.headers.get("x-session-token-response")?.trim() === "1";
  const payload = includeToken
    ? { ...body, sessionToken: sessionId }
    : { ...body, sessionToken: null };
  return new Response(JSON.stringify(payload), { status, headers });
}

export async function getSessionUser(
  request: Request,
  env: AuthEnv,
): Promise<{ user: UserRecord; sessionId: string } | null> {
  if (!env.BILLING_KV) return null;
  const sessionId = readSessionId(request);
  if (!sessionId) return null;

  const raw = await env.BILLING_KV.get(sessionKey(sessionId));
  if (!raw) return null;

  let session: SessionRecord;
  try {
    session = JSON.parse(raw) as SessionRecord;
  } catch {
    return null;
  }

  if (new Date(session.expiresAt).getTime() <= Date.now()) {
    await env.BILLING_KV.delete(sessionKey(sessionId));
    return null;
  }

  const userRaw = await env.BILLING_KV.get(userKey(session.userId));
  if (!userRaw) return null;

  try {
    const user = JSON.parse(userRaw) as UserRecord;
    // Guard against leftover password-era records
    if (!user.fingerprint || !user.publicKeyArmored) return null;
    return { user, sessionId };
  } catch {
    return null;
  }
}

export async function registerUser(
  request: Request,
  env: AuthEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const limited = rateLimitOrNull(
    `auth:register:${clientIp(request)}`,
    5,
    60_000,
    applySecurityHeaders,
  );
  if (limited) return limited;

  if (!env.BILLING_KV) {
    return json(
      { error: "kv_missing", message: "BILLING_KV is required for auth." },
      { status: 503 },
      applySecurityHeaders,
    );
  }

  let body: { publicKeyArmored?: string } = {};
  try {
    body = (await request.json()) as typeof body;
    assertNoPrivateKeyMaterial(body);
  } catch (error) {
    if (error instanceof Error && error.message === "private_key_rejected") {
      return json(
        {
          error: "private_key_rejected",
          message:
            "Never upload a private key. Register with your public key only.",
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

  const armored = body.publicKeyArmored?.trim() || "";
  let parsed: Awaited<ReturnType<typeof parseAndValidatePublicKey>>;
  try {
    parsed = await parseAndValidatePublicKey(armored);
  } catch (error) {
    const code = error instanceof Error ? error.message : "invalid_public_key";
    if (code === "private_key_rejected") {
      return json(
        {
          error: "private_key_rejected",
          message:
            "Never upload a private key. Register with your public key only.",
        },
        { status: 400 },
        applySecurityHeaders,
      );
    }
    if (code === "weak_key") {
      return json(
        {
          error: "weak_key",
          message:
            "Key too weak or unsupported (RSA must be ≥ 2048 bits; DSA/ElGamal rejected).",
        },
        { status: 400 },
        applySecurityHeaders,
      );
    }
    return json(
      {
        error: "invalid_public_key",
        message: "Could not parse that OpenPGP public key.",
      },
      { status: 400 },
      applySecurityHeaders,
    );
  }

  const existingUserId = await env.BILLING_KV.get(
    fingerprintKey(parsed.fingerprint),
  );
  if (existingUserId) {
    return json(
      {
        error: "fingerprint_taken",
        message:
          "This key is already registered. Sign in with the device that holds the private key.",
      },
      { status: 409 },
      applySecurityHeaders,
    );
  }

  const user: UserRecord = {
    id: randomId(16),
    fingerprint: parsed.fingerprint,
    publicKeyArmored: parsed.publicKeyArmored,
    primaryUserId: parsed.primaryUserId,
    createdAt: new Date().toISOString(),
    transitPaid: false,
  };

  await env.BILLING_KV.put(userKey(user.id), JSON.stringify(user));
  await env.BILLING_KV.put(fingerprintKey(user.fingerprint), user.id);

  const sessionId = await createSession(env, user.id);
  if (!sessionId) {
    return json(
      { error: "session_create_failed" },
      { status: 500 },
      applySecurityHeaders,
    );
  }

  return sessionResponse(
    request,
    sessionId,
    {
      user: toPublicUser(user),
      ...adminFlags(user, env),
      message:
        "Public key registered. Keep the private key on your device for future sign-in (never upload it).",
    },
    201,
    applySecurityHeaders,
  );
}

export async function createAuthChallenge(
  request: Request,
  env: AuthEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const limited = rateLimitOrNull(
    `auth:challenge:${clientIp(request)}`,
    10,
    60_000,
    applySecurityHeaders,
  );
  if (limited) return limited;

  if (!env.BILLING_KV) {
    return json(
      { error: "kv_missing", message: "BILLING_KV is required for auth." },
      { status: 503 },
      applySecurityHeaders,
    );
  }

  let body: { fingerprint?: string; publicKeyArmored?: string } = {};
  try {
    body = (await request.json()) as typeof body;
    assertNoPrivateKeyMaterial(body);
  } catch (error) {
    if (error instanceof Error && error.message === "private_key_rejected") {
      return json(
        {
          error: "private_key_rejected",
          message: "Do not send private keys to the server.",
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

  let fingerprint = body.fingerprint
    ? normalizeFingerprint(body.fingerprint)
    : null;

  // Allow resolving fingerprint from a public key paste
  if (!fingerprint && body.publicKeyArmored?.trim()) {
    if (looksLikePrivateKey(body.publicKeyArmored)) {
      return json(
        {
          error: "private_key_rejected",
          message: "Do not send private keys to the server.",
        },
        { status: 400 },
        applySecurityHeaders,
      );
    }
    try {
      const parsed = await parseAndValidatePublicKey(body.publicKeyArmored);
      fingerprint = parsed.fingerprint;
    } catch {
      return json(
        { error: "invalid_public_key" },
        { status: 400 },
        applySecurityHeaders,
      );
    }
  }

  if (!fingerprint) {
    return json(
      {
        error: "fingerprint_required",
        message: "Provide your key fingerprint (or public key) to start login.",
      },
      { status: 400 },
      applySecurityHeaders,
    );
  }

  const userId = await env.BILLING_KV.get(fingerprintKey(fingerprint));
  if (!userId) {
    // Generic response — do not confirm whether fingerprint exists after challenge
    // For challenge we still need known identity; return generic auth failure style
    return json(
      {
        error: "unknown_identity",
        message: "No account for that fingerprint. Register the public key first.",
      },
      { status: 404 },
      applySecurityHeaders,
    );
  }

  const origin = new URL(request.url).origin;
  const challengeId = randomId(16);
  const nonce = randomId(16);
  const expiresAtMs = Date.now() + CHALLENGE_TTL_SECONDS * 1000;
  const expiresAt = new Date(expiresAtMs).toISOString();
  const message = [
    AUTH_PROTOCOL,
    origin,
    fingerprint,
    nonce,
    String(expiresAtMs),
  ].join(":");

  const record: ChallengeRecord = {
    fingerprint,
    message,
    createdAt: new Date().toISOString(),
    expiresAt,
  };

  await env.BILLING_KV.put(challengeKey(challengeId), JSON.stringify(record), {
    expirationTtl: CHALLENGE_TTL_SECONDS,
  });

  return json(
    {
      challengeId,
      message,
      expiresAt,
      fingerprint,
    },
    { status: 200 },
    applySecurityHeaders,
  );
}

export async function loginUser(
  request: Request,
  env: AuthEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const limited = rateLimitOrNull(
    `auth:login:${clientIp(request)}`,
    10,
    60_000,
    applySecurityHeaders,
  );
  if (limited) return limited;

  if (!env.BILLING_KV) {
    return json(
      { error: "kv_missing", message: "BILLING_KV is required for auth." },
      { status: 503 },
      applySecurityHeaders,
    );
  }

  let body: {
    fingerprint?: string;
    challengeId?: string;
    signatureArmored?: string;
  } = {};
  try {
    body = (await request.json()) as typeof body;
    assertNoPrivateKeyMaterial(body);
  } catch (error) {
    if (error instanceof Error && error.message === "private_key_rejected") {
      return json(
        {
          error: "private_key_rejected",
          message: "Send a detached signature, never a private key.",
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

  const fingerprint = body.fingerprint
    ? normalizeFingerprint(body.fingerprint)
    : null;
  const challengeId = body.challengeId?.trim() || "";
  const signatureArmored = body.signatureArmored?.trim() || "";

  if (
    !fingerprint ||
    !challengeId ||
    !/^[a-f0-9]{16,128}$/i.test(challengeId) ||
    !signatureArmored ||
    signatureArmored.length > MAX_SIGNATURE_CHARS
  ) {
    return json(
      {
        error: "invalid_login",
        message: "fingerprint, challengeId, and signatureArmored are required.",
      },
      { status: 400 },
      applySecurityHeaders,
    );
  }

  if (looksLikePrivateKey(signatureArmored)) {
    return json(
      {
        error: "private_key_rejected",
        message: "Send a detached signature, never a private key.",
      },
      { status: 400 },
      applySecurityHeaders,
    );
  }

  // Single-use: mark consumed first (reduces double-login race window)
  const usedKey = challengeUsedKey(challengeId);
  const alreadyUsed = await env.BILLING_KV.get(usedKey);
  if (alreadyUsed) {
    return json(
      {
        error: "invalid_challenge",
        message: "Challenge expired or already used. Request a new one.",
      },
      { status: 401 },
      applySecurityHeaders,
    );
  }
  await env.BILLING_KV.put(usedKey, "1", {
    expirationTtl: CHALLENGE_TTL_SECONDS + 60,
  });

  const challengeRaw = await env.BILLING_KV.get(challengeKey(challengeId));
  if (challengeRaw) {
    await env.BILLING_KV.delete(challengeKey(challengeId));
  }

  if (!challengeRaw) {
    return json(
      {
        error: "invalid_challenge",
        message: "Challenge expired or already used. Request a new one.",
      },
      { status: 401 },
      applySecurityHeaders,
    );
  }

  let challenge: ChallengeRecord;
  try {
    challenge = JSON.parse(challengeRaw) as ChallengeRecord;
  } catch {
    return json(
      { error: "invalid_challenge" },
      { status: 401 },
      applySecurityHeaders,
    );
  }

  if (
    challenge.fingerprint !== fingerprint ||
    new Date(challenge.expiresAt).getTime() <= Date.now()
  ) {
    return json(
      {
        error: "invalid_challenge",
        message: "Challenge expired or does not match this key.",
      },
      { status: 401 },
      applySecurityHeaders,
    );
  }

  const userId = await env.BILLING_KV.get(fingerprintKey(fingerprint));
  if (!userId) {
    return json(
      {
        error: "auth_failed",
        message: "Could not verify signature.",
      },
      { status: 401 },
      applySecurityHeaders,
    );
  }

  const userRaw = await env.BILLING_KV.get(userKey(userId));
  if (!userRaw) {
    return json(
      { error: "auth_failed", message: "Could not verify signature." },
      { status: 401 },
      applySecurityHeaders,
    );
  }

  let user: UserRecord;
  try {
    user = JSON.parse(userRaw) as UserRecord;
  } catch {
    return json(
      { error: "auth_failed", message: "Could not verify signature." },
      { status: 401 },
      applySecurityHeaders,
    );
  }

  try {
    const publicKey = await openpgp.readKey({
      armoredKey: user.publicKeyArmored,
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
    if (!sig) {
      throw new Error("no_signature");
    }
    await sig.verified;
  } catch {
    return json(
      {
        error: "auth_failed",
        message: "Could not verify signature.",
      },
      { status: 401 },
      applySecurityHeaders,
    );
  }

  const sessionId = await createSession(env, user.id);
  if (!sessionId) {
    return json(
      { error: "session_create_failed" },
      { status: 500 },
      applySecurityHeaders,
    );
  }

  return sessionResponse(
    request,
    sessionId,
    {
      user: toPublicUser(user),
      ...adminFlags(user, env),
      message: "Logged in. Session token issued (not a private key).",
    },
    200,
    applySecurityHeaders,
  );
}

/**
 * Adopt a session token into an HttpOnly cookie (e.g. after ?auth_token= URL handoff).
 * Body: { sessionToken } or uses token already present on the request.
 */
export async function adoptSessionToken(
  request: Request,
  env: AuthEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const limited = rateLimitOrNull(
    `auth:adopt:${clientIp(request)}`,
    20,
    60_000,
    applySecurityHeaders,
  );
  if (limited) return limited;

  let bodyToken: string | null = null;
  try {
    if (request.method === "POST") {
      const body = (await request.json()) as { sessionToken?: string };
      assertNoPrivateKeyMaterial(body);
      bodyToken = parseSessionTokenCandidate(body.sessionToken);
    }
  } catch (error) {
    if (error instanceof Error && error.message === "private_key_rejected") {
      return json(
        { error: "private_key_rejected" },
        { status: 400 },
        applySecurityHeaders,
      );
    }
  }

  // Prefer explicit body token, else cookie / header / query (adopt handoff)
  let session: { user: UserRecord; sessionId: string } | null = null;
  if (bodyToken) {
    const synthetic = new Request(request.url, {
      headers: { authorization: `Bearer ${bodyToken}` },
    });
    session = await getSessionUser(synthetic, env);
  }
  if (!session) {
    // Query allowed only for adopt-token handoff
    const sid = readSessionId(request, { allowQuery: true });
    if (sid && env.BILLING_KV) {
      const raw = await env.BILLING_KV.get(sessionKey(sid));
      if (raw) {
        try {
          const rec = JSON.parse(raw) as SessionRecord;
          if (new Date(rec.expiresAt).getTime() > Date.now()) {
            const user = await getUserById(env, rec.userId);
            if (user) session = { user, sessionId: sid };
          }
        } catch {
          // ignore
        }
      }
    }
  }
  if (!session) {
    return json(
      {
        error: "invalid_token",
        message: "Session token is missing or expired.",
      },
      { status: 401 },
      applySecurityHeaders,
    );
  }

  return sessionResponse(
    request,
    session.sessionId,
    {
      user: toPublicUser(session.user),
      ...adminFlags(session.user, env),
      message: "Session adopted into cookie.",
    },
    200,
    applySecurityHeaders,
  );
}

export async function logoutUser(
  request: Request,
  env: AuthEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  let all = false;
  try {
    if (request.headers.get("content-type")?.includes("application/json")) {
      const body = (await request.json()) as { all?: boolean };
      all = Boolean(body?.all);
    }
  } catch {
    // empty body ok
  }

  const current = await getSessionUser(request, env);
  if (current && env.BILLING_KV) {
    if (all) {
      const sessions = await listUserSessions(env, current.user.id);
      for (const sid of sessions) {
        await env.BILLING_KV.delete(sessionKey(sid));
      }
      await env.BILLING_KV.delete(userSessionsKey(current.user.id));
      // Also drop current if not in list
      await env.BILLING_KV.delete(sessionKey(current.sessionId));
    } else {
      await env.BILLING_KV.delete(sessionKey(current.sessionId));
      await untrackUserSession(env, current.user.id, current.sessionId);
    }
  } else {
    const sessionId = readSessionId(request);
    if (sessionId && env.BILLING_KV) {
      await env.BILLING_KV.delete(sessionKey(sessionId));
    }
  }

  const headers = new Headers();
  headers.append("set-cookie", clearSessionCookie(request));
  applySecurityHeaders?.(headers);
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");

  return new Response(
    JSON.stringify({ ok: true, allSessions: all }),
    { status: 200, headers },
  );
}

export async function getMe(
  request: Request,
  env: AuthEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const session = await getSessionUser(request, env);
  if (!session) {
    return json(
      { authenticated: false, user: null, sessionToken: null },
      { status: 200 },
      applySecurityHeaders,
    );
  }

  // Do not echo sessionToken on every /me (reduces token harvest surface).
  // Clients receive sessionToken only from login/register/adopt-token.
  return json(
    {
      authenticated: true,
      user: toPublicUser(session.user),
      ...adminFlags(session.user, env),
    },
    { status: 200 },
    applySecurityHeaders,
  );
}

export function paymentEnforcementEnabled(env: AuthEnv): boolean {
  const v = env.TRANSIT_REQUIRE_PAYMENT?.trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes";
}

/**
 * Mark a user as transit-paid (used by hardened Stripe webhook later).
 */
export async function setUserTransitPaid(
  env: AuthEnv,
  userId: string,
  paid: boolean,
): Promise<UserRecord | null> {
  if (!env.BILLING_KV) return null;
  const raw = await env.BILLING_KV.get(userKey(userId));
  if (!raw) return null;
  const user = JSON.parse(raw) as UserRecord;
  user.transitPaid = paid;
  await env.BILLING_KV.put(userKey(userId), JSON.stringify(user));
  return user;
}

/**
 * Gate for paid / sensitive features (transit, nearby maps, etc.):
 * 1. Rate limit
 * 2. Must be logged in
 * 3. If TRANSIT_REQUIRE_PAYMENT, must have transitPaid
 */
export async function requireTransitAccess(
  request: Request,
  env: AuthEnv,
  applySecurityHeaders?: SecurityHeadersFn,
  options?: {
    rateKey?: string;
    rateLimit?: number;
    featureName?: string;
  },
): Promise<Response | null> {
  const rateKey = options?.rateKey ?? "transit";
  const rateLimit = options?.rateLimit ?? 30;
  const featureName = options?.featureName ?? "Local Transit";

  const limited = rateLimitOrNull(
    `${rateKey}:${clientIp(request)}`,
    rateLimit,
    60_000,
    applySecurityHeaders,
  );
  if (limited) return limited;

  if (!env.BILLING_KV) {
    return json(
      {
        error: "kv_missing",
        message: "App KV is not bound. Configure BILLING_KV in wrangler.json.",
        code: "auth_unavailable",
      },
      { status: 503 },
      applySecurityHeaders,
    );
  }

  const session = await getSessionUser(request, env);
  if (!session) {
    return json(
      {
        error: "login_required",
        code: "login_required",
        message: `Sign in with your PGP key to use ${featureName}.`,
      },
      { status: 401 },
      applySecurityHeaders,
    );
  }

  if (paymentEnforcementEnabled(env) && !session.user.transitPaid) {
    return json(
      {
        error: "payment_required",
        code: "payment_required",
        message: `${featureName} is locked until you complete Stripe checkout. Use Menu → Buy Stripe access ($20). Unlocks Transit, Nearby maps, and Live Feed after payment.`,
      },
      { status: 402 },
      applySecurityHeaders,
    );
  }

  return null;
}

/**
 * Login required only (no payment) — public-ish authenticated APIs.
 */
export async function requireLogin(
  request: Request,
  env: AuthEnv,
  applySecurityHeaders?: SecurityHeadersFn,
  options?: { rateKey?: string; rateLimit?: number },
): Promise<Response | null> {
  const limited = rateLimitOrNull(
    `${options?.rateKey ?? "login-api"}:${clientIp(request)}`,
    options?.rateLimit ?? 60,
    60_000,
    applySecurityHeaders,
  );
  if (limited) return limited;

  if (!env.BILLING_KV) {
    return json(
      {
        error: "kv_missing",
        code: "auth_unavailable",
        message: "App KV is not bound.",
      },
      { status: 503 },
      applySecurityHeaders,
    );
  }

  const session = await getSessionUser(request, env);
  if (!session) {
    return json(
      {
        error: "login_required",
        code: "login_required",
        message: "Sign in required.",
      },
      { status: 401 },
      applySecurityHeaders,
    );
  }
  return null;
}

export { SESSION_COOKIE };
