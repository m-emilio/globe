/**
 * ML-DSA sign-in beside OpenPGP.
 * The browser proves it holds the private key. This worker stores the public key
 * and checks the signature. A matching session cookie is the same globe_session
 * cookie OpenPGP already uses. Admin allowlists are not granted here.
 */
import {
  assertNoPrivateKeyMaterial,
  authFingerprintStorageKey,
  authUserStorageKey,
  clientIp,
  issueLoginSession,
  normalizeFingerprint,
  rateLimitDurable,
  readJsonBody,
  type AuthEnv,
  type SecurityHeadersFn,
  type UserRecord,
} from "./auth";
import {
  PQC_SIG_SUITES,
  assertPqcSigLengths,
  b64ToFixedBytes,
  buildPqcLoginMessage,
  bytesToB64,
  decodeStoredPublicKey,
  encodeStoredPublicKey,
  isPqcSigSuite,
  verifyPqcSignature,
  type PqcSigSuiteId,
} from "./pqcVerify";

const CHALLENGE_TTL_SECONDS = 180;
const MAX_SIGNATURE_CHARS = 70_000;
const MAX_PUBLIC_CHARS = 4096;
const MAX_PQC_BODY_BYTES = 96_000;

type ChallengeRecord = {
  fingerprint: string;
  suite: PqcSigSuiteId;
  message: string;
  createdAt: string;
  expiresAt: string;
  decoy?: boolean;
};

function json(
  data: unknown,
  status: number,
  applySecurityHeaders?: SecurityHeadersFn,
): Response {
  const headers = new Headers();
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  applySecurityHeaders?.(headers);
  return new Response(JSON.stringify(data), { status, headers });
}

function bodyTooLarge(applySecurityHeaders?: SecurityHeadersFn): Response {
  return json(
    { error: "body_too_large", message: "Request body exceeds size limit." },
    413,
    applySecurityHeaders,
  );
}

function privateKeyRejected(applySecurityHeaders?: SecurityHeadersFn): Response {
  return json(
    {
      error: "private_key_rejected",
      message: "Send the ML-DSA public key or signature only. Never upload a private key.",
    },
    400,
    applySecurityHeaders,
  );
}

function randomId(bytes = 16): string {
  const buf = crypto.getRandomValues(new Uint8Array(bytes));
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function challengeKey(id: string): string {
  return `auth:pqc-challenge:${id}`;
}

function challengeUsedKey(id: string): string {
  return `auth:pqc-challenge-used:${id}`;
}

async function fingerprintOf(publicKey: Uint8Array): Promise<string | null> {
  const digest = await crypto.subtle.digest("SHA-256", publicKey);
  return normalizeFingerprint(
    [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join(""),
  );
}

function looksLikeSecretText(value: string): boolean {
  return /BEGIN (?:PGP )?PRIVATE KEY|BEGIN PGP PRIVATE KEY BLOCK|secretKey/i.test(value);
}

async function readObject(
  request: Request,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<{ body: Record<string, unknown> } | { error: Response }> {
  try {
    const parsed = await readJsonBody(request, MAX_PQC_BODY_BYTES);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { error: json({ error: "invalid_json" }, 400, applySecurityHeaders) };
    }
    assertNoPrivateKeyMaterial(parsed);
    return { body: parsed as Record<string, unknown> };
  } catch (error) {
    if (error instanceof Error && error.message === "body_too_large") {
      return { error: bodyTooLarge(applySecurityHeaders) };
    }
    if (error instanceof Error && error.message === "private_key_rejected") {
      return { error: privateKeyRejected(applySecurityHeaders) };
    }
    return { error: json({ error: "invalid_json" }, 400, applySecurityHeaders) };
  }
}

function suiteFrom(body: Record<string, unknown>): PqcSigSuiteId | null {
  const suite = body.suite;
  if (typeof suite !== "string" || !isPqcSigSuite(suite)) return null;
  return suite;
}

export async function registerPqcUser(
  request: Request,
  env: AuthEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const limited = await rateLimitDurable(
    env,
    `auth:register:${clientIp(request)}`,
    5,
    60_000,
    applySecurityHeaders,
  );
  if (limited) return limited;
  if (!env.BILLING_KV) {
    return json(
      { error: "kv_missing", message: "BILLING_KV is required for auth." },
      503,
      applySecurityHeaders,
    );
  }

  const read = await readObject(request, applySecurityHeaders);
  if ("error" in read) return read.error;
  const suite = suiteFrom(read.body);
  const publicKeyB64 = read.body.publicKeyB64;
  if (!suite || typeof publicKeyB64 !== "string") {
    return json(
      {
        error: "invalid_public_key",
        message: "Choose a post-quantum suite and send the public key only.",
      },
      400,
      applySecurityHeaders,
    );
  }
  if (publicKeyB64.length > MAX_PUBLIC_CHARS || looksLikeSecretText(publicKeyB64)) {
    return privateKeyRejected(applySecurityHeaders);
  }

  let publicKey: Uint8Array;
  try {
    assertPqcSigLengths(suite);
    const peeked = b64ToFixedBytes(publicKeyB64, atob(publicKeyB64.replace(/\s+/g, "")).length);
    const expected = PQC_SIG_SUITES[suite];
    if (
      peeked.length === expected.secretKey &&
      expected.secretKey !== expected.publicKey
    ) {
      peeked.fill(0);
      throw new Error("private_key_rejected");
    }
    if (peeked.length !== expected.publicKey) {
      peeked.fill(0);
      throw new Error("invalid_length");
    }
    publicKey = peeked;
  } catch (error) {
    if (error instanceof Error && error.message === "private_key_rejected") {
      return privateKeyRejected(applySecurityHeaders);
    }
    return json(
      { error: "invalid_public_key", message: "That public key does not match the selected ML-DSA suite." },
      400,
      applySecurityHeaders,
    );
  }

  const fingerprint = await fingerprintOf(publicKey);
  if (!fingerprint) {
    return json(
      { error: "invalid_public_key", message: "That public key does not match the selected ML-DSA suite." },
      400,
      applySecurityHeaders,
    );
  }

  const existing = await env.BILLING_KV.get(authFingerprintStorageKey(fingerprint));
  if (existing) {
    return json(
      {
        error: "fingerprint_taken",
        message: "This key is already registered. Sign in with the device that holds the private key.",
      },
      409,
      applySecurityHeaders,
    );
  }

  const user: UserRecord = {
    id: randomId(16),
    fingerprint,
    publicKeyArmored: encodeStoredPublicKey(suite, bytesToB64(publicKey)),
    primaryUserId: PQC_SIG_SUITES[suite].label,
    createdAt: new Date().toISOString(),
    transitPaid: false,
  };
  await env.BILLING_KV.put(authUserStorageKey(user.id), JSON.stringify(user));
  await env.BILLING_KV.put(authFingerprintStorageKey(user.fingerprint), user.id);

  return issueLoginSession(
    request,
    env,
    user,
    "Public key registered. The ML-DSA private key stays on this device.",
    201,
    applySecurityHeaders,
  );
}

export async function createPqcChallenge(
  request: Request,
  env: AuthEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const limited = await rateLimitDurable(
    env,
    `auth:challenge:${clientIp(request)}`,
    10,
    60_000,
    applySecurityHeaders,
  );
  if (limited) return limited;
  if (!env.BILLING_KV) {
    return json(
      { error: "kv_missing", message: "BILLING_KV is required for auth." },
      503,
      applySecurityHeaders,
    );
  }

  const read = await readObject(request, applySecurityHeaders);
  if ("error" in read) return read.error;
  const suite = suiteFrom(read.body);
  const fingerprint =
    typeof read.body.fingerprint === "string"
      ? normalizeFingerprint(read.body.fingerprint)
      : null;
  if (!suite || !fingerprint || fingerprint.length !== 64) {
    return json(
      {
        error: "fingerprint_required",
        message: "Provide the ML-DSA suite and key fingerprint to start login.",
      },
      400,
      applySecurityHeaders,
    );
  }

  const userId = await env.BILLING_KV.get(authFingerprintStorageKey(fingerprint));
  const registered = Boolean(userId);
  const origin = new URL(request.url).origin;
  const challengeId = randomId(16);
  const nonce = randomId(16);
  const expiresAtMs = Date.now() + CHALLENGE_TTL_SECONDS * 1000;
  let message: string;
  try {
    message = buildPqcLoginMessage({
      origin,
      suite,
      fingerprint,
      nonce,
      expiresAtMs,
    });
  } catch {
    return json({ error: "invalid_login", message: "Could not start sign-in." }, 400, applySecurityHeaders);
  }

  const record: ChallengeRecord = {
    fingerprint,
    suite,
    message,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(expiresAtMs).toISOString(),
    decoy: !registered,
  };
  await env.BILLING_KV.put(challengeKey(challengeId), JSON.stringify(record), {
    expirationTtl: CHALLENGE_TTL_SECONDS,
  });

  return json(
    { challengeId, message, expiresAt: record.expiresAt, fingerprint, suite },
    200,
    applySecurityHeaders,
  );
}

export async function loginPqcUser(
  request: Request,
  env: AuthEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const limited = await rateLimitDurable(
    env,
    `auth:login:${clientIp(request)}`,
    10,
    60_000,
    applySecurityHeaders,
  );
  if (limited) return limited;
  if (!env.BILLING_KV) {
    return json(
      { error: "kv_missing", message: "BILLING_KV is required for auth." },
      503,
      applySecurityHeaders,
    );
  }

  const read = await readObject(request, applySecurityHeaders);
  if ("error" in read) return read.error;
  const suite = suiteFrom(read.body);
  const fingerprint =
    typeof read.body.fingerprint === "string"
      ? normalizeFingerprint(read.body.fingerprint)
      : null;
  const challengeId =
    typeof read.body.challengeId === "string" ? read.body.challengeId.trim() : "";
  const signatureB64 =
    typeof read.body.signatureB64 === "string" ? read.body.signatureB64.trim() : "";

  if (
    !suite ||
    !fingerprint ||
    fingerprint.length !== 64 ||
    !/^[a-f0-9]{16,128}$/i.test(challengeId) ||
    !signatureB64 ||
    signatureB64.length > MAX_SIGNATURE_CHARS
  ) {
    return json(
      {
        error: "invalid_login",
        message: "suite, fingerprint, challengeId, and signatureB64 are required.",
      },
      400,
      applySecurityHeaders,
    );
  }
  if (looksLikeSecretText(signatureB64)) return privateKeyRejected(applySecurityHeaders);

  const usedKey = challengeUsedKey(challengeId);
  const alreadyUsed = await env.BILLING_KV.get(usedKey);
  if (alreadyUsed) {
    return json(
      {
        error: "invalid_challenge",
        message: "Challenge expired or already used. Request a new one.",
      },
      401,
      applySecurityHeaders,
    );
  }
  await env.BILLING_KV.put(usedKey, "1", {
    expirationTtl: CHALLENGE_TTL_SECONDS + 60,
  });

  const challengeRaw = await env.BILLING_KV.get(challengeKey(challengeId));
  if (challengeRaw) await env.BILLING_KV.delete(challengeKey(challengeId));
  if (!challengeRaw) {
    return json(
      {
        error: "invalid_challenge",
        message: "Challenge expired or already used. Request a new one.",
      },
      401,
      applySecurityHeaders,
    );
  }

  let challenge: ChallengeRecord;
  try {
    challenge = JSON.parse(challengeRaw) as ChallengeRecord;
  } catch {
    return json({ error: "invalid_challenge" }, 401, applySecurityHeaders);
  }
  if (
    challenge.fingerprint !== fingerprint ||
    challenge.suite !== suite ||
    new Date(challenge.expiresAt).getTime() <= Date.now()
  ) {
    return json(
      {
        error: "invalid_challenge",
        message: "Challenge expired or does not match this key.",
      },
      401,
      applySecurityHeaders,
    );
  }
  if (challenge.decoy) {
    return json({ error: "auth_failed", message: "Could not verify signature." }, 401, applySecurityHeaders);
  }

  const userId = await env.BILLING_KV.get(authFingerprintStorageKey(fingerprint));
  const userRaw = userId ? await env.BILLING_KV.get(authUserStorageKey(userId)) : null;
  if (!userRaw) {
    return json({ error: "auth_failed", message: "Could not verify signature." }, 401, applySecurityHeaders);
  }
  let user: UserRecord;
  try {
    user = JSON.parse(userRaw) as UserRecord;
  } catch {
    return json({ error: "auth_failed", message: "Could not verify signature." }, 401, applySecurityHeaders);
  }

  const stored = decodeStoredPublicKey(user.publicKeyArmored);
  if (!stored || stored.suite !== suite) {
    return json({ error: "auth_failed", message: "Could not verify signature." }, 401, applySecurityHeaders);
  }

  let signature: Uint8Array;
  try {
    signature = b64ToFixedBytes(signatureB64, PQC_SIG_SUITES[suite].signature);
  } catch (error) {
    if (error instanceof Error && error.message === "private_key_rejected") {
      return privateKeyRejected(applySecurityHeaders);
    }
    return json({ error: "auth_failed", message: "Could not verify signature." }, 401, applySecurityHeaders);
  }

  let verified = false;
  try {
    verified = verifyPqcSignature(suite, signature, challenge.message, stored.publicKey);
  } catch {
    verified = false;
  }
  if (!verified) {
    return json({ error: "auth_failed", message: "Could not verify signature." }, 401, applySecurityHeaders);
  }

  return issueLoginSession(
    request,
    env,
    user,
    "Logged in. Session token issued (not a private key).",
    200,
    applySecurityHeaders,
  );
}
