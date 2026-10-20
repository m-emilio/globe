/**
 * Sign-in for the ECDHE lab and the post-quantum key-agreement lab.
 * The browser proves it can derive the same secret. The private key is not uploaded.
 * A matching proof gets the same globe_session cookie as OpenPGP and ML-DSA.
 */
import { ml_kem1024, ml_kem512, ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import {
  ml_kem1024_p384,
  ml_kem768_p256,
  ml_kem768_x25519,
} from "@noble/post-quantum/hybrid.js";
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
  buildLabLoginMessage,
  hmacLogin,
  hmacMatches,
  macKeyFromShared,
  type LabFamily,
} from "./labMac";

const CHALLENGE_TTL_SECONDS = 180;
const MAX_BODY = 96_000;

const ECDHE_CURVES = ["P-256", "P-384", "P-521", "X25519"] as const;
type EcdheCurve = (typeof ECDHE_CURVES)[number];

const KEMS = {
  "ml-kem768-x25519": { label: "X-Wing", publicKey: 1216, cipherText: 1120, kem: ml_kem768_x25519 },
  "ml-kem512": { label: "ML-KEM-512", publicKey: 800, cipherText: 768, kem: ml_kem512 },
  "ml-kem768": { label: "ML-KEM-768", publicKey: 1184, cipherText: 1088, kem: ml_kem768 },
  "ml-kem1024": { label: "ML-KEM-1024", publicKey: 1568, cipherText: 1568, kem: ml_kem1024 },
  "ml-kem768-p256": { label: "ML-KEM-768 + P-256", publicKey: 1249, cipherText: 1153, kem: ml_kem768_p256 },
  "ml-kem1024-p384": { label: "ML-KEM-1024 + P-384", publicKey: 1665, cipherText: 1665, kem: ml_kem1024_p384 },
} as const;
type KemId = keyof typeof KEMS;

type ChallengeRecord = {
  family: LabFamily;
  suite: string;
  fingerprint: string;
  message: string;
  macKeyB64: string;
  expiresAt: string;
  decoy?: boolean;
};

function json(data: unknown, status: number, applySecurityHeaders?: SecurityHeadersFn): Response {
  const headers = new Headers();
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  applySecurityHeaders?.(headers);
  return new Response(JSON.stringify(data), { status, headers });
}

function randomId(bytes = 16): string {
  const buf = crypto.getRandomValues(new Uint8Array(bytes));
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function bytesToB64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s);
}

function b64ToBytes(b64: string, maxChars: number): Uint8Array {
  const clean = b64.replace(/\s+/g, "");
  if (!clean || clean.length > maxChars || !/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) {
    throw new Error("invalid_base64");
  }
  const raw = atob(clean);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function isCurve(value: string): value is EcdheCurve {
  return (ECDHE_CURVES as readonly string[]).includes(value);
}

function isKem(value: string): value is KemId {
  return Object.prototype.hasOwnProperty.call(KEMS, value);
}

function curveAlg(curve: EcdheCurve): SubtleCryptoGenerateKeyAlgorithm {
  if (curve === "X25519") return { name: "X25519" };
  return { name: "ECDH", namedCurve: curve };
}

/** Runtime WebCrypto uses `public`. Worker types rename that field. */
function deriveParams(name: string, peer: CryptoKey): SubtleCryptoDeriveKeyAlgorithm {
  const params: Record<string, unknown> = { name, public: peer };
  return params as unknown as SubtleCryptoDeriveKeyAlgorithm;
}

async function exportSpki(key: CryptoKey): Promise<Uint8Array<ArrayBufferLike>> {
  const exported = await crypto.subtle.exportKey("spki", key);
  if (!(exported instanceof ArrayBuffer)) throw new Error("invalid_public_key");
  return new Uint8Array(exported);
}

function sharedBits(curve: EcdheCurve): number {
  if (curve === "P-521") return 528;
  if (curve === "P-384") return 384;
  return 256;
}

async function fingerprintOf(bytes: Uint8Array): Promise<string | null> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return normalizeFingerprint(
    [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join(""),
  );
}

async function canonicalEcdhePublic(curve: EcdheCurve, spki: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("spki", spki, curveAlg(curve), true, []);
  return exportSpki(key);
}

async function ecdheMacKey(curve: EcdheCurve, clientSpki: Uint8Array): Promise<{ token: Uint8Array<ArrayBufferLike>; macKey: Uint8Array<ArrayBufferLike> }> {
  const alg = curveAlg(curve);
  const pair = (await crypto.subtle.generateKey(alg, true, ["deriveBits"])) as CryptoKeyPair;
  const token = await exportSpki(pair.publicKey);
  const client = await crypto.subtle.importKey("spki", clientSpki, alg, false, []);
  const shared = new Uint8Array(
    await crypto.subtle.deriveBits(
      deriveParams(curve === "X25519" ? "X25519" : "ECDH", client),
      pair.privateKey,
      sharedBits(curve),
    ),
  );
  try {
    const macKey = await macKeyFromShared(shared, "ecdhe", curve);
    return { token, macKey };
  } finally {
    shared.fill(0);
  }
}

function kemMacMaterial(suite: KemId, publicKey: Uint8Array): { token: Uint8Array; shared: Uint8Array } {
  const row = KEMS[suite];
  if (publicKey.length !== row.publicKey || row.kem.lengths.publicKey !== row.publicKey) {
    throw new Error("invalid_public_key");
  }
  const enc = row.kem.encapsulate(publicKey);
  return { token: enc.cipherText, shared: enc.sharedSecret };
}

function storedPrefix(family: LabFamily): string {
  return family === "ecdhe" ? "globe-ecdhe:v1:" : "globe-kem:v1:";
}

function encodeStored(family: LabFamily, suite: string, publicB64: string): string {
  return `${storedPrefix(family)}${suite}:${publicB64}`;
}

function decodeStored(stored: string): { family: LabFamily; suite: string; publicKey: Uint8Array } | null {
  const family: LabFamily | null = stored.startsWith("globe-ecdhe:v1:")
    ? "ecdhe"
    : stored.startsWith("globe-kem:v1:")
      ? "kem"
      : null;
  if (!family) return null;
  const rest = stored.slice(storedPrefix(family).length);
  const splitAt = rest.indexOf(":");
  if (splitAt <= 0) return null;
  const suite = rest.slice(0, splitAt);
  try {
    const publicKey = b64ToBytes(rest.slice(splitAt + 1), 8000);
    if (family === "ecdhe" && !isCurve(suite)) return null;
    if (family === "kem" && (!isKem(suite) || publicKey.length !== KEMS[suite].publicKey)) return null;
    return { family, suite, publicKey };
  } catch {
    return null;
  }
}

async function readObject(
  request: Request,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<{ body: Record<string, unknown> } | { error: Response }> {
  try {
    const parsed = await readJsonBody(request, MAX_BODY);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { error: json({ error: "invalid_json" }, 400, applySecurityHeaders) };
    }
    assertNoPrivateKeyMaterial(parsed);
    return { body: parsed as Record<string, unknown> };
  } catch (error) {
    if (error instanceof Error && error.message === "body_too_large") {
      return { error: json({ error: "body_too_large" }, 413, applySecurityHeaders) };
    }
    if (error instanceof Error && error.message === "private_key_rejected") {
      return {
        error: json(
          { error: "private_key_rejected", message: "Send the public key only." },
          400,
          applySecurityHeaders,
        ),
      };
    }
    return { error: json({ error: "invalid_json" }, 400, applySecurityHeaders) };
  }
}

function familySuite(body: Record<string, unknown>): { family: LabFamily; suite: string } | null {
  const family = body.family;
  const suite = body.suite;
  if (family === "ecdhe" && typeof suite === "string" && isCurve(suite)) return { family, suite };
  if (family === "kem" && typeof suite === "string" && isKem(suite)) return { family, suite };
  return null;
}

export async function registerLabUser(
  request: Request,
  env: AuthEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const limited = await rateLimitDurable(env, `auth:register:${clientIp(request)}`, 5, 60_000, applySecurityHeaders);
  if (limited) return limited;
  if (!env.BILLING_KV) return json({ error: "kv_missing" }, 503, applySecurityHeaders);
  const read = await readObject(request, applySecurityHeaders);
  if ("error" in read) return read.error;
  const picked = familySuite(read.body);
  const publicKeyB64 = read.body.publicKeyB64;
  if (!picked || typeof publicKeyB64 !== "string" || /BEGIN PRIVATE KEY/i.test(publicKeyB64)) {
    return json({ error: "invalid_public_key", message: "Send the lab public key only." }, 400, applySecurityHeaders);
  }
  let publicKey: Uint8Array;
  try {
    const raw = b64ToBytes(publicKeyB64, 8000);
    publicKey = picked.family === "ecdhe" ? await canonicalEcdhePublic(picked.suite as EcdheCurve, raw) : raw;
    if (picked.family === "kem" && publicKey.length !== KEMS[picked.suite as KemId].publicKey) {
      throw new Error("invalid_length");
    }
  } catch {
    return json({ error: "invalid_public_key", message: "That public key does not match the selected lab suite." }, 400, applySecurityHeaders);
  }
  const fingerprint = await fingerprintOf(publicKey);
  if (!fingerprint) {
    return json({ error: "invalid_public_key" }, 400, applySecurityHeaders);
  }
  const existing = await env.BILLING_KV.get(authFingerprintStorageKey(fingerprint));
  if (existing) {
    return json(
      {
        error: "fingerprint_taken",
        message: "This key is already registered. Sign in with the device that holds it.",
        fingerprint,
      },
      409,
      applySecurityHeaders,
    );
  }
  const label = picked.family === "ecdhe" ? `ECDHE-${picked.suite}` : `KEM-${picked.suite}`;
  const user: UserRecord = {
    id: randomId(16),
    fingerprint,
    publicKeyArmored: encodeStored(picked.family, picked.suite, bytesToB64(publicKey)),
    primaryUserId: label,
    createdAt: new Date().toISOString(),
    transitPaid: false,
  };
  await env.BILLING_KV.put(authUserStorageKey(user.id), JSON.stringify(user));
  await env.BILLING_KV.put(authFingerprintStorageKey(user.fingerprint), user.id);
  return json(
    { registered: true, family: picked.family, suite: picked.suite, fingerprint },
    201,
    applySecurityHeaders,
  );
}

export async function createLabChallenge(
  request: Request,
  env: AuthEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const limited = await rateLimitDurable(env, `auth:challenge:${clientIp(request)}`, 10, 60_000, applySecurityHeaders);
  if (limited) return limited;
  if (!env.BILLING_KV) return json({ error: "kv_missing" }, 503, applySecurityHeaders);
  const read = await readObject(request, applySecurityHeaders);
  if ("error" in read) return read.error;
  const picked = familySuite(read.body);
  const fingerprint = typeof read.body.fingerprint === "string" ? normalizeFingerprint(read.body.fingerprint) : null;
  if (!picked || !fingerprint || fingerprint.length !== 64) {
    return json({ error: "fingerprint_required" }, 400, applySecurityHeaders);
  }
  const userId = await env.BILLING_KV.get(authFingerprintStorageKey(fingerprint));
  const userRaw = userId ? await env.BILLING_KV.get(authUserStorageKey(userId)) : null;
  let stored: ReturnType<typeof decodeStored> = null;
  if (userRaw) {
    try {
      stored = decodeStored((JSON.parse(userRaw) as { publicKeyArmored?: string }).publicKeyArmored || "");
    } catch {
      stored = null;
    }
  }
  const registered = Boolean(stored && stored.family === picked.family && stored.suite === picked.suite);
  if (!registered) stored = null;

  const origin = new URL(request.url).origin;
  const challengeId = randomId(16);
  const nonce = randomId(16);
  const expiresAtMs = Date.now() + CHALLENGE_TTL_SECONDS * 1000;
  let message: string;
  try {
    message = buildLabLoginMessage({
      origin,
      family: picked.family,
      suite: picked.suite,
      fingerprint,
      nonce,
      expiresAtMs,
    });
  } catch {
    return json({ error: "invalid_login" }, 400, applySecurityHeaders);
  }

  let token: Uint8Array<ArrayBufferLike> = new Uint8Array(32);
  let macKey: Uint8Array<ArrayBufferLike> = new Uint8Array(32);
  crypto.getRandomValues(token);
  crypto.getRandomValues(macKey);
  if (stored) {
    try {
      if (stored.family === "ecdhe") {
        const opened = await ecdheMacKey(stored.suite as EcdheCurve, stored.publicKey);
        token = opened.token;
        macKey = opened.macKey;
      } else {
        const opened = kemMacMaterial(stored.suite as KemId, stored.publicKey);
        token = opened.token;
        macKey = await macKeyFromShared(opened.shared, "kem", stored.suite);
        opened.shared.fill(0);
      }
    } catch {
      stored = null;
    }
  }
  if (!stored && picked.family === "kem") {
    token = crypto.getRandomValues(new Uint8Array(KEMS[picked.suite as KemId].cipherText));
  }
  if (!stored && picked.family === "ecdhe") {
    const pair = (await crypto.subtle.generateKey(curveAlg(picked.suite as EcdheCurve), true, ["deriveBits"])) as CryptoKeyPair;
    token = await exportSpki(pair.publicKey);
  }

  const record: ChallengeRecord = {
    family: picked.family,
    suite: picked.suite,
    fingerprint,
    message,
    macKeyB64: bytesToB64(macKey),
    expiresAt: new Date(expiresAtMs).toISOString(),
    decoy: !stored,
  };
  macKey.fill(0);
  await env.BILLING_KV.put(`auth:lab-challenge:${challengeId}`, JSON.stringify(record), {
    expirationTtl: CHALLENGE_TTL_SECONDS,
  });
  return json(
    {
      challengeId,
      message,
      fingerprint,
      family: picked.family,
      suite: picked.suite,
      tokenB64: bytesToB64(token),
    },
    200,
    applySecurityHeaders,
  );
}

export async function loginLabUser(
  request: Request,
  env: AuthEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const limited = await rateLimitDurable(env, `auth:login:${clientIp(request)}`, 10, 60_000, applySecurityHeaders);
  if (limited) return limited;
  if (!env.BILLING_KV) return json({ error: "kv_missing" }, 503, applySecurityHeaders);
  const read = await readObject(request, applySecurityHeaders);
  if ("error" in read) return read.error;
  const picked = familySuite(read.body);
  const fingerprint = typeof read.body.fingerprint === "string" ? normalizeFingerprint(read.body.fingerprint) : null;
  const challengeId = typeof read.body.challengeId === "string" ? read.body.challengeId.trim() : "";
  const macB64 = typeof read.body.macB64 === "string" ? read.body.macB64.trim() : "";
  if (!picked || !fingerprint || fingerprint.length !== 64 || !/^[a-f0-9]{16,128}$/i.test(challengeId) || macB64.length < 40 || macB64.length > 80) {
    return json({ error: "invalid_login" }, 400, applySecurityHeaders);
  }
  const usedKey = `auth:lab-challenge-used:${challengeId}`;
  if (await env.BILLING_KV.get(usedKey)) {
    return json({ error: "invalid_challenge" }, 401, applySecurityHeaders);
  }
  await env.BILLING_KV.put(usedKey, "1", { expirationTtl: CHALLENGE_TTL_SECONDS + 60 });
  const raw = await env.BILLING_KV.get(`auth:lab-challenge:${challengeId}`);
  if (raw) await env.BILLING_KV.delete(`auth:lab-challenge:${challengeId}`);
  if (!raw) return json({ error: "invalid_challenge" }, 401, applySecurityHeaders);
  let challenge: ChallengeRecord;
  try {
    challenge = JSON.parse(raw) as ChallengeRecord;
  } catch {
    return json({ error: "invalid_challenge" }, 401, applySecurityHeaders);
  }
  if (
    challenge.decoy ||
    challenge.family !== picked.family ||
    challenge.suite !== picked.suite ||
    challenge.fingerprint !== fingerprint ||
    new Date(challenge.expiresAt).getTime() <= Date.now()
  ) {
    return json({ error: "auth_failed", message: "Could not verify sign-in." }, 401, applySecurityHeaders);
  }
  const userId = await env.BILLING_KV.get(authFingerprintStorageKey(fingerprint));
  const userRaw = userId ? await env.BILLING_KV.get(authUserStorageKey(userId)) : null;
  if (!userRaw) return json({ error: "auth_failed", message: "Could not verify sign-in." }, 401, applySecurityHeaders);
  let user: UserRecord;
  try {
    user = JSON.parse(userRaw) as UserRecord;
  } catch {
    return json({ error: "auth_failed", message: "Could not verify sign-in." }, 401, applySecurityHeaders);
  }
  let macKey: Uint8Array;
  let mac: Uint8Array;
  try {
    macKey = b64ToBytes(challenge.macKeyB64, 80);
    mac = b64ToBytes(macB64, 80);
  } catch {
    return json({ error: "auth_failed", message: "Could not verify sign-in." }, 401, applySecurityHeaders);
  }
  let ok = false;
  try {
    ok = await hmacMatches(macKey, challenge.message, mac);
  } finally {
    macKey.fill(0);
    mac.fill(0);
  }
  if (!ok) return json({ error: "auth_failed", message: "Could not verify sign-in." }, 401, applySecurityHeaders);
  return issueLoginSession(
    request,
    env,
    user,
    "Logged in. Session token issued (not a private key).",
    200,
    applySecurityHeaders,
  );
}

export async function labLoginSelfTest(): Promise<{ ok: true; ecdhe: "P-256"; kem: "ml-kem512" }> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair;
  const spki = await exportSpki(pair.publicKey);
  const opened = await ecdheMacKey("P-256", spki);
  const message = buildLabLoginMessage({
    origin: "https://globe.example",
    family: "ecdhe",
    suite: "P-256",
    fingerprint: "ab".repeat(32),
    nonce: "cd".repeat(16),
    expiresAtMs: Date.now() + 60_000,
  });
  const peer = await crypto.subtle.importKey("spki", opened.token, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(
    await crypto.subtle.deriveBits(deriveParams("ECDH", peer), pair.privateKey, 256),
  );
  const clientKey = await macKeyFromShared(shared, "ecdhe", "P-256");
  shared.fill(0);
  const mac = await hmacLogin(clientKey, message);
  if (!(await hmacMatches(opened.macKey, message, mac))) throw new Error("ecdhe lab login mac mismatch");
  clientKey.fill(0);
  opened.macKey.fill(0);

  const kem = KEMS["ml-kem512"].kem;
  const keys = kem.keygen();
  const enc = kemMacMaterial("ml-kem512", keys.publicKey);
  const dec = kem.decapsulate(enc.token, keys.secretKey);
  const serverMac = await macKeyFromShared(enc.shared, "kem", "ml-kem512");
  const clientMac = await macKeyFromShared(dec, "kem", "ml-kem512");
  enc.shared.fill(0);
  dec.fill(0);
  keys.secretKey.fill(0);
  const kemMac = await hmacLogin(clientMac, message);
  if (!(await hmacMatches(serverMac, message, kemMac))) throw new Error("kem lab login mac mismatch");
  clientMac.fill(0);
  serverMac.fill(0);
  return { ok: true, ecdhe: "P-256", kem: "ml-kem512" };
}
