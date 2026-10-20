/**
 * ML-DSA login checks shared by the worker and the browser.
 * The private key never enters this file. Callers pass a signature and a public key.
 */
import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import {
  slh_dsa_sha2_128f,
  slh_dsa_sha2_128s,
  slh_dsa_sha2_192f,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_256f,
  slh_dsa_sha2_256s,
  slh_dsa_shake_128f,
  slh_dsa_shake_128s,
  slh_dsa_shake_192f,
  slh_dsa_shake_192s,
  slh_dsa_shake_256f,
  slh_dsa_shake_256s,
} from "@noble/post-quantum/slh-dsa.js";

export const PQC_LOGIN_PROTOCOL = "globe-pqc-login:v1";
export const PQC_LOGIN_CONTEXT_LABEL = "globe-pqc-login:v1";
export const PQC_PUBLIC_PREFIX = "globe-ml-dsa:v1:";
export const SLH_PUBLIC_PREFIX = "globe-slh-dsa:v1:";

export const ML_DSA_SUITES = {
  "ml-dsa44": {
    id: "ml-dsa44",
    label: "ML-DSA-44",
    publicKey: 1312,
    secretKey: 2560,
    signature: 2420,
  },
  "ml-dsa65": {
    id: "ml-dsa65",
    label: "ML-DSA-65",
    publicKey: 1952,
    secretKey: 4032,
    signature: 3309,
  },
  "ml-dsa87": {
    id: "ml-dsa87",
    label: "ML-DSA-87",
    publicKey: 2592,
    secretKey: 4896,
    signature: 4627,
  },
} as const;

export type MlDsaSuiteId = keyof typeof ML_DSA_SUITES;

export const SLH_DSA_SUITES = {
  "slh-dsa-sha2-128s": { id: "slh-dsa-sha2-128s", label: "SLH-DSA-SHA2-128s", publicKey: 32, secretKey: 64, signature: 7856 },
  "slh-dsa-sha2-128f": { id: "slh-dsa-sha2-128f", label: "SLH-DSA-SHA2-128f", publicKey: 32, secretKey: 64, signature: 17088 },
  "slh-dsa-sha2-192s": { id: "slh-dsa-sha2-192s", label: "SLH-DSA-SHA2-192s", publicKey: 48, secretKey: 96, signature: 16224 },
  "slh-dsa-sha2-192f": { id: "slh-dsa-sha2-192f", label: "SLH-DSA-SHA2-192f", publicKey: 48, secretKey: 96, signature: 35664 },
  "slh-dsa-sha2-256s": { id: "slh-dsa-sha2-256s", label: "SLH-DSA-SHA2-256s", publicKey: 64, secretKey: 128, signature: 29792 },
  "slh-dsa-sha2-256f": { id: "slh-dsa-sha2-256f", label: "SLH-DSA-SHA2-256f", publicKey: 64, secretKey: 128, signature: 49856 },
  "slh-dsa-shake-128s": { id: "slh-dsa-shake-128s", label: "SLH-DSA-SHAKE-128s", publicKey: 32, secretKey: 64, signature: 7856 },
  "slh-dsa-shake-128f": { id: "slh-dsa-shake-128f", label: "SLH-DSA-SHAKE-128f", publicKey: 32, secretKey: 64, signature: 17088 },
  "slh-dsa-shake-192s": { id: "slh-dsa-shake-192s", label: "SLH-DSA-SHAKE-192s", publicKey: 48, secretKey: 96, signature: 16224 },
  "slh-dsa-shake-192f": { id: "slh-dsa-shake-192f", label: "SLH-DSA-SHAKE-192f", publicKey: 48, secretKey: 96, signature: 35664 },
  "slh-dsa-shake-256s": { id: "slh-dsa-shake-256s", label: "SLH-DSA-SHAKE-256s", publicKey: 64, secretKey: 128, signature: 29792 },
  "slh-dsa-shake-256f": { id: "slh-dsa-shake-256f", label: "SLH-DSA-SHAKE-256f", publicKey: 64, secretKey: 128, signature: 49856 },
} as const;

export type SlhDsaSuiteId = keyof typeof SLH_DSA_SUITES;
export type PqcSigSuiteId = MlDsaSuiteId | SlhDsaSuiteId;

export const PQC_SIG_SUITES = { ...ML_DSA_SUITES, ...SLH_DSA_SUITES };

const SIGNERS = {
  "ml-dsa44": ml_dsa44,
  "ml-dsa65": ml_dsa65,
  "ml-dsa87": ml_dsa87,
  "slh-dsa-sha2-128s": slh_dsa_sha2_128s,
  "slh-dsa-sha2-128f": slh_dsa_sha2_128f,
  "slh-dsa-sha2-192s": slh_dsa_sha2_192s,
  "slh-dsa-sha2-192f": slh_dsa_sha2_192f,
  "slh-dsa-sha2-256s": slh_dsa_sha2_256s,
  "slh-dsa-sha2-256f": slh_dsa_sha2_256f,
  "slh-dsa-shake-128s": slh_dsa_shake_128s,
  "slh-dsa-shake-128f": slh_dsa_shake_128f,
  "slh-dsa-shake-192s": slh_dsa_shake_192s,
  "slh-dsa-shake-192f": slh_dsa_shake_192f,
  "slh-dsa-shake-256s": slh_dsa_shake_256s,
  "slh-dsa-shake-256f": slh_dsa_shake_256f,
} as const;

const SECRET_LENGTHS = new Set<number>([
  ML_DSA_SUITES["ml-dsa44"].secretKey,
  ML_DSA_SUITES["ml-dsa65"].secretKey,
  ML_DSA_SUITES["ml-dsa87"].secretKey,
]);

export function isMlDsaSuite(value: string): value is MlDsaSuiteId {
  return Object.prototype.hasOwnProperty.call(ML_DSA_SUITES, value);
}

export function isSlhDsaSuite(value: string): value is SlhDsaSuiteId {
  return Object.prototype.hasOwnProperty.call(SLH_DSA_SUITES, value);
}

export function isPqcSigSuite(value: string): value is PqcSigSuiteId {
  return isMlDsaSuite(value) || isSlhDsaSuite(value);
}

export function pqcLoginContext(): Uint8Array {
  return new TextEncoder().encode(PQC_LOGIN_CONTEXT_LABEL);
}

export function assertMlDsaLengths(suite: MlDsaSuiteId): void {
  assertPqcSigLengths(suite);
}

export function assertPqcSigLengths(suite: PqcSigSuiteId): void {
  const expected = PQC_SIG_SUITES[suite];
  const lens = SIGNERS[suite].lengths;
  if (
    lens.publicKey !== expected.publicKey ||
    lens.secretKey !== expected.secretKey ||
    lens.signature !== expected.signature
  ) {
    throw new Error("pqc_sig_lengths");
  }
}

export function buildPqcLoginMessage(parts: {
  origin: string;
  suite: PqcSigSuiteId;
  fingerprint: string;
  nonce: string;
  expiresAtMs: number;
}): string {
  if (!isSafeOrigin(parts.origin)) throw new Error("invalid_origin");
  if (!/^[a-f0-9]{64}$/.test(parts.fingerprint)) throw new Error("invalid_fingerprint");
  if (!/^[a-f0-9]{32}$/.test(parts.nonce)) throw new Error("invalid_nonce");
  if (!Number.isSafeInteger(parts.expiresAtMs) || parts.expiresAtMs <= 0) {
    throw new Error("invalid_expiry");
  }
  return [
    PQC_LOGIN_PROTOCOL,
    parts.origin,
    parts.suite,
    parts.fingerprint,
    parts.nonce,
    String(parts.expiresAtMs),
  ].join("\n");
}

export function pqcLoginMessageMatches(
  message: string,
  expected: { origin: string; suite: PqcSigSuiteId; fingerprint: string },
): boolean {
  const lines = message.split("\n");
  if (lines.length !== 6) return false;
  if (lines[0] !== PQC_LOGIN_PROTOCOL) return false;
  if (lines[1] !== expected.origin) return false;
  if (lines[2] !== expected.suite) return false;
  if (lines[3] !== expected.fingerprint) return false;
  if (!/^[a-f0-9]{32}$/.test(lines[4] || "")) return false;
  if (!/^\d{10,16}$/.test(lines[5] || "")) return false;
  const expiresAt = Number(lines[5]);
  const now = Date.now();
  return expiresAt > now && expiresAt < now + 10 * 60 * 1000;
}

function isSafeOrigin(origin: string): boolean {
  if (origin.length > 200 || /[\s\\<>]/.test(origin)) return false;
  return (
    /^https:\/\/[A-Za-z0-9.-]+(?::\d+)?$/.test(origin) ||
    /^http:\/\/(?:localhost|127\.0\.0\.1)(?::\d+)?$/.test(origin)
  );
}

export function bytesToB64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s);
}

export function b64ToFixedBytes(b64: string, length: number): Uint8Array {
  const clean = b64.replace(/\s+/g, "");
  if (!clean || clean.length > 80_000 || !/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) {
    throw new Error("invalid_base64");
  }
  let raw: string;
  try {
    raw = atob(clean);
  } catch {
    throw new Error("invalid_base64");
  }
  if (raw.length !== length) throw new Error("invalid_length");
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

export function rejectPrivateSizedKey(bytes: Uint8Array): void {
  if (SECRET_LENGTHS.has(bytes.length)) throw new Error("private_key_rejected");
}

export function encodeStoredPublicKey(suite: PqcSigSuiteId, publicKeyB64: string): string {
  const prefix = isMlDsaSuite(suite) ? PQC_PUBLIC_PREFIX : SLH_PUBLIC_PREFIX;
  return `${prefix}${suite}:${publicKeyB64}`;
}

export function decodeStoredPublicKey(
  stored: string,
): { suite: PqcSigSuiteId; publicKey: Uint8Array } | null {
  const prefix = stored.startsWith(PQC_PUBLIC_PREFIX)
    ? PQC_PUBLIC_PREFIX
    : stored.startsWith(SLH_PUBLIC_PREFIX)
      ? SLH_PUBLIC_PREFIX
      : "";
  if (!prefix) return null;
  const rest = stored.slice(prefix.length);
  const splitAt = rest.indexOf(":");
  if (splitAt <= 0) return null;
  const suite = rest.slice(0, splitAt);
  const b64 = rest.slice(splitAt + 1);
  if (!isPqcSigSuite(suite)) return null;
  if (prefix === PQC_PUBLIC_PREFIX && !isMlDsaSuite(suite)) return null;
  if (prefix === SLH_PUBLIC_PREFIX && !isSlhDsaSuite(suite)) return null;
  try {
    assertPqcSigLengths(suite);
    const publicKey = b64ToFixedBytes(b64, PQC_SIG_SUITES[suite].publicKey);
    rejectPrivateSizedKey(publicKey);
    return { suite, publicKey };
  } catch {
    return null;
  }
}

/** True when the signature matches. False for a bad signature. Throws on a bad API shape. */
export function verifyPqcSignature(
  suite: PqcSigSuiteId,
  signature: Uint8Array,
  message: string,
  publicKey: Uint8Array,
): boolean {
  assertPqcSigLengths(suite);
  const expected = PQC_SIG_SUITES[suite];
  if (publicKey.length !== expected.publicKey) return false;
  if (signature.length !== expected.signature) return false;
  if (SECRET_LENGTHS.has(signature.length) || SECRET_LENGTHS.has(publicKey.length)) {
    return false;
  }
  return SIGNERS[suite].verify(signature, new TextEncoder().encode(message), publicKey, {
    context: pqcLoginContext(),
  });
}
