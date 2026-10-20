/**
 * ML-DSA login checks shared by the worker and the browser.
 * The private key never enters this file. Callers pass a signature and a public key.
 */
import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";

export const PQC_LOGIN_PROTOCOL = "globe-pqc-login:v1";
export const PQC_LOGIN_CONTEXT_LABEL = "globe-pqc-login:v1";
export const PQC_PUBLIC_PREFIX = "globe-ml-dsa:v1:";

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

const SIGNERS = {
  "ml-dsa44": ml_dsa44,
  "ml-dsa65": ml_dsa65,
  "ml-dsa87": ml_dsa87,
} as const;

const SECRET_LENGTHS = new Set<number>([
  ML_DSA_SUITES["ml-dsa44"].secretKey,
  ML_DSA_SUITES["ml-dsa65"].secretKey,
  ML_DSA_SUITES["ml-dsa87"].secretKey,
]);

export function isMlDsaSuite(value: string): value is MlDsaSuiteId {
  return Object.prototype.hasOwnProperty.call(ML_DSA_SUITES, value);
}

export function pqcLoginContext(): Uint8Array {
  return new TextEncoder().encode(PQC_LOGIN_CONTEXT_LABEL);
}

export function assertMlDsaLengths(suite: MlDsaSuiteId): void {
  const expected = ML_DSA_SUITES[suite];
  const lens = SIGNERS[suite].lengths;
  if (
    lens.publicKey !== expected.publicKey ||
    lens.secretKey !== expected.secretKey ||
    lens.signature !== expected.signature
  ) {
    throw new Error("ml_dsa_lengths");
  }
}

export function buildPqcLoginMessage(parts: {
  origin: string;
  suite: MlDsaSuiteId;
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
  expected: { origin: string; suite: MlDsaSuiteId; fingerprint: string },
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
  if (!clean || clean.length > 8192 || !/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) {
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

export function encodeStoredPublicKey(suite: MlDsaSuiteId, publicKeyB64: string): string {
  return `${PQC_PUBLIC_PREFIX}${suite}:${publicKeyB64}`;
}

export function decodeStoredPublicKey(
  stored: string,
): { suite: MlDsaSuiteId; publicKey: Uint8Array } | null {
  if (!stored.startsWith(PQC_PUBLIC_PREFIX)) return null;
  const rest = stored.slice(PQC_PUBLIC_PREFIX.length);
  const splitAt = rest.indexOf(":");
  if (splitAt <= 0) return null;
  const suite = rest.slice(0, splitAt);
  const b64 = rest.slice(splitAt + 1);
  if (!isMlDsaSuite(suite)) return null;
  try {
    assertMlDsaLengths(suite);
    const publicKey = b64ToFixedBytes(b64, ML_DSA_SUITES[suite].publicKey);
    rejectPrivateSizedKey(publicKey);
    return { suite, publicKey };
  } catch {
    return null;
  }
}

/** True when the signature matches. False for a bad signature. Throws on a bad API shape. */
export function verifyPqcSignature(
  suite: MlDsaSuiteId,
  signature: Uint8Array,
  message: string,
  publicKey: Uint8Array,
): boolean {
  assertMlDsaLengths(suite);
  const expected = ML_DSA_SUITES[suite];
  if (publicKey.length !== expected.publicKey) return false;
  if (signature.length !== expected.signature) return false;
  if (SECRET_LENGTHS.has(signature.length) || SECRET_LENGTHS.has(publicKey.length)) {
    return false;
  }
  return SIGNERS[suite].verify(signature, new TextEncoder().encode(message), publicKey, {
    context: pqcLoginContext(),
  });
}
