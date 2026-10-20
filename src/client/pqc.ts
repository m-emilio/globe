/**
 * Post-quantum key agreement for the browser lab.
 *
 * X-Wing (ML-KEM-768 + X25519) stays the original suite: public 1216,
 * secret 32, ciphertext 1120, shared 32, HKDF info
 * `globe-pqc-xwing:v1:ml-kem768-x25519`. The other suites are separate.
 * Pure JavaScript from `@noble/post-quantum`. No WASM.
 *
 * This is not an OpenPGP identity key and not an ML-DSA login key.
 * Secret keys stay in this module's memory map. Callers receive a SHA-256
 * fingerprint and a non-extractable AES-GCM session key, never the raw
 * shared secret.
 */

import { ml_kem1024, ml_kem512, ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import {
  ml_kem1024_p384,
  ml_kem768_p256,
  ml_kem768_x25519,
} from "@noble/post-quantum/hybrid.js";
import { equalBytes } from "@noble/post-quantum/utils.js";
import { hmacLogin, macKeyFromShared } from "../server/labMac";

export const PQC_SUITE_ID = "ml-kem768-x25519" as const;
export const PQC_SUITE_LABEL = "X-Wing (ML-KEM-768 + X25519)";
/** HKDF info label for X-Wing. Both peers must use the same string. */
export const PQC_HKDF_INFO = "globe-pqc-xwing:v1:ml-kem768-x25519";

/**
 * X-Wing sizes from `ml_kem768_x25519.lengths`.
 * The in-memory secret is the 32-byte seed. Public key and ciphertext are
 * ML-KEM-768 (1184 / 1088) plus a 32-byte X25519 element.
 */
export const PQC_LENGTHS = {
  publicKey: 1216,
  secretKey: 32,
  cipherText: 1120,
  sharedSecret: 32,
} as const;

type KemLike = {
  lengths: {
    publicKey?: number;
    secretKey?: number;
    cipherText?: number;
    msg?: number;
  };
  keygen: () => { secretKey: Uint8Array; publicKey: Uint8Array };
  encapsulate: (publicKey: Uint8Array) => {
    cipherText: Uint8Array;
    sharedSecret: Uint8Array;
  };
  decapsulate: (cipherText: Uint8Array, secretKey: Uint8Array) => Uint8Array;
};

export const PQC_KEM_SUITES = [
  {
    id: PQC_SUITE_ID,
    label: PQC_SUITE_LABEL,
    publicKey: PQC_LENGTHS.publicKey,
    secretKey: PQC_LENGTHS.secretKey,
    cipherText: PQC_LENGTHS.cipherText,
    sharedSecret: PQC_LENGTHS.sharedSecret,
    hkdfInfo: PQC_HKDF_INFO,
  },
  {
    id: "ml-kem512",
    label: "ML-KEM-512",
    publicKey: 800,
    secretKey: 1632,
    cipherText: 768,
    sharedSecret: 32,
    hkdfInfo: "globe-pqc-ml-kem512:v1",
  },
  {
    id: "ml-kem768",
    label: "ML-KEM-768",
    publicKey: 1184,
    secretKey: 2400,
    cipherText: 1088,
    sharedSecret: 32,
    hkdfInfo: "globe-pqc-ml-kem768:v1",
  },
  {
    id: "ml-kem1024",
    label: "ML-KEM-1024",
    publicKey: 1568,
    secretKey: 3168,
    cipherText: 1568,
    sharedSecret: 32,
    hkdfInfo: "globe-pqc-ml-kem1024:v1",
  },
  {
    id: "ml-kem768-p256",
    label: "ML-KEM-768 + P-256",
    publicKey: 1249,
    secretKey: 32,
    cipherText: 1153,
    sharedSecret: 32,
    hkdfInfo: "globe-pqc-ml-kem768-p256:v1",
  },
  {
    id: "ml-kem1024-p384",
    label: "ML-KEM-1024 + P-384",
    publicKey: 1665,
    secretKey: 32,
    cipherText: 1665,
    sharedSecret: 32,
    hkdfInfo: "globe-pqc-ml-kem1024-p384:v1",
  },
] as const;

export type PqcKemId = (typeof PQC_KEM_SUITES)[number]["id"];

const KEMS: Record<PqcKemId, KemLike> = {
  "ml-kem768-x25519": ml_kem768_x25519,
  "ml-kem512": ml_kem512,
  "ml-kem768": ml_kem768,
  "ml-kem1024": ml_kem1024,
  "ml-kem768-p256": ml_kem768_p256,
  "ml-kem1024-p384": ml_kem1024_p384,
};

export type PqcLocalPublic = {
  id: string;
  suite: PqcKemId;
  publicKeyB64: string;
  createdAt: string;
};

export type PqcAgreement = {
  suite: PqcKemId;
  cipherTextB64?: string;
  sharedSecretSha256Hex: string;
  /** Non-extractable AES-GCM-256 key. Not returned to the page as bytes. */
  sessionKey: CryptoKey;
};

type StoredSecret = { suite: PqcKemId; secret: Uint8Array };

const secrets = new Map<string, StoredSecret>();

export function isPqcKemId(value: string): value is PqcKemId {
  return PQC_KEM_SUITES.some((suite) => suite.id === value);
}

export function pqcKemSuite(id: PqcKemId): (typeof PQC_KEM_SUITES)[number] {
  const suite = PQC_KEM_SUITES.find((item) => item.id === id);
  if (!suite) throw new Error("Unknown key-agreement suite.");
  return suite;
}

function requireSubtle(): SubtleCrypto {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is required for the PQC session key.");
  }
  return crypto.subtle;
}

function wipe(bytes: Uint8Array | undefined): void {
  if (bytes) bytes.fill(0);
}

function bytesToB64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s);
}

function b64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/\s+/g, "");
  if (!clean) throw new Error("Expected base64 bytes.");
  let raw: string;
  try {
    raw = atob(clean);
  } catch {
    throw new Error("That text is not valid base64.");
  }
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function bufferToHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function assertSuiteLengths(id: PqcKemId): (typeof PQC_KEM_SUITES)[number] {
  const expected = pqcKemSuite(id);
  const lens = KEMS[id].lengths;
  if (
    lens.publicKey !== expected.publicKey ||
    lens.secretKey !== expected.secretKey ||
    lens.cipherText !== expected.cipherText ||
    lens.msg !== expected.sharedSecret
  ) {
    throw new Error(`Unexpected ${expected.label} lengths.`);
  }
  return expected;
}

async function sessionFromShared(
  shared: Uint8Array,
  hkdfInfo: string,
): Promise<{ sharedSecretSha256Hex: string; sessionKey: CryptoKey }> {
  const subtle = requireSubtle();
  const copy = new Uint8Array(shared);
  try {
    const digest = await subtle.digest("SHA-256", copy);
    const baseKey = await subtle.importKey("raw", copy, "HKDF", false, ["deriveKey"]);
    const sessionKey = await subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(0),
        info: new TextEncoder().encode(hkdfInfo),
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    return { sharedSecretSha256Hex: bufferToHex(digest), sessionKey };
  } finally {
    wipe(copy);
  }
}

function assertKemAgrees(id: PqcKemId): void {
  const expected = assertSuiteLengths(id);
  const kem = KEMS[id];
  const alice = kem.keygen();
  const bob = kem.keygen();
  const enc = kem.encapsulate(bob.publicKey);
  const dec = kem.decapsulate(enc.cipherText, bob.secretKey);
  const flipped = new Uint8Array(enc.cipherText);
  flipped[flipped.length - 1] ^= 0x01;
  let tampered: Uint8Array | undefined;
  let tamperRejected = false;
  try {
    if (
      alice.publicKey.length !== expected.publicKey ||
      bob.secretKey.length !== expected.secretKey ||
      enc.cipherText.length !== expected.cipherText ||
      enc.sharedSecret.length !== expected.sharedSecret ||
      dec.length !== expected.sharedSecret ||
      !equalBytes(enc.sharedSecret, dec)
    ) {
      throw new Error(`${expected.label} self-test failed: shared secrets do not match`);
    }
    try {
      tampered = kem.decapsulate(flipped, bob.secretKey);
      tamperRejected = !equalBytes(enc.sharedSecret, tampered);
    } catch {
      tamperRejected = true;
    }
    if (!tamperRejected) {
      throw new Error(
        `${expected.label} self-test failed: tampered ciphertext matched the shared secret`,
      );
    }
  } finally {
    wipe(alice.secretKey);
    wipe(alice.publicKey);
    wipe(bob.secretKey);
    wipe(bob.publicKey);
    wipe(enc.cipherText);
    wipe(enc.sharedSecret);
    wipe(dec);
    wipe(flipped);
    wipe(tampered);
  }
}

/** Ephemeral key pair for one lab suite. The secret stays in memory under `id`. */
export function generatePqcKeyPair(suite: PqcKemId = PQC_SUITE_ID): PqcLocalPublic {
  const expected = assertSuiteLengths(suite);
  const { secretKey, publicKey } = KEMS[suite].keygen();
  if (publicKey.length !== expected.publicKey || secretKey.length !== expected.secretKey) {
    wipe(secretKey);
    wipe(publicKey);
    throw new Error(`Could not generate a ${expected.label} key.`);
  }
  const id = crypto.randomUUID();
  secrets.set(id, { suite, secret: secretKey });
  const publicKeyB64 = bytesToB64(publicKey);
  wipe(publicKey);
  return {
    id,
    suite,
    publicKeyB64,
    createdAt: new Date().toISOString(),
  };
}

export function clearPqcSecret(id: string): void {
  const stored = secrets.get(id);
  if (!stored) return;
  wipe(stored.secret);
  secrets.delete(id);
}

/** Initiator: encapsulate to a peer public key for the selected suite. */
export async function encapsulateToPeer(
  peerPublicKeyB64: string,
  suite: PqcKemId = PQC_SUITE_ID,
): Promise<PqcAgreement> {
  const expected = assertSuiteLengths(suite);
  const peer = b64ToBytes(peerPublicKeyB64);
  if (peer.length !== expected.publicKey) {
    wipe(peer);
    throw new Error(
      `Peer public key must be ${expected.publicKey} bytes for ${expected.label}.`,
    );
  }
  const enc = KEMS[suite].encapsulate(peer);
  wipe(peer);
  const cipherTextB64 = bytesToB64(enc.cipherText);
  try {
    const session = await sessionFromShared(enc.sharedSecret, expected.hkdfInfo);
    return {
      suite,
      cipherTextB64,
      sharedSecretSha256Hex: session.sharedSecretSha256Hex,
      sessionKey: session.sessionKey,
    };
  } finally {
    wipe(enc.cipherText);
    wipe(enc.sharedSecret);
  }
}

/** MAC over a server ciphertext. The shared secret is wiped and is not returned. */
export async function kemLoginProof(
  id: string,
  ciphertextB64: string,
  message: string,
): Promise<string> {
  const stored = secrets.get(id);
  if (!stored) throw new Error("Generate a local key first.");
  return kemLoginProofFromSecret(stored.suite, stored.secret, ciphertextB64, message);
}

export async function kemLoginProofFromSecret(
  suite: PqcKemId,
  secret: Uint8Array,
  ciphertextB64: string,
  message: string,
): Promise<string> {
  const expected = assertSuiteLengths(suite);
  const cipherText = b64ToBytes(ciphertextB64);
  if (cipherText.length !== expected.cipherText) {
    wipe(cipherText);
    throw new Error("That sign-in challenge does not match this suite.");
  }
  const shared = KEMS[suite].decapsulate(cipherText, secret);
  wipe(cipherText);
  try {
    const macKey = await macKeyFromShared(shared, "kem", suite);
    try {
      return bytesToB64(await hmacLogin(macKey, message));
    } finally {
      macKey.fill(0);
    }
  } finally {
    wipe(shared);
  }
}

export function copyPqcSecret(id: string): Uint8Array | null {
  const stored = secrets.get(id);
  if (!stored) return null;
  return new Uint8Array(stored.secret);
}

/** Responder: recover the session from a ciphertext and the local secret. */
export async function decapsulateWithLocal(
  id: string,
  cipherTextB64: string,
): Promise<PqcAgreement> {
  const stored = secrets.get(id);
  if (!stored) {
    throw new Error("Generate a local key first. Its secret stays in this page's memory only.");
  }
  const expected = assertSuiteLengths(stored.suite);
  const cipherText = b64ToBytes(cipherTextB64);
  if (cipherText.length !== expected.cipherText) {
    wipe(cipherText);
    throw new Error(
      `Ciphertext must be ${expected.cipherText} bytes for ${expected.label}.`,
    );
  }
  const shared = KEMS[stored.suite].decapsulate(cipherText, stored.secret);
  wipe(cipherText);
  try {
    const session = await sessionFromShared(shared, expected.hkdfInfo);
    return {
      suite: stored.suite,
      sharedSecretSha256Hex: session.sharedSecretSha256Hex,
      sessionKey: session.sessionKey,
    };
  } finally {
    wipe(shared);
  }
}

/**
 * Every lab suite agrees with itself, a flipped ciphertext does not, and
 * X-Wing still returns the original sizes plus one SHA-256 fingerprint.
 * Does not leave secrets in the page map and does not return raw key material.
 */
export async function pqcSelfTest(): Promise<{
  ok: true;
  suite: typeof PQC_SUITE_ID;
  publicKeyBytes: number;
  secretKeyBytes: number;
  cipherTextBytes: number;
  sharedSecretBytes: number;
  sharedSecretSha256Hex: string;
  kemSuites: number;
}> {
  for (const suite of PQC_KEM_SUITES) {
    if (suite.id === PQC_SUITE_ID) continue;
    assertKemAgrees(suite.id);
  }
  assertSuiteLengths(PQC_SUITE_ID);
  const alice = ml_kem768_x25519.keygen();
  const bob = ml_kem768_x25519.keygen();
  const enc = ml_kem768_x25519.encapsulate(bob.publicKey);
  const dec = ml_kem768_x25519.decapsulate(enc.cipherText, bob.secretKey);
  const flipped = new Uint8Array(enc.cipherText);
  flipped[flipped.length - 1] ^= 0x01;
  let tampered: Uint8Array | undefined;
  let tamperRejected = false;
  try {
    if (
      enc.sharedSecret.length !== PQC_LENGTHS.sharedSecret ||
      dec.length !== PQC_LENGTHS.sharedSecret ||
      !equalBytes(enc.sharedSecret, dec)
    ) {
      throw new Error("X-Wing self-test failed: shared secrets do not match");
    }
    try {
      tampered = ml_kem768_x25519.decapsulate(flipped, bob.secretKey);
      tamperRejected = !equalBytes(enc.sharedSecret, tampered);
    } catch {
      tamperRejected = true;
    }
    if (!tamperRejected) {
      throw new Error(
        "X-Wing self-test failed: tampered ciphertext matched the shared secret",
      );
    }
    const session = await sessionFromShared(enc.sharedSecret, PQC_HKDF_INFO);
    if (!/^[0-9a-f]{64}$/.test(session.sharedSecretSha256Hex)) {
      throw new Error("X-Wing self-test failed: fingerprint was not 32 bytes");
    }
    if (
      bob.publicKey.length !== PQC_LENGTHS.publicKey ||
      bob.secretKey.length !== PQC_LENGTHS.secretKey ||
      enc.cipherText.length !== PQC_LENGTHS.cipherText
    ) {
      throw new Error("X-Wing self-test failed: wire sizes changed");
    }
    return {
      ok: true,
      suite: PQC_SUITE_ID,
      publicKeyBytes: bob.publicKey.length,
      secretKeyBytes: bob.secretKey.length,
      cipherTextBytes: enc.cipherText.length,
      sharedSecretBytes: enc.sharedSecret.length,
      sharedSecretSha256Hex: session.sharedSecretSha256Hex,
      kemSuites: PQC_KEM_SUITES.length,
    };
  } finally {
    wipe(alice.secretKey);
    wipe(alice.publicKey);
    wipe(bob.secretKey);
    wipe(bob.publicKey);
    wipe(enc.cipherText);
    wipe(enc.sharedSecret);
    wipe(dec);
    wipe(flipped);
    wipe(tampered);
  }
}
