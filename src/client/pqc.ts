/**
 * Experimental hybrid post-quantum key agreement for the browser lab.
 *
 * Suite: X-Wing, ML-KEM-768 (FIPS 203) + X25519, from `@noble/post-quantum`.
 * Pure JavaScript, no WASM. That is a better fit here than OpenPGP.js PQC
 * (large) or a liboqs WASM build (Worker and browser hostile). Built-in
 * WebCrypto ML-KEM is still too uneven to rely on.
 *
 * This is not an OpenPGP identity key. Secret keys stay in this module's
 * memory map for the page lifetime. Callers receive a SHA-256 fingerprint
 * and a non-extractable AES-GCM session key, never the raw shared secret.
 */

import { ml_kem768_x25519 } from "@noble/post-quantum/hybrid.js";
import { equalBytes } from "@noble/post-quantum/utils.js";

export const PQC_SUITE_ID = "ml-kem768-x25519" as const;
export const PQC_SUITE_LABEL = "X-Wing (ML-KEM-768 + X25519)";
/** HKDF info label. Both peers must use the same string. */
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

export type PqcLocalPublic = {
  id: string;
  suite: typeof PQC_SUITE_ID;
  publicKeyB64: string;
  createdAt: string;
};

export type PqcAgreement = {
  suite: typeof PQC_SUITE_ID;
  cipherTextB64?: string;
  sharedSecretSha256Hex: string;
  /** Non-extractable AES-GCM-256 key. Not returned to the page as bytes. */
  sessionKey: CryptoKey;
};

const secrets = new Map<string, Uint8Array>();

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

function assertSuiteLengths(): void {
  const lens = ml_kem768_x25519.lengths;
  if (
    lens.publicKey !== PQC_LENGTHS.publicKey ||
    lens.secretKey !== PQC_LENGTHS.secretKey ||
    lens.cipherText !== PQC_LENGTHS.cipherText ||
    lens.msg !== PQC_LENGTHS.sharedSecret
  ) {
    throw new Error(
      `Unexpected X-Wing lengths public=${String(lens.publicKey)} secret=${String(lens.secretKey)} ciphertext=${String(lens.cipherText)} shared=${String(lens.msg)}`,
    );
  }
}

async function sessionFromShared(shared: Uint8Array): Promise<{
  sharedSecretSha256Hex: string;
  sessionKey: CryptoKey;
}> {
  const subtle = requireSubtle();
  const copy = new Uint8Array(shared);
  try {
    const digest = await subtle.digest("SHA-256", copy);
    const baseKey = await subtle.importKey("raw", copy, "HKDF", false, [
      "deriveKey",
    ]);
    const sessionKey = await subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(0),
        info: new TextEncoder().encode(PQC_HKDF_INFO),
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    return {
      sharedSecretSha256Hex: bufferToHex(digest),
      sessionKey,
    };
  } finally {
    wipe(copy);
  }
}

/** Ephemeral X-Wing key pair. The secret stays in memory under `id`. */
export function generatePqcKeyPair(): PqcLocalPublic {
  assertSuiteLengths();
  const { secretKey, publicKey } = ml_kem768_x25519.keygen();
  const id = crypto.randomUUID();
  secrets.set(id, secretKey);
  const publicKeyB64 = bytesToB64(publicKey);
  wipe(publicKey);
  return {
    id,
    suite: PQC_SUITE_ID,
    publicKeyB64,
    createdAt: new Date().toISOString(),
  };
}

export function clearPqcSecret(id: string): void {
  const secret = secrets.get(id);
  if (!secret) return;
  wipe(secret);
  secrets.delete(id);
}

/** Initiator: encapsulate to a peer X-Wing public key. */
export async function encapsulateToPeer(
  peerPublicKeyB64: string,
): Promise<PqcAgreement> {
  assertSuiteLengths();
  const peer = b64ToBytes(peerPublicKeyB64);
  if (peer.length !== PQC_LENGTHS.publicKey) {
    wipe(peer);
    throw new Error(
      `Peer public key must be ${PQC_LENGTHS.publicKey} bytes (X-Wing public key, base64).`,
    );
  }
  const enc = ml_kem768_x25519.encapsulate(peer);
  wipe(peer);
  const cipherTextB64 = bytesToB64(enc.cipherText);
  try {
    const session = await sessionFromShared(enc.sharedSecret);
    return {
      suite: PQC_SUITE_ID,
      cipherTextB64,
      sharedSecretSha256Hex: session.sharedSecretSha256Hex,
      sessionKey: session.sessionKey,
    };
  } finally {
    wipe(enc.cipherText);
    wipe(enc.sharedSecret);
  }
}

/** Responder: recover the session from a ciphertext and the local secret. */
export async function decapsulateWithLocal(
  id: string,
  cipherTextB64: string,
): Promise<PqcAgreement> {
  assertSuiteLengths();
  const secret = secrets.get(id);
  if (!secret) {
    throw new Error(
      "Generate a local X-Wing key first. Its secret stays in this page's memory only.",
    );
  }
  const cipherText = b64ToBytes(cipherTextB64);
  if (cipherText.length !== PQC_LENGTHS.cipherText) {
    wipe(cipherText);
    throw new Error(
      `Ciphertext must be ${PQC_LENGTHS.cipherText} bytes (X-Wing ciphertext, base64).`,
    );
  }
  const shared = ml_kem768_x25519.decapsulate(cipherText, secret);
  wipe(cipherText);
  try {
    const session = await sessionFromShared(shared);
    return {
      suite: PQC_SUITE_ID,
      sharedSecretSha256Hex: session.sharedSecretSha256Hex,
      sessionKey: session.sessionKey,
    };
  } finally {
    wipe(shared);
  }
}

/**
 * Two parties agree, a flipped ciphertext does not, and HKDF yields a fingerprint.
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
}> {
  assertSuiteLengths();
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
    const session = await sessionFromShared(enc.sharedSecret);
    if (!/^[0-9a-f]{64}$/.test(session.sharedSecretSha256Hex)) {
      throw new Error("X-Wing self-test failed: fingerprint was not 32 bytes");
    }
    return {
      ok: true,
      suite: PQC_SUITE_ID,
      publicKeyBytes: bob.publicKey.length,
      secretKeyBytes: bob.secretKey.length,
      cipherTextBytes: enc.cipherText.length,
      sharedSecretBytes: enc.sharedSecret.length,
      sharedSecretSha256Hex: session.sharedSecretSha256Hex,
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
