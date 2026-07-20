/**
 * Experimental ECDHE (Elliptic-Curve Diffie–Hellman Ephemeral) helpers.
 *
 * - Ephemeral WebCrypto key agreement only — NOT OpenPGP identity keys.
 * - Private keys stay non-extractable in memory (not uploaded, not IndexedDB).
 * - Public keys export as JWK + SPKI (base64) for peer exchange.
 * - Shared secret is shown only as a SHA-256 fingerprint by default.
 *
 * Browser support: ECDH P-256/P-384/P-521 widely; X25519 is newer (Chrome/Firefox recent).
 */

export type EcdheCurveId = "P-256" | "P-384" | "P-521" | "X25519";

export type EcdheCurveInfo = {
  id: EcdheCurveId;
  label: string;
  description: string;
  /** Approximate classical security bits */
  securityBits: number;
  experimental: boolean;
};

export const ECDHE_CURVES: EcdheCurveInfo[] = [
  {
    id: "P-256",
    label: "ECDHE P-256 (secp256r1)",
    description: "NIST P-256 ECDH — wide WebCrypto support.",
    securityBits: 128,
    experimental: true,
  },
  {
    id: "P-384",
    label: "ECDHE P-384",
    description: "NIST P-384 ECDH — CNSA classical key-agreement curve.",
    securityBits: 192,
    experimental: true,
  },
  {
    id: "P-521",
    label: "ECDHE P-521",
    description: "NIST P-521 ECDH — highest NIST prime curve here.",
    securityBits: 256,
    experimental: true,
  },
  {
    id: "X25519",
    label: "X25519 (ECDH)",
    description:
      "Modern Montgomery ECDH. Requires a recent browser with WebCrypto X25519.",
    securityBits: 128,
    experimental: true,
  },
];

export type EcdheEphemeralPair = {
  curve: EcdheCurveId;
  /** Non-extractable private key — memory only */
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicKeyJwk: JsonWebKey;
  /** SPKI SubjectPublicKeyInfo, base64 (not URL-safe) */
  publicKeySpkiB64: string;
  createdAt: string;
};

export type EcdheDeriveResult = {
  curve: EcdheCurveId;
  /** Raw ECDH shared bits length */
  sharedBitsLength: number;
  /** SHA-256 of shared secret (safe to display / compare) */
  sharedSecretSha256Hex: string;
  /** AES-GCM-256 session key derived via HKDF-SHA-256 (non-extractable) */
  sessionKey: CryptoKey;
  derivedAt: string;
};

function requireSubtle(): SubtleCrypto {
  if (!globalThis.crypto?.subtle) {
    throw new Error(
      "WebCrypto is required for ECDHE. Use a modern browser on HTTPS.",
    );
  }
  return crypto.subtle;
}

function bytesToB64(buf: ArrayBuffer): string {
  const u8 = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]!);
  return btoa(s);
}

function b64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/\s+/g, "");
  const s = atob(clean);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function bufferToHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function isX25519(curve: EcdheCurveId): boolean {
  return curve === "X25519";
}

function generateAlgorithm(
  curve: EcdheCurveId,
): EcKeyGenParams | Algorithm {
  if (isX25519(curve)) {
    // Chromium/Firefox: { name: "X25519" }
    return { name: "X25519" };
  }
  return { name: "ECDH", namedCurve: curve };
}

function importPublicAlgorithm(
  curve: EcdheCurveId,
): EcKeyImportParams | Algorithm {
  if (isX25519(curve)) {
    return { name: "X25519" };
  }
  return { name: "ECDH", namedCurve: curve };
}

/** Probe whether this browser can generate the given ECDHE curve. */
export async function isEcdheCurveSupported(
  curve: EcdheCurveId,
): Promise<boolean> {
  try {
    const subtle = requireSubtle();
    const pair = await subtle.generateKey(generateAlgorithm(curve), false, [
      "deriveBits",
      "deriveKey",
    ]);
    // Touch the keys so TS keeps them; discard immediately.
    void pair;
    return true;
  } catch {
    return false;
  }
}

export async function listSupportedEcdheCurves(): Promise<EcdheCurveInfo[]> {
  const out: EcdheCurveInfo[] = [];
  for (const c of ECDHE_CURVES) {
    if (await isEcdheCurveSupported(c.id)) out.push(c);
  }
  return out;
}

/**
 * Generate an ephemeral ECDHE key pair.
 * Private key is non-extractable and must stay in process memory only.
 */
export async function generateEcdheKeyPair(
  curve: EcdheCurveId = "P-256",
): Promise<EcdheEphemeralPair> {
  const subtle = requireSubtle();
  let keyPair: CryptoKeyPair;
  try {
    keyPair = (await subtle.generateKey(generateAlgorithm(curve), false, [
      "deriveBits",
      "deriveKey",
    ])) as CryptoKeyPair;
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    throw new Error(
      `ECDHE generate failed for ${curve}: ${msg}. Try P-256 if this curve is unsupported.`,
    );
  }

  const publicKeyJwk = (await subtle.exportKey(
    "jwk",
    keyPair.publicKey,
  )) as JsonWebKey;
  const spki = await subtle.exportKey("spki", keyPair.publicKey);

  return {
    curve,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    publicKeyJwk,
    publicKeySpkiB64: bytesToB64(spki),
    createdAt: new Date().toISOString(),
  };
}

/**
 * Import a peer ECDHE public key from JWK JSON or SPKI base64.
 */
export async function importEcdhePeerPublicKey(
  curve: EcdheCurveId,
  input: string,
): Promise<CryptoKey> {
  const subtle = requireSubtle();
  const trimmed = input.trim();
  if (!trimmed) {
    throw new Error("Paste the peer public key (JWK JSON or SPKI base64).");
  }

  // JWK
  if (trimmed.startsWith("{")) {
    let jwk: JsonWebKey;
    try {
      jwk = JSON.parse(trimmed) as JsonWebKey;
    } catch {
      throw new Error("Peer public key looks like JSON but is not valid JWK.");
    }
    try {
      return await subtle.importKey(
        "jwk",
        jwk,
        importPublicAlgorithm(curve),
        false,
        [],
      );
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      throw new Error(`Could not import peer JWK for ${curve}: ${msg}`);
    }
  }

  // SPKI base64
  try {
    const raw = b64ToBytes(trimmed);
    const copy = new Uint8Array(raw.byteLength);
    copy.set(raw);
    return await subtle.importKey(
      "spki",
      copy.buffer,
      importPublicAlgorithm(curve),
      false,
      [],
    );
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Could not import peer SPKI for ${curve}: ${msg}. Expect base64 SPKI or JWK JSON.`,
    );
  }
}

/**
 * ECDHE derive: local ephemeral private × peer public → shared secret + HKDF session key.
 * Does not return raw shared bits to callers — only SHA-256 fingerprint + AES session key.
 */
export async function deriveEcdheSession(
  localPrivateKey: CryptoKey,
  peerPublicKey: CryptoKey,
  curve: EcdheCurveId,
  options?: {
    /** HKDF info / context string */
    info?: string;
    /** HKDF salt (defaults to empty) */
    salt?: Uint8Array;
  },
): Promise<EcdheDeriveResult> {
  const subtle = requireSubtle();

  // Bit length of shared secret depends on curve
  const bits =
    curve === "P-521" ? 528 : curve === "P-384" ? 384 : curve === "P-256" ? 256 : 256;

  let shared: ArrayBuffer;
  try {
    if (isX25519(curve)) {
      shared = await subtle.deriveBits(
        { name: "X25519", public: peerPublicKey },
        localPrivateKey,
        256,
      );
    } else {
      shared = await subtle.deriveBits(
        { name: "ECDH", public: peerPublicKey },
        localPrivateKey,
        bits,
      );
    }
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    throw new Error(
      `ECDHE deriveBits failed: ${msg}. Curves must match and peer key must be valid.`,
    );
  }

  const digest = await subtle.digest("SHA-256", shared);
  const sharedSecretSha256Hex = bufferToHex(digest);

  // HKDF-SHA-256 → AES-GCM-256 session key (non-extractable)
  const baseKey = await subtle.importKey("raw", shared, "HKDF", false, [
    "deriveKey",
  ]);
  const info = new TextEncoder().encode(
    options?.info || `globe-ecdhe-experimental:v1:${curve}`,
  );
  const salt =
    options?.salt && options.salt.byteLength > 0
      ? options.salt
      : new Uint8Array(0);

  let sessionKey: CryptoKey;
  try {
    sessionKey = await subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt,
        info,
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    throw new Error(`ECDHE HKDF session key failed: ${msg}`);
  }

  return {
    curve,
    sharedBitsLength: shared.byteLength * 8,
    sharedSecretSha256Hex,
    sessionKey,
    derivedAt: new Date().toISOString(),
  };
}

/** Self-test: two ephemeral parties should derive the same shared fingerprint. */
export async function ecdheSelfTest(
  curve: EcdheCurveId = "P-256",
): Promise<{ ok: true; curve: EcdheCurveId; sharedSecretSha256Hex: string }> {
  const a = await generateEcdheKeyPair(curve);
  const b = await generateEcdheKeyPair(curve);
  const peerA = await importEcdhePeerPublicKey(curve, a.publicKeySpkiB64);
  const peerB = await importEcdhePeerPublicKey(curve, b.publicKeySpkiB64);
  const d1 = await deriveEcdheSession(a.privateKey, peerB, curve);
  const d2 = await deriveEcdheSession(b.privateKey, peerA, curve);
  if (d1.sharedSecretSha256Hex !== d2.sharedSecretSha256Hex) {
    throw new Error("ECDHE self-test failed: shared secrets do not match");
  }
  return {
    ok: true,
    curve,
    sharedSecretSha256Hex: d1.sharedSecretSha256Hex,
  };
}

export function getEcdheCurve(id: EcdheCurveId): EcdheCurveInfo {
  return ECDHE_CURVES.find((c) => c.id === id) || ECDHE_CURVES[0]!;
}
