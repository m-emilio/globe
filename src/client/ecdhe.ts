/**
 * Experimental ECDHE (Elliptic-Curve Diffie–Hellman Ephemeral) helpers.
 *
 * - Ephemeral WebCrypto key agreement only — NOT OpenPGP identity keys.
 * - Private keys are extractable so the lab can show PKCS#8 and JWK.
 *   They are not uploaded and they are not OpenPGP login keys.
 * - Public keys export as JWK + SPKI (base64) for peer exchange.
 * - Shared secret is shown only as a SHA-256 fingerprint by default.
 *
 * Browser support: ECDH P-256/P-384/P-521 widely; X25519 is newer (Chrome/Firefox recent).
 */

import { peerPublicMaterial, sanitizeKeyMaterial, KEY_MATERIAL_MAX_CHARS } from "./keyMaterial";

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
  /** Extractable ephemeral private key. Not an OpenPGP identity key. */
  privateKey: CryptoKey;
  /** PKCS#8, base64 (not URL-safe). */
  privateKeyPkcs8B64: string;
  /** PKCS#8 PEM, so it can be copied into other tools. */
  privateKeyPkcs8Pem: string;
  /** Private JWK, including `d`. */
  privateKeyJwk: JsonWebKey;
  /** Raw private scalar, base64. Present when this browser can export it (X25519). */
  privateKeyRawB64?: string;
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

function toPkcs8Pem(pkcs8B64: string): string {
  const lines = pkcs8B64.match(/.{1,64}/g) ?? [pkcs8B64];
  return `-----BEGIN PRIVATE KEY-----\n${lines.join("\n")}\n-----END PRIVATE KEY-----`;
}

/** ASCII-armored PKCS#8 for a local `.asc` download. Not an OpenPGP login key. */
export function ecdhePrivateKeyAsc(pem: string): string {
  const trimmed = pem.trim();
  if (
    !trimmed.startsWith("-----BEGIN PRIVATE KEY-----") ||
    !trimmed.endsWith("-----END PRIVATE KEY-----")
  ) {
    throw new Error("ECDHE .asc export needs a PKCS#8 private key.");
  }
  return `${trimmed}\n`;
}

export function ecdhePrivateKeyAscFilename(curve: EcdheCurveId): string {
  return `globe-ecdhe-${curve}-private.asc`;
}

function publishEcdheExport(detail: {
  curve: EcdheCurveId;
  privateKeyPkcs8Pem: string;
  privateKeyJwk: JsonWebKey;
  privateKeyRawB64?: string;
}): void {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent("globe-ecdhe-export", { detail }));
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
 * The private key is extractable (PKCS#8, JWK, and raw when the browser allows it).
 * Pass `{ publish: false }` for tests so they do not replace the export panel.
 */
export async function generateEcdheKeyPair(
  curve: EcdheCurveId = "P-256",
  options?: { publish?: boolean },
): Promise<EcdheEphemeralPair> {
  const subtle = requireSubtle();
  let keyPair: CryptoKeyPair;
  try {
    keyPair = (await subtle.generateKey(generateAlgorithm(curve), true, [
      "deriveBits",
      "deriveKey",
    ])) as CryptoKeyPair;
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    throw new Error(
      `ECDHE generate failed for ${curve}: ${msg}. Try P-256 if this curve is unsupported.`,
    );
  }

  if (!keyPair.privateKey.extractable) {
    throw new Error(`ECDHE private key for ${curve} was not extractable.`);
  }

  const publicKeyJwk = (await subtle.exportKey(
    "jwk",
    keyPair.publicKey,
  )) as JsonWebKey;
  const spki = await subtle.exportKey("spki", keyPair.publicKey);
  const privateKeyJwk = (await subtle.exportKey(
    "jwk",
    keyPair.privateKey,
  )) as JsonWebKey;
  const pkcs8 = await subtle.exportKey("pkcs8", keyPair.privateKey);
  const privateKeyPkcs8B64 = bytesToB64(pkcs8);
  let privateKeyRawB64: string | undefined;
  try {
    const raw = await subtle.exportKey("raw", keyPair.privateKey);
    privateKeyRawB64 = bytesToB64(raw);
  } catch {
    privateKeyRawB64 = undefined;
  }

  const pair: EcdheEphemeralPair = {
    curve,
    privateKey: keyPair.privateKey,
    privateKeyPkcs8B64,
    privateKeyPkcs8Pem: toPkcs8Pem(privateKeyPkcs8B64),
    privateKeyJwk,
    privateKeyRawB64,
    publicKey: keyPair.publicKey,
    publicKeyJwk,
    publicKeySpkiB64: bytesToB64(spki),
    createdAt: new Date().toISOString(),
  };
  if (options?.publish !== false) {
    publishEcdheExport({
      curve,
      privateKeyPkcs8Pem: pair.privateKeyPkcs8Pem,
      privateKeyJwk,
      privateKeyRawB64,
    });
  }
  return pair;
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
 * Import an extractable ephemeral private key from PKCS#8 PEM/base64 or a private JWK (`d`).
 * The imported key is used only to derive. It is not an OpenPGP login key.
 */
export async function importEcdhePrivateKey(
  curve: EcdheCurveId,
  input: string,
  options?: { extractable?: boolean },
): Promise<CryptoKey> {
  const subtle = requireSubtle();
  const trimmed = input.trim();
  if (!trimmed) {
    throw new Error(
      "Paste a PKCS#8 private key or a private JWK (it must include d).",
    );
  }

  const algorithm = generateAlgorithm(curve);
  const usages: KeyUsage[] = ["deriveBits", "deriveKey"];
  const extractable = options?.extractable === true;

  if (trimmed.startsWith("{")) {
    let parsed: JsonWebKey;
    try {
      parsed = JSON.parse(trimmed) as JsonWebKey;
    } catch {
      throw new Error("Private key looks like JSON but is not a valid JWK.");
    }
    if (!parsed.d) {
      throw new Error(
        "Private JWK is missing d. Paste a private JWK, not the public key.",
      );
    }
    if (parsed.crv && parsed.crv !== curve) {
      throw new Error(
        `Private JWK curve is ${parsed.crv}. This lab selected ${curve}.`,
      );
    }
    const jwk: JsonWebKey = {
      kty: parsed.kty,
      crv: parsed.crv,
      x: parsed.x,
      y: parsed.y,
      d: parsed.d,
    };
    try {
      return await subtle.importKey("jwk", jwk, algorithm, extractable, usages);
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      throw new Error(`Could not import private JWK for ${curve}: ${msg}`);
    }
  }

  const body = trimmed
    .replace(/-----BEGIN [A-Z0-9 ]+-----/gi, "")
    .replace(/-----END [A-Z0-9 ]+-----/gi, "")
    .replace(/\s+/g, "");
  if (!body) {
    throw new Error("PKCS#8 private key was empty.");
  }
  try {
    const raw = b64ToBytes(body);
    const copy = new Uint8Array(raw.byteLength);
    copy.set(raw);
    return await subtle.importKey(
      "pkcs8",
      copy.buffer,
      algorithm,
      extractable,
      usages,
    );
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Could not import PKCS#8 private key for ${curve}: ${msg}. Expect PEM or base64 PKCS#8.`,
    );
  }
}

/**
 * Derive from copied PKCS#8 or a private JWK plus the peer public key.
 * Returns the SHA-256 fingerprint and a non-extractable AES-GCM session key.
 */
export async function deriveEcdheFromPrivateMaterial(
  curve: EcdheCurveId,
  privateMaterial: string,
  peerPublic: string,
): Promise<EcdheDeriveResult> {
  const privateKey = await importEcdhePrivateKey(curve, privateMaterial);
  const peer = await importEcdhePeerPublicKey(curve, peerPublic);
  return deriveEcdheSession(privateKey, peer, curve);
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

/** Self-test: in-memory, PKCS#8, and private JWK derives must match. */
export async function ecdheSelfTest(
  curve: EcdheCurveId = "P-256",
): Promise<{ ok: true; curve: EcdheCurveId; sharedSecretSha256Hex: string }> {
  const a = await generateEcdheKeyPair(curve, { publish: false });
  const b = await generateEcdheKeyPair(curve, { publish: false });
  const peerA = await importEcdhePeerPublicKey(curve, a.publicKeySpkiB64);
  const peerB = await importEcdhePeerPublicKey(curve, b.publicKeySpkiB64);
  const d1 = await deriveEcdheSession(a.privateKey, peerB, curve);
  const d2 = await deriveEcdheSession(b.privateKey, peerA, curve);
  if (d1.sharedSecretSha256Hex !== d2.sharedSecretSha256Hex) {
    throw new Error("ECDHE self-test failed: shared secrets do not match");
  }
  if (!a.privateKey.extractable || !a.privateKeyJwk.d || !a.privateKeyPkcs8Pem.includes("PRIVATE KEY")) {
    throw new Error("ECDHE self-test failed: private key was not extractable");
  }
  const fromPem = await deriveEcdheFromPrivateMaterial(
    curve,
    a.privateKeyPkcs8Pem,
    b.publicKeySpkiB64,
  );
  const fromJwk = await deriveEcdheFromPrivateMaterial(
    curve,
    JSON.stringify(a.privateKeyJwk),
    JSON.stringify(b.publicKeyJwk),
  );
  if (
    fromPem.sharedSecretSha256Hex !== d1.sharedSecretSha256Hex ||
    fromJwk.sharedSecretSha256Hex !== d1.sharedSecretSha256Hex
  ) {
    throw new Error("ECDHE self-test failed: imported private key did not match");
  }
  if (fromPem.sessionKey.extractable || fromJwk.sessionKey.extractable || d1.sessionKey.extractable) {
    throw new Error("ECDHE self-test failed: session key was extractable");
  }
  const asc = ecdhePrivateKeyAsc(a.privateKeyPkcs8Pem);
  if (
    !asc.startsWith("-----BEGIN PRIVATE KEY-----") ||
    !asc.endsWith("-----END PRIVATE KEY-----\n") ||
    asc.includes("PGP PRIVATE KEY")
  ) {
    throw new Error("ECDHE self-test failed: .asc armor was not PKCS#8");
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

export type EcdheLoadedPrivate = {
  curve: EcdheCurveId;
  pem: string;
  privateJwk: JsonWebKey;
  publicJwk: JsonWebKey;
  publicSpkiB64: string;
};

const CURVE_TRY_ORDER: EcdheCurveId[] = ["X25519", "P-256", "P-384", "P-521"];

/** Load a sanitized PKCS#8 or private JWK and its public half. */
export async function loadEcdhePrivateMaterial(
  material: string,
  preferred?: EcdheCurveId,
): Promise<EcdheLoadedPrivate> {
  const order = preferred
    ? [preferred, ...CURVE_TRY_ORDER.filter((curve) => curve !== preferred)]
    : CURVE_TRY_ORDER;
  let last = "Could not read that ECDHE private key.";
  for (const curve of order) {
    try {
      const subtle = requireSubtle();
      const key = await importEcdhePrivateKey(curve, material, { extractable: true });
      const privateJwk = (await subtle.exportKey("jwk", key)) as JsonWebKey;
      if (!privateJwk.d) throw new Error("Imported key had no private scalar.");
      const pkcs8 = await subtle.exportKey("pkcs8", key);
      const publicJwk: JsonWebKey = {
        kty: privateJwk.kty,
        crv: privateJwk.crv,
        x: privateJwk.x,
        y: privateJwk.y,
      };
      const pub = await subtle.importKey(
        "jwk",
        publicJwk,
        importPublicAlgorithm(curve),
        true,
        [],
      );
      const spki = await subtle.exportKey("spki", pub);
      return {
        curve,
        pem: toPkcs8Pem(bytesToB64(pkcs8)),
        privateJwk,
        publicJwk,
        publicSpkiB64: bytesToB64(spki),
      };
    } catch (error) {
      last = error instanceof Error ? error.message : last;
    }
  }
  throw new Error(last);
}

export type EcdheSecurityCheck = { id: string; label: string; pass: boolean };

/** Local derivation and field checks. Results carry no key material. */
export async function runEcdheSecurityChecks(
  curve: EcdheCurveId = "X25519",
): Promise<EcdheSecurityCheck[]> {
  const checks: EcdheSecurityCheck[] = [];
  const push = (id: string, label: string, pass: boolean) => {
    checks.push({ id, label, pass });
  };
  try {
    const result = await ecdheSelfTest(curve);
    push(
      "agreement",
      "PKCS#8 and JWK agree, and the session key stays non-extractable",
      result.ok && result.sharedSecretSha256Hex.length === 64,
    );
  } catch {
    push(
      "agreement",
      "PKCS#8 and JWK agree, and the session key stays non-extractable",
      false,
    );
  }

  try {
    const pair = await generateEcdheKeyPair(curve, { publish: false });
    let rejectedPublic = false;
    try {
      await importEcdhePrivateKey(curve, JSON.stringify(pair.publicKeyJwk));
    } catch (error) {
      rejectedPublic =
        error instanceof Error && error.message.startsWith("Private JWK is missing d");
    }
    push("reject-public-as-private", "A public key is rejected as a private key", rejectedPublic);

    let rejectedEmpty = false;
    try {
      peerPublicMaterial("  ");
    } catch (error) {
      rejectedEmpty =
        error instanceof Error && error.message.startsWith("Paste the peer public key");
    }
    push("reject-empty-peer", "An empty peer field is rejected", rejectedEmpty);

    let rejectedPrivatePeer = false;
    try {
      peerPublicMaterial(pair.privateKeyPkcs8Pem);
    } catch (error) {
      rejectedPrivatePeer =
        error instanceof Error && error.message === "Peer field must be a public key.";
    }
    push(
      "reject-private-peer",
      "A private key is rejected in the peer field",
      rejectedPrivatePeer,
    );

    const sanitized = sanitizeKeyMaterial(
      `<script>alert(1)</script>\n${pair.privateKeyPkcs8Pem}\n`,
    );
    push(
      "strip-html",
      "HTML around a private key is removed",
      sanitized.kind === "pkcs8" &&
        sanitized.pem.startsWith("-----BEGIN PRIVATE KEY-----") &&
        !sanitized.pem.includes("<"),
    );

    const cleaned = sanitizeKeyMaterial(`\uFEFF\0${pair.privateKeyPkcs8Pem}`);
    push(
      "strip-controls",
      "A byte-order mark and NUL bytes are removed",
      cleaned.kind === "pkcs8" &&
        cleaned.pem.startsWith("-----BEGIN PRIVATE KEY-----") &&
        !cleaned.pem.includes("\0"),
    );

    const mixed = sanitizeKeyMaterial(
      `${pair.privateKeyPkcs8Pem}\n-----BEGIN PGP PRIVATE KEY BLOCK-----\nAA==\n-----END PGP PRIVATE KEY BLOCK-----\n`,
    );
    push(
      "reject-mixed",
      "OpenPGP and PKCS#8 in one field are rejected",
      mixed.kind === "rejected",
    );

    const scriptUrl = sanitizeKeyMaterial("javascript:alert(1)");
    push(
      "reject-script-url",
      "A script URL in the key field is rejected",
      scriptUrl.kind === "rejected",
    );

    const asc = ecdhePrivateKeyAsc(pair.privateKeyPkcs8Pem);
    push(
      "asc-pkcs8",
      "The .asc file is PKCS#8, not an OpenPGP login key",
      asc.startsWith("-----BEGIN PRIVATE KEY-----") &&
        asc.endsWith("-----END PRIVATE KEY-----\n") &&
        !asc.includes("PGP PRIVATE KEY"),
    );

    const other = await generateEcdheKeyPair(curve, { publish: false });
    const agreed = await deriveEcdheFromPrivateMaterial(
      curve,
      pair.privateKeyPkcs8Pem,
      pair.publicKeySpkiB64,
    );
    const changed = await deriveEcdheFromPrivateMaterial(
      curve,
      pair.privateKeyPkcs8Pem,
      other.publicKeySpkiB64,
    );
    push(
      "peer-changes-secret",
      "A different peer public key changes the shared secret",
      agreed.sharedSecretSha256Hex.length === 64 &&
        agreed.sharedSecretSha256Hex !== changed.sharedSecretSha256Hex &&
        !agreed.sessionKey.extractable &&
        !changed.sessionKey.extractable,
    );
  } catch {
    const missing: Array<[string, string]> = [
      ["reject-public-as-private", "A public key is rejected as a private key"],
      ["reject-empty-peer", "An empty peer field is rejected"],
      ["reject-private-peer", "A private key is rejected in the peer field"],
      ["strip-html", "HTML around a private key is removed"],
      ["strip-controls", "A byte-order mark and NUL bytes are removed"],
      ["reject-mixed", "OpenPGP and PKCS#8 in one field are rejected"],
      ["reject-script-url", "A script URL in the key field is rejected"],
      ["asc-pkcs8", "The .asc file is PKCS#8, not an OpenPGP login key"],
      ["peer-changes-secret", "A different peer public key changes the shared secret"],
    ];
    for (let i = 0; i < missing.length; i++) {
      const item = missing[i]!;
      if (checks.some((row) => row.id === item[0])) continue;
      push(item[0], item[1], false);
    }
  }

  const oversized = sanitizeKeyMaterial("A".repeat(KEY_MATERIAL_MAX_CHARS + 1));
  push(
    "reject-oversize",
    "Oversized key material is rejected",
    oversized.kind === "rejected",
  );
  return checks;
}
