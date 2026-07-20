/**
 * Client-side OpenPGP helpers for Globe auth.
 *
 * Protocol:
 * - Generate keypair in the browser; store private key in **this device's** IndexedDB only
 * - At rest: AES-GCM wrapped with a **non-extractable** WebCrypto key (device-bound).
 *   Browsers do not expose a secret hardware serial; this is the secure equivalent.
 * - Register/login never upload the private key — only public key + challenge signatures
 * - Login = “use device key” (optional OpenPGP passphrase only if the key itself is encrypted)
 * - Session: **HttpOnly cookie only** (no session token in sessionStorage / JS)
 */

/**
 * Lazy-load OpenPGP (~380KB) only when crypto is actually used (auth/sign).
 * Keeps the initial globe shell fast without removing any security checks.
 */
type OpenPgpModule = typeof import("openpgp");
let openpgpModule: OpenPgpModule | null = null;
let openpgpLoadPromise: Promise<OpenPgpModule> | null = null;

/** Prefetch or load the OpenPGP library (safe to call early when opening Auth). */
export async function ensureOpenPgp(): Promise<OpenPgpModule> {
  if (openpgpModule) return openpgpModule;
  if (!openpgpLoadPromise) {
    openpgpLoadPromise = import("openpgp").then((mod) => {
      openpgpModule = mod;
      return mod;
    });
  }
  return openpgpLoadPromise;
}

/** Public fingerprint only (not secret). Prefer device vault over this. */
const LAST_FP_KEY = "globe_pgp_last_fp";
/** Legacy key — cleared on load; sessions use HttpOnly cookie only. */
const LEGACY_SESSION_TOKEN_KEY = "globe_session_token";
const IDB_NAME = "globe-device-keys";
/** v2: device-bound wrap key store + wrapped private keys */
const IDB_VERSION = 2;
const IDB_STORE = "keys";
const IDB_WRAP_STORE = "device_secrets";
const DEVICE_WRAP_KEY_ID = "aes-gcm-device-wrap-v1";
const WRAP_ALG = "AES-GCM-256-v1" as const;

export type GeneratedKeypair = {
  fingerprint: string;
  publicKeyArmored: string;
  privateKeyArmored: string;
  revocationCertificate: string;
  profileLabel: string;
};

/** Public-only material kept after generate (private key wiped from app memory). */
export type PublicIdentity = {
  fingerprint: string;
  publicKeyArmored: string;
};

/**
 * Key generation algorithm / size profiles (client-only).
 * Safety labels map roughly to NIST SP 800-57, BSI TR-02102, ENISA, ANSSI, CNSA guidance.
 * "canRegister" reflects this app's server floor (RSA ≥ 2048; no DSA/ElGamal).
 */
export type KeyGenProfileId =
  | "curve25519"
  | "curve448"
  | "ecc_p256"
  | "ecc_p384"
  | "ecc_p521"
  | "ecc_brainpool256"
  | "ecc_brainpool384"
  | "ecc_brainpool512"
  | "ecc_secp256k1"
  | "ecc_ed25519_legacy"
  | "rsa1024"
  | "rsa1536"
  | "rsa2048"
  | "rsa3072"
  | "rsa4096";

/** International / sector compliance-oriented safety tier for display. */
export type SafetyLevelId =
  | "insecure"
  | "legacy"
  | "acceptable"
  | "recommended"
  | "high"
  | "special";

export type ComplianceRefs = {
  /** NIST SP 800-57 / FIPS-oriented note */
  nist: string;
  /** BSI TR-02102 (Germany) */
  bsi: string;
  /** ENISA / EU crypto guidance */
  enisa: string;
  /** ANSSI (France) */
  anssi: string;
  /** NSA CNSA suite */
  cnsa: string;
};

export type KeyGenProfile = {
  id: KeyGenProfileId;
  label: string;
  description: string;
  family: "ecc" | "rsa" | "modern-ecc";
  /** Approximate classical security bits (order-of-magnitude). */
  securityBits: number;
  safety: SafetyLevelId;
  safetyLabel: string;
  compliance: ComplianceRefs;
  /** Whether this app will accept the public key at registration. */
  canRegister: boolean;
  registerNote?: string;
};

export const SAFETY_LEVEL_META: Record<
  SafetyLevelId,
  { short: string; color: string; rank: number }
> = {
  insecure: { short: "INSECURE", color: "#ff5c5c", rank: 0 },
  legacy: { short: "LEGACY", color: "#ffb020", rank: 1 },
  acceptable: { short: "ACCEPTABLE", color: "#e6d36a", rank: 2 },
  recommended: { short: "RECOMMENDED", color: "#3dffa8", rank: 3 },
  high: { short: "HIGH", color: "#7aa2ff", rank: 4 },
  special: { short: "SPECIAL-USE", color: "#c4bbff", rank: 2 },
};

export const KEY_GEN_PROFILES: KeyGenProfile[] = [
  {
    id: "curve25519",
    label: "Curve25519 / Ed25519",
    description: "Modern ECC (X25519 + Ed25519). Fast default for new identities.",
    family: "modern-ecc",
    securityBits: 128,
    safety: "recommended",
    safetyLabel: "Recommended — modern ECC (~128-bit)",
    compliance: {
      nist: "Aligns with ~128-bit classical strength (SP 800-57 comparable).",
      bsi: "BSI TR-02102 accepts Curve25519/Ed25519 for many use cases.",
      enisa: "ENISA lists Curve25519/Ed25519 among modern recommended curves.",
      anssi: "ANSSI allows X25519/Ed25519 in current recommendations.",
      cnsa: "Not CNSA classical suite (CNSA prefers NIST P-384); fine for civilian apps.",
    },
    canRegister: true,
  },
  {
    id: "curve448",
    label: "Curve448 / Ed448",
    description: "Higher-security modern ECC (~224-bit classical).",
    family: "modern-ecc",
    securityBits: 224,
    safety: "high",
    safetyLabel: "High — long-term modern ECC (~224-bit)",
    compliance: {
      nist: "Exceeds 128-bit floor; suitable for long-term confidentiality goals.",
      bsi: "Strong modern curve; preferred where higher margins are required.",
      enisa: "Higher security margin than Curve25519.",
      anssi: "Strong ECC choice for high assurance.",
      cnsa: "Not CNSA P-384 path; higher classical margin than P-256.",
    },
    canRegister: true,
  },
  {
    id: "ecc_ed25519_legacy",
    label: "Ed25519 (legacy OpenPGP)",
    description: "ed25519Legacy curve id for older OpenPGP interop.",
    family: "ecc",
    securityBits: 128,
    safety: "acceptable",
    safetyLabel: "Acceptable — legacy Ed25519 packet form",
    compliance: {
      nist: "~128-bit classical strength.",
      bsi: "Acceptable modern ECC strength; packet format is legacy-oriented.",
      enisa: "Same security class as Ed25519.",
      anssi: "Acceptable if implementations interoperate.",
      cnsa: "Not CNSA suite.",
    },
    canRegister: true,
  },
  {
    id: "ecc_p256",
    label: "NIST P-256 (secp256r1)",
    description: "ECDSA/ECDH on nistP256 — wide government/interop support.",
    family: "ecc",
    securityBits: 128,
    safety: "acceptable",
    safetyLabel: "Acceptable — NIST/FIPS common floor (~128-bit)",
    compliance: {
      nist: "NIST SP 800-57: 128-bit security (acceptable through at least 2030 for many uses).",
      bsi: "BSI still documents P-256; migration to stronger curves preferred long-term.",
      enisa: "Widely accepted; not the strongest long-term choice.",
      anssi: "ANSSI has tightened guidance; prefer P-384+ for new high-assurance systems.",
      cnsa: "CNSA 1.0 used P-256 historically; CNSA 2.0 moves away for new systems.",
    },
    canRegister: true,
  },
  {
    id: "ecc_p384",
    label: "NIST P-384",
    description: "ECDSA/ECDH on nistP384 — CNSA classical target curve.",
    family: "ecc",
    securityBits: 192,
    safety: "recommended",
    safetyLabel: "Recommended — NIST/CNSA classical (~192-bit)",
    compliance: {
      nist: "SP 800-57: ~192-bit security; strong government interop.",
      bsi: "Meets higher BSI ECC strength bands.",
      enisa: "Strong ECC choice for EU public-sector style requirements.",
      anssi: "Aligns with higher ANSSI ECC preferences.",
      cnsa: "CNSA classical ECC: P-384 for key agreement/signatures.",
    },
    canRegister: true,
  },
  {
    id: "ecc_p521",
    label: "NIST P-521",
    description: "ECDSA/ECDH on nistP521 — highest NIST prime curve here.",
    family: "ecc",
    securityBits: 256,
    safety: "high",
    safetyLabel: "High — max NIST P-curve (~256-bit)",
    compliance: {
      nist: "SP 800-57: ~256-bit classical security.",
      bsi: "Exceeds typical minimums; good for long-term secrets.",
      enisa: "High-margin ECC.",
      anssi: "High assurance ECC.",
      cnsa: "Stronger than P-384 classical target (heavier).",
    },
    canRegister: true,
  },
  {
    id: "ecc_brainpool256",
    label: "Brainpool P256r1",
    description: "BSI-originated Brainpool 256-bit curve.",
    family: "ecc",
    securityBits: 128,
    safety: "acceptable",
    safetyLabel: "Acceptable — BSI Brainpool (~128-bit)",
    compliance: {
      nist: "Not a NIST curve; classical strength ~128-bit.",
      bsi: "Brainpool family defined for BSI/German eID contexts.",
      enisa: "Recognized European curve family.",
      anssi: "Interop-dependent; prefer NIST/modern curves unless required.",
      cnsa: "Not CNSA.",
    },
    canRegister: true,
  },
  {
    id: "ecc_brainpool384",
    label: "Brainpool P384r1",
    description: "Brainpool 384-bit curve (BSI family).",
    family: "ecc",
    securityBits: 192,
    safety: "recommended",
    safetyLabel: "Recommended — BSI Brainpool (~192-bit)",
    compliance: {
      nist: "Comparable to ~192-bit classical strength.",
      bsi: "Strong Brainpool option in TR-02102 ecosystems.",
      enisa: "European high-strength ECC option.",
      anssi: "Acceptable high-strength non-NIST ECC where allowed.",
      cnsa: "Not CNSA.",
    },
    canRegister: true,
  },
  {
    id: "ecc_brainpool512",
    label: "Brainpool P512r1",
    description: "Brainpool 512-bit curve (BSI family).",
    family: "ecc",
    securityBits: 256,
    safety: "high",
    safetyLabel: "High — BSI Brainpool (~256-bit)",
    compliance: {
      nist: "High classical margin (~256-bit class).",
      bsi: "Top Brainpool strength in this list.",
      enisa: "High-margin European ECC.",
      anssi: "High assurance if Brainpool is mandated.",
      cnsa: "Not CNSA.",
    },
    canRegister: true,
  },
  {
    id: "ecc_secp256k1",
    label: "secp256k1",
    description: "Koblitz curve used in many blockchains — special-purpose.",
    family: "ecc",
    securityBits: 128,
    safety: "special",
    safetyLabel: "Special-use — not a government default",
    compliance: {
      nist: "Not a NIST-recommended curve for general federal use.",
      bsi: "Not a BSI general-purpose recommendation.",
      enisa: "Specialized; not preferred for general PKI.",
      anssi: "Not a general ANSSI recommendation.",
      cnsa: "Not CNSA.",
    },
    canRegister: true,
    registerNote: "Interop varies; prefer Curve25519/P-384 for general accounts.",
  },
  {
    id: "rsa1024",
    label: "RSA 1024",
    description: "Broken/withdrawn size — export/testing only.",
    family: "rsa",
    securityBits: 80,
    safety: "insecure",
    safetyLabel: "Insecure — withdrawn by NIST/BSI/ENISA",
    compliance: {
      nist: "SP 800-57: RSA-1024 deprecated/disallowed for new use.",
      bsi: "BSI: RSA-1024 not approved.",
      enisa: "ENISA: RSA-1024 considered broken for practical use.",
      anssi: "ANSSI: RSA-1024 forbidden for new systems.",
      cnsa: "Far below CNSA RSA-3072+ expectations.",
    },
    canRegister: false,
    registerNote: "Server rejects RSA < 2048. Export-only / lab use.",
  },
  {
    id: "rsa1536",
    label: "RSA 1536",
    description: "Legacy intermediate size — too small for new systems.",
    family: "rsa",
    securityBits: 96,
    safety: "legacy",
    safetyLabel: "Legacy — below modern floors",
    compliance: {
      nist: "Below current NIST recommended RSA sizes for new applications.",
      bsi: "Below BSI preferred RSA lengths for new keys.",
      enisa: "Not recommended for new deployments.",
      anssi: "Below ANSSI minimums for new systems.",
      cnsa: "Below CNSA.",
    },
    canRegister: false,
    registerNote: "Server rejects RSA < 2048. Export-only / migration testing.",
  },
  {
    id: "rsa2048",
    label: "RSA 2048",
    description: "Common minimum RSA size for interoperability.",
    family: "rsa",
    securityBits: 112,
    safety: "acceptable",
    safetyLabel: "Acceptable minimum — phase-out horizon",
    compliance: {
      nist: "SP 800-57: ~112-bit; often minimum until ~2030 depending on use.",
      bsi: "BSI still sees 2048 as a lower bound; prefer larger for long-term.",
      enisa: "Minimum class; migrate upward for long-lived keys.",
      anssi: "Often minimum; stronger sizes preferred for new high-assurance.",
      cnsa: "Below CNSA RSA-3072 classical requirement.",
    },
    canRegister: true,
  },
  {
    id: "rsa3072",
    label: "RSA 3072",
    description: "Strong RSA; matches many government classical targets.",
    family: "rsa",
    securityBits: 128,
    safety: "recommended",
    safetyLabel: "Recommended RSA — NIST/CNSA classical (~128-bit)",
    compliance: {
      nist: "SP 800-57: ~128-bit classical security.",
      bsi: "Comfortable RSA length for many BSI scenarios.",
      enisa: "Recommended RSA strength band for new systems.",
      anssi: "Aligns with stronger ANSSI RSA preferences.",
      cnsa: "CNSA classical RSA: 3072-bit modulus.",
    },
    canRegister: true,
  },
  {
    id: "rsa4096",
    label: "RSA 4096",
    description: "Large RSA — high margin, slower generate/sign.",
    family: "rsa",
    securityBits: 144,
    safety: "high",
    safetyLabel: "High RSA margin (slow)",
    compliance: {
      nist: "Above 128-bit classical RSA estimates; heavy performance cost.",
      bsi: "High RSA length for long-term or high-value keys.",
      enisa: "High margin; ECC often preferred for performance.",
      anssi: "Acceptable high RSA size.",
      cnsa: "Exceeds CNSA RSA-3072 size (slower).",
    },
    canRegister: true,
  },
];

export function getKeyGenProfile(id: KeyGenProfileId): KeyGenProfile {
  return (
    KEY_GEN_PROFILES.find((p) => p.id === id) ||
    KEY_GEN_PROFILES.find((p) => p.id === "curve25519")!
  );
}

/** Profiles grouped for UI optgroups by safety tier. */
export function keyGenProfilesBySafety(): {
  safety: SafetyLevelId;
  label: string;
  profiles: KeyGenProfile[];
}[] {
  const order: SafetyLevelId[] = [
    "recommended",
    "high",
    "acceptable",
    "special",
    "legacy",
    "insecure",
  ];
  return order
    .map((safety) => ({
      safety,
      label: SAFETY_LEVEL_META[safety].short,
      profiles: KEY_GEN_PROFILES.filter((p) => p.safety === safety),
    }))
    .filter((g) => g.profiles.length > 0);
}

export type SymmetricCipherId = "aes128" | "aes192" | "aes256";
export type S2kProtocolId = "iterated" | "argon2";
export type AeadModeId = "eax" | "ocb" | "gcm";

/** Passphrase wrapping options for private-key export (OpenPGP S2K + cipher). */
export type PrivateKeyExportEncryption = {
  passphrase: string;
  /** Symmetric algorithm protecting the secret key material */
  cipher: SymmetricCipherId;
  /** String-to-key KDF for the passphrase */
  s2k: S2kProtocolId;
  /**
   * Iterated+Salted S2K iteration count byte (0–255). Higher = slower KDF.
   * OpenPGP maps this byte to the real iteration count.
   */
  s2kIterationCountByte?: number;
  /** Argon2id parameters (used when s2k === 'argon2') */
  argon2?: {
    passes: number;
    parallelism: number;
    /** Memory = 2^memoryExponent KiB (OpenPGP convention) */
    memoryExponent: number;
  };
  /** Prefer AEAD-protected secret key packets (OpenPGP v6 style when supported) */
  aeadProtect?: boolean;
  aeadMode?: AeadModeId;
};

export const SYMMETRIC_CIPHERS: {
  id: SymmetricCipherId;
  label: string;
}[] = [
  { id: "aes128", label: "AES-128" },
  { id: "aes192", label: "AES-192" },
  { id: "aes256", label: "AES-256 (recommended)" },
];

export const S2K_PROTOCOLS: {
  id: S2kProtocolId;
  label: string;
  description: string;
}[] = [
  {
    id: "argon2",
    label: "Argon2id (recommended)",
    description: "Memory-hard KDF; best against GPU cracking",
  },
  {
    id: "iterated",
    label: "Iterated+Salted S2K",
    description: "Classic OpenPGP iterated SHA KDF",
  },
];

export function normalizeFingerprint(input: string): string | null {
  const hex = input.replace(/[\s:]/g, "").toLowerCase();
  if (!/^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(hex)) return null;
  return hex;
}

export function formatFingerprint(fp: string): string {
  const clean = fp.replace(/[\s:]/g, "").toUpperCase();
  return clean.replace(/(.{4})/g, "$1 ").trim();
}

export function shortFingerprint(fp: string): string {
  const clean = fp.replace(/[\s:]/g, "").toUpperCase();
  if (clean.length <= 8) return clean;
  return `${clean.slice(0, 4)}…${clean.slice(-4)}`;
}

export function containsPrivateKeyBlock(text: string): boolean {
  return /BEGIN PGP PRIVATE KEY BLOCK/i.test(text);
}

/** Hard fail if a network payload would include private key material. */
export function assertPayloadHasNoPrivateKey(payload: unknown): void {
  const scan = (value: unknown, depth = 0): void => {
    if (depth > 6 || value == null) return;
    if (typeof value === "string") {
      if (containsPrivateKeyBlock(value)) {
        throw new Error(
          "Refusing to send private key material to the network.",
        );
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

export function getLastFingerprint(): string | null {
  try {
    return normalizeFingerprint(localStorage.getItem(LAST_FP_KEY) || "");
  } catch {
    return null;
  }
}

export function setLastFingerprint(fp: string | null) {
  try {
    if (!fp) localStorage.removeItem(LAST_FP_KEY);
    else localStorage.setItem(LAST_FP_KEY, fp);
  } catch {
    // ignore
  }
}

/** Clear public fingerprint remember-me (localStorage is not “browser cache”). */
export function clearLastFingerprint() {
  setLastFingerprint(null);
}

/**
 * Sessions use HttpOnly cookies only. These helpers clear legacy JS storage
 * and never persist session ids where XSS can read them.
 */
export function getSessionToken(): string | null {
  // Intentionally always null — do not read session tokens from JS storage.
  clearSessionToken();
  return null;
}

/** @deprecated No-op: session ids must not be stored in sessionStorage. */
export function setSessionToken(_token: string | null) {
  clearSessionToken();
}

export function clearSessionToken() {
  try {
    sessionStorage.removeItem(LEGACY_SESSION_TOKEN_KEY);
    sessionStorage.removeItem("globe_session_token");
  } catch {
    // ignore
  }
}

// --- Device-local private key vault (never uploaded) ---

/** Runtime record: private key material available in memory after unwrap. */
export type DeviceKeyRecord = {
  fingerprint: string;
  publicKeyArmored: string;
  privateKeyArmored: string;
  /** True when the OpenPGP private key itself is passphrase-protected */
  encrypted: boolean;
  /** True when at-rest blob is AES-wrapped with device-bound WebCrypto key */
  deviceBound: boolean;
  profileLabel?: string;
  createdAt: string;
};

/** Persisted shape in IndexedDB (ciphertext, not raw private key when wrapped). */
type StoredDeviceKey = {
  fingerprint: string;
  publicKeyArmored: string;
  /** Legacy plaintext — migrated on read */
  privateKeyArmored?: string;
  wrappedPrivateKeyB64?: string;
  wrapIvB64?: string;
  wrapAlg?: typeof WRAP_ALG;
  encrypted: boolean;
  deviceBound?: boolean;
  profileLabel?: string;
  createdAt: string;
};

function openDeviceDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") {
      reject(
        new Error(
          "This browser has no IndexedDB for device keys. Private/incognito mode or some in-app browsers block it — try Safari/Chrome with a normal (non-private) tab.",
        ),
      );
      return;
    }
    const req = indexedDB.open(IDB_NAME, IDB_VERSION);
    req.onerror = () =>
      reject(req.error || new Error("Could not open device key store"));
    req.onblocked = () =>
      reject(
        new Error(
          "Device key store is blocked (another tab may have an older version open). Close other tabs for this site and try again.",
        ),
      );
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(IDB_STORE)) {
        db.createObjectStore(IDB_STORE, { keyPath: "fingerprint" });
      }
      if (!db.objectStoreNames.contains(IDB_WRAP_STORE)) {
        db.createObjectStore(IDB_WRAP_STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
  });
}

function idbReq<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(request.error || new Error("IndexedDB request failed"));
  });
}

/**
 * Wait for the full transaction to commit before closing the DB.
 * Mobile Safari often drops writes if the connection closes early.
 */
function idbTxDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () =>
      reject(tx.error || new Error("IndexedDB transaction aborted"));
    tx.onerror = () =>
      reject(tx.error || new Error("IndexedDB transaction failed"));
  });
}

async function idbPut(
  storeName: string,
  value: unknown,
  key?: IDBValidKey,
): Promise<void> {
  const db = await openDeviceDb();
  try {
    const tx = db.transaction(storeName, "readwrite");
    const store = tx.objectStore(storeName);
    const req =
      key === undefined ? store.put(value) : store.put(value, key);
    await idbReq(req);
    await idbTxDone(tx);
  } finally {
    try {
      db.close();
    } catch {
      // ignore
    }
  }
}

async function idbGet<T>(
  storeName: string,
  key: IDBValidKey,
): Promise<T | undefined> {
  const db = await openDeviceDb();
  try {
    const tx = db.transaction(storeName, "readonly");
    const result = await idbReq(
      tx.objectStore(storeName).get(key) as IDBRequest<T | undefined>,
    );
    // readonly still waits so mobile doesn't tear down mid-read
    await idbTxDone(tx).catch(() => undefined);
    return result;
  } finally {
    try {
      db.close();
    } catch {
      // ignore
    }
  }
}

/** Ask the browser to keep device keys (helps mobile Safari / Chrome eviction). */
export async function requestPersistentDeviceStorage(): Promise<boolean> {
  try {
    if (!navigator.storage?.persist) return false;
    if (await navigator.storage.persisted?.()) return true;
    return await navigator.storage.persist();
  } catch {
    return false;
  }
}

function bytesToB64(bytes: ArrayBuffer | Uint8Array): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]!);
  return btoa(s);
}

function b64ToBytes(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

const DEVICE_WRAP_RAW_ID = "aes-gcm-device-wrap-raw-v1";

type StoredWrapBlob =
  | CryptoKey
  | { v: 1; kind: "raw-aes-gcm-256"; keyB64: string };

/**
 * Import AES-GCM key from raw bytes (used when CryptoKey structured-clone
 * fails on some mobile browsers — still origin-bound IndexedDB only).
 */
async function importWrapKeyFromRaw(raw: Uint8Array): Promise<CryptoKey> {
  // Ensure we pass a pure ArrayBuffer (not SharedArrayBuffer) for TS/DOM.
  const copy = new Uint8Array(raw.byteLength);
  copy.set(raw);
  return crypto.subtle.importKey(
    "raw",
    copy.buffer,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Device-bound AES-GCM key.
 * Prefer non-extractable CryptoKey in IndexedDB. Some mobile browsers fail to
 * persist CryptoKey objects — fall back to raw key bytes in the same store
 * (still never sent to the network).
 */
async function getOrCreateDeviceWrapKey(): Promise<CryptoKey> {
  if (!globalThis.crypto?.subtle) {
    throw new Error(
      "WebCrypto is required to protect device keys. Use a modern browser on HTTPS (not plain HTTP).",
    );
  }

  // 1) Non-extractable CryptoKey (preferred)
  try {
    const existing = await idbGet<CryptoKey>(
      IDB_WRAP_STORE,
      DEVICE_WRAP_KEY_ID,
    );
    if (existing && typeof existing === "object") {
      // Basic shape check — CryptoKey has algorithm/type
      if ("type" in existing && (existing as CryptoKey).type === "secret") {
        return existing as CryptoKey;
      }
    }
  } catch {
    // fall through to raw / create
  }

  // 2) Raw key material fallback (mobile Safari / some WebViews)
  try {
    const rawBlob = await idbGet<StoredWrapBlob>(
      IDB_WRAP_STORE,
      DEVICE_WRAP_RAW_ID,
    );
    if (
      rawBlob &&
      typeof rawBlob === "object" &&
      "kind" in rawBlob &&
      rawBlob.kind === "raw-aes-gcm-256" &&
      typeof rawBlob.keyB64 === "string"
    ) {
      return importWrapKeyFromRaw(b64ToBytes(rawBlob.keyB64));
    }
  } catch {
    // create new
  }

  // 3) Create new wrap key — try non-extractable store, then raw fallback
  try {
    const key = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    await idbPut(IDB_WRAP_STORE, key, DEVICE_WRAP_KEY_ID);
    // Verify round-trip (critical on mobile)
    const check = await idbGet<CryptoKey>(IDB_WRAP_STORE, DEVICE_WRAP_KEY_ID);
    if (check && "type" in check && check.type === "secret") {
      return key;
    }
  } catch {
    // CryptoKey persistence failed — use raw fallback
  }

  const raw = crypto.getRandomValues(new Uint8Array(32));
  const rawRecord: StoredWrapBlob = {
    v: 1,
    kind: "raw-aes-gcm-256",
    keyB64: bytesToB64(raw),
  };
  await idbPut(IDB_WRAP_STORE, rawRecord, DEVICE_WRAP_RAW_ID);
  const verify = await idbGet<StoredWrapBlob>(
    IDB_WRAP_STORE,
    DEVICE_WRAP_RAW_ID,
  );
  if (
    !verify ||
    typeof verify !== "object" ||
    !("keyB64" in verify) ||
    !verify.keyB64
  ) {
    throw new Error(
      "Could not save device key protection material. On mobile: leave private/incognito mode, allow site data, and avoid in-app browsers (open in Safari or Chrome).",
    );
  }
  return importWrapKeyFromRaw(raw);
}

async function wrapPrivateKeyForDevice(
  privateKeyArmored: string,
): Promise<{ wrappedPrivateKeyB64: string; wrapIvB64: string }> {
  const key = await getOrCreateDeviceWrapKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode(privateKeyArmored);
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plain,
  );
  return {
    wrappedPrivateKeyB64: bytesToB64(cipher),
    wrapIvB64: bytesToB64(iv),
  };
}

async function unwrapPrivateKeyFromDevice(
  wrappedPrivateKeyB64: string,
  wrapIvB64: string,
): Promise<string> {
  const key = await getOrCreateDeviceWrapKey();
  const iv = b64ToBytes(wrapIvB64);
  const cipher = b64ToBytes(wrappedPrivateKeyB64);
  try {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      cipher,
    );
    return new TextDecoder().decode(plain);
  } catch {
    throw new Error(
      "Could not unlock device-bound key. This key was wrapped for another browser profile or the site data was reset.",
    );
  }
}

async function hydrateStoredKey(
  row: StoredDeviceKey,
): Promise<DeviceKeyRecord | null> {
  let privateKeyArmored = "";
  let deviceBound = false;

  if (row.wrappedPrivateKeyB64 && row.wrapIvB64) {
    privateKeyArmored = await unwrapPrivateKeyFromDevice(
      row.wrappedPrivateKeyB64,
      row.wrapIvB64,
    );
    deviceBound = true;
  } else if (row.privateKeyArmored?.trim()) {
    // Legacy plaintext vault → re-wrap for device binding
    privateKeyArmored = row.privateKeyArmored;
    deviceBound = false;
    try {
      await persistWrappedKey({
        fingerprint: row.fingerprint,
        publicKeyArmored: row.publicKeyArmored,
        privateKeyArmored,
        encrypted: row.encrypted,
        profileLabel: row.profileLabel,
        createdAt: row.createdAt,
      });
      deviceBound = true;
    } catch {
      // Keep usable even if wrap fails (old browser)
      deviceBound = false;
    }
  } else {
    return null;
  }

  return {
    fingerprint: row.fingerprint,
    publicKeyArmored: row.publicKeyArmored,
    privateKeyArmored,
    encrypted: Boolean(row.encrypted),
    deviceBound,
    profileLabel: row.profileLabel,
    createdAt: row.createdAt,
  };
}

async function persistWrappedKey(
  record: Omit<DeviceKeyRecord, "deviceBound" | "createdAt"> & {
    createdAt?: string;
  },
): Promise<DeviceKeyRecord> {
  const fp =
    normalizeFingerprint(record.fingerprint) || record.fingerprint;
  if (!fp) {
    throw new Error("Invalid fingerprint — cannot store device key.");
  }
  const createdAt = record.createdAt || new Date().toISOString();
  const wrap = await wrapPrivateKeyForDevice(record.privateKeyArmored);
  const stored: StoredDeviceKey = {
    fingerprint: fp,
    publicKeyArmored: record.publicKeyArmored,
    wrappedPrivateKeyB64: wrap.wrappedPrivateKeyB64,
    wrapIvB64: wrap.wrapIvB64,
    wrapAlg: WRAP_ALG,
    // Never persist plaintext private key once wrapped
    privateKeyArmored: undefined,
    encrypted: record.encrypted,
    deviceBound: true,
    profileLabel: record.profileLabel,
    createdAt,
  };
  await idbPut(IDB_STORE, stored);

  // Verify we can read + unwrap immediately (catches mobile silent write failures)
  const row = await idbGet<StoredDeviceKey>(IDB_STORE, fp);
  if (!row?.wrappedPrivateKeyB64 || !row.wrapIvB64) {
    throw new Error(
      "Device key did not save correctly. On mobile: use a normal (non-private) tab in Safari or Chrome — not Instagram/Facebook/TikTok in-app browsers — and allow site data/cookies.",
    );
  }
  try {
    const check = await unwrapPrivateKeyFromDevice(
      row.wrappedPrivateKeyB64,
      row.wrapIvB64,
    );
    if (!check.includes("BEGIN PGP PRIVATE KEY")) {
      throw new Error("unwrap produced invalid key material");
    }
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Device key saved but could not be unlocked for sign-in (${detail}). Try again, or export a backup .asc and re-import.`,
    );
  }

  setLastFingerprint(fp);
  return {
    fingerprint: fp,
    publicKeyArmored: record.publicKeyArmored,
    privateKeyArmored: record.privateKeyArmored,
    encrypted: record.encrypted,
    deviceBound: true,
    profileLabel: record.profileLabel,
    createdAt,
  };
}

export async function saveDeviceKey(
  record: Omit<DeviceKeyRecord, "createdAt" | "deviceBound"> & {
    createdAt?: string;
    deviceBound?: boolean;
  },
): Promise<DeviceKeyRecord> {
  return persistWrappedKey(record);
}

export async function getDeviceKey(
  fingerprint: string,
): Promise<DeviceKeyRecord | null> {
  const fp = normalizeFingerprint(fingerprint);
  if (!fp) return null;
  const row = await idbGet<StoredDeviceKey>(IDB_STORE, fp);
  if (!row) return null;
  return hydrateStoredKey(row);
}

export async function listDeviceKeys(): Promise<DeviceKeyRecord[]> {
  const db = await openDeviceDb();
  let rows: StoredDeviceKey[] = [];
  try {
    const tx = db.transaction(IDB_STORE, "readonly");
    rows =
      (await idbReq(
        tx.objectStore(IDB_STORE).getAll() as IDBRequest<StoredDeviceKey[]>,
      )) || [];
    await idbTxDone(tx).catch(() => undefined);
  } finally {
    try {
      db.close();
    } catch {
      // ignore
    }
  }
  const out: DeviceKeyRecord[] = [];
  for (const row of rows) {
    try {
      // Normalize legacy rows that may have stored mixed-case fingerprints
      if (row.fingerprint) {
        const n = normalizeFingerprint(row.fingerprint);
        if (n && n !== row.fingerprint) {
          row.fingerprint = n;
        }
      }
      const hydrated = await hydrateStoredKey(row);
      if (hydrated) out.push(hydrated);
    } catch {
      // Skip keys that cannot be unwrapped on this device
    }
  }
  return out.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export async function deleteDeviceKey(fingerprint: string): Promise<void> {
  const fp = normalizeFingerprint(fingerprint);
  if (!fp) return;
  const db = await openDeviceDb();
  try {
    const tx = db.transaction(IDB_STORE, "readwrite");
    await idbReq(tx.objectStore(IDB_STORE).delete(fp));
    await idbTxDone(tx);
  } finally {
    try {
      db.close();
    } catch {
      // ignore
    }
  }
  if (getLastFingerprint() === fp) {
    const rest = await listDeviceKeys();
    setLastFingerprint(rest[0]?.fingerprint || null);
  }
}

export async function getPreferredDeviceKey(): Promise<DeviceKeyRecord | null> {
  const last = getLastFingerprint();
  if (last) {
    const k = await getDeviceKey(last);
    if (k) return k;
  }
  const all = await listDeviceKeys();
  return all[0] || null;
}

export async function privateKeyIsEncrypted(
  privateKeyArmored: string,
): Promise<boolean> {
  const openpgp = await ensureOpenPgp();
  const key = await openpgp.readPrivateKey({
    armoredKey: privateKeyArmored.trim(),
  });
  return !key.isDecrypted();
}

/**
 * One-click / one-passphrase device login.
 * Private key never leaves the browser; only a signature is sent.
 */
export async function signInWithDeviceKey(options: {
  deviceKey: DeviceKeyRecord;
  /** Only required when deviceKey.encrypted is true (OpenPGP layer) */
  passphrase?: string;
}): Promise<{
  user: {
    id: string;
    fingerprint: string;
    primaryUserId: string | null;
    transitPaid: boolean;
  };
  /** Always empty — session lives in HttpOnly cookie only */
  sessionToken: string;
  isAdmin: boolean;
  adminActionSecretRequired: boolean;
  message?: string;
}> {
  const { deviceKey, passphrase } = options;
  if (deviceKey.encrypted && !passphrase) {
    throw new Error(
      "This device key is encrypted — enter the key passphrase (not an account password).",
    );
  }

  const payload = await buildChallengeLoginPayload({
    privateKeyArmored: deviceKey.privateKeyArmored,
    passphrase: deviceKey.encrypted ? passphrase : undefined,
    fingerprintHint: deviceKey.fingerprint,
  });

  const loginRes = await authFetch("/api/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = (await loginRes.json()) as {
    user?: {
      id: string;
      fingerprint: string;
      primaryUserId: string | null;
      transitPaid: boolean;
    };
    sessionToken?: string;
    isAdmin?: boolean;
    adminActionSecretRequired?: boolean;
    message?: string;
    error?: string;
  };
  // Session is established via Set-Cookie (HttpOnly). Do not store sessionToken in JS.
  if (!loginRes.ok || !data.user) {
    const code = data.error || "";
    const base = data.message || data.error || "Device sign-in failed";
    // New keys that were never registered produce the same auth_failed as a bad signature
    // (anti-enumeration). Guide mobile users who often skip Register.
    if (
      code === "auth_failed" ||
      /could not verify signature/i.test(base)
    ) {
      throw new Error(
        `${base} If this is a newly generated key, open Create identity → Register & stay signed in first (public key only). Also use a normal browser tab (not private/in-app), then try Sign in again.`,
      );
    }
    if (code === "rate_limited") {
      throw new Error(
        "Too many sign-in attempts. Wait about a minute and try again.",
      );
    }
    throw new Error(base);
  }
  clearSessionToken();
  setLastFingerprint(data.user.fingerprint);
  return {
    user: data.user,
    sessionToken: "",
    isAdmin: Boolean(data.isAdmin),
    adminActionSecretRequired: Boolean(data.adminActionSecretRequired),
    message: data.message,
  };
}

/**
 * Generate a keypair, keep private key on this device only, return public material.
 * OpenPGP layer unencrypted by default (no login password). At rest the private key
 * is AES-GCM wrapped with a non-extractable device-bound WebCrypto key.
 */
export async function generateAndKeepOnDevice(options?: {
  name?: string;
  email?: string;
  profile?: KeyGenProfileId;
}): Promise<{
  public: PublicIdentity;
  deviceKey: DeviceKeyRecord;
  profileLabel: string;
}> {
  // Best-effort: reduce mobile Safari/Chrome auto-eviction of IndexedDB
  await requestPersistentDeviceStorage();

  let pair: GeneratedKeypair;
  try {
    pair = await generateKeypair({
      name: options?.name,
      email: options?.email,
      profile: options?.profile,
      // No OpenPGP passphrase at generate → login needs no password
    });
  } catch (error) {
    throw new Error(formatCryptoError(error, "Generate key on this device"));
  }
  const encrypted = await privateKeyIsEncrypted(pair.privateKeyArmored);
  try {
    const deviceKey = await saveDeviceKey({
      fingerprint: pair.fingerprint,
      publicKeyArmored: pair.publicKeyArmored,
      privateKeyArmored: pair.privateKeyArmored,
      encrypted,
      profileLabel: pair.profileLabel,
    });
    return {
      public: {
        fingerprint: pair.fingerprint,
        publicKeyArmored: pair.publicKeyArmored,
      },
      deviceKey,
      profileLabel: pair.profileLabel,
    };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    throw new Error(
      msg.includes("Device key") || msg.includes("IndexedDB")
        ? msg
        : `Could not store the new key on this device: ${msg}`,
    );
  }
}

/**
 * Authenticated fetch: **HttpOnly cookie only** (credentials: same-origin).
 * Does not attach Bearer tokens from JS storage (XSS-resistant session handling).
 * Rejects any body that contains a PGP private key block.
 */
export async function authFetch(
  input: string,
  init: RequestInit = {},
): Promise<Response> {
  // Drop any leftover legacy session tokens from older builds
  clearSessionToken();

  const headers = new Headers(init.headers || {});
  if (!headers.has("accept")) {
    headers.set("accept", "application/json");
  }
  // Never send Authorization from client storage
  headers.delete("authorization");
  headers.delete("x-session-token");

  if (init.body != null) {
    let parsed: unknown = init.body;
    if (typeof init.body === "string") {
      try {
        parsed = JSON.parse(init.body);
      } catch {
        parsed = init.body;
      }
    }
    assertPayloadHasNoPrivateKey(parsed);
  }

  return fetch(input, {
    ...init,
    headers,
    credentials: "same-origin",
  });
}

/** True when WebAssembly API exists (CSP may still block instantiate). */
export function hasWebAssemblyApi(): boolean {
  return typeof WebAssembly !== "undefined" && typeof WebAssembly.instantiate === "function";
}

function errorText(error: unknown): string {
  if (error instanceof Error) {
    return `${error.name}: ${error.message}${error.cause ? ` (${String(error.cause)})` : ""}`;
  }
  return String(error);
}

function isWasmOrCspError(error: unknown): boolean {
  const msg = errorText(error).toLowerCase();
  return (
    msg.includes("webassembly") ||
    msg.includes("wasm") ||
    msg.includes("content security policy") ||
    msg.includes("blocked by csp") ||
    msg.includes("wasm-unsafe-eval") ||
    msg.includes("compilestreaming") ||
    msg.includes("instantiatestreaming") ||
    msg.includes("instantiate()")
  );
}

function isUnsupportedCurveOrAlgoError(error: unknown): boolean {
  const msg = errorText(error).toLowerCase();
  return (
    msg.includes("curve") ||
    msg.includes("algorithm") ||
    msg.includes("not supported") ||
    msg.includes("unsupported") ||
    msg.includes("unknown") ||
    msg.includes("invalid") ||
    msg.includes("operationerror") ||
    msg.includes("not implemented")
  );
}

/**
 * Human-readable crypto failure for any browser.
 * Suggests CSP reload, iterated S2K, or a different profile when relevant.
 */
export function formatCryptoError(error: unknown, context: string): string {
  const raw = errorText(error);
  if (isWasmOrCspError(error)) {
    return (
      `${context} failed: WebAssembly was blocked (often CSP). ` +
      `Hard-refresh the page after deploy so script-src includes 'wasm-unsafe-eval'. ` +
      `If it persists, use Iterated+Salted S2K instead of Argon2id. Details: ${raw}`
    );
  }
  if (
    raw.toLowerCase().includes("secure") ||
    raw.toLowerCase().includes("crypto.subtle")
  ) {
    return (
      `${context} failed: Web Crypto requires a secure context (HTTPS or localhost). Details: ${raw}`
    );
  }
  if (isUnsupportedCurveOrAlgoError(error)) {
    return (
      `${context} failed: this algorithm/curve may be unsupported in this browser. ` +
      `Try Curve25519 or RSA-2048. Details: ${raw}`
    );
  }
  return `${context} failed: ${raw}`;
}

/** Prefer Argon2 when WASM is available; otherwise iterated S2K (no WASM). */
export function preferredExportS2k(): S2kProtocolId {
  return hasWebAssemblyApi() ? "argon2" : "iterated";
}

async function buildEncryptConfig(
  openpgp: OpenPgpModule,
  enc: PrivateKeyExportEncryption,
): Promise<NonNullable<Parameters<OpenPgpModule["encryptKey"]>[0]["config"]>> {
  const config: NonNullable<
    Parameters<OpenPgpModule["encryptKey"]>[0]["config"]
  > = {
    preferredSymmetricAlgorithm: openpgp.enums.symmetric[enc.cipher],
    s2kType:
      enc.s2k === "argon2"
        ? openpgp.enums.s2k.argon2
        : openpgp.enums.s2k.iterated,
  };

  if (enc.s2k === "iterated") {
    const byte = Math.min(
      255,
      Math.max(0, enc.s2kIterationCountByte ?? 224),
    );
    config.s2kIterationCountByte = byte;
  }

  if (enc.s2k === "argon2") {
    config.s2kArgon2Params = {
      passes: Math.min(10, Math.max(1, enc.argon2?.passes ?? 3)),
      parallelism: Math.min(16, Math.max(1, enc.argon2?.parallelism ?? 4)),
      memoryExponent: Math.min(
        21,
        Math.max(16, enc.argon2?.memoryExponent ?? 16),
      ),
    };
  }

  if (enc.aeadProtect) {
    config.aeadProtect = true;
    const mode = enc.aeadMode || "gcm";
    config.preferredAEADAlgorithm = openpgp.enums.aead[mode];
  }

  return config;
}

async function encryptPrivateKeyWithFallback(
  privateKey: Awaited<ReturnType<OpenPgpModule["readPrivateKey"]>>,
  enc: PrivateKeyExportEncryption,
): Promise<{
  key: Awaited<ReturnType<OpenPgpModule["encryptKey"]>>;
  usedS2k: S2kProtocolId;
  notice?: string;
}> {
  const openpgp = await ensureOpenPgp();
  const tryEncrypt = async (settings: PrivateKeyExportEncryption) =>
    openpgp.encryptKey({
      privateKey,
      passphrase: settings.passphrase,
      config: await buildEncryptConfig(openpgp, settings),
    });

  if (enc.s2k !== "argon2") {
    try {
      const key = await tryEncrypt(enc);
      return { key, usedS2k: enc.s2k };
    } catch (error) {
      throw new Error(formatCryptoError(error, "Encrypt private key"));
    }
  }

  try {
    const key = await tryEncrypt(enc);
    return { key, usedS2k: "argon2" };
  } catch (error) {
    // Argon2 needs WebAssembly; CSP (Firefox) or missing WASM → iterated S2K.
    try {
      const fallback: PrivateKeyExportEncryption = {
        ...enc,
        s2k: "iterated",
        s2kIterationCountByte: enc.s2kIterationCountByte ?? 224,
        aeadProtect: false,
      };
      const key = await tryEncrypt(fallback);
      return {
        key,
        usedS2k: "iterated",
        notice: isWasmOrCspError(error)
          ? "Argon2/WebAssembly was blocked; exported with Iterated+Salted S2K + your cipher instead. Hard-refresh if you want Argon2 after CSP update."
          : `Argon2 encrypt failed; exported with Iterated+Salted S2K instead. (${errorText(error)})`,
      };
    } catch (fallbackError) {
      throw new Error(formatCryptoError(fallbackError, "Encrypt private key"));
    }
  }
}

/**
 * Generate keypair entirely client-side.
 * Caller must export/backup privateKeyArmored then discard it — never upload.
 */
export async function generateKeypair(options?: {
  name?: string;
  email?: string;
  /** If set, private key is encrypted at generation time with default S2K */
  passphrase?: string;
  profile?: KeyGenProfileId;
}): Promise<GeneratedKeypair> {
  const openpgp = await ensureOpenPgp();
  const name = options?.name?.trim() || "Globe User";
  const email = options?.email?.trim() || "globe-user@localhost";
  const profile = options?.profile || "curve25519";
  const userIDs = [{ name, email }];
  // Generate unencrypted first when possible, then encrypt via export path with fallbacks.
  // Passphrase on generateKey uses default S2K (may hit Argon2/WASM on some openpgp builds).
  const passphrase = options?.passphrase || undefined;

  let privateKey: string;
  let publicKey: string;
  let revocationCertificate: string;

  const common = {
    userIDs,
    // Avoid WASM during generate: encrypt separately if passphrase set
    passphrase: undefined as string | undefined,
    format: "armored" as const,
  };

  try {
  switch (profile) {
    case "curve448": {
      const r = await openpgp.generateKey({ ...common, type: "curve448" });
      privateKey = r.privateKey;
      publicKey = r.publicKey;
      revocationCertificate = r.revocationCertificate;
      break;
    }
    case "ecc_p256": {
      const r = await openpgp.generateKey({
        ...common,
        type: "ecc",
        curve: "nistP256",
      });
      privateKey = r.privateKey;
      publicKey = r.publicKey;
      revocationCertificate = r.revocationCertificate;
      break;
    }
    case "ecc_p384": {
      const r = await openpgp.generateKey({
        ...common,
        type: "ecc",
        curve: "nistP384",
      });
      privateKey = r.privateKey;
      publicKey = r.publicKey;
      revocationCertificate = r.revocationCertificate;
      break;
    }
    case "ecc_p521": {
      const r = await openpgp.generateKey({
        ...common,
        type: "ecc",
        curve: "nistP521",
      });
      privateKey = r.privateKey;
      publicKey = r.publicKey;
      revocationCertificate = r.revocationCertificate;
      break;
    }
    case "ecc_brainpool256": {
      const r = await openpgp.generateKey({
        ...common,
        type: "ecc",
        curve: "brainpoolP256r1",
      });
      privateKey = r.privateKey;
      publicKey = r.publicKey;
      revocationCertificate = r.revocationCertificate;
      break;
    }
    case "ecc_brainpool384": {
      const r = await openpgp.generateKey({
        ...common,
        type: "ecc",
        curve: "brainpoolP384r1",
      });
      privateKey = r.privateKey;
      publicKey = r.publicKey;
      revocationCertificate = r.revocationCertificate;
      break;
    }
    case "ecc_brainpool512": {
      const r = await openpgp.generateKey({
        ...common,
        type: "ecc",
        curve: "brainpoolP512r1",
      });
      privateKey = r.privateKey;
      publicKey = r.publicKey;
      revocationCertificate = r.revocationCertificate;
      break;
    }
    case "ecc_secp256k1": {
      const r = await openpgp.generateKey({
        ...common,
        type: "ecc",
        curve: "secp256k1",
      });
      privateKey = r.privateKey;
      publicKey = r.publicKey;
      revocationCertificate = r.revocationCertificate;
      break;
    }
    case "ecc_ed25519_legacy": {
      const r = await openpgp.generateKey({
        ...common,
        type: "ecc",
        curve: "ed25519Legacy",
      });
      privateKey = r.privateKey;
      publicKey = r.publicKey;
      revocationCertificate = r.revocationCertificate;
      break;
    }
    case "rsa1024": {
      const r = await openpgp.generateKey({
        ...common,
        type: "rsa",
        rsaBits: 1024,
        config: { minRSABits: 1024 },
      });
      privateKey = r.privateKey;
      publicKey = r.publicKey;
      revocationCertificate = r.revocationCertificate;
      break;
    }
    case "rsa1536": {
      const r = await openpgp.generateKey({
        ...common,
        type: "rsa",
        rsaBits: 1536,
        config: { minRSABits: 1024 },
      });
      privateKey = r.privateKey;
      publicKey = r.publicKey;
      revocationCertificate = r.revocationCertificate;
      break;
    }
    case "rsa2048": {
      const r = await openpgp.generateKey({
        ...common,
        type: "rsa",
        rsaBits: 2048,
      });
      privateKey = r.privateKey;
      publicKey = r.publicKey;
      revocationCertificate = r.revocationCertificate;
      break;
    }
    case "rsa3072": {
      const r = await openpgp.generateKey({
        ...common,
        type: "rsa",
        rsaBits: 3072,
      });
      privateKey = r.privateKey;
      publicKey = r.publicKey;
      revocationCertificate = r.revocationCertificate;
      break;
    }
    case "rsa4096": {
      const r = await openpgp.generateKey({
        ...common,
        type: "rsa",
        rsaBits: 4096,
      });
      privateKey = r.privateKey;
      publicKey = r.publicKey;
      revocationCertificate = r.revocationCertificate;
      break;
    }
    case "curve25519":
    default: {
      const r = await openpgp.generateKey({ ...common, type: "curve25519" });
      privateKey = r.privateKey;
      publicKey = r.publicKey;
      revocationCertificate = r.revocationCertificate;
      break;
    }
  }
  } catch (error) {
    const hint =
      profile !== "curve25519" && isUnsupportedCurveOrAlgoError(error)
        ? ` Try Curve25519 or RSA-2048 if ${getKeyGenProfile(profile).label} is unsupported here.`
        : "";
    throw new Error(formatCryptoError(error, "Generate key") + hint);
  }

  if (containsPrivateKeyBlock(publicKey)) {
    throw new Error("openpgp returned unexpected private material as public key");
  }

  // Optional passphrase: encrypt with fallback-friendly path (no WASM hard-fail)
  if (passphrase) {
    try {
      let priv = await openpgp.readPrivateKey({ armoredKey: privateKey });
      const { key, notice } = await encryptPrivateKeyWithFallback(priv, {
        passphrase,
        cipher: "aes256",
        s2k: preferredExportS2k(),
        s2kIterationCountByte: 224,
        argon2: { passes: 3, parallelism: 4, memoryExponent: 16 },
      });
      privateKey = key.armor();
      if (notice) {
        // Non-fatal; caller may surface via console
        console.info(notice);
      }
    } catch (error) {
      throw new Error(formatCryptoError(error, "Protect generated private key"));
    }
  }

  const key = await openpgp.readKey({ armoredKey: publicKey });
  const fingerprint = normalizeFingerprint(key.getFingerprint());
  if (!fingerprint) {
    throw new Error("Could not read fingerprint from generated key");
  }

  return {
    fingerprint,
    publicKeyArmored: publicKey,
    privateKeyArmored: privateKey,
    revocationCertificate,
    profileLabel: getKeyGenProfile(profile).label,
  };
}

/**
 * Re-encrypt / wrap a private key for file export (client-only).
 * Optionally decrypt first if the source key already has a passphrase.
 * Argon2 automatically falls back to iterated S2K if WebAssembly/CSP blocks it.
 */
export async function exportPrivateKeyToArmoredFile(options: {
  privateKeyArmored: string;
  /** Passphrase of the source key if already encrypted */
  sourcePassphrase?: string;
  /**
   * If set, re-encrypt with these settings.
   * If omitted / empty passphrase, export unlocked (not recommended).
   */
  encryption?: PrivateKeyExportEncryption | null;
}): Promise<{
  armored: string;
  fingerprint: string;
  encrypted: boolean;
  filename: string;
  notice?: string;
}> {
  const openpgp = await ensureOpenPgp();
  let key: Awaited<ReturnType<OpenPgpModule["readPrivateKey"]>>;
  try {
    key = await openpgp.readPrivateKey({
      armoredKey: options.privateKeyArmored.trim(),
    });
  } catch (error) {
    throw new Error(formatCryptoError(error, "Read private key"));
  }

  if (!key.isDecrypted()) {
    if (!options.sourcePassphrase) {
      throw new Error(
        "Source private key is encrypted — enter its current passphrase.",
      );
    }
    try {
      key = await openpgp.decryptKey({
        privateKey: key,
        passphrase: options.sourcePassphrase,
      });
    } catch (error) {
      throw new Error(
        formatCryptoError(error, "Decrypt source private key (check passphrase)"),
      );
    }
  }

  const fingerprint =
    normalizeFingerprint(key.getFingerprint()) || "unknown";
  const enc = options.encryption;
  let armored: string;
  let encrypted = false;
  let notice: string | undefined;

  let usedS2k: S2kProtocolId | null = null;
  if (enc?.passphrase) {
    if (enc.passphrase.length < 8) {
      throw new Error("Export passphrase must be at least 8 characters.");
    }
    const result = await encryptPrivateKeyWithFallback(key, enc);
    armored = result.key.armor();
    encrypted = true;
    notice = result.notice;
    usedS2k = result.usedS2k;
  } else {
    armored = key.armor();
    encrypted = false;
  }

  if (!containsPrivateKeyBlock(armored)) {
    throw new Error("Export failed: result is not a private key block");
  }

  const tag = encrypted ? "encrypted" : "unencrypted";
  const s2kTag = usedS2k ? `-${usedS2k}` : "";
  const filename = `globe-private-${fingerprint.slice(0, 8)}-${tag}${encrypted ? s2kTag : ""}.asc`;

  return { armored, fingerprint, encrypted, filename, notice };
}

/** Download armored private key to a local file (never uploaded). */
export function downloadPrivateKeyFile(
  armored: string,
  filename: string,
): void {
  downloadTextFile(filename, armored);
}

export async function fingerprintFromPrivateKey(
  privateKeyArmored: string,
): Promise<string> {
  const openpgp = await ensureOpenPgp();
  const key = await openpgp.readPrivateKey({
    armoredKey: privateKeyArmored.trim(),
  });
  const fingerprint = normalizeFingerprint(key.getFingerprint());
  if (!fingerprint) throw new Error("Invalid private key fingerprint");
  return fingerprint;
}

export async function signChallenge(
  message: string,
  privateKeyArmored: string,
  passphrase?: string,
): Promise<string> {
  try {
    const openpgp = await ensureOpenPgp();
    let privateKey = await openpgp.readPrivateKey({
      armoredKey: privateKeyArmored.trim(),
    });

    if (!privateKey.isDecrypted()) {
      if (!passphrase) {
        throw new Error("This private key requires a passphrase");
      }
      privateKey = await openpgp.decryptKey({
        privateKey,
        passphrase,
      });
    }

    const unsigned = await openpgp.createMessage({ text: message });
    const detached = await openpgp.sign({
      message: unsigned,
      signingKeys: privateKey,
      detached: true,
      format: "armored",
    });

    return detached as string;
  } catch (error) {
    if (error instanceof Error && error.message.includes("passphrase")) {
      throw error;
    }
    throw new Error(formatCryptoError(error, "Sign challenge"));
  }
}

/**
 * Build login body for POST /api/auth/login.
 * Only fingerprint + challengeId + signature leave the client — never the private key.
 */
export async function buildChallengeLoginPayload(options: {
  privateKeyArmored: string;
  passphrase?: string;
  fingerprintHint?: string;
}): Promise<{
  fingerprint: string;
  challengeId: string;
  signatureArmored: string;
}> {
  const fingerprint =
    normalizeFingerprint(options.fingerprintHint || "") ||
    (await fingerprintFromPrivateKey(options.privateKeyArmored));

  const challengeRes = await authFetch("/api/auth/challenge", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ fingerprint }),
  });
  const challenge = (await challengeRes.json()) as {
    challengeId?: string;
    message?: string;
    fingerprint?: string;
    error?: string;
  };
  if (!challengeRes.ok || !challenge.challengeId || !challenge.message) {
    throw new Error(
      challenge.message || challenge.error || "Could not start login challenge",
    );
  }

  const signatureArmored = await signChallenge(
    challenge.message,
    options.privateKeyArmored,
    options.passphrase,
  );

  const payload = {
    fingerprint: challenge.fingerprint || fingerprint,
    challengeId: challenge.challengeId,
    signatureArmored,
  };
  assertPayloadHasNoPrivateKey(payload);
  return payload;
}

export function readKeyFile(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const text = typeof reader.result === "string" ? reader.result : "";
      if (!text.trim()) reject(new Error("Empty key file"));
      else resolve(text);
    };
    reader.onerror = () => reject(new Error("Could not read key file"));
    reader.readAsText(file);
  });
}

export function downloadTextFile(filename: string, content: string) {
  const blob = new Blob([content], { type: "application/pgp-keys;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/**
 * Same-origin URL for navigation. Cookie-only sessions travel automatically;
 * do not put session ids in query strings (leak via history / Referer).
 */
export function buildAuthTokenUrl(path = "/"): string {
  return new URL(path, window.location.origin).toString();
}
