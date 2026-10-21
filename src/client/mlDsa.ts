/**
 * Device-local ML-DSA keys for sign-in.
 * The secret is AES-GCM wrapped in IndexedDB. Register and login send the
 * public key and a signature only.
 */
import {
  ML_DSA_SUITES,
  PQC_SIG_SUITES,
  SLH_DSA_SUITES,
  assertMlDsaLengths,
  assertPqcSigLengths,
  b64ToFixedBytes,
  buildPqcLoginMessage,
  bytesToB64,
  isPqcSigSuite,
  pqcLoginContext,
  pqcLoginMessageMatches,
  verifyPqcSignature,
  type MlDsaSuiteId,
  type PqcSigSuiteId,
  type SlhDsaSuiteId,
} from "../server/pqcVerify";
import { decodeMldsa87PrivateAsc } from "../server/mldsaAsc";
import {
  globePrivateFile,
  mldsa87PrivateFile,
  privateFileMatches,
  type PrivateKeyFile,
} from "./privateKeyFile";
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

const DB_NAME = "globe-pqc-login";
const DB_VERSION = 1;
const KEY_STORE = "keys";
const WRAP_STORE = "wrap";
const WRAP_KEY_ID = "aes-gcm-256";
const WRAP_RAW_ID = "aes-gcm-256-raw";

export type MlDsaDeviceRecord = {
  fingerprint: string;
  suite: PqcSigSuiteId;
  createdAt: string;
};

type StoredKey = {
  fingerprint: string;
  suite: PqcSigSuiteId;
  publicKeyB64: string;
  wrappedSecretB64: string;
  wrapIvB64: string;
  createdAt: string;
};

type RawWrap = { v: 1; kind: "raw-aes-gcm-256"; keyB64: string };

function wipe(bytes: Uint8Array | undefined): void {
  if (bytes) bytes.fill(0);
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") {
      reject(new Error("This browser cannot store a device key. Use a normal tab, not private mode."));
      return;
    }
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onerror = () => reject(req.error || new Error("Could not open the ML-DSA device store."));
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(KEY_STORE)) {
        db.createObjectStore(KEY_STORE, { keyPath: "fingerprint" });
      }
      if (!db.objectStoreNames.contains(WRAP_STORE)) {
        db.createObjectStore(WRAP_STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
  });
}

function idbReq<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("IndexedDB request failed"));
  });
}

function idbDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error || new Error("IndexedDB transaction failed"));
    tx.onabort = () => reject(tx.error || new Error("IndexedDB transaction aborted"));
  });
}

async function withDb<T>(mode: IDBTransactionMode, store: string, run: (store: IDBObjectStore) => Promise<T>): Promise<T> {
  const db = await openDb();
  try {
    const tx = db.transaction(store, mode);
    const result = await run(tx.objectStore(store));
    await idbDone(tx);
    return result;
  } finally {
    try {
      db.close();
    } catch {
      // ignore
    }
  }
}

async function importRawWrap(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
}

async function getWrapKey(): Promise<CryptoKey> {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is required to protect the ML-DSA key.");
  }
  const existing = await withDb<CryptoKey | RawWrap | undefined>("readonly", WRAP_STORE, (store) =>
    idbReq(store.get(WRAP_KEY_ID)),
  ).catch(() => undefined);
  if (existing && typeof existing === "object" && "type" in existing && existing.type === "secret") {
    return existing;
  }
  const rawRecord = await withDb<RawWrap | undefined>("readonly", WRAP_STORE, (store) =>
    idbReq(store.get(WRAP_RAW_ID)),
  ).catch(() => undefined);
  if (rawRecord && rawRecord.kind === "raw-aes-gcm-256" && rawRecord.keyB64) {
    const raw = b64ToFixedBytes(rawRecord.keyB64, 32);
    try {
      return await importRawWrap(raw);
    } finally {
      wipe(raw);
    }
  }
  try {
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
      "encrypt",
      "decrypt",
    ]);
    await withDb("readwrite", WRAP_STORE, async (store) => {
      await idbReq(store.put(key, WRAP_KEY_ID));
    });
    const check = await withDb<CryptoKey | undefined>("readonly", WRAP_STORE, (store) =>
      idbReq(store.get(WRAP_KEY_ID)),
    );
    if (check && check.type === "secret") return key;
  } catch {
    // Some mobile browsers cannot persist a CryptoKey. Fall back to wrapped raw bytes.
  }
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const record: RawWrap = { v: 1, kind: "raw-aes-gcm-256", keyB64: bytesToB64(raw) };
  try {
    await withDb("readwrite", WRAP_STORE, async (store) => {
      await idbReq(store.put(record, WRAP_RAW_ID));
    });
    return await importRawWrap(raw);
  } finally {
    wipe(raw);
  }
}

async function wrapSecret(secret: Uint8Array): Promise<{ wrappedSecretB64: string; wrapIvB64: string }> {
  const key = await getWrapKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, secret));
  try {
    return { wrappedSecretB64: bytesToB64(cipher), wrapIvB64: bytesToB64(iv) };
  } finally {
    wipe(cipher);
    wipe(iv);
  }
}

async function unwrapSecret(row: StoredKey): Promise<Uint8Array> {
  const key = await getWrapKey();
  const iv = b64ToFixedBytes(row.wrapIvB64, 12);
  const cipher = b64ToFixedBytes(row.wrappedSecretB64, PQC_SIG_SUITES[row.suite].secretKey + 16);
  try {
    const plain = new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher),
    );
    if (plain.length !== PQC_SIG_SUITES[row.suite].secretKey) {
      wipe(plain);
      throw new Error("Could not unlock the ML-DSA key on this device.");
    }
    return plain;
  } finally {
    wipe(iv);
    wipe(cipher);
  }
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function createMlDsaDeviceKey(suite: PqcSigSuiteId): Promise<{
  fingerprint: string;
  publicKeyB64: string;
  suite: PqcSigSuiteId;
}> {
  assertPqcSigLengths(suite);
  const existing = await listMlDsaDeviceKeys();
  if (existing.some((row) => row.suite === suite)) {
    throw new Error(`This device already has a ${PQC_SIG_SUITES[suite].label} key. Remove it before creating another.`);
  }
  const pair = SIGNERS[suite].keygen();
  try {
    if (pair.publicKey.length !== PQC_SIG_SUITES[suite].publicKey) {
      throw new Error("Could not generate that ML-DSA key.");
    }
    const fingerprint = await sha256Hex(pair.publicKey);
    const publicKeyB64 = bytesToB64(pair.publicKey);
    const wrapped = await wrapSecret(pair.secretKey);
    const row: StoredKey = {
      fingerprint,
      suite,
      publicKeyB64,
      wrappedSecretB64: wrapped.wrappedSecretB64,
      wrapIvB64: wrapped.wrapIvB64,
      createdAt: new Date().toISOString(),
    };
    await withDb("readwrite", KEY_STORE, async (store) => {
      await idbReq(store.put(row));
    });
    const check = await unwrapSecret(row);
    wipe(check);
    return { fingerprint, publicKeyB64, suite };
  } finally {
    wipe(pair.secretKey);
    wipe(pair.publicKey);
  }
}

/** Store an ML-DSA-87 .asc on this device. The private key is not uploaded. */
export async function importMldsa87PrivateAsc(armored: string): Promise<{ fingerprint: string }> {
  const decoded = decodeMldsa87PrivateAsc(armored);
  if (!decoded) throw new Error("That .asc is not the ML-DSA-87 sign-in key.");
  const message = "globe-ml-dsa87-armor:v1";
  const signature = SIGNERS["ml-dsa87"].sign(new TextEncoder().encode(message), decoded.secretKey, {
    context: pqcLoginContext(),
  });
  try {
    if (!verifyPqcSignature("ml-dsa87", signature, message, decoded.publicKey)) {
      throw new Error("That .asc does not match this ML-DSA-87 account.");
    }
  } finally {
    wipe(signature);
  }
  try {
    const fingerprint = await sha256Hex(decoded.publicKey);
    const wrapped = await wrapSecret(decoded.secretKey);
    const row: StoredKey = {
      fingerprint,
      suite: "ml-dsa87",
      publicKeyB64: bytesToB64(decoded.publicKey),
      wrappedSecretB64: wrapped.wrappedSecretB64,
      wrapIvB64: wrapped.wrapIvB64,
      createdAt: new Date().toISOString(),
    };
    await withDb("readwrite", KEY_STORE, async (store) => {
      await idbReq(store.put(row));
    });
    return { fingerprint };
  } finally {
    wipe(decoded.secretKey);
    wipe(decoded.publicKey);
  }
}

/** Download the private key already wrapped in this browser. Nothing is uploaded. */
export async function exportStoredPqcPrivateKey(suite: PqcSigSuiteId): Promise<PrivateKeyFile> {
  const rows = await withDb<StoredKey[]>("readonly", KEY_STORE, (store) =>
    idbReq(store.getAll() as IDBRequest<StoredKey[]>),
  ).catch(() => [] as StoredKey[]);
  const row = rows
    .filter((item) => item.suite === suite)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0];
  if (!row) throw new Error(`No ${PQC_SIG_SUITES[suite].label} private key is stored in this browser.`);
  const secret = await unwrapSecret(row);
  const publicKey = b64ToFixedBytes(row.publicKeyB64, PQC_SIG_SUITES[suite].publicKey);
  try {
    const file = suite === "ml-dsa87"
      ? mldsa87PrivateFile(publicKey, secret)
      : globePrivateFile({ kind: "pqc", suite, publicKey, secretKey: secret });
    if (!privateFileMatches(file.text, publicKey, secret)) {
      throw new Error("Could not export that private key.");
    }
    return file;
  } finally {
    wipe(secret);
    wipe(publicKey);
  }
}

export async function listMlDsaDeviceKeys(): Promise<MlDsaDeviceRecord[]> {
  const rows = await withDb<StoredKey[]>("readonly", KEY_STORE, (store) =>
    idbReq(store.getAll() as IDBRequest<StoredKey[]>),
  ).catch(() => [] as StoredKey[]);
  const out: MlDsaDeviceRecord[] = [];
  for (const row of rows) {
    if (!row || !isPqcSigSuite(row.suite) || !/^[a-f0-9]{64}$/.test(row.fingerprint)) continue;
    out.push({ fingerprint: row.fingerprint, suite: row.suite, createdAt: row.createdAt });
  }
  return out;
}

export async function deleteMlDsaDeviceKey(suite: PqcSigSuiteId): Promise<void> {
  const rows = await withDb<StoredKey[]>("readonly", KEY_STORE, (store) =>
    idbReq(store.getAll() as IDBRequest<StoredKey[]>),
  );
  const doomed = rows.filter((row) => row.suite === suite).map((row) => row.fingerprint);
  if (doomed.length === 0) return;
  await withDb("readwrite", KEY_STORE, async (store) => {
    for (const fingerprint of doomed) await idbReq(store.delete(fingerprint));
  });
}

export async function signMlDsaLogin(
  suite: PqcSigSuiteId,
  message: string,
  origin: string,
): Promise<{ fingerprint: string; signatureB64: string }> {
  const rows = await withDb<StoredKey[]>("readonly", KEY_STORE, (store) =>
    idbReq(store.getAll() as IDBRequest<StoredKey[]>),
  );
  const matches = rows
    .filter((row) => row.suite === suite)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  const row = matches[0];
  if (!row) throw new Error(`Create a ${PQC_SIG_SUITES[suite].label} key on this device first.`);
  if (!pqcLoginMessageMatches(message, { origin, suite, fingerprint: row.fingerprint })) {
    throw new Error("The sign-in challenge did not match this device key.");
  }
  const secret = await unwrapSecret(row);
  try {
    const signature = SIGNERS[suite].sign(new TextEncoder().encode(message), secret, {
      context: pqcLoginContext(),
    });
    try {
      if (signature.length !== PQC_SIG_SUITES[suite].signature) {
        throw new Error("Could not sign in with this post-quantum key.");
      }
      return { fingerprint: row.fingerprint, signatureB64: bytesToB64(signature) };
    } finally {
      wipe(signature);
    }
  } finally {
    wipe(secret);
  }
}

function allowedAdminSignature(message: string): boolean {
  if (message.length > 2000) return false;
  if (message.startsWith("globe-admin-elevate:v1|")) return true;
  if (!message.startsWith("globe-unlimited-keys:v1|")) return false;
  const parts = message.split("|");
  return (
    parts.length === 4 &&
    (parts[1] === "grant" || parts[1] === "revoke") &&
    /^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(parts[2] || "") &&
    /^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(parts[3] || "")
  );
}

/** Sign an admin elevation or unlimited-key statement with the post-quantum key on this device. */
export async function signStoredPqcMessage(fingerprint: string, message: string): Promise<string> {
  const fp = fingerprint.replace(/[\s:]/g, "").toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(fp)) throw new Error("This account does not use a post-quantum device key.");
  if (!allowedAdminSignature(message)) {
    throw new Error("This device will only sign an admin elevation or unlimited-key statement.");
  }
  const rows = await withDb<StoredKey[]>("readonly", KEY_STORE, (store) =>
    idbReq(store.getAll() as IDBRequest<StoredKey[]>),
  );
  const row = rows.find((item) => item.fingerprint === fp && isPqcSigSuite(item.suite));
  if (!row) throw new Error("Create the post-quantum admin key on this device first.");
  const secret = await unwrapSecret(row);
  try {
    const signature = SIGNERS[row.suite].sign(new TextEncoder().encode(message), secret, {
      context: pqcLoginContext(),
    });
    try {
      if (signature.length !== PQC_SIG_SUITES[row.suite].signature) {
        throw new Error("Could not sign the admin elevation challenge.");
      }
      return bytesToB64(signature);
    } finally {
      wipe(signature);
    }
  } finally {
    wipe(secret);
  }
}

export async function mlDsaLoginSelfTest(): Promise<{ ok: true; suites: number }> {
  const origin = "https://globe.example";
  let count = 0;
  for (const suite of Object.keys(ML_DSA_SUITES) as MlDsaSuiteId[]) {
    assertMlDsaLengths(suite);
    const pair = SIGNERS[suite].keygen();
    const fingerprint = await sha256Hex(pair.publicKey);
    const message = buildPqcLoginMessage({
      origin,
      suite,
      fingerprint,
      nonce: "ab".repeat(16),
      expiresAtMs: Date.now() + 60_000,
    });
    const signature = SIGNERS[suite].sign(new TextEncoder().encode(message), pair.secretKey, {
      context: pqcLoginContext(),
    });
    const flipped = new Uint8Array(signature);
    flipped[flipped.length - 1] ^= 0x01;
    try {
      if (!pqcLoginMessageMatches(message, { origin, suite, fingerprint })) {
        throw new Error("ML-DSA self-test failed: message fields");
      }
      if (!verifyPqcSignature(suite, signature, message, pair.publicKey)) {
        throw new Error("ML-DSA self-test failed: signature did not verify");
      }
      if (verifyPqcSignature(suite, flipped, message, pair.publicKey)) {
        throw new Error("ML-DSA self-test failed: tampered signature verified");
      }
      const wrong = verifyPqcSignature(suite, signature, `${message}\n`, pair.publicKey);
      if (wrong) throw new Error("ML-DSA self-test failed: a different message verified");
      count += 1;
    } finally {
      wipe(pair.secretKey);
      wipe(pair.publicKey);
      wipe(signature);
      wipe(flipped);
    }
  }
  if (count !== 3) throw new Error("ML-DSA self-test failed: suite count");
  return { ok: true, suites: count };
}

/** Checks every SLH-DSA length, and signs only SHA2-128f so the check stays short. */
export async function slhDsaLoginSelfTest(): Promise<{ ok: true; suites: number; signed: SlhDsaSuiteId }> {
  const origin = "https://globe.example";
  const ids = Object.keys(SLH_DSA_SUITES) as SlhDsaSuiteId[];
  for (const suite of ids) assertPqcSigLengths(suite);
  const suite: SlhDsaSuiteId = "slh-dsa-sha2-128f";
  const pair = SIGNERS[suite].keygen();
  const fingerprint = await sha256Hex(pair.publicKey);
  const message = buildPqcLoginMessage({
    origin,
    suite,
    fingerprint,
    nonce: "cd".repeat(16),
    expiresAtMs: Date.now() + 60_000,
  });
  const signature = SIGNERS[suite].sign(new TextEncoder().encode(message), pair.secretKey, {
    context: pqcLoginContext(),
  });
  const flipped = new Uint8Array(signature);
  flipped[0] ^= 0x01;
  try {
    if (!verifyPqcSignature(suite, signature, message, pair.publicKey)) {
      throw new Error("SLH-DSA self-test failed: signature did not verify");
    }
    if (verifyPqcSignature(suite, flipped, message, pair.publicKey)) {
      throw new Error("SLH-DSA self-test failed: tampered signature verified");
    }
  } finally {
    wipe(pair.secretKey);
    wipe(pair.publicKey);
    wipe(signature);
    wipe(flipped);
  }
  return { ok: true, suites: ids.length, signed: suite };
}
