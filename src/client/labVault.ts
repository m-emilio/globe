/**
 * Device store and sign-in requests for the ECDHE and KEM labs.
 * The wrapped secret stays in IndexedDB. The server receives a public key and a MAC.
 */
import { labLoginMessageMatches, type LabFamily } from "../server/labMac";

const DB_NAME = "globe-lab-login";
const DB_VERSION = 1;
const STORE = "keys";

type Row = {
  id: string;
  family: LabFamily;
  suite: string;
  publicKeyB64: string;
  wrappedB64: string;
  ivB64: string;
  createdAt: string;
};

function wipe(bytes: Uint8Array | undefined): void {
  if (bytes) bytes.fill(0);
}

function b64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s);
}

function fromB64(value: string): Uint8Array {
  const raw = atob(value.replace(/\s+/g, ""));
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") {
      reject(new Error("This browser cannot store a device key."));
      return;
    }
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onerror = () => reject(req.error || new Error("Could not open the lab key store."));
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE, { keyPath: "id" });
    };
    req.onsuccess = () => resolve(req.result);
  });
}

async function withStore<T>(mode: IDBTransactionMode, run: (store: IDBObjectStore) => Promise<T>): Promise<T> {
  const db = await openDb();
  try {
    const tx = db.transaction(STORE, mode);
    const done = new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error || new Error("IndexedDB failed"));
      tx.onabort = () => reject(tx.error || new Error("IndexedDB aborted"));
    });
    const result = await run(tx.objectStore(STORE));
    await done;
    return result;
  } finally {
    db.close();
  }
}

function req<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("IndexedDB request failed"));
  });
}

async function wrapKey(): Promise<CryptoKey> {
  const existing = await withStore<{ key?: CryptoKey } | undefined>("readonly", (store) => req(store.get("wrap"))).catch(
    () => undefined,
  );
  if (existing?.key && existing.key.type === "secret") return existing.key;
  const created = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  await withStore("readwrite", async (store) => {
    await req(store.put({ id: "wrap", key: created }));
  });
  return created;
}

async function saveMaterial(family: LabFamily, suite: string, publicKeyB64: string, material: Uint8Array): Promise<void> {
  const key = await wrapKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, material));
  const row: Row = {
    id: `${family}:${suite}`,
    family,
    suite,
    publicKeyB64,
    wrappedB64: b64(cipher),
    ivB64: b64(iv),
    createdAt: new Date().toISOString(),
  };
  wipe(cipher);
  wipe(iv);
  await withStore("readwrite", async (store) => {
    await req(store.put(row));
  });
}

export async function loadLabMaterial(family: LabFamily, suite: string): Promise<{ publicKeyB64: string; material: Uint8Array } | null> {
  const row = await withStore<Row | undefined>("readonly", (store) => req(store.get(`${family}:${suite}`))).catch(() => undefined);
  if (!row || row.family !== family || row.suite !== suite) return null;
  const key = await wrapKey();
  const iv = fromB64(row.ivB64);
  const cipher = fromB64(row.wrappedB64);
  try {
    const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher));
    return { publicKeyB64: row.publicKeyB64, material: plain };
  } finally {
    wipe(iv);
    wipe(cipher);
  }
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function publicBytes(b64: string): Uint8Array {
  return fromB64(b64);
}

async function post(path: string, body: Record<string, string>): Promise<{ ok: boolean; status: number; code: string; extra: Record<string, string> }> {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  let code = "";
  const extra: Record<string, string> = {};
  try {
    const data = (await response.json()) as Record<string, unknown>;
    if (typeof data.error === "string") code = data.error;
    for (const key of ["fingerprint", "challengeId", "message", "tokenB64", "family", "suite"]) {
      if (typeof data[key] === "string") extra[key] = data[key];
    }
  } catch {
    code = "";
  }
  return { ok: response.ok, status: response.status, code, extra };
}

function fixed(code: string, status: number): string {
  if (code === "rate_limited" || status === 429) return "Too many sign-in attempts. Wait a minute and try again.";
  if (code === "private_key_rejected") return "The private key stays on this device.";
  if (code === "invalid_challenge") return "That sign-in challenge expired. Try again.";
  if (code === "auth_failed") return "Could not verify the lab sign-in.";
  if (code === "kv_missing") return "Sign-in storage is not available right now.";
  return "Lab sign-in failed.";
}

export async function signInWithLabKey(args: {
  family: LabFamily;
  suite: string;
  publicKeyB64: string;
  material: Uint8Array;
  prove: (message: string, tokenB64: string) => Promise<string>;
}): Promise<void> {
  await saveMaterial(args.family, args.suite, args.publicKeyB64, args.material);
  const registered = await post("/api/auth/lab/register", {
    family: args.family,
    suite: args.suite,
    publicKeyB64: args.publicKeyB64,
  });
  let fingerprint = registered.extra.fingerprint || "";
  if (!fingerprint && (registered.ok || registered.code === "fingerprint_taken")) {
    fingerprint = await sha256Hex(publicBytes(args.publicKeyB64));
  }
  if (!fingerprint) throw new Error(fixed(registered.code, registered.status));
  const challenge = await post("/api/auth/lab/challenge", {
    family: args.family,
    suite: args.suite,
    fingerprint,
  });
  if (!challenge.ok) throw new Error(fixed(challenge.code, challenge.status));
  const message = challenge.extra.message || "";
  const tokenB64 = challenge.extra.tokenB64 || "";
  const challengeId = challenge.extra.challengeId || "";
  if (!labLoginMessageMatches(message, { origin: location.origin, family: args.family, suite: args.suite, fingerprint })) {
    throw new Error("The sign-in challenge did not match this device key.");
  }
  const macB64 = await args.prove(message, tokenB64);
  const loggedIn = await post("/api/auth/lab/login", {
    family: args.family,
    suite: args.suite,
    fingerprint,
    challengeId,
    macB64,
  });
  if (!loggedIn.ok) throw new Error(fixed(loggedIn.code, loggedIn.status));
  location.reload();
}
