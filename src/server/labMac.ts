/**
 * Shared MAC for ECDHE and post-quantum KEM sign-in.
 * The shared secret is the HKDF input. Callers wipe it. Only the MAC is sent.
 */
export const LAB_LOGIN_PROTOCOL = "globe-lab-login:v1";

export type LabFamily = "ecdhe" | "kem";

export function labLoginInfo(family: LabFamily, suite: string): string {
  return `${LAB_LOGIN_PROTOCOL}:${family}:${suite}`;
}

export function buildLabLoginMessage(parts: {
  origin: string;
  family: LabFamily;
  suite: string;
  fingerprint: string;
  nonce: string;
  expiresAtMs: number;
}): string {
  if (!/^https:\/\/[A-Za-z0-9.-]+(?::\d+)?$/.test(parts.origin) &&
      !/^http:\/\/(?:localhost|127\.0\.0\.1)(?::\d+)?$/.test(parts.origin)) {
    throw new Error("invalid_origin");
  }
  if (parts.family !== "ecdhe" && parts.family !== "kem") throw new Error("invalid_family");
  if (!/^[A-Za-z0-9-]{1,40}$/.test(parts.suite)) throw new Error("invalid_suite");
  if (!/^[a-f0-9]{64}$/.test(parts.fingerprint)) throw new Error("invalid_fingerprint");
  if (!/^[a-f0-9]{32}$/.test(parts.nonce)) throw new Error("invalid_nonce");
  if (!Number.isSafeInteger(parts.expiresAtMs) || parts.expiresAtMs <= 0) throw new Error("invalid_expiry");
  return [
    LAB_LOGIN_PROTOCOL,
    parts.origin,
    parts.family,
    parts.suite,
    parts.fingerprint,
    parts.nonce,
    String(parts.expiresAtMs),
  ].join("\n");
}

export function labLoginMessageMatches(
  message: string,
  expected: { origin: string; family: LabFamily; suite: string; fingerprint: string },
): boolean {
  const lines = message.split("\n");
  if (lines.length !== 7) return false;
  if (lines[0] !== LAB_LOGIN_PROTOCOL) return false;
  if (lines[1] !== expected.origin) return false;
  if (lines[2] !== expected.family) return false;
  if (lines[3] !== expected.suite) return false;
  if (lines[4] !== expected.fingerprint) return false;
  if (!/^[a-f0-9]{32}$/.test(lines[5] || "")) return false;
  if (!/^\d{10,16}$/.test(lines[6] || "")) return false;
  const expiresAt = Number(lines[6]);
  const now = Date.now();
  return expiresAt > now && expiresAt < now + 10 * 60 * 1000;
}

export async function macKeyFromShared(shared: Uint8Array, family: LabFamily, suite: string): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(labLoginInfo(family, suite)),
    },
    base,
    256,
  );
  const out = new Uint8Array(bits.byteLength);
  out.set(new Uint8Array(bits));
  return out;
}

export async function hmacLogin(macKey: Uint8Array, message: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    macKey,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return new Uint8Array(mac);
}

export async function hmacMatches(macKey: Uint8Array, message: string, mac: Uint8Array): Promise<boolean> {
  if (mac.length !== 32) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    macKey,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify("HMAC", key, mac, new TextEncoder().encode(message));
}
