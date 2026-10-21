/** Local key-field cleanup. Rejected reasons never include the field contents. */

export const KEY_MATERIAL_MAX_CHARS = 512_000;

export type SanitizedKeyMaterial =
  | { kind: "openpgp-private"; armored: string }
  | { kind: "mldsa87-private"; armored: string }
  | { kind: "pkcs8"; pem: string }
  | { kind: "public-jwk"; json: string }
  | { kind: "spki"; b64: string }
  | { kind: "private-jwk"; json: string }
  | { kind: "rejected"; reason: string };

const PGP_RE =
  /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/;
const PKCS8_RE =
  /-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/;

function cleanText(input: string): string {
  return input
    .replace(/^\uFEFF/, "")
    .replace(/\0/g, "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .replace(/[\u0001-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .trim();
}

function hasMarkup(text: string): boolean {
  return /<\s*\/?\s*[a-z!]/i.test(text) || /javascript\s*:/i.test(text);
}

function armorBlock(text: string, kind: "pgp" | "pkcs8"): string | null {
  const match = text.match(kind === "pgp" ? PGP_RE : PKCS8_RE);
  if (!match) return null;
  const block = match[0].trim();
  if (hasMarkup(block) || block.length > KEY_MATERIAL_MAX_CHARS) return null;
  return `${block}\n`;
}

function sanitizeJwk(text: string): SanitizedKeyMaterial {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { kind: "rejected", reason: "Private JWK is not valid." };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { kind: "rejected", reason: "Private JWK is not valid." };
  }
  const src = parsed as Record<string, unknown>;
  const out: Record<string, string> = {};
  for (const key of ["kty", "crv", "x", "y", "d", "kid"] as const) {
    const value = src[key];
    if (value == null) continue;
    if (typeof value !== "string" || value.length > 512 || hasMarkup(value)) {
      return { kind: "rejected", reason: "Private JWK is not valid." };
    }
    out[key] = value;
  }
  if (!out.kty || !out.crv) {
    return { kind: "rejected", reason: "Private JWK is not valid." };
  }
  if (out.d) return { kind: "private-jwk", json: JSON.stringify(out) };
  if (out.x) return { kind: "public-jwk", json: JSON.stringify(out) };
  return { kind: "rejected", reason: "Private JWK is not valid." };
}

export function sanitizeKeyMaterial(input: string): SanitizedKeyMaterial {
  if (typeof input !== "string") {
    return { kind: "rejected", reason: "Key field is empty." };
  }
  const text = cleanText(input);
  if (!text) return { kind: "rejected", reason: "Key field is empty." };
  if (text.length > KEY_MATERIAL_MAX_CHARS) {
    return { kind: "rejected", reason: "Key material is too large." };
  }
  if (hasMarkup(text) || /&(?:#\d+|#x[0-9a-f]+|[a-z]{2,12});/i.test(text)) {
    return { kind: "rejected", reason: "Unsupported content in the key field." };
  }
  const pgp = armorBlock(text, "pgp");
  const pkcs8 = armorBlock(text, "pkcs8");
  if (pgp && pkcs8) return { kind: "rejected", reason: "Mixed key formats." };
  if (pgp && pgp.includes("Comment: globe-ml-dsa:v1:ml-dsa87")) {
    return { kind: "mldsa87-private", armored: pgp };
  }
  if (pgp) return { kind: "openpgp-private", armored: pgp };
  if (pkcs8) return { kind: "pkcs8", pem: pkcs8 };
  if (hasMarkup(text)) {
    return { kind: "rejected", reason: "Unsupported content in the key field." };
  }
  if (text.startsWith("{")) return sanitizeJwk(text);
  const b64 = text.replace(/\s+/g, "");
  if (/^[A-Za-z0-9+/=]+$/.test(b64) && b64.length >= 40 && b64.length <= 4000) {
    return { kind: "spki", b64 };
  }
  return { kind: "rejected", reason: "Unrecognized key material." };
}

/** Sign-in picker on desktop. iOS must not use this string alone. */
export const LOGIN_FILE_ACCEPT = ".asc,.pgp,.gpg";
/** Lab picker. PKCS#8 uses .pem so it cannot be confused with an OpenPGP .asc. */
export const LAB_FILE_ACCEPT = ".pem";

/**
 * iOS Safari maps ".asc" to text/plain. The Files picker then shows the
 * key and leaves it disabled, because a saved .asc is public.data, not
 * plain text. application/octet-stream is public.data, so the file can
 * be chosen. The name and the armor are still checked after that.
 * text/plain is not added: as the only type, it is what disables the file.
 */
export function pickerAccept(extensions: string, ios: boolean): string {
  if (!ios || extensions.includes("application/octet-stream")) return extensions;
  return `${extensions},application/octet-stream`;
}

export function appleTouchPicker(): boolean {
  if (typeof navigator === "undefined") return false;
  const ua = navigator.userAgent || "";
  if (/iPhone|iPad|iPod/.test(ua)) return true;
  return navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1;
}

const LOGIN_EXTENSIONS = new Set([".asc", ".pgp", ".gpg"]);
const LAB_EXTENSIONS = new Set([".pem"]);

function keyFilenameExtension(
  filename: string,
  allowed: ReadonlySet<string>,
): { ok: true; extension: string } | { ok: false; reason: string } {
  if (typeof filename !== "string" || filename.length < 3 || filename.length > 120) {
    return { ok: false, reason: "That file name is not allowed." };
  }
  if (/[\u0000-\u001F\u007F\u202A-\u202E\u2066-\u2069]/.test(filename)) {
    return { ok: false, reason: "That file name is not allowed." };
  }
  if (/[\\/<>:"|?*#%]/.test(filename) || /[\s.]$/.test(filename)) {
    return { ok: false, reason: "That file name is not allowed." };
  }
  const parts = filename.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return { ok: false, reason: "That file name is not allowed." };
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9 _-]{0,80}$/.test(parts[0])) {
    return { ok: false, reason: "That file name is not allowed." };
  }
  const extension = `.${parts[1].toLowerCase()}`;
  if (!allowed.has(extension)) {
    return { ok: false, reason: "That file extension is not allowed here." };
  }
  return { ok: true, extension };
}

/** Reject types that execute or render. Empty and generic binary types are ignored. */
export function isActiveUploadType(type: string): boolean {
  const value = type.trim().toLowerCase().split(";")[0]?.trim() ?? "";
  return (
    value === "text/html" ||
    value === "application/xhtml+xml" ||
    value === "image/svg+xml" ||
    value === "text/xml" ||
    value === "application/xml" ||
    value === "text/javascript" ||
    value === "application/javascript"
  );
}

export function acceptLoginPaste(input: string): SanitizedKeyMaterial {
  const clean = sanitizeKeyMaterial(input);
  if (clean.kind === "openpgp-private" || clean.kind === "mldsa87-private") return clean;
  if (clean.kind === "pkcs8" || clean.kind === "private-jwk") {
    return { kind: "rejected", reason: "That file is an ECDHE .pem. Use the key lab." };
  }
  if (clean.kind === "public-jwk" || clean.kind === "spki") {
    return { kind: "rejected", reason: "That file is a public key. Sign-in needs the private key .asc." };
  }
  if (clean.kind === "rejected" && clean.reason === "Unrecognized key material.") {
    return {
      kind: "rejected",
      reason: "Sign-in needs an OpenPGP private key (.asc, .pgp, or .gpg).",
    };
  }
  return clean;
}

export function acceptLabPaste(input: string): SanitizedKeyMaterial {
  const clean = sanitizeKeyMaterial(input);
  if (clean.kind === "pkcs8" || clean.kind === "private-jwk") return clean;
  if (clean.kind === "openpgp-private" || clean.kind === "mldsa87-private") {
    return {
      kind: "rejected",
      reason: "That file is a sign-in key. Import it on the sign-in screen.",
    };
  }
  if (clean.kind === "public-jwk" || clean.kind === "spki") {
    return { kind: "rejected", reason: "The lab needs an ECDHE private key, not a public key." };
  }
  if (clean.kind === "rejected" && clean.reason === "Unrecognized key material.") {
    return { kind: "rejected", reason: "The lab needs an ECDHE .pem or a private JWK." };
  }
  return clean;
}

export function readLoginKeyFile(file: {
  name: string;
  type: string;
  text: string;
}): SanitizedKeyMaterial {
  if (isActiveUploadType(file.type)) {
    return { kind: "rejected", reason: "That file type is not allowed." };
  }
  const named = keyFilenameExtension(file.name, LOGIN_EXTENSIONS);
  if (!named.ok) return { kind: "rejected", reason: named.reason };
  return acceptLoginPaste(file.text);
}

export function readLabKeyFile(file: {
  name: string;
  type: string;
  text: string;
}): SanitizedKeyMaterial {
  if (isActiveUploadType(file.type)) {
    return { kind: "rejected", reason: "That file type is not allowed." };
  }
  const named = keyFilenameExtension(file.name, LAB_EXTENSIONS);
  if (!named.ok) return { kind: "rejected", reason: named.reason };
  const clean = acceptLabPaste(file.text);
  if (clean.kind === "private-jwk") {
    return { kind: "rejected", reason: "A private JWK is pasted, not a .pem file." };
  }
  if (clean.kind !== "pkcs8") {
    return clean.kind === "rejected"
      ? clean
      : { kind: "rejected", reason: "The lab needs an ECDHE .pem private key." };
  }
  return clean;
}

/** Fixed label for a key field. The label never includes the field contents. */
export function describeKeyMaterial(input: string): string {
  const clean = sanitizeKeyMaterial(input);
  switch (clean.kind) {
    case "openpgp-private":
      return "OpenPGP private key. Import it on the sign-in screen.";
    case "mldsa87-private":
      return "ML-DSA-87 sign-in key. Import it on the sign-in screen.";
    case "pkcs8":
      return "ECDHE private key (PKCS#8).";
    case "private-jwk":
      return "ECDHE private key (JWK).";
    case "public-jwk":
      return "Public key (JWK).";
    case "spki":
      return "Public key (SPKI).";
    case "rejected":
      return clean.reason;
  }
}

/** Peer box: public JWK or SPKI only. Private material is refused. */
export function peerPublicMaterial(input: string): string {
  const clean = sanitizeKeyMaterial(input);
  if (clean.kind === "rejected" && clean.reason === "Key field is empty.") {
    throw new Error("Paste the peer public key (JWK JSON or SPKI base64).");
  }
  if (clean.kind === "public-jwk") return clean.json;
  if (clean.kind === "spki") return clean.b64;
  throw new Error("Peer field must be a public key.");
}
