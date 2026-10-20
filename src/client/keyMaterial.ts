/** Local key-field cleanup. Rejected reasons never include the field contents. */

export const KEY_MATERIAL_MAX_CHARS = 512_000;

export type SanitizedKeyMaterial =
  | { kind: "openpgp-private"; armored: string }
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
  const pgp = armorBlock(text, "pgp");
  const pkcs8 = armorBlock(text, "pkcs8");
  if (pgp && pkcs8) return { kind: "rejected", reason: "Mixed key formats." };
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
  return {
    kind: "rejected",
    reason: "Paste an OpenPGP private key (.asc) or an ECDHE private key.",
  };
}

/** Fixed label for a key field. The label never includes the field contents. */
export function describeKeyMaterial(input: string): string {
  const clean = sanitizeKeyMaterial(input);
  switch (clean.kind) {
    case "openpgp-private":
      return "OpenPGP private key. Import it on the sign-in screen.";
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
