/**
 * Local private-key files. Callers download the text and must not upload it.
 * ML-DSA-87 keeps the existing OpenPGP armor. Other suites use a Globe block.
 */
import { decodeMldsa87PrivateAsc, encodeMldsa87PrivateAsc } from "../server/mldsaAsc";

export type PrivateKeyFile = {
  filename: string;
  text: string;
  mime: string;
};

const BEGIN = "-----BEGIN GLOBE PRIVATE KEY-----";
const END = "-----END GLOBE PRIVATE KEY-----";
const MARKER = "globe-private-export:v1";

function crc24(bytes: Uint8Array): number {
  let crc = 0xb704ce;
  for (let i = 0; i < bytes.length; i++) {
    crc ^= bytes[i]! << 16;
    for (let bit = 0; bit < 8; bit++) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= 0x1864cfb;
    }
  }
  return crc & 0xffffff;
}

function bytesToB64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

export function decodeBase64(value: string): Uint8Array {
  const bytes = b64ToBytes(value.replace(/\s+/g, ""));
  if (!bytes) throw new Error("Could not export that private key.");
  return bytes;
}

function b64ToBytes(value: string): Uint8Array | null {
  try {
    const binary = atob(value);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i++) diff |= left[i]! ^ right[i]!;
  return diff === 0;
}

function suiteName(suite: string): string {
  if (!/^[a-z0-9-]{1,40}$/.test(suite)) throw new Error("Could not name that private-key file.");
  return suite;
}

function armor(comment: string, packet: Uint8Array): string {
  const b64 = bytesToB64(packet);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  const crc = crc24(packet);
  const crcBytes = Uint8Array.of((crc >>> 16) & 0xff, (crc >>> 8) & 0xff, crc & 0xff);
  return [BEGIN, "", `Comment: ${comment}`, "", ...lines, `=${bytesToB64(crcBytes)}`, END, ""].join("\n");
}

export function encodeGlobePrivateKey(args: {
  kind: "pqc" | "kem";
  suite: string;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}): string {
  const suite = suiteName(args.suite);
  if (args.publicKey.length < 1 || args.publicKey.length > 8192) throw new Error("Could not export that private key.");
  if (args.secretKey.length < 1 || args.secretKey.length > 8192) throw new Error("Could not export that private key.");
  const suiteBytes = new TextEncoder().encode(suite);
  const packet = new Uint8Array(4 + 1 + 1 + suiteBytes.length + 4 + args.publicKey.length + 4 + args.secretKey.length);
  packet[0] = 0x47;
  packet[1] = 0x50;
  packet[2] = 0x4b;
  packet[3] = 0x31;
  packet[4] = args.kind === "pqc" ? 1 : 2;
  packet[5] = suiteBytes.length;
  let at = 6;
  packet.set(suiteBytes, at);
  at += suiteBytes.length;
  const view = new DataView(packet.buffer);
  view.setUint32(at, args.publicKey.length);
  at += 4;
  packet.set(args.publicKey, at);
  at += args.publicKey.length;
  view.setUint32(at, args.secretKey.length);
  at += 4;
  packet.set(args.secretKey, at);
  return armor(`${MARKER}:${args.kind}:${suite}`, packet);
}

export function decodeGlobePrivateKey(text: string): {
  kind: "pqc" | "kem";
  suite: string;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
} | null {
  const match = text.match(/-----BEGIN GLOBE PRIVATE KEY-----([\s\S]*?)-----END GLOBE PRIVATE KEY-----/);
  if (!match) return null;
  const lines = (match[1] ?? "").split("\n").map((line) => line.trim()).filter((line) => line.length > 0);
  let comment = "";
  const data: string[] = [];
  let crcLine = "";
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.startsWith("Comment:")) {
      if (comment) return null;
      comment = line.slice("Comment:".length).trim();
      continue;
    }
    if (line.startsWith("=")) {
      crcLine = line.slice(1);
      if (i !== lines.length - 1) return null;
      break;
    }
    if (!/^[A-Za-z0-9+/=]+$/.test(line)) return null;
    data.push(line);
  }
  const marked = comment.match(/^globe-private-export:v1:(pqc|kem):([a-z0-9-]{1,40})$/);
  if (!marked || !crcLine || data.length === 0) return null;
  const packet = b64ToBytes(data.join(""));
  const crcBytes = b64ToBytes(crcLine);
  if (!packet || !crcBytes || crcBytes.length !== 3) return null;
  const expected = crc24(packet);
  const actual = ((crcBytes[0]! << 16) | (crcBytes[1]! << 8) | crcBytes[2]!) >>> 0;
  if (expected !== actual) return null;
  if (packet.length < 6 || packet[0] !== 0x47 || packet[1] !== 0x50 || packet[2] !== 0x4b || packet[3] !== 0x31) return null;
  const kindByte = packet[4];
  const kind = kindByte === 1 ? "pqc" : kindByte === 2 ? "kem" : null;
  if (!kind || kind !== marked[1]) return null;
  const suiteLength = packet[5] ?? 0;
  if (suiteLength < 1 || 6 + suiteLength + 8 > packet.length) return null;
  const suite = new TextDecoder().decode(packet.subarray(6, 6 + suiteLength));
  if (suite !== marked[2]) return null;
  const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength);
  let at = 6 + suiteLength;
  const publicLength = view.getUint32(at);
  at += 4;
  if (publicLength < 1 || publicLength > 8192 || at + publicLength + 4 > packet.length) return null;
  const publicKey = packet.slice(at, at + publicLength);
  at += publicLength;
  const secretLength = view.getUint32(at);
  at += 4;
  if (secretLength < 1 || secretLength > 8192 || at + secretLength !== packet.length) return null;
  const secretKey = packet.slice(at, at + secretLength);
  return { kind, suite, publicKey, secretKey };
}

export function mldsa87PrivateFile(publicKey: Uint8Array, secretKey: Uint8Array): PrivateKeyFile {
  return {
    filename: "globe-ml-dsa87-private.asc",
    text: encodeMldsa87PrivateAsc(publicKey, secretKey),
    mime: "application/pgp-keys",
  };
}

export function globePrivateFile(args: {
  kind: "pqc" | "kem";
  suite: string;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}): PrivateKeyFile {
  const suite = suiteName(args.suite);
  return {
    filename: `globe-${args.kind}-${suite}-private.asc`,
    text: encodeGlobePrivateKey({ ...args, suite }),
    mime: "application/pgp-keys",
  };
}

export function ecdheSavedPemFile(curve: string, pem: string): PrivateKeyFile {
  if (!/^[A-Za-z0-9-]{1,20}$/.test(curve)) throw new Error("Could not name that private-key file.");
  if (!pem.includes("BEGIN") || !pem.includes("PRIVATE KEY")) throw new Error("The saved ECDHE key is not a private key.");
  return {
    filename: `globe-ecdhe-${curve}-private.pem`,
    text: pem.endsWith("\n") ? pem : `${pem}\n`,
    mime: "application/x-pem-file",
  };
}

/** Confirm the file decodes to the same key before it is offered for download. */
export function privateFileMatches(text: string, publicKey: Uint8Array, secretKey: Uint8Array): boolean {
  const globe = decodeGlobePrivateKey(text);
  if (globe) {
    const ok = sameBytes(globe.publicKey, publicKey) && sameBytes(globe.secretKey, secretKey);
    globe.publicKey.fill(0);
    globe.secretKey.fill(0);
    return ok;
  }
  const mldsa = decodeMldsa87PrivateAsc(text);
  if (!mldsa) return false;
  const ok = sameBytes(mldsa.publicKey, publicKey) && sameBytes(mldsa.secretKey, secretKey);
  mldsa.publicKey.fill(0);
  mldsa.secretKey.fill(0);
  return ok;
}

export function downloadLocalPrivateFile(file: PrivateKeyFile): void {
  const filename = file.filename.replace(/[^A-Za-z0-9._-]/g, "");
  if (!filename || filename !== file.filename) throw new Error("Could not name that private-key file.");
  const blob = new Blob([file.text], { type: file.mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noopener";
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
