/**
 * OpenPGP v6 secret-key armor for the existing ML-DSA-87 account.
 * Algorithm 100 is the private-use id. The account fingerprint stays
 * SHA-256 of the raw ML-DSA-87 public key, not the OpenPGP fingerprint.
 * The secret is unencrypted in the armor. Callers must not upload it.
 */

export const ML_DSA87_ARMOR_MARKER = "globe-ml-dsa:v1:ml-dsa87";
export const ML_DSA87_PUBLIC_LENGTH = 2592;
export const ML_DSA87_SECRET_LENGTH = 4896;

const PRIVATE_ALGORITHM = 100;
const CREATED_AT = 1719792000;
const SECRET_TAG = 5;

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

function checksum(secret: Uint8Array): number {
  let sum = 0;
  for (let i = 0; i < secret.length; i++) sum = (sum + secret[i]!) & 0xffff;
  return sum;
}

function packetLengthOctets(length: number): Uint8Array {
  if (length < 192) return Uint8Array.of(length);
  if (length < 8384) {
    const adjusted = length - 192;
    return Uint8Array.of(((adjusted >> 8) & 0xff) + 192, adjusted & 0xff);
  }
  throw new Error("ml-dsa87 packet is too large");
}

function readPacketLength(bytes: Uint8Array, offset: number): { length: number; next: number } | null {
  const first = bytes[offset];
  if (first == null) return null;
  if (first < 192) return { length: first, next: offset + 1 };
  if (first < 224) {
    const second = bytes[offset + 1];
    if (second == null) return null;
    return { length: ((first - 192) << 8) + second + 192, next: offset + 2 };
  }
  return null;
}

function encodePacket(publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array {
  const count = ML_DSA87_PUBLIC_LENGTH;
  const body = new Uint8Array(1 + 4 + 1 + 4 + count + 1 + ML_DSA87_SECRET_LENGTH + 2);
  let at = 0;
  body[at++] = 6;
  body[at++] = (CREATED_AT >>> 24) & 0xff;
  body[at++] = (CREATED_AT >>> 16) & 0xff;
  body[at++] = (CREATED_AT >>> 8) & 0xff;
  body[at++] = CREATED_AT & 0xff;
  body[at++] = PRIVATE_ALGORITHM;
  body[at++] = (count >>> 24) & 0xff;
  body[at++] = (count >>> 16) & 0xff;
  body[at++] = (count >>> 8) & 0xff;
  body[at++] = count & 0xff;
  body.set(publicKey, at);
  at += publicKey.length;
  body[at++] = 0;
  body.set(secretKey, at);
  at += secretKey.length;
  const sum = checksum(secretKey);
  body[at++] = (sum >>> 8) & 0xff;
  body[at++] = sum & 0xff;
  const length = packetLengthOctets(body.length);
  const packet = new Uint8Array(1 + length.length + body.length);
  packet[0] = 0xc0 | SECRET_TAG;
  packet.set(length, 1);
  packet.set(body, 1 + length.length);
  return packet;
}

function bytesToArmor(packet: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < packet.length; i++) binary += String.fromCharCode(packet[i]!);
  const b64 = btoa(binary);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  const crc = crc24(packet);
  const crcBytes = Uint8Array.of((crc >>> 16) & 0xff, (crc >>> 8) & 0xff, crc & 0xff);
  let crcBinary = "";
  for (let i = 0; i < crcBytes.length; i++) crcBinary += String.fromCharCode(crcBytes[i]!);
  return [
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "",
    `Comment: ${ML_DSA87_ARMOR_MARKER}`,
    "",
    ...lines,
    `=${btoa(crcBinary)}`,
    "-----END PGP PRIVATE KEY BLOCK-----",
    "",
  ].join("\n");
}

export function encodeMldsa87PrivateAsc(publicKey: Uint8Array, secretKey: Uint8Array): string {
  if (publicKey.length !== ML_DSA87_PUBLIC_LENGTH || secretKey.length !== ML_DSA87_SECRET_LENGTH) {
    throw new Error("ml-dsa87 key length");
  }
  return bytesToArmor(encodePacket(publicKey, secretKey));
}

function armorBody(text: string): string | null {
  const match = text.match(/-----BEGIN PGP PRIVATE KEY BLOCK-----([\s\S]*?)-----END PGP PRIVATE KEY BLOCK-----/);
  if (!match) return null;
  return match[1] ?? null;
}

export function decodeMldsa87PrivateAsc(text: string): { publicKey: Uint8Array; secretKey: Uint8Array } | null {
  if (!text.includes(`Comment: ${ML_DSA87_ARMOR_MARKER}`)) return null;
  const body = armorBody(text);
  if (!body) return null;
  const lines = body.split("\n").map((line) => line.trim()).filter((line) => line.length > 0);
  const dataLines: string[] = [];
  let crcLine = "";
  let pastHeaders = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (!pastHeaders) {
      if (line.startsWith("Comment:") || line.startsWith("Version:") || line.startsWith("Charset:")) continue;
      pastHeaders = true;
    }
    if (line.startsWith("=")) {
      crcLine = line.slice(1);
      if (i !== lines.length - 1) return null;
      break;
    }
    if (!/^[A-Za-z0-9+/=]+$/.test(line)) return null;
    dataLines.push(line);
  }
  if (!crcLine || dataLines.length === 0) return null;
  let packet: Uint8Array;
  let crcBytes: Uint8Array;
  try {
    const binary = atob(dataLines.join(""));
    packet = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) packet[i] = binary.charCodeAt(i);
    const crcBinary = atob(crcLine);
    crcBytes = new Uint8Array(crcBinary.length);
    for (let i = 0; i < crcBinary.length; i++) crcBytes[i] = crcBinary.charCodeAt(i);
  } catch {
    return null;
  }
  if (crcBytes.length !== 3) return null;
  const expected = crc24(packet);
  const actual = ((crcBytes[0]! << 16) | (crcBytes[1]! << 8) | crcBytes[2]!) >>> 0;
  if (expected !== actual) return null;
  if (packet[0] !== (0xc0 | SECRET_TAG)) return null;
  const sized = readPacketLength(packet, 1);
  if (!sized) return null;
  if (sized.next + sized.length !== packet.length) return null;
  const bodyBytes = packet.subarray(sized.next);
  if (bodyBytes.length !== 1 + 4 + 1 + 4 + ML_DSA87_PUBLIC_LENGTH + 1 + ML_DSA87_SECRET_LENGTH + 2) return null;
  if (bodyBytes[0] !== 6) return null;
  if (bodyBytes[5] !== PRIVATE_ALGORITHM) return null;
  const count = ((bodyBytes[6]! << 24) | (bodyBytes[7]! << 16) | (bodyBytes[8]! << 8) | bodyBytes[9]!) >>> 0;
  if (count !== ML_DSA87_PUBLIC_LENGTH) return null;
  const publicAt = 10;
  const usageAt = publicAt + ML_DSA87_PUBLIC_LENGTH;
  if (bodyBytes[usageAt] !== 0) return null;
  const secretAt = usageAt + 1;
  const publicKey = bodyBytes.slice(publicAt, usageAt);
  const secretKey = bodyBytes.slice(secretAt, secretAt + ML_DSA87_SECRET_LENGTH);
  const sumAt = secretAt + ML_DSA87_SECRET_LENGTH;
  const storedSum = ((bodyBytes[sumAt]! << 8) | bodyBytes[sumAt + 1]!) & 0xffff;
  if (storedSum !== checksum(secretKey)) return null;
  return { publicKey, secretKey };
}
