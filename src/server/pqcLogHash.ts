/**
 * SHAKE256 seals for sign-in attempts and admin audits.
 * SHAKE256 is the FIPS 202 hash inside ML-DSA and SLH-DSA.
 * The digest is 32 bytes. Callers store the digest, not the raw network or account.
 */
import { shake256 } from "@noble/hashes/sha3.js";

export const PQC_LOG_ALG = "SHAKE256";
export const PQC_LOG_DOMAIN = "globe-pqc-log:v1";
export const PQC_LOG_BYTES = 32;

export type LoginSealFields = {
  at: string;
  family: string;
  phase: string;
  suite: string;
  result: string;
  code: string;
  networkHash: string;
  accountHash: string;
};

export type AuditSealFields = {
  at: string;
  action: string;
  ok: boolean;
  detail: string;
  adminHash: string;
  targetHash: string;
  networkHash: string;
};

function hex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i]!.toString(16).padStart(2, "0");
  return out;
}

export function pqcLogDigest(label: string, value: string): string {
  const text = `${PQC_LOG_DOMAIN}:${label}:${value}`;
  return hex(shake256(new TextEncoder().encode(text), { dkLen: PQC_LOG_BYTES }));
}

export function networkHash(ip: string): string {
  return pqcLogDigest("network", ip);
}

export function accountHash(fingerprint: string): string {
  const hexId = fingerprint.replace(/[\s:]/g, "").toLowerCase();
  if (!/^[a-f0-9]{8,128}$/.test(hexId)) return "";
  return pqcLogDigest("account", hexId);
}

export function loginRecordHash(fields: LoginSealFields): string {
  return pqcLogDigest(
    "login-record",
    [fields.at, fields.family, fields.phase, fields.suite, fields.result, fields.code, fields.networkHash, fields.accountHash].join("|"),
  );
}

export function auditRecordHash(fields: AuditSealFields): string {
  return pqcLogDigest(
    "audit-record",
    [fields.at, fields.action, fields.ok ? "1" : "0", fields.detail, fields.adminHash, fields.targetHash, fields.networkHash].join("|"),
  );
}

export function chainHash(prevHash: string, recordHash: string): string {
  return pqcLogDigest("chain", `${prevHash}|${recordHash}`);
}

export function isPqcLogHash(value: string): boolean {
  return /^[a-f0-9]{64}$/.test(value);
}

/** SHAKE256 seal for a privilege bound to one key fingerprint. */
export function privilegeSeal(kind: "unlock" | "unlimited-key", fingerprint: string): string {
  const hexId = fingerprint.replace(/[\s:]/g, "").toLowerCase();
  if (!/^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(hexId)) return "";
  return pqcLogDigest(kind, hexId);
}

/** SHAKE256 seal for an elevation user id. */
export function userSeal(userId: string): string {
  return pqcLogDigest("elev-user", userId);
}
