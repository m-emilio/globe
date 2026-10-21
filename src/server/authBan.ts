/**
 * Pause a network after repeated rejected sign-ins.
 * fail2ban watches a host log and inserts firewall rules. This Worker has no
 * host firewall, so the pause is a short KV record keyed by the SHAKE256
 * network hash. An unknown address is never paused, because every such
 * request would share one bucket.
 */
import { clientIp, type AuthEnv } from "./auth";
import { networkHash } from "./pqcLogHash";

export const AUTH_FAIL_LIMIT = 8;
export const AUTH_FAIL_WINDOW_SECONDS = 10 * 60;
export const AUTH_BAN_SECONDS = 15 * 60;

const COUNTED = new Set([
  "auth_failed",
  "invalid_challenge",
  "private_key_rejected",
  "invalid_public_key",
  "fingerprint_required",
  "invalid_json",
  "rejected",
]);

type HeadersFn = (headers: Headers) => void;

function bannedResponse(applySecurityHeaders?: HeadersFn): Response {
  const headers = new Headers();
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  headers.set("retry-after", String(AUTH_BAN_SECONDS));
  applySecurityHeaders?.(headers);
  return new Response(
    JSON.stringify({
      error: "banned",
      message: "This network is paused after repeated sign-in failures. Try again later.",
    }),
    { status: 429, headers },
  );
}

export function countsAsAuthFailure(code: string): boolean {
  return COUNTED.has(code);
}

export function failureDecision(previous: number): "count" | "ban" {
  return previous + 1 >= AUTH_FAIL_LIMIT ? "ban" : "count";
}

/** Failures still inside the 10-minute window. A missing clock resets the count. */
export function countedFailures(raw: string | null, now: number): number {
  if (!raw) return 0;
  const [countPart, startPart] = raw.split(":");
  const count = Number.parseInt(countPart || "", 10);
  if (!Number.isFinite(count) || count <= 0) return 0;
  if (!startPart) return count;
  const start = Number.parseInt(startPart, 10);
  if (!Number.isFinite(start) || now - start >= AUTH_FAIL_WINDOW_SECONDS * 1000) return 0;
  return count;
}

function windowStart(raw: string | null, now: number): number {
  if (!raw || countedFailures(raw, now) === 0) return now;
  const startPart = raw.split(":")[1];
  const start = startPart ? Number.parseInt(startPart, 10) : now;
  return Number.isFinite(start) ? start : now;
}

export async function rejectIfAuthBanned(
  request: Request,
  env: AuthEnv,
  applySecurityHeaders?: HeadersFn,
): Promise<Response | null> {
  try {
    if (!env.BILLING_KV) return null;
    const ip = clientIp(request);
    if (ip === "unknown") return null;
    const banned = await env.BILLING_KV.get(`auth:ban:${networkHash(ip)}`);
    if (!banned) return null;
    return bannedResponse(applySecurityHeaders);
  } catch {
    return null;
  }
}

export async function noteAuthFailure(env: AuthEnv, ip: string, code: string): Promise<void> {
  if (!env.BILLING_KV || ip === "unknown" || !countsAsAuthFailure(code)) return;
  const now = Date.now();
  const hash = networkHash(ip);
  const failKey = `auth:fail:${hash}`;
  const raw = await env.BILLING_KV.get(failKey);
  const count = countedFailures(raw, now);
  const decision = failureDecision(count);
  const start = windowStart(raw, now);
  const elapsed = Math.floor((now - start) / 1000);
  const ttl = Math.max(60, AUTH_FAIL_WINDOW_SECONDS - Math.max(0, elapsed));
  await env.BILLING_KV.put(failKey, `${count + 1}:${start}`, { expirationTtl: ttl });
  if (decision === "ban") {
    await env.BILLING_KV.put(`auth:ban:${hash}`, "1", { expirationTtl: AUTH_BAN_SECONDS });
  }
}
