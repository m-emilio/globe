import type { PublicAudit } from "./admin";
import type { PublicLoginAttempt } from "./loginLog";
import type { ToolFinding } from "./verifiedDomainScan";

export const OPERATIONS_PATH = "/admin/purple-team/operations";
export const RECENT_LOGIN_LIMIT = 18;
export const RECENT_AUDIT_LIMIT = 12;
export type AlertState = "open" | "acknowledged" | "resolved";
export type OperationsAlert = {
  id: string;
  at: number;
  kind: "rejected-logins" | "admin-change" | "fingerprint-denial";
  detail: string;
  exercise: boolean;
};
export type AlertRow = OperationsAlert & {
  state: AlertState;
  updatedAt: number;
  updatedBy: string;
};

type LoginEvent = Pick<PublicLoginAttempt, "at" | "phase" | "result" | "networkHash">;
type AdminEvent = Pick<PublicAudit, "at" | "action" | "ok" | "recordHash">;
const WINDOW_MS = 15 * 60_000;
const MAX_ALERTS = 20;

export function detectOperationsAlerts(
  logins: LoginEvent[],
  audits: AdminEvent[],
  now: number,
  exerciseId?: string,
): OperationsAlert[] {
  const alerts: OperationsAlert[] = [];
  const groups = new Map<string, { last: number; count: number }>();
  for (const login of logins) {
    const at = Date.parse(login.at);
    if (!Number.isFinite(at) || now - at > WINDOW_MS || at > now ||
        login.phase !== "login" || login.result !== "rejected" || !login.networkHash) continue;
    const group = groups.get(login.networkHash) ?? { last: 0, count: 0 };
    group.count++;
    group.last = Math.max(group.last, at);
    groups.set(login.networkHash, group);
  }
  for (const [network, group] of groups) {
    if (group.count < 5) continue;
    alerts.push({
      id: "login-burst:" + network + ":" + Math.floor(group.last / WINDOW_MS),
      at: group.last,
      kind: "rejected-logins",
      detail: group.count + " rejected sign-ins from one network in the sampled 15-minute window.",
      exercise: false,
    });
  }
  for (const audit of audits) {
    const at = Date.parse(audit.at);
    if (!Number.isFinite(at) || now - at > 60 * 60_000 || at > now || !audit.recordHash) continue;
    const roleChange = audit.ok && ["admin_add", "admin_remove"].includes(audit.action);
    const denial = !audit.ok && audit.action === "admin_fingerprint_denied";
    if (!roleChange && !denial) continue;
    alerts.push({
      id: "admin:" + audit.recordHash,
      at,
      kind: roleChange ? "admin-change" : "fingerprint-denial",
      detail: roleChange
        ? (audit.action === "admin_add" ? "An administrator was added." : "An administrator was removed.")
        : "The admin fingerprint check denied a request.",
      exercise: false,
    });
  }
  const recent = alerts.sort((a, b) => b.at - a.at).slice(0, MAX_ALERTS);
  return exerciseId ? recent.map(alert => ({
    ...alert, id: "exercise:" + exerciseId + ":" + alert.kind, exercise: true,
  })) : recent;
}

export function rehearsalAlerts(runId: string, now: number): OperationsAlert[] {
  const attempts: LoginEvent[] = Array.from({ length: 5 }, (_, i) => ({
    at: new Date(now - i * 5_000).toISOString(), phase: "login",
    result: "rejected", networkHash: "exercise-network",
  }));
  const audit = {
    at: new Date(now).toISOString(), action: "admin_add", ok: true, recordHash: "exercise-audit",
  };
  return detectOperationsAlerts(attempts, [audit], now, runId);
}

type Policy = { requireFingerprint: boolean; sameOrigin: boolean; quota: number };
const policyCases = [
  { label: "Signed-out request", session: false, admin: false, fingerprint: false, origin: true, earlierRequests: 0, expected: 401 },
  { label: "Regular signed-in user", session: true, admin: false, fingerprint: false, origin: true, earlierRequests: 0, expected: 403 },
  { label: "Admin ID without approved fingerprint", session: true, admin: true, fingerprint: false, origin: true, earlierRequests: 0, expected: 403 },
  { label: "Approved admin on Globe", session: true, admin: true, fingerprint: true, origin: true, earlierRequests: 0, expected: 200 },
  { label: "Approved admin after three requests", session: true, admin: true, fingerprint: true, origin: true, earlierRequests: 3, expected: 200 },
  { label: "Approved admin posting from a different origin", session: true, admin: true, fingerprint: true, origin: false, earlierRequests: 0, expected: 403 },
  { label: "Five earlier requests in the fixture window", session: true, admin: true, fingerprint: true, origin: true, earlierRequests: 5, expected: 429 },
];

export function previewOperationsPolicy(policy: Policy): ToolFinding[] {
  return policyCases.map(test => {
    let observed = 200;
    if (!test.session) observed = 401;
    else if (!test.admin || (policy.requireFingerprint && !test.fingerprint) ||
        (policy.sameOrigin && !test.origin)) observed = 403;
    else if (test.earlierRequests >= policy.quota) observed = 429;
    return {
      check: test.label,
      status: observed === test.expected ? "pass" : "review",
      evidence: "Expected HTTP " + test.expected + " · Preview HTTP " + observed + ".",
      remediation: observed !== test.expected
        ? (observed === 200 ? "This change admits a request the fixture expects to deny." : "This fixture would be denied differently under the proposed policy.")
        : undefined,
    };
  });
}
