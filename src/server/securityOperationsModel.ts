import type { PublicAudit } from "./admin";
import type { PublicLoginAttempt } from "./loginLog";

export const OPERATIONS_PATH = "/admin/purple-team";
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
  return alerts.sort((a, b) => b.at - a.at).slice(0, MAX_ALERTS);
}
