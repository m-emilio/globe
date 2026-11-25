import { DurableObject } from "cloudflare:workers";
import { checkDnsProof, scanHostname, type DnsProof } from "./purpleTeamDns";
import { scanVerifiedDomain, type WebFinding } from "./verifiedDomainScan";

export type Schedule = "off" | "daily" | "weekly";
type HostStatus = "pending" | "verified" | "paused" | "revoked";
type ActorRecord = { by: string; at: string };
export type HostState = {
  hostname: string;
  challenge: string;
  status: HostStatus;
  registered: ActorRecord;
  verified: ActorRecord | null;
  revoked: ActorRecord | null;
  proof: { result: DnsProof; checkedAt: string } | null;
  schedule: Schedule;
  nextScanAt: number | null;
  generation: number;
};
export type ScanReport = {
  id: string;
  at: string;
  actor: string | null;
  source: "manual" | "scheduled";
  findings: WebFinding[];
};
export type Baseline = ActorRecord & { report: ScanReport };
export type HostView = {
  state: HostState | null;
  report: ScanReport | null;
  history: Omit<ScanReport, "findings">[];
  baseline: Baseline | null;
};

type CommandResult = { ok: true; reportId?: string } | { ok: false; error: string };
const STATE = "state";
const BASELINE = "baseline";
const REPORT_PREFIX = "report:";
const HISTORY_LIMIT = 30;
const DAY = 86_400_000;
const success: CommandResult = { ok: true };

function failure(error: string): CommandResult {
  return { ok: false, error };
}

function nextScan(schedule: Schedule, now: number): number | null {
  if (schedule === "off") return null;
  return now + (schedule === "weekly" ? 7 * DAY : DAY);
}

async function saveState(txn: DurableObjectTransaction, state: HostState) {
  await txn.put(STATE, state);
  if (state.nextScanAt === null) await txn.deleteAlarm();
  else await txn.setAlarm(state.nextScanAt);
}

function visibleReport(report: ScanReport): ScanReport {
  // Older scans can contain the retired observer's result. Keep the stored record.
  return { ...report, findings: report.findings.filter((finding) => finding.id !== "tls.served-certificate") };
}

export function compareWithBaseline(report: ScanReport, baseline: ScanReport) {
  const old = new Map(baseline.findings.map((finding) => [finding.id, finding]));
  const current = new Map(report.findings.map((finding) => [finding.id, finding]));
  const changes: { check: string; status: "new" | "recurring" | "resolved" | "unknown" }[] = [];
  for (const item of report.findings.filter((finding) => finding.status === "review")) {
    changes.push({ check: item.check, status: old.get(item.id)?.status === "review" ? "recurring" : "new" });
  }
  for (const item of baseline.findings.filter((finding) => finding.status === "review")) {
    const result = current.get(item.id);
    if (result?.status === "review") continue;
    changes.push({ check: item.check, status: result?.status === "pass" ? "resolved" : "unknown" });
  }
  return changes;
}

export class PurpleTeamHost extends DurableObject {
  private scanning = false;

  async view(reportId?: string): Promise<HostView> {
    return this.ctx.storage.transaction(async (txn) => {
      const state = await txn.get<HostState>(STATE) ?? null;
      const reports = [...(await txn.list<ScanReport>({ prefix: REPORT_PREFIX, reverse: true, limit: HISTORY_LIMIT })).values()];
      const report = (reportId ? reports.find((entry) => entry.id === reportId) : reports[0]) ?? null;
      const baseline = await txn.get<Baseline>(BASELINE);
      return {
        state,
        report: report ? visibleReport(report) : null,
        history: reports.map(({ id, at, actor, source }) => ({ id, at, actor, source })),
        baseline: baseline ? { ...baseline, report: visibleReport(baseline.report) } : null,
      };
    });
  }

  async register(hostname: string, by: string): Promise<CommandResult> {
    if (scanHostname(hostname) !== hostname) return failure("invalid_hostname");
    const challenge = "globe-" + crypto.randomUUID().replaceAll("-", "");
    const registered = { by, at: new Date().toISOString() };
    return this.ctx.storage.transaction(async (txn) => {
      const previous = await txn.get<HostState>(STATE);
      if (previous && previous.hostname !== hostname) return failure("invalid_hostname");
      if (previous && previous.status !== "revoked") return success;
      await saveState(txn, {
        hostname, challenge, registered, status: "pending", verified: null, revoked: null,
        proof: null, schedule: "off", nextScanAt: null, generation: (previous?.generation ?? 0) + 1,
      });
      return success;
    });
  }

  async verify(by: string): Promise<CommandResult> {
    const state = await this.ctx.storage.get<HostState>(STATE);
    if (!state || state.status === "revoked") return failure("host_not_pending");
    const result = await checkDnsProof(state.hostname, state.challenge);
    const now = Date.now();
    const at = new Date(now).toISOString();
    return this.ctx.storage.transaction(async (txn) => {
      const current = await txn.get<HostState>(STATE);
      if (!current || current.generation !== state.generation) return failure("authorization_changed");
      const verified = result === "present";
      await saveState(txn, {
        ...current,
        status: verified ? "verified" : current.verified ? "paused" : "pending",
        verified: verified ? { by, at } : current.verified,
        proof: { result, checkedAt: at },
        nextScanAt: verified ? nextScan(current.schedule, now) : null,
        generation: current.generation + 1,
      });
      return verified ? success : failure("proof_" + result);
    });
  }

  async revoke(by: string): Promise<CommandResult> {
    const revoked = { by, at: new Date().toISOString() };
    return this.ctx.storage.transaction(async (txn) => {
      const state = await txn.get<HostState>(STATE);
      if (!state) return failure("unknown_host");
      if (state.status === "revoked") return success;
      await saveState(txn, {
        ...state, status: "revoked", revoked, schedule: "off", nextScanAt: null,
        generation: state.generation + 1,
      });
      return success;
    });
  }

  async setSchedule(schedule: Schedule): Promise<CommandResult> {
    if (schedule !== "off" && schedule !== "daily" && schedule !== "weekly") return failure("invalid_schedule");
    return this.ctx.storage.transaction(async (txn) => {
      const state = await txn.get<HostState>(STATE);
      if (!state || (state.status !== "verified" && schedule !== "off")) return failure("proof_required");
      await saveState(txn, {
        ...state, schedule, nextScanAt: nextScan(schedule, Date.now()), generation: state.generation + 1,
      });
      return success;
    });
  }

  async approveBaseline(reportId: string, by: string): Promise<CommandResult> {
    const at = new Date().toISOString();
    return this.ctx.storage.transaction(async (txn) => {
      const report = await txn.get<ScanReport>(REPORT_PREFIX + reportId);
      if (!report) return failure("unknown_report");
      await txn.put<Baseline>(BASELINE, { at, by, report });
      return success;
    });
  }

  async scan(by: string): Promise<CommandResult> {
    return this.runScan("manual", by);
  }

  async alarm(): Promise<void> {
    const state = await this.ctx.storage.get<HostState>(STATE);
    if (!state || state.status !== "verified" || state.nextScanAt === null) return;
    const due = state.nextScanAt;
    if (due > Date.now()) return;
    const result = await this.runScan("scheduled", null, due);
    if (!result.ok && result.error === "scan_in_progress") {
      await this.ctx.storage.transaction(async (txn) => {
        const current = await txn.get<HostState>(STATE);
        if (current?.status === "verified" && current.nextScanAt === due) {
          await txn.setAlarm(Date.now() + 60_000);
        }
      });
    }
  }

  private async runScan(source: ScanReport["source"], actor: string | null, due?: number): Promise<CommandResult> {
    if (this.scanning) return failure("scan_in_progress");
    this.scanning = true;
    try {
      const state = await this.ctx.storage.get<HostState>(STATE);
      if (!state || state.status !== "verified" || (due !== undefined && state.nextScanAt !== due)) {
        return failure("proof_required");
      }
      const result = await checkDnsProof(state.hostname, state.challenge);
      const checkedAt = new Date().toISOString();
      const proof = { result, checkedAt };
      if (result !== "present") {
        return this.ctx.storage.transaction(async (txn) => {
          const current = await txn.get<HostState>(STATE);
          if (!current || current.generation !== state.generation) return failure("authorization_changed");
          await saveState(txn, {
            ...current, proof, status: "paused", nextScanAt: null, generation: current.generation + 1,
          });
          return failure("proof_" + result);
        });
      }

      const authorized = await this.ctx.storage.get<HostState>(STATE);
      if (!authorized || authorized.generation !== state.generation || authorized.status !== "verified") {
        return failure("authorization_changed");
      }
      const findings = await scanVerifiedDomain(authorized.hostname);
      const now = Date.now();
      const report: ScanReport = {
        id: now + "-" + crypto.randomUUID(), at: new Date(now).toISOString(),
        actor, source, findings,
      };
      return this.ctx.storage.transaction(async (txn) => {
        const current = await txn.get<HostState>(STATE);
        if (!current || current.generation !== state.generation || current.status !== "verified") {
          return failure("authorization_changed");
        }
        await txn.put(REPORT_PREFIX + report.id, report);
        const reports = await txn.list({ prefix: REPORT_PREFIX, reverse: true, limit: HISTORY_LIMIT + 1 });
        const expired = [...reports.keys()].slice(HISTORY_LIMIT);
        if (expired.length) await txn.delete(expired);
        if (source === "scheduled") {
          await saveState(txn, { ...current, proof, nextScanAt: nextScan(current.schedule, now) });
        } else {
          await txn.put(STATE, { ...current, proof });
        }
        return { ok: true, reportId: report.id };
      });
    } finally {
      this.scanning = false;
    }
  }
}
