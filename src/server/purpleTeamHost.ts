import { DurableObject } from "cloudflare:workers";
import type { ToolFinding } from "./purpleTeamTools";

type ActorRecord = { by: string; at: string };
export type ScanReport = {
  id: string;
  at: string;
  actor: string | null;
  source: "manual" | "scheduled";
  findings: (ToolFinding & { id: string })[];
};
export type Baseline = ActorRecord & { report: ScanReport };
export type HostView = {
  state: { hostname: string } | null;
  report: ScanReport | null;
  history: Omit<ScanReport, "findings">[];
  baseline: Baseline | null;
};

const STATE = "state";
const BASELINE = "baseline";
const REPORT_PREFIX = "report:";
const HISTORY_LIMIT = 30;

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
  async view(reportId?: string): Promise<HostView> {
    return this.ctx.storage.transaction(async (txn) => {
      const state = await txn.get<{ hostname: string }>(STATE) ?? null;
      const reports = [...(await txn.list<ScanReport>({ prefix: REPORT_PREFIX, reverse: true, limit: HISTORY_LIMIT })).values()];
      const report = (reportId ? reports.find((entry) => entry.id === reportId) : reports[0]) ?? null;
      const baseline = await txn.get<Baseline>(BASELINE);
      return {
        state: state ? { hostname: state.hostname } : null,
        report: report ? visibleReport(report) : null,
        history: reports.map(({ id, at, actor, source }) => ({ id, at, actor, source })),
        baseline: baseline ? { ...baseline, report: visibleReport(baseline.report) } : null,
      };
    });
  }

  async alarm(): Promise<void> {
    // The old schedules are retired. Existing reports and baselines remain readable.
    await this.ctx.storage.deleteAlarm();
  }
}
