import { compareWithBaseline, type HostView } from "./purpleTeamHost";
import { escapeHtml, showChecks, type ToolResult } from "./purpleTeamTools";
import { OPERATIONS_PATH, RECENT_AUDIT_LIMIT, RECENT_LOGIN_LIMIT, type AlertRow } from "./securityOperationsModel";

export type OperationsPageData = {
  checkedAt: string;
  edge: string;
  room: { sockets: number; signedIn: number; feedEnabled: number; optedIn: number; pending: number } | null;
  inbox: AlertRow[] | null;
  notice?: string;
  status?: number;
  result?: ToolResult;
  archive?: HostView;
};

const alertTitles = {
  "rejected-logins": "Repeated denied sign-ins",
  "admin-change": "Admin role change",
  "fingerprint-denial": "Admin fingerprint denial",
};
const alertStates = { open: "Open", acknowledged: "Acknowledged", resolved: "Resolved" };

function timestamp(iso: string): string {
  return `<time datetime="${escapeHtml(iso)}">${escapeHtml(iso.replace("T", " ").slice(0, 19))} UTC</time>`;
}

function tool(value: string, label: string, target = "results", secondary = false): string {
  return `<form method="post" action="${OPERATIONS_PATH}#${target}">
    <button${secondary ? ' class="secondary"' : ""} name="tool" value="${value}">${label}</button>
  </form>`;
}

function renderAlert(alert: AlertRow): string {
  const action = alert.state === "resolved" ? '<button class="secondary" name="state" value="open">Reopen</button>'
    : `${alert.state === "open" ? '<button name="state" value="acknowledged">Acknowledge</button>' : ""}
       <button class="secondary" name="state" value="resolved">Resolve</button>`;
  const updated = alert.updatedAt
    ? ` · Updated ${timestamp(new Date(alert.updatedAt).toISOString())}${alert.updatedBy ? " by " + escapeHtml(alert.updatedBy.slice(0, 12)) : ""}` : "";
  return `<li>
    <div class="controls"><strong>${escapeHtml(alertTitles[alert.kind] ?? "Operations event")}</strong>
      <span class="status">${escapeHtml(alertStates[alert.state] ?? "Unknown")}</span>
    </div>
    <p>${escapeHtml(alert.detail)}</p>
    <p class="small">${timestamp(new Date(alert.at).toISOString())}${updated}</p>
    <form method="post" action="${OPERATIONS_PATH}#inbox" class="controls">
      <input type="hidden" name="tool" value="alert_state">
      <input type="hidden" name="alert" value="${escapeHtml(alert.id)}">
      ${action}
    </form>
  </li>`;
}

function renderInbox(inbox: AlertRow[] | null): string {
  if (inbox === null) return "<p>Alert storage is unavailable.</p>";
  if (inbox.length === 0) return "<p>No alerts in the inbox.</p>";
  const active = inbox.filter((alert) => alert.state !== "resolved");
  const resolved = inbox.filter((alert) => alert.state === "resolved");
  return `${active.length ? `<ul class="rows">${active.map(renderAlert).join("")}</ul>` : "<p>No active alerts.</p>"}
    ${resolved.length ? `<details><summary>Resolved alerts (${resolved.length})</summary>
      <ul class="rows">${resolved.map(renderAlert).join("")}</ul>
    </details>` : ""}`;
}

function renderArchive({ state, report, history, baseline }: HostView): string {
  const host = state?.hostname ?? "";
  const link = OPERATIONS_PATH + "?host=" + encodeURIComponent(host) + "&amp;report=";
  const changes = report && baseline ? compareWithBaseline(report, baseline.report) : [];
  return `<section class="panel" id="results" aria-labelledby="archive-title">
    <h2 id="archive-title">Saved website reports</h2>
    <p><strong>${escapeHtml(host)}</strong> · Scheduled scans retired</p>
    ${report ? `<p class="small">${report.source === "scheduled" ? "Scheduled" : "Manual"} scan · ${timestamp(report.at)}
      ${report.actor ? " · Run by " + escapeHtml(report.actor) : ""}</p>
      ${showChecks(report.findings)}` : "<p>No matching saved report.</p>"}
    ${report && baseline ? `<details>
      <summary>Approved baseline</summary>
      <p class="small">${timestamp(baseline.at)} · Approved by ${escapeHtml(baseline.by)}</p>
      ${changes.length ? `<ul>${changes.map(({ check, status }) =>
        `<li>${escapeHtml(check)} · ${status[0].toUpperCase() + status.slice(1)}</li>`).join("")}</ul>`
        : "<p>No findings need review in this comparison.</p>"}
    </details>` : ""}
    ${history.length > 1 ? `<details>
      <summary>Report history (${history.length})</summary>
      <ul>${history.map((entry) => `<li><a href="${link}${encodeURIComponent(entry.id)}#results"${
        entry.id === report?.id ? ' aria-current="page"' : ""}>${timestamp(entry.at)} · ${entry.source === "scheduled" ? "Scheduled" : "Manual"}</a></li>`).join("")}</ul>
    </details>` : ""}
  </section>`;
}

function renderDashboard(page: OperationsPageData): string {
  const metrics = [
    ["Open sockets", page.room?.sockets],
    ["Signed in", page.room?.signedIn],
    ["Feed access", page.room?.feedEnabled],
    ["Accepting requests", page.room?.optedIn],
    ["Pending requests", page.room?.pending],
  ] as const;
  return `<section class="panel" aria-labelledby="health-title">
    <div class="heading">
      <h2 id="health-title">Globe health</h2>
      <span class="status ${page.room ? "pass" : "unknown"}">${page.room ? "Live Feed responding" : "Live Feed unavailable"}</span>
    </div>
    <p class="small">Default room · ${timestamp(page.checkedAt)}${page.edge ? " · Edge " + escapeHtml(page.edge) : ""}</p>
    <dl class="metrics">${metrics.map(([label, value]) =>
      `<div><dt>${label}</dt><dd>${value ?? "Unknown"}</dd></div>`).join("")}</dl>
    <div class="controls">
      ${tool("checks", "Run Globe checks")}
      ${tool("drills", "Run local drills", "results", true)}
      <a href="${OPERATIONS_PATH}">Refresh snapshot</a>
    </div>
    <p class="small">Drills use disposable sessions and Live Feed connections.</p>
  </section>
  ${page.result ? `<section class="panel" id="results" aria-labelledby="result-title">
    <h2 id="result-title">${escapeHtml(page.result.title)}</h2>
    ${page.result.runId ? `<p class="small">Run <code>${escapeHtml(page.result.runId)}</code> · <a href="/api/admin/audit">Admin audit</a></p>` : ""}
    ${showChecks(page.result.findings)}
  </section>` : ""}
  <section class="panel" id="inbox" aria-labelledby="inbox-title">
    <div class="heading">
      <h2 id="inbox-title">Alert inbox</h2>
      ${tool("evaluate", "Evaluate recent events", "inbox")}
    </div>
    <p class="small">Samples up to ${RECENT_LOGIN_LIMIT} sign-in and ${RECENT_AUDIT_LIMIT} audit records on demand.</p>
    ${renderInbox(page.inbox)}
  </section>`;
}

export function operationsPage(page: OperationsPageData, applySecurityHeaders: (headers: Headers) => void): Response {
  const headers = new Headers({
    "content-type": "text/html; charset=utf-8",
    "cache-control": "private, no-store",
    vary: "Cookie",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    "x-robots-tag": "noindex, nofollow, noarchive",
    "referrer-policy": "same-origin",
  });
  applySecurityHeaders(headers);
  return new Response(`<!doctype html><html lang="en"><head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Purple Team · Globe</title>
    <style>
      :root{color-scheme:dark;--bg:#100d19;--panel:#1b1529;--line:#3f3453;--text:#f3ebff;--muted:#c9bdd8;--link:#d0b0ff;--green:#9ce8c7;--warn:#ffd291}
      *{box-sizing:border-box}
      body{margin:0;background:radial-gradient(ellipse at top left,#261839,transparent 36rem),var(--bg);color:var(--text);font:1rem/1.5 system-ui,sans-serif}
      main{max-width:64rem;margin:auto;padding:clamp(1rem,3.5vw,2.6rem)}
      h1{margin:0;font-size:clamp(2rem,4.6vw,3rem);line-height:1.12;letter-spacing:-.04em}
      h2{margin:0;font-size:1.18rem}
      p{margin:.45rem 0;color:var(--muted)}
      a{color:var(--link);text-underline-offset:.2em}
      header{margin-bottom:1.2rem}
      nav,.controls,.heading,.check-head{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem .85rem}
      nav,.small{font-size:.875rem;color:var(--muted)}
      .heading{justify-content:space-between}
      .panel,.notice{padding:clamp(.9rem,2vw,1.25rem);margin:0 0 .85rem;background:var(--panel);border:1px solid var(--line);border-radius:.8rem}
      .notice{color:var(--text)}
      .metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(7.5rem,1fr));gap:.75rem;margin:.9rem 0}
      .metrics div{border-left:2px solid var(--line);padding-left:.65rem}
      .metrics dt{font-size:.85rem;color:var(--muted)}
      .metrics dd{margin:.1rem 0 0;font-size:1.45rem;font-variant-numeric:tabular-nums;font-weight:750}
      form{margin:0}
      button{min-height:2.5rem;padding:.45rem .75rem;border:1px solid #cba8ff;border-radius:.45rem;font:inherit;font-size:.9rem;font-weight:700;cursor:pointer;background:#cba8ff;color:#200d34}
      button:hover{background:#e0c6ff}
      .secondary{background:#2e2442;color:var(--text);border-color:#684f85}
      .secondary:hover{background:#443057}
      :focus-visible{outline:2px solid #f2dbff;outline-offset:3px}
      .status{border:1px solid currentColor;border-radius:1rem;padding:.04rem .5rem;font-size:.75rem;font-weight:750;color:var(--muted)}
      .pass{color:var(--green)} .review{color:var(--warn)} .unknown{color:var(--link)}
      .checks,.rows{list-style:none;padding:0;margin:.65rem 0 0}
      .checks li,.rows li{border-top:1px solid var(--line);padding:.75rem 0;overflow-wrap:anywhere}
      .checks li:last-child,.rows li:last-child{padding-bottom:0}
      details{margin-top:1rem}
      summary{color:var(--link);cursor:pointer;font-size:.9rem;font-weight:650}
      #results,#inbox{scroll-margin-top:.75rem;overflow-wrap:anywhere}
      code{color:var(--link)}
    </style></head><body><main>
      <header class="heading">
        <h1>Purple Team</h1>
        <nav aria-label="Admin links">
          ${page.archive ? `<a href="${OPERATIONS_PATH}">Back to Purple Team</a>` : ""}
          <a href="/api/admin/audit">Admin audit</a><a href="/api/admin/login-attempts">Sign-in activity</a>
        </nav>
      </header>
      ${page.notice ? `<p class="notice" role="status">${escapeHtml(page.notice)}</p>` : ""}
      ${page.archive ? renderArchive(page.archive) : renderDashboard(page)}
    </main></body></html>`, { status: page.status ?? 200, headers });
}
