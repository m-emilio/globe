import { escapeHtml, showChecks, type ToolResult } from "./purpleTeamTools";
import { OPERATIONS_PATH, RECENT_AUDIT_LIMIT, RECENT_LOGIN_LIMIT, type AlertRow } from "./securityOperationsModel";

export type OperationsPageData = {
  checkedAt: string;
  edge: string;
  room: { sockets: number; signedIn: number; feedEnabled: number; optedIn: number; pending: number } | null;
  paused: boolean | null;
  inbox: AlertRow[] | null;
  notice?: string;
  status?: number;
  result?: ToolResult;
  policy?: { requireFingerprint: boolean; sameOrigin: boolean; quota: number };
};

const alertTitles = {
  "rejected-logins": "Repeated denied sign-ins",
  "admin-change": "Admin role change",
  "fingerprint-denial": "Admin fingerprint denial",
};
const alertStates = { open: "Open", acknowledged: "Acknowledged", resolved: "Resolved" };

function timeLabel(iso: string): string {
  return iso.replace("T", " ").slice(0, 19) + " UTC";
}

function tool(value: string, label: string, target = "results") {
  return `<form method="post" action="${OPERATIONS_PATH}#${target}">
    <button name="tool" value="${value}">${label}</button>
  </form>`;
}

function renderAlert(alert: AlertRow): string {
  const when = new Date(alert.at).toISOString();
  const updated = alert.updatedAt ? new Date(alert.updatedAt).toISOString() : "";
  const action = alert.state === "resolved" ? '<button name="state" value="open">Reopen</button>'
    : `${alert.state === "open" ? '<button name="state" value="acknowledged">Acknowledge</button>' : ""}
       <button class="secondary" name="state" value="resolved">Resolve</button>`;
  return `<li class="alert">
    <div class="alert-title"><strong>${escapeHtml(alertTitles[alert.kind] ?? "Operations event")}</strong>
      <span class="status">${escapeHtml(alertStates[alert.state] ?? "Unknown")}</span>
      ${alert.exercise ? '<span class="status exercise">Exercise</span>' : ''}
    </div>
    <p>${escapeHtml(alert.detail)}</p>
    <p class="small"><time datetime="${when}">${timeLabel(when)}</time>${updated
      ? " · Updated " + timeLabel(updated) + (alert.updatedBy ? " by " + escapeHtml(alert.updatedBy.slice(0, 12)) : "") : ""}</p>
    <form method="post" action="${OPERATIONS_PATH}#inbox" class="controls">
      <input type="hidden" name="tool" value="alert_state">
      <input type="hidden" name="alert" value="${escapeHtml(alert.id)}">
      ${action}
    </form>
  </li>`;
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
  const policy = page.policy ?? { requireFingerprint: true, sameOrigin: true, quota: 4 };
  const metrics = [
    ["Open sockets", page.room?.sockets], ["Signed in", page.room?.signedIn],
    ["Feed access", page.room?.feedEnabled], ["Opted in", page.room?.optedIn],
    ["Pending requests", page.room?.pending],
  ] as const;
  const result = page.result;
  return new Response(`<!doctype html><html lang="en"><head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Security Operations · Globe</title>
    <style>
      :root{color-scheme:dark;--bg:#100d19;--panel:#1b1529;--line:#3f3453;--text:#f3ebff;--muted:#c9bdd8;--link:#d0b0ff;--green:#9ce8c7;--warn:#ffd291}
      *{box-sizing:border-box}
      body{margin:0;background:radial-gradient(ellipse at top left,#261839,transparent 36rem),var(--bg);color:var(--text);font:1rem/1.5 system-ui,sans-serif}
      main{max-width:70rem;margin:auto;padding:clamp(1rem,3.5vw,2.75rem)}
      h1{margin:.35rem 0 1.15rem;font-size:clamp(2.1rem,4.6vw,3.25rem);line-height:1.08;letter-spacing:-.04em}
      h2{margin:0;font-size:1.18rem}
      p{margin:.45rem 0;color:var(--muted)}
      a{color:var(--link);text-underline-offset:.2em}
      nav,.controls,.alert-title,.heading{display:flex;flex-wrap:wrap;align-items:center;gap:.45rem .85rem}
      nav{padding-bottom:1rem;margin-bottom:1rem;border-bottom:1px solid var(--line);font-size:.94rem}
      nav [aria-current]{font-weight:750}
      .heading{justify-content:space-between}
      .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,18rem),1fr));gap:.85rem;margin:.85rem 0}
      .panel,.notice{padding:clamp(.85rem,2vw,1.2rem);background:var(--panel);border:1px solid var(--line);border-radius:.8rem}
      .notice{color:var(--text);margin-bottom:.85rem}
      .metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(7.5rem,1fr));gap:.65rem;margin:.9rem 0}
      .metrics div{border-left:2px solid var(--line);padding-left:.65rem}
      .metrics dt,.small{font-size:.85rem;color:var(--muted)}
      .metrics dd{margin:.1rem 0 0;font-size:1.45rem;font-variant-numeric:tabular-nums;font-weight:750}
      form{margin:.5rem 0 0}
      label{display:block;margin:.4rem 0;font-weight:600;font-size:.9rem}
      input[type=number]{width:5rem;max-width:100%;min-height:2.35rem;padding:.3rem;color:var(--text);background:var(--bg);border:1px solid var(--line);border-radius:.35rem}
      input[type=checkbox]{accent-color:#c39cff}
      button,.action-link{min-height:2.5rem;padding:.45rem .7rem;border:1px solid #cba8ff;border-radius:.45rem;font:inherit;font-size:.9rem;font-weight:700;cursor:pointer;background:#cba8ff;color:#200d34;text-decoration:none;display:inline-flex;align-items:center}
      button:hover,.action-link:hover{background:#e0c6ff}
      .secondary{background:#2e2442;color:var(--text);border-color:#684f85}
      .secondary:hover{background:#443057}
      :focus-visible{outline:2px solid #f2dbff;outline-offset:3px}
      .status{display:inline-block;border:1px solid currentColor;border-radius:1rem;padding:.04rem .5rem;font-size:.75rem;font-weight:750;color:var(--muted)}
      .pass,.enabled{color:var(--green)} .review,.paused{color:var(--warn)} .unknown,.exercise{color:var(--link)}
      .checks,.alert-list{list-style:none;padding:0;margin:.5rem 0 0}
      .checks li,.alert{border-top:1px solid var(--line);padding:.8rem 0;overflow-wrap:anywhere}
      .checks li:last-child,.alert:last-child{padding-bottom:0}
      .check-head{display:flex;align-items:center;flex-wrap:wrap;gap:.5rem}
      #results{margin:.85rem 0;scroll-margin-top:.75rem}
      code{color:var(--link);overflow-wrap:anywhere}
    </style></head><body><main>
      <h1>Security Operations</h1>
      <nav aria-label="Purple Team">
        <a href="/admin/purple-team">Tools</a><span aria-current="page">Operations</span>
        <a href="/api/admin/audit">Admin audit</a><a href="/api/admin/login-attempts">Sign-in activity</a>
      </nav>
      ${page.notice ? `<p class="notice" role="status">${escapeHtml(page.notice)}</p>` : ""}
      <section class="panel" aria-labelledby="noc-title">
        <div class="heading"><h2 id="noc-title">NOC · Globe health</h2>
          <span class="status ${page.room ? "enabled" : "unknown"}">${page.room ? "Room responding" : "Room unavailable"}</span></div>
        <p>Default Live Feed room · Snapshot <time datetime="${escapeHtml(page.checkedAt)}">${escapeHtml(timeLabel(page.checkedAt))}</time>${page.edge ? " · Edge " + escapeHtml(page.edge) : ""}</p>
        <dl class="metrics">${metrics.map(([label, value]) =>
          `<div><dt>${label}</dt><dd>${value ?? "Unknown"}</dd></div>`).join("")}</dl>
        <div class="controls">
          <a href="${OPERATIONS_PATH}">Refresh snapshot</a>
          ${tool("health", "Run service checks")}
        </div>
      </section>
      <div class="grid">
        <section class="panel" aria-labelledby="exercise-title">
          <h2 id="exercise-title">Run an exercise</h2>
          <p>Use disposable identities and a local exercise room to validate session and Live Feed controls.</p>
          ${tool("revocation", "Revoke and retest")}
          ${tool("isolation", "Run Live Feed isolation drill")}
          ${tool("rehearsal", "Rehearse detection")}
        </section>
        <section class="panel" aria-labelledby="policy-title">
          <h2 id="policy-title">Policy preview</h2>
          <p>Compare proposed controls with expected decisions on built-in fixtures.</p>
          <form method="post" action="${OPERATIONS_PATH}#results">
            <label><input type="checkbox" name="fingerprint"${policy.requireFingerprint ? " checked" : ""}> Require approved fingerprint</label>
            <label><input type="checkbox" name="same_origin"${policy.sameOrigin ? " checked" : ""}> Require same-origin submissions</label>
            <label>Requests per fixture window <input type="number" name="quota" min="1" max="20" value="${policy.quota}" required></label>
            <button name="tool" value="preview">Preview policy</button>
          </form>
        </section>
        <section class="panel" aria-labelledby="containment-title">
          <h2 id="containment-title">Live containment</h2>
          <p>New peer requests <span class="status ${page.paused === null ? "unknown" : page.paused ? "paused" : "enabled"}">${page.paused === null ? "Unknown" : page.paused ? "Paused" : "Enabled"}</span></p>
          <p>Unlock Admin with your device key to revoke a selected session, verify disconnection, or pause peer requests.</p>
          <p><a class="action-link" href="/?admin=containment">Open containment controls</a></p>
        </section>
      </div>
      ${result ? `<section class="panel" id="results">
        <h2>${escapeHtml(result.title)}</h2>
        ${result.runId ? `<p>Exercise <code>${escapeHtml(result.runId)}</code> · <a href="/api/admin/audit">Audit receipt</a></p>` : ""}
        ${showChecks(result.findings)}
      </section>` : ""}
      <section class="panel" id="inbox" aria-labelledby="soc-title">
        <div class="heading"><h2 id="soc-title">SOC · Alert inbox</h2>${tool("evaluate", "Evaluate recent events", "inbox")}</div>
        <p>On-demand sample of up to ${RECENT_LOGIN_LIMIT} sign-in and ${RECENT_AUDIT_LIMIT} sealed audit records. Exercise alerts are labeled.</p>
        ${page.inbox === null ? "<p>Alert storage is unavailable.</p>" : page.inbox.length
          ? `<ul class="alert-list">${page.inbox.map(renderAlert).join("")}</ul>` : "<p>No alerts in the inbox.</p>"}
      </section>
    </main></body></html>`, { status: page.status ?? 200, headers });
}
