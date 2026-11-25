import { PROOF_LABEL } from "./purpleTeamDns";
import { compareWithBaseline, type HostView } from "./purpleTeamHost";
import type { ToolFinding } from "./verifiedDomainScan";

export const PURPLE_TEAM_PATH = "/admin/purple-team";

type SecurityHeadersFn = (headers: Headers) => void;
type Dispatch = (request: Request) => Promise<Response>;

export type ToolResult = {
  title: string;
  findings: ToolFinding[];
  runId?: string;
};

type ToolsPage = {
  hostnames: string[];
  view: HostView | null;
  result?: ToolResult;
  notice?: string;
  status?: number;
};

export async function runAdminControlChecks(request: Request, dispatch: Dispatch): Promise<ToolFinding[]> {
  const sessionHeaders = new Headers();
  for (const name of ["cookie", "authorization", "x-session-token"]) {
    const value = request.headers.get(name);
    if (value) sessionHeaders.set(name, value);
  }
  const sourceIp = request.headers.get("cf-connecting-ip");
  const anonymousHeaders = new Headers();
  if (sourceIp) {
    anonymousHeaders.set("cf-connecting-ip", sourceIp);
    sessionHeaders.set("cf-connecting-ip", sourceIp);
  }

  const crossOriginHeaders = new Headers(sessionHeaders);
  crossOriginHeaders.set("origin", "https://purple-team.invalid");
  const probes = [
    {
      check: "Require sign-in",
      expected: 401,
      send: new Request(new URL(PURPLE_TEAM_PATH, request.url), { headers: anonymousHeaders }),
      remediation: "Check that the console route requires an admin session before rendering.",
    },
    {
      check: "Reject unsupported methods",
      expected: 405,
      send: new Request(new URL(PURPLE_TEAM_PATH + "/osv", request.url), { method: "POST", headers: anonymousHeaders }),
      remediation: "Limit the advisory route to GET and HEAD.",
    },
    {
      check: "Reject cross-origin submissions",
      expected: 403,
      send: new Request(new URL(PURPLE_TEAM_PATH, request.url), { method: "POST", headers: crossOriginHeaders }),
      remediation: "Require an Origin matching the console before processing tool submissions.",
    },
    {
      check: "Keep admin pages private",
      expected: 200,
      send: new Request(new URL(PURPLE_TEAM_PATH, request.url), { headers: sessionHeaders }),
      remediation: "Apply private, no-store caching and deny framing on the console.",
    },
  ];

  const findings: ToolFinding[] = [];
  // Dispatch fixed same-Worker routes locally. Session headers stay inside the Worker.
  for (const [index, { check, expected, send, remediation }] of probes.entries()) {
    try {
      const response = await dispatch(send);
      const cache = response.headers.get("cache-control") ?? "";
      const directives = cache.toLowerCase().split(",").map((value) => value.trim());
      const csp = response.headers.get("content-security-policy") ?? "";
      const blocksFraming = /(?:^|;)\s*frame-ancestors\s+'none'\s*(?:;|$)/i.test(csp);
      await response.body?.cancel();
      const checkHeaders = index === probes.length - 1;
      const ok = response.status === expected &&
        (!checkHeaders || (directives.includes("private") && directives.includes("no-store") && blocksFraming));
      const evidence = checkHeaders
        ? "HTTP " + response.status + ". Cache-Control: " + (cache || "missing") +
          ". Framing: " + (blocksFraming ? "denied" : "policy missing") + "."
        : "Expected HTTP " + expected + ". Observed HTTP " + response.status + ".";
      findings.push({
        check, status: response.status === 429 ? "unknown" : ok ? "pass" : "review",
        evidence, remediation: response.status === 429 ? "Wait for the admin rate limit to reset and rerun."
          : ok ? undefined : remediation,
      });
    } catch {
      findings.push({ check, status: "unknown", evidence: "The Worker did not return a response. Retry the check." });
    }
  }
  return findings;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character] ?? character,
  );
}

export async function runSignedOutView(request: Request, dispatch: Dispatch): Promise<ToolFinding[]> {
  const pages = [
    ["/", false],
    [PURPLE_TEAM_PATH, true],
    [PURPLE_TEAM_PATH + "/recon", true],
    [PURPLE_TEAM_PATH + "/vulnerabilities", true],
    [PURPLE_TEAM_PATH + "/assessment", true],
    [PURPLE_TEAM_PATH + "/dependency-audit", true],
  ] as const;
  const findings: ToolFinding[] = [];
  for (const [path, guarded] of pages) {
    try {
      const response = await dispatch(new Request(new URL(path, request.url)));
      await response.body?.cancel();
      const allowed = response.status >= 200 && response.status < 300;
      const denied = response.status === 401 || response.status === 403;
      findings.push({
        check: path,
        status: guarded && denied || !guarded && allowed ? "pass"
          : guarded && allowed || !guarded && denied ? "review" : "unknown",
        evidence: "Signed-out request returned HTTP " + response.status + ".",
        remediation: guarded && allowed ? "Review whether this route enforces the admin session and device key." : undefined,
      });
    } catch {
      findings.push({ check: path, status: "unknown", evidence: "The route did not return a usable response." });
    }
  }
  return findings;
}

function showChecks(findings: ToolFinding[]): string {
  const labels = { pass: "Pass", review: "Review", unknown: "Unknown" };
  return `<ul class="checks">${findings.map(({ check, status, evidence, remediation }) => `
    <li>
      <div class="check-head"><strong>${escapeHtml(check)}</strong><span class="status ${status}">${labels[status]}</span></div>
      <p>${escapeHtml(evidence)}</p>
      ${remediation ? `<p class="fix">${escapeHtml(remediation)}</p>` : ""}
    </li>`).join("")}</ul>`;
}

function button(tool: string, label: string, hostname?: string): string {
  return `<form method="post" action="/admin/purple-team#results">
    ${hostname ? `<input type="hidden" name="hostname" value="${escapeHtml(hostname)}">` : ""}
    <button class="secondary" name="tool" value="${tool}">${label}</button>
  </form>`;
}

function showHost(hostnames: string[], view: HostView | null): string {
  const record = view?.state;
  const chosen = record?.hostname;
  const allHosts = `<form class="host-list" method="get" action="/admin/purple-team">
      <label for="host">Enrolled hostname</label>
      <div class="controls"><select id="host" name="host">${hostnames.map((hostname) =>
        `<option${hostname === chosen ? " selected" : ""}>${escapeHtml(hostname)}</option>`,
      ).join("")}</select><button class="secondary">View hostname</button></div>
    </form>`;
  if (!record) return hostnames.length ? allHosts : "";
  const status = { pending: "Pending proof", verified: "Verified", paused: "Verification paused", revoked: "Revoked" };
  const next = record.nextScanAt === null ? "" : new Date(record.nextScanAt).toISOString();
  const proof = record.proof?.result === "missing" ? "TXT challenge missing"
    : record.proof?.result === "unavailable" ? "DNS unavailable" : "TXT challenge matched";
  return `${allHosts}<div class="host-detail">
      <h3>${escapeHtml(record.hostname)} · ${status[record.status]}</h3>
      ${record.verified ? `<p>Verified ${escapeHtml(record.verified.at)} by ${escapeHtml(record.verified.by)}.</p>` : ""}
      ${record.revoked ? `<p>Revoked ${escapeHtml(record.revoked.at)} by ${escapeHtml(record.revoked.by)}.</p>` : ""}
      ${record.proof ? `<p>Last DNS check ${escapeHtml(record.proof.checkedAt)} · ${proof}.</p>` : ""}
      ${record.status === "revoked"
        ? button("register", "Issue a new challenge", record.hostname)
        : `<p>Create a TXT record at <code>${PROOF_LABEL + escapeHtml(record.hostname)}</code>
          with value <code>${escapeHtml(record.challenge)}</code>.</p>
          <div class="controls">${button("verify", record.status === "verified" ? "Recheck DNS" : "Verify hostname", record.hostname)}
            ${record.status === "verified" ? button("web", view?.report ? "Retest" : "Run web checks", record.hostname) : ""}
            ${button("revoke", "Revoke verification", record.hostname)}</div>`}
      ${record.status === "verified" || record.schedule !== "off" ? `
        <form method="post" action="/admin/purple-team">
          <label for="schedule">Recurring scans</label>
          <input type="hidden" name="hostname" value="${escapeHtml(record.hostname)}">
          <div class="controls"><select id="schedule" name="schedule">
            <option value="off"${record.schedule === "off" ? " selected" : ""}>Off</option>
            ${record.status === "verified" ? `
              <option value="daily"${record.schedule === "daily" ? " selected" : ""}>Daily</option>
              <option value="weekly"${record.schedule === "weekly" ? " selected" : ""}>Weekly</option>`
              : `<option value="${record.schedule}" selected disabled>Paused · ${record.schedule}</option>`}
          </select><button class="secondary" name="tool" value="schedule">Save schedule</button></div>
          ${next ? `<p>Next scan ${escapeHtml(next)}.</p>` : ""}
        </form>` : ""}
    </div>`;
}

function showWebReport(view: HostView | null, showAnchor: boolean): string {
  if (!view?.state || !view.history.length) return "";
  const { report, history, baseline } = view;
  const hostname = view.state.hostname;
  const changes = report && baseline && report.id !== baseline.report.id
    ? compareWithBaseline(report, baseline.report) : null;
  const labels = { new: "New", recurring: "Recurring", resolved: "Resolved", unknown: "Unknown" };
  return `<section${showAnchor ? ' id="results"' : ''} class="panel host-report" aria-labelledby="report-title">
    <h2 id="report-title">Web checks for ${escapeHtml(hostname)}</h2>
    ${baseline ? `<p class="report-meta">Baseline from ${escapeHtml(baseline.report.at)}.
      Approved ${escapeHtml(baseline.at)} by ${escapeHtml(baseline.by)}.</p>` : ""}
    ${report ? `<p class="report-meta">${escapeHtml(report.at)} · ${report.source === "manual" && report.actor
      ? "Manual scan by " + escapeHtml(report.actor) : "Scheduled scan"}.</p>
      ${changes ? `<h3>Changes from baseline</h3>${changes.length
        ? `<ul class="changes">${changes.map((item) => `<li>${labels[item.status]} · ${escapeHtml(item.check)}</li>`).join("")}</ul>`
        : "<p>No review findings changed.</p>"}` : ""}
      ${showChecks(report.findings)}
      ${baseline?.report.id === report.id ? '<p>This scan is the approved baseline.</p>' : `
        <form method="post" action="/admin/purple-team#results">
          <input type="hidden" name="hostname" value="${escapeHtml(hostname)}">
          <input type="hidden" name="report" value="${escapeHtml(report.id)}">
          <button name="tool" value="baseline">Approve this baseline</button>
        </form>`}` : "<p>This scan is unavailable.</p>"}
    <div class="history"><h3>Scan history</h3><ul>
      ${history.map((entry) => `<li><a href="/admin/purple-team?host=${encodeURIComponent(hostname)}&amp;report=${encodeURIComponent(entry.id)}#results">
        ${escapeHtml(entry.at)}</a> · ${entry.actor ? escapeHtml(entry.actor) : "Scheduled"}</li>`).join("")}
    </ul></div>
  </section>`;
}

export function purpleTeamToolsPage(page: ToolsPage, applySecurityHeaders?: SecurityHeadersFn): Response {
  const headers = new Headers({
    "content-type": "text/html; charset=utf-8",
    "cache-control": "private, no-store",
    vary: "Cookie",
    "x-robots-tag": "noindex, nofollow, noarchive",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    "referrer-policy": "same-origin",
  });
  applySecurityHeaders?.(headers);
  const { hostnames, view, result, notice } = page;
  return new Response(`<!doctype html><html lang="en"><head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Purple Team Tools</title>
    <style>
      :root{color-scheme:dark;--bg:#100c19;--panel:#191328;--border:#3c3052;--muted:#c4b8d5;--text:#f3ebff;--accent:#cba8ff}
      *{box-sizing:border-box}
      body{margin:0;background:radial-gradient(ellipse at top left,#271639,transparent 35rem),var(--bg);color:var(--text);font:1rem/1.55 system-ui,sans-serif}
      main{max-width:66rem;margin:0 auto;padding:clamp(1rem,4vw,3rem)}
      h1{margin:.55rem 0 1.4rem;font-size:clamp(2rem,5vw,3.35rem);line-height:1.05;letter-spacing:-.04em}
      h2{margin:0;font-size:1.2rem;line-height:1.3}
      p{margin:.55rem 0;color:var(--muted)}
      a{color:var(--accent);text-underline-offset:.22em}
      nav{display:flex;flex-wrap:wrap;gap:.4rem 1.2rem;margin:0 0 1.5rem;padding:0 0 1rem;border-bottom:1px solid var(--border)}
      nav a,nav span{font-size:.94rem}
      nav [aria-current]{color:var(--text);font-weight:700}
      .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,20rem),1fr));gap:.85rem}
      .panel{display:flex;flex-direction:column;gap:.45rem;padding:1.25rem;border:1px solid var(--border);border-radius:1rem;background:var(--panel)}
      form{margin-top:auto;padding-top:.6rem}
      label{display:block;font-size:.9rem;font-weight:650;margin-bottom:.3rem}
      select,button{min-height:2.65rem;font:inherit;padding:.5rem .85rem;border-radius:.55rem;border:1px solid var(--border)}
      select{min-width:10rem;max-width:100%;color:var(--text);background:#110e1b}
      .controls{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem}
      button{background:#c39cff;color:#1b0c2d;border-color:#c39cff;font-weight:700;cursor:pointer}
      button:hover{background:#d8bbff}
      :focus-visible{outline:2px solid #f8daff;outline-offset:.2rem}
      .results{margin-top:1rem;scroll-margin-top:1rem}
      .checks{list-style:none;margin:0;padding:0}
      .checks li{padding:.8rem 0;border-bottom:1px solid var(--border);overflow-wrap:anywhere}
      .checks li:last-child{border-bottom:0;padding-bottom:0}
      .check-head{display:flex;flex-wrap:wrap;align-items:baseline;gap:.45rem}
      .status{font-size:.75rem;font-weight:700;border:1px solid currentColor;border-radius:1rem;padding:.02rem .5rem}
      .pass{color:#99edc1}.review{color:#ffcf88}.unknown{color:#ddbdff}
      .checks p{margin:.2rem 0;font-size:.92rem}
      .checks .fix{color:var(--text)}
      code{font: .9em ui-monospace,monospace;color:var(--accent);overflow-wrap:anywhere}
      form + form,.host-detail,.host-list{margin-top:.85rem}
      .host-report,.history{margin-top:1.1rem}
      .host-detail h3{margin:.35rem 0;font-size:1.05rem}
      .host-detail code{display:inline-block;max-width:100%;overflow-wrap:anywhere}
      input{min-height:2.65rem;max-width:100%;font:inherit;background:#110e1b;color:var(--text);border:1px solid var(--border);border-radius:.55rem;padding:.5rem}
      button.secondary{background:#2b203e;color:var(--text);border-color:#644982}
      button.secondary:hover{background:#3f2b59}
      .notice{padding:.65rem .8rem;border:1px solid var(--border);border-radius:.6rem;color:var(--text)}
      .report-meta{font-size:.9rem}
      .changes,.history ul{padding-left:1.2rem}
    </style></head><body><main>
      <h1>Purple Team</h1>
      <nav aria-label="Purple Team">
        <span aria-current="page">Tools</span>
        <a href="/admin/purple-team/recon">Recon</a>
        <a href="/admin/purple-team/vulnerabilities">Advisory lookup</a>
        <a href="/admin/purple-team/dependency-audit">Dependency audit</a>
        <a href="/admin/purple-team/assessment">Assessment</a>
      </nav>
      ${notice ? `<p class="notice" role="status">${escapeHtml(notice)}</p>` : ""}
      <div class="grid">
        <section class="panel" id="website-controls" aria-labelledby="website-title">
          <h2 id="website-title">Verified website controls</h2>
          <p>Verify an exact public hostname with DNS, then check its root response and public Certificate Transparency records.</p>
          <form method="post" action="/admin/purple-team">
            <label for="new-host">Public hostname</label>
            <div class="controls"><input id="new-host" name="hostname" required maxlength="253" autocomplete="off" spellcheck="false">
              <button name="tool" value="register">Add hostname</button></div>
          </form>
          ${showHost(hostnames, view)}
        </section>
        <section class="panel" id="access-controls" aria-labelledby="access-title">
          <h2 id="access-title">Globe control drills</h2>
          <p>Exercise the console’s controls and verify the matching audit evidence.</p>
          ${button("visibility", "View Globe as signed out")}
          ${button("drill", "Run access and containment drill")}
          ${button("canary", "Run canary drill")}
          ${button("access", "Test admin route controls")}
        </section>
      </div>
      ${result ? `<section id="results" class="panel results" aria-labelledby="result-title">
        <h2 id="result-title">${escapeHtml(result.title)}</h2>
        ${result.runId ? `<p>Exercise <code>${escapeHtml(result.runId)}</code> · <a href="/api/admin/audit">Globe audit log</a></p>` : ""}
        ${showChecks(result.findings)}
      </section>` : ""}
      ${showWebReport(view, !result)}
    </main></body></html>`, { headers, status: page.status ?? 200 });
}
