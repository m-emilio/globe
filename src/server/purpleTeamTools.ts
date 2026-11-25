import type { ToolFinding } from "./verifiedDomainScan";

export const PURPLE_TEAM_PATH = "/admin/purple-team";

type SecurityHeadersFn = (headers: Headers) => void;
type Dispatch = (request: Request) => Promise<Response>;

export type ToolResult =
  | { tool: "web"; hostname: string; findings: ToolFinding[] }
  | { tool: "access"; findings: ToolFinding[] };

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

function showFindings(result: ToolResult): string {
  const labels = { pass: "Pass", review: "Review", unknown: "Inconclusive" };
  const title = result.tool === "web" ? "Results for " + result.hostname : "Globe access checks";
  return `<section id="results" class="panel results" aria-labelledby="results-title" tabindex="-1">
    <h2 id="results-title">${escapeHtml(title)}</h2>
    <ul class="checks">${result.findings.map(({ check, status, evidence, remediation }) => `
      <li>
        <div class="check-head"><strong>${escapeHtml(check)}</strong><span class="status ${status}">${labels[status]}</span></div>
        <p>${escapeHtml(evidence)}</p>
        ${remediation ? `<p class="fix">${escapeHtml(remediation)}</p>` : ""}
      </li>`).join("")}</ul>
  </section>`;
}

export function purpleTeamToolsPage(domains: string[], result?: ToolResult, applySecurityHeaders?: SecurityHeadersFn): Response {
  const headers = new Headers({
    "content-type": "text/html; charset=utf-8",
    "cache-control": "private, no-store",
    vary: "Cookie",
    "x-robots-tag": "noindex, nofollow, noarchive",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    "referrer-policy": "same-origin",
  });
  applySecurityHeaders?.(headers);
  const selected = result?.tool === "web" ? result.hostname : domains[0];
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
    </style></head><body><main>
      <h1>Purple Team</h1>
      <nav aria-label="Purple Team">
        <span aria-current="page">Tools</span>
        <a href="/admin/purple-team/recon">Recon</a>
        <a href="/admin/purple-team/vulnerabilities">Advisory lookup</a>
        <a href="/admin/purple-team/dependency-audit">Dependency audit</a>
        <a href="/admin/purple-team/assessment">Assessment</a>
      </nav>
      <div class="grid">
        <section class="panel" id="website-controls" aria-labelledby="website-title">
          <h2 id="website-title">Website controls</h2>
          <p>Check a verified hostname’s home page for HTTPS redirection, security headers, cookie flags, mixed content, and certificate transparency expiry.</p>
          ${domains.length ? `
            <form method="post" action="/admin/purple-team#results">
              <label for="hostname">Verified hostname</label>
              <div class="controls">
                <select id="hostname" name="hostname" required>
                ${domains.map((domain) => `<option value="${escapeHtml(domain)}"${domain === selected ? " selected" : ""}>${escapeHtml(domain)}</option>`).join("")}
                </select>
                <button name="tool" value="web">${result?.tool === "web" ? "Rerun checks" : "Run checks"}</button>
              </div>
            </form>` : `<p>Add hostnames you have verified to the Worker’s <code>VERIFIED_SCAN_DOMAINS</code> setting.</p>`}
        </section>
        <section class="panel" id="access-controls" aria-labelledby="access-title">
          <h2 id="access-title">Globe access controls</h2>
          <p>Check sign-in enforcement, allowed methods, cross-origin form protection, and private caching on this console.</p>
          <form method="post" action="/admin/purple-team#results">
            <button name="tool" value="access">${result?.tool === "access" ? "Rerun access checks" : "Test admin controls"}</button>
          </form>
        </section>
      </div>
      ${result ? showFindings(result) : ""}
    </main></body></html>`, { headers });
}
