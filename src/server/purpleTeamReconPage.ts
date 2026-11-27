import { purpleTeamPage } from "./purpleTeamPage";
import { RECON_PATH, type CertificateResults, type DnsRecordGroup, type ReconResults } from "./purpleTeamRecon";
import { escapeHtml } from "./purpleTeamTools";
import { OPERATIONS_PATH } from "./securityOperationsModel";

type ReconPageData = {
  domain: string;
  results?: ReconResults;
  notice?: string;
  status?: number;
};

function renderDns(records: DnsRecordGroup[]): string {
  return `<section class="panel" aria-labelledby="dns-title">
    <h2 id="dns-title">DNS and mail records</h2>
    <p class="small">Source · Cloudflare Public DNS</p>
    <dl class="dns-results">
      ${records.map(({ label, values, limited }) => `<div>
        <dt>${escapeHtml(label)}</dt>
        <dd>${values === null ? '<span class="status unknown">Lookup unavailable</span>'
          : values.length === 0 ? "No record returned"
          : values.map(value => `<code>${escapeHtml(value)}</code>`).join("")}
        ${limited ? '<p class="small">Extra values or long records were shortened.</p>' : ""}</dd>
      </div>`).join("")}
    </dl>
  </section>`;
}

function renderCertificateLog(result: CertificateResults | null): string {
  return `<section class="panel" aria-labelledby="ct-title">
    <h2 id="ct-title">Certificate Transparency</h2>
    <p class="small">Logged certificates · SSLMate Cert Spotter</p>
    ${result === null ? '<p class="status unknown">Certificate log unavailable</p>'
    : result.recordCount === 0 ? "<p>No matching certificate entries returned.</p>"
    : `<details open>
      <summary>Logged DNS names (${result.nameCount})</summary>
      <ul class="names">${result.names.map(name => `<li><code>${escapeHtml(name)}</code></li>`).join("")}</ul>
      ${result.nameCount > result.names.length ? `<p class="small">Showing ${result.names.length} names.</p>` : ""}
    </details>
    <p class="small">Showing ${result.records.length} of ${result.recordCount} returned certificates. Dates in UTC.</p>
    <ul class="rows">${result.records.map(record => `<li>
      <strong><code>${escapeHtml(record.names[0])}</code></strong>
      ${record.names.length > 1 ? ` <span class="small">+${record.names.length - 1} more</span>` : ""}
      <p>${escapeHtml(record.issuer ?? "Issuer unknown")}</p>
      <p class="small">Issued ${record.issued ?? "Unknown"} · Expires ${record.expires ?? "Unknown"}</p>
      ${record.revoked ? '<span class="status review">Revoked in source</span>' : ""}
    </li>`).join("")}</ul>`}
  </section>`;
}

export function reconPage(page: ReconPageData, applySecurityHeaders: (headers: Headers) => void): Response {
  const content = `${page.notice ? `<p class="notice" role="status">${escapeHtml(page.notice)}</p>` : ""}
    <section class="panel">
      <form class="domain-form" method="post" action="${RECON_PATH}" aria-describedby="recon-help">
        <label for="domain">Public domain</label>
        <div class="query">
          <input id="domain" name="domain" type="text" inputmode="url" placeholder="example.com" value="${escapeHtml(page.domain)}"
            maxlength="254" autocomplete="off" autocapitalize="none" spellcheck="false" required>
          <button type="submit">Run recon</button>
        </div>
        <p id="recon-help" class="small">Look up DNS, email policies, and certificate log entries.</p>
      </form>
    </section>
    ${page.results ? `<div class="recon-results">${renderDns(page.results.dns)}
      ${renderCertificateLog(page.results.certificates)}</div>` : ""}`;
  return purpleTeamPage({
    title: "Purple Team Recon",
    navigation: `<a href="${OPERATIONS_PATH}">Globe operations</a>`,
    content,
    status: page.status,
  }, applySecurityHeaders);
}
