import type { MailPolicyReview } from "./purpleTeamMail";
import type { ReconSnapshot, ReconSnapshotInfo } from "./purpleTeamHost";
import { purpleTeamPage } from "./purpleTeamPage";
import { RECON_PATH, type CertificateResults, type DnsRecordGroup, type ReconResults } from "./purpleTeamRecon";
import { escapeHtml } from "./purpleTeamTools";
import { OPERATIONS_PATH } from "./securityOperationsModel";

type ReconPageData = {
  domain: string;
  results?: ReconResults;
  notice?: string;
  status?: number;
  snapshot?: ReconSnapshotInfo;
  previous?: ReconSnapshot | null;
  entries?: ReconSnapshotInfo[];
  savedDomains?: string[];
  download?: boolean;
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

function renderMail({ spf, dmarc, dkim }: MailPolicyReview): string {
  const states = { published: "Published", none: "No record returned", multiple: "Multiple policies", unknown: "Unavailable" };
  return `<section class="panel" aria-labelledby="mail-title">
    <h2 id="mail-title">Email policy details</h2>
    <h3>SPF policy links</h3>
    <p>${spf.terms} DNS lookup terms across ${spf.policies.length} policies checked. SPF allows 10 DNS lookup terms per evaluation.</p>
    ${spf.terms > 10 ? '<p class="status review">Review lookup budget</p>' : ""}
    ${spf.partial ? "<p>Some policy links were unavailable, cyclic, or exceeded the lookup budget.</p>" : ""}
    <ul class="rows">${spf.policies.map(policy => `<li>
      <strong>${escapeHtml(policy.domain)}</strong>
      ${policy.parent ? " · Linked by " + escapeHtml(policy.parent) : ""}
      · ${states[policy.status]}${policy.status === "published" ? " · " + policy.terms + " lookup terms" : ""}
    </li>`).join("")}</ul>
    <h3>DMARC report destination domains</h3>
    <p>${dmarc.status === "unknown" ? "Unavailable" : dmarc.domains.length
      ? dmarc.domains.map(escapeHtml).join(", ") : "No destination domains returned"}
      ${dmarc.unknownDestinations ? " · " + dmarc.unknownDestinations + " unparsed destination" +
        (dmarc.unknownDestinations === 1 ? "" : "s") : ""}</p>
    ${dkim ? `<h3>DKIM selector</h3><p><code>${escapeHtml(dkim.selector)}</code> · ${dkim.status}</p>` : ""}
  </section>`;
}

function snapshotLink(domain: string, id: string): string {
  return RECON_PATH + "?t=" + encodeURIComponent(domain) + "&amp;snapshot=" + encodeURIComponent(id);
}

function snapshotTime(at: string): string {
  return `<time datetime="${escapeHtml(at)}">${escapeHtml(at.replace("T", " ").slice(0, 19))} UTC</time>`;
}

function renderComparison(current: ReconResults, previous: ReconSnapshot): string {
  const before = new Map(previous.results.dns.map(record => [record.label, record]));
  const comparable = current.dns.flatMap(record => {
    const old = before.get(record.label);
    if (!old?.values || !record.values || old.limited || record.limited) return [];
    return [{ label: record.label, before: old.values, after: record.values }];
  });
  const currentCt = current.certificates;
  const previousCt = previous.results.certificates;
  if (currentCt && previousCt && currentCt.nameCount === currentCt.names.length && previousCt.nameCount === previousCt.names.length) {
    comparable.push({ label: "Names in returned certificate records", before: previousCt.names, after: currentCt.names });
  }
  const changes = comparable.flatMap(({ label, before, after }) => {
    const oldValues = new Set(before);
    const newValues = new Set(after);
    const added = after.filter(value => !oldValues.has(value));
    const removed = before.filter(value => !newValues.has(value));
    if (!added.length && !removed.length) return [];
    return [`<li><strong>${escapeHtml(label)}</strong>
      ${added.length ? `<p>Added in this result · ${added.map(escapeHtml).join(", ")}</p>` : ""}
      ${removed.length ? `<p>Missing from this result · ${removed.map(escapeHtml).join(", ")}</p>` : ""}
    </li>`];
  });
  return `<section class="panel" aria-labelledby="diff-title">
    <h2 id="diff-title">Changes from previous snapshot</h2>
    <p class="small">Baseline · ${snapshotTime(previous.at)} · ${comparable.length} comparable groups</p>
    ${changes.length ? `<ul class="rows">${changes.join("")}</ul>`
      : `<p>${comparable.length ? "Comparable groups match the previous snapshot." : "Comparable data is unavailable."}</p>`}
  </section>`;
}

export function reconPage(page: ReconPageData, applySecurityHeaders: (headers: Headers) => void): Response {
  const results = page.results
    ? `${page.snapshot ? `<section class="panel"><h2>${escapeHtml(page.domain)}</h2>
      <p class="small">Saved ${snapshotTime(page.snapshot.at)}</p>
      ${!page.download ? `<a href="${snapshotLink(page.domain, page.snapshot.id)}&amp;download=1">Download report</a>` : ""}
    </section>` : ""}
    <div class="recon-results">${renderDns(page.results.dns)}${renderCertificateLog(page.results.certificates)}</div>
    ${page.results.mail ? renderMail(page.results.mail) : ""}
    ${page.previous ? renderComparison(page.results, page.previous) : ""}`
    : "";
  const form = `<section class="panel">
    <form class="domain-form" method="post" action="${RECON_PATH}" aria-describedby="recon-help">
      <label for="domain">Public domain</label>
      <div class="query">
        <input id="domain" name="domain" type="text" inputmode="url" placeholder="example.com" value="${escapeHtml(page.domain)}"
          maxlength="254" autocomplete="off" autocapitalize="none" spellcheck="false" required>
        <button type="submit">Run recon</button>
      </div>
      <label class="save-option"><input name="save" value="1" type="checkbox"> Save snapshot</label>
      <details class="mail-options"${page.results?.mail ? " open" : ""}>
        <summary>Email policy details</summary>
        <label class="save-option"><input name="mail" value="1" type="checkbox"${page.results?.mail ? " checked" : ""}> Review mail policy details</label>
        <label for="selector">DKIM selector (optional)</label>
        <div class="query"><input id="selector" name="selector" value="${escapeHtml(page.results?.mail?.dkim?.selector ?? "")}"
          maxlength="63" placeholder="selector1" autocomplete="off" spellcheck="false"></div>
      </details>
      <p id="recon-help" class="small">Look up DNS, email policies, and certificate log entries.</p>
    </form>
  </section>`;
  const history = page.entries?.length
    ? `<section class="panel" aria-labelledby="history-title">
      <h2 id="history-title">Snapshot history</h2>
      <ul class="rows">${page.entries.map(entry => `<li><a href="${snapshotLink(page.domain, entry.id)}"${
        entry.id === page.snapshot?.id ? ' aria-current="page"' : ""}>${snapshotTime(entry.at)}</a>
        <small> · Saved by ${escapeHtml(entry.by.slice(0, 12))}</small></li>`).join("")}</ul>
    </section>` : "";
  const savedDomains = page.savedDomains?.length ? `<section class="panel" aria-labelledby="saved-domains-title">
    <h2 id="saved-domains-title">Recently saved domains</h2>
    <ul class="rows">${page.savedDomains.map(domain =>
      `<li><a href="${RECON_PATH}?t=${encodeURIComponent(domain)}">${escapeHtml(domain)}</a></li>`).join("")}</ul>
  </section>` : "";
  const notice = page.notice ? `<p class="notice" role="status">${escapeHtml(page.notice)}</p>` : "";
  const response = purpleTeamPage({
    title: page.download ? "Globe domain recon report" : "Purple Team Recon",
    navigation: page.download ? "" : `
      ${page.domain ? `<a href="${RECON_PATH}">Recon home</a>` : ""}
      <a href="${OPERATIONS_PATH}">Globe operations</a>`,
    content: page.download ? results : notice + form + results + history + savedDomains,
    status: page.status,
  }, applySecurityHeaders);
  if (page.download) response.headers.set("Content-Disposition", `attachment; filename="globe-recon-${page.domain}.html"`);
  return response;
}
