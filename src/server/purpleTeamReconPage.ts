import type { ConnectionDetails } from "../connectionSignals";
import type { ReconAddress } from "../reconAddress";
import type { IpRecon } from "./reconIp";
import type { MailPolicyReview } from "./purpleTeamMail";
import type { ReconSnapshot, ReconSnapshotInfo } from "./purpleTeamHost";
import { purpleTeamPage } from "./purpleTeamPage";
import { RECON_CERTIFICATE_PATH, RECON_PATH, type CertificateResults, type DnsRecordGroup, type ReconResults } from "./purpleTeamRecon";
import { escapeHtml } from "./purpleTeamTools";
import { OPERATIONS_PATH } from "./securityOperationsModel";

type OwnConnection = Omit<ConnectionDetails, "sessionCookie"> & { address: ReconAddress | null };

export type ReconPageData = {
  domain: string;
  results?: ReconResults;
  notice?: string;
  status?: number;
  snapshot?: ReconSnapshotInfo;
  previous?: ReconSnapshot | null;
  entries?: ReconSnapshotInfo[];
  savedDomains?: string[];
  download?: boolean;
  ownConnection?: OwnConnection;
  ipResults?: IpRecon;
};

function labelRows(rows: [string, string][]): string {
  return `<dl class="connection-rows">${rows.map(([label, value]) =>
    `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value || "Unavailable")}</dd>`).join("")}</dl>`;
}

function renderOwnConnection(connection: OwnConnection): string {
  const address = connection.address?.value;
  const network = [connection.networkOrganization, connection.networkAsn && "AS" + connection.networkAsn].filter(Boolean).join(" · ");
  const legacyTls = /^(?:SSLv?[23](?:\\.0)?|TLSv?1(?:\\.[01])?)$/i.test(connection.tlsVersion ?? "");
  return `<section class="panel" aria-labelledby="own-connection-title">
    <h2 id="own-connection-title">My connection</h2>
    ${labelRows([
      ["IP seen by Globe", address ?? ""],
      ["HTTP / TLS", [connection.httpProtocol, connection.tlsVersion].filter(Boolean).join(" · ")],
      ["TLS cipher", connection.tlsCipher ?? ""],
      ["Network", network],
      ["Cloudflare edge", [connection.edge, connection.country].filter(Boolean).join(" · ")],
      ["Edge TCP estimate", connection.edgeTcpMs === null ? "" : connection.edgeTcpMs + " ms"],
    ])}
    ${legacyTls ? '<p><span class="status review">Legacy TLS version observed</span></p>' : ""}
    ${address ? `<form method="post" action="${RECON_PATH}">
      <button type="submit" name="domain" value="${escapeHtml(address)}">Look up my IP</button>
    </form>` : ""}
  </section>`;
}

function renderIpResults(result: IpRecon): string {
  const { address, routing, names } = result;
  const subject = escapeHtml(address.value);
  const inspector = RECON_CERTIFICATE_PATH + "?name=" + encodeURIComponent(address.value);
  return `<section class="panel" aria-labelledby="ip-recon-title">
    <h2 id="ip-recon-title">IPv${address.family} address ${subject}</h2>
    ${address.isPublic ? `
      <p class="small">Routing · RIPEstat. Reverse DNS · Cloudflare Public DNS.</p>
      ${labelRows([
        ["Routed prefix", routing ? routing.prefix ?? "No prefix returned" : "Lookup unavailable"],
        ["Announcing ASNs", routing ? routing.asns.map(asn => "AS" + asn).join(", ") || "No ASNs returned" : "Lookup unavailable"],
      ])}
      <h3>Reverse DNS</h3>
      ${names === null ? "<p>Lookup unavailable.</p>" : names.length === 0 ? "<p>No public PTR name returned.</p>"
        : `<ul class="names">${names.map(name =>
          `<li><a href="${RECON_PATH}?t=${encodeURIComponent(name)}"><code>${escapeHtml(name)}</code></a></li>`).join("")}</ul>
          <p class="small">Open a PTR name to look up DNS and logged certificates for that hostname.</p>`}`
      : "<p>This address is outside public unicast space.</p>"}
    <p><a href="${inspector}">Inspect a certificate for this IP</a></p>
  </section>`;
}

function logExpiry(expires: string | null, observedAt: string): string {
  if (!expires) return "";
  const remainingDays = (Date.parse(expires) - Date.parse(observedAt.slice(0, 10))) / 86_400_000;
  if (!Number.isFinite(remainingDays)) return "";
  const label = remainingDays < 0 ? "Expired" : remainingDays === 0 ? "Expires today (UTC)"
    : remainingDays <= 30 ? "Expires within 30 days" : "";
  return label ? `<span class="status review">${label}</span>` : "";
}

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

function renderCertificateLog(result: CertificateResults | null, observedAt: string): string {
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
      ${logExpiry(record.expires, observedAt)}
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

export function reconCertificatePage(expected: string, applySecurityHeaders: (headers: Headers) => void): Response {
  const content = `<section class="panel">
    <p>Open a public certificate file or paste a PEM certificate. Inspection runs in this browser.</p>
    <form class="domain-form certificate-form" id="certificate-form">
      <label for="certificate-name">Expected hostname or IP address (optional)</label>
      <div class="query"><input id="certificate-name" value="${escapeHtml(expected)}" type="text" maxlength="254"
        placeholder="example.com" autocomplete="off" spellcheck="false"></div>
      <label for="certificate-file">Certificate file</label>
      <input id="certificate-file" type="file" accept=".pem,.crt,.cer,.der,application/pkix-cert">
      <label for="certificate-pem">PEM certificate</label>
      <textarea id="certificate-pem" maxlength="32768" rows="7" spellcheck="false" autocomplete="off"
        placeholder="-----BEGIN CERTIFICATE-----"></textarea>
      <button type="submit" id="inspect-certificate" disabled>Inspect certificate</button>
    </form>
    <p id="certificate-status" class="certificate-status" role="status"></p>
    <noscript><p>Enable JavaScript in this tab to inspect a certificate locally.</p></noscript>
  </section>
  <section id="certificate-result" class="panel" aria-labelledby="certificate-result-title" hidden>
    <h2 id="certificate-result-title">Certificate findings</h2>
    <p class="small">Source · Supplied certificate. Checks cover its dates, names, key, and signature algorithm.</p>
    <dl id="certificate-metadata" class="connection-rows"></dl>
    <ul id="certificate-findings" class="checks"></ul>
  </section>`;
  return purpleTeamPage({
    title: "Certificate inspector", navigation: `<a href="${RECON_PATH}">Recon</a>`, content, certificateInspector: true,
  }, applySecurityHeaders);
}

export function reconPage(page: ReconPageData, applySecurityHeaders: (headers: Headers) => void): Response {
  const results = page.results
    ? `${page.snapshot ? `<section class="panel"><h2>${escapeHtml(page.domain)}</h2>
      <p class="small">Saved ${snapshotTime(page.snapshot.at)}</p>
      ${!page.download ? `<a href="${snapshotLink(page.domain, page.snapshot.id)}&amp;download=1">Download report</a>` : ""}
    </section>` : ""}
    <div class="recon-results">${renderDns(page.results.dns)}${renderCertificateLog(page.results.certificates, page.snapshot?.at ?? new Date().toISOString())}</div>
    ${page.results.mail ? renderMail(page.results.mail) : ""}
    ${page.previous ? renderComparison(page.results, page.previous) : ""}`
    : "";
  const form = `<section class="panel">
    <form class="domain-form" method="post" action="${RECON_PATH}" aria-describedby="recon-help">
      <label for="domain">Public domain or IP address</label>
      <div class="query">
        <input id="domain" name="domain" type="text" inputmode="url" placeholder="example.com" value="${escapeHtml(page.domain)}"
          maxlength="254" autocomplete="off" autocapitalize="none" spellcheck="false" required>
        <button type="submit">Run recon</button>
      </div>
      <label class="save-option"><input name="save" value="1" type="checkbox"> Save domain snapshot</label>
      <details class="mail-options"${page.results?.mail ? " open" : ""}>
        <summary>Email policy details</summary>
        <label class="save-option"><input name="mail" value="1" type="checkbox"${page.results?.mail ? " checked" : ""}> Review mail policy details</label>
        <label for="selector">DKIM selector (optional)</label>
        <div class="query"><input id="selector" name="selector" value="${escapeHtml(page.results?.mail?.dkim?.selector ?? "")}"
          maxlength="63" placeholder="selector1" autocomplete="off" spellcheck="false"></div>
      </details>
      <p id="recon-help" class="small">Look up public DNS, routed IP prefixes, and certificate log entries.</p>
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
      <a href="${RECON_CERTIFICATE_PATH}">Certificate inspector</a><a href="${OPERATIONS_PATH}">Globe operations</a>`,
    content: page.download ? results : notice +
      `<div class="recon-toolbar">${form}${page.ownConnection ? renderOwnConnection(page.ownConnection) : ""}</div>` +
      (page.ipResults ? renderIpResults(page.ipResults) : "") + results + history + savedDomains,
    status: page.status,
  }, applySecurityHeaders);
  if (page.download) response.headers.set("Content-Disposition", `attachment; filename="globe-recon-${page.domain}.html"`);
  return response;
}
