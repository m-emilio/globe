import type { ConnectionDetails } from "../connectionSignals";
import type { ReconAddress } from "../reconAddress";
import type { IpRecon } from "./reconIp";
import type { MailPolicyReview } from "./purpleTeamMail";
import type { ReconSnapshot, ReconSnapshotInfo } from "./purpleTeamHost";
import { purpleTeamPage } from "./purpleTeamPage";
import { RECON_CERTIFICATE_PATH, RECON_PATH, type CertificateResults, type DnsRecordGroup, type LoggedCertificate, type ReconResults } from "./purpleTeamRecon";
import { escapeHtml } from "./purpleTeamTools";
import { assessRed, type ExposureHost, type RedAssessment, type RedExtras, type Severity } from "./redTeamRecon";
import { OPERATIONS_PATH, PURPLE_TEAM_ROOT } from "./securityOperationsModel";

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
  extras?: RedExtras;
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
          <p class="small">Open a PTR name for the full DNS lookup.</p>`}`
      : "<p>This address is outside public unicast space.</p>"}
    <p><a href="${inspector}">Inspect a certificate for this IP</a></p>
  </section>`;
}

function daysFromObservation(date: string | null, observedAt: string): number {
  return (Date.parse(date ?? "") - Date.parse(observedAt.slice(0, 10))) / 86_400_000;
}

function logExpiry(expires: string | null, observedAt: string): string {
  const remainingDays = daysFromObservation(expires, observedAt);
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
    ${renderCertificateRows(result.records, observedAt)}`}
  </section>`;
}

function renderCertificateRows(records: LoggedCertificate[], observedAt: string): string {
  return `<ul class="rows">${records.map(record => `<li>
    <strong><code>${escapeHtml(record.names[0])}</code></strong>
    ${record.names.length > 1 ? ` <span class="small">+${record.names.length - 1} more</span>` : ""}
    <p>${escapeHtml(record.issuer ?? "Issuer unknown")}</p>
    <p class="small">Issued ${record.issued ?? "Unknown"} · Expires ${record.expires ?? "Unknown"}</p>
    ${logExpiry(record.expires, observedAt)}
    ${record.revoked ? '<span class="status review">Revoked in source</span>' : ""}
    ${record.matchesAddress === true ? '<span class="status pass">Exact IP listed</span>'
      : record.matchesAddress === false ? '<span class="status">No matching IP identity</span>' : ""}
  </li>`).join("")}</ul>`;
}

function describeCaa(records: DnsRecordGroup | null): string {
  if (!records?.values) return "<p>CAA lookup unavailable.</p>";
  if (!records.values.length) return "<p>No CAA records returned for this query.</p>";
  const properties = records.values.flatMap(record => {
    const match = record.trim().match(/^(\d{1,3})\s+([a-z0-9]+)\s+(?:"([^"]*)"|(\S+))$/i);
    if (!match || Number(match[1]) > 255) return [];
    return [{ flags: Number(match[1]), tag: match[2].toLowerCase(), value: match[3] ?? match[4] }];
  });
  const issuerPolicy = (tag: "issue" | "issuewild", empty: string) => {
    const values = properties.filter(property => property.tag === tag).map(property => property.value.trim());
    if (!values.length) return empty;
    return [...new Set(values)].map(value => value.split(";")[0].trim() ? value : "No issuer authorized by this record").join(" · ");
  };
  const critical = properties.filter(property => (property.flags & 128) !== 0)
    .map(property => property.tag);
  const reports = properties.filter(property => property.tag === "iodef").map(property => property.value);
  return `${labelRows([
    ["CAA issue", issuerPolicy("issue", "No issue property returned")],
    ["CAA issuewild", issuerPolicy("issuewild", "Uses issue policy when present")],
    ["CAA reports", reports.join(" · ") || "No reporting property returned"],
    ...(critical.length ? [["Issuer-critical tags", [...new Set(critical)].join(", ")] as [string, string]] : []),
  ])}
  ${records.limited || properties.length < records.values.length
    ? '<p class="small">CAA findings cover the complete records that could be read.</p>' : ""}`;
}

function renderPkiFacts(caa: DnsRecordGroup | null, certificates: CertificateResults | null, observedAt: string): string {
  const records = certificates?.records ?? [];
  const issuers = new Map<string, { name: string; key?: string; count: number }>();
  for (const record of records) {
    const name = record.issuer ?? "Issuer unknown";
    const id = record.issuerKeySha256 ? "key:" + record.issuerKeySha256 : "name:" + name;
    const entry = issuers.get(id);
    if (entry) entry.count++;
    else issuers.set(id, { name, key: record.issuerKeySha256, count: 1 });
  }
  return `<div class="recon-results">
    <div>
      <h3>CAA issuance policy</h3>
      <p class="small">Cloudflare Public DNS · Policy returned for this name</p>
      ${describeCaa(caa)}
    </div>
    <div>
      <h3>Logged CA issuers</h3>
      <p class="small">Certificate Transparency · SSLMate Cert Spotter</p>
      ${!certificates ? "<p>Certificate log unavailable.</p>"
        : !records.length ? "<p>No logged certificates returned for this name.</p>"
        : `<p class="small">Summary of ${records.length} displayed certificate records.</p>
          ${labelRows([
            ["Expired", String(records.filter(record => daysFromObservation(record.expires, observedAt) < 0).length)],
            ["Due within 30 days", String(records.filter(record => {
              const days = daysFromObservation(record.expires, observedAt);
              return days >= 0 && days <= 30;
            }).length)],
            ["Not yet valid", String(records.filter(record => daysFromObservation(record.issued, observedAt) > 0).length)],
            ["Revoked in source", String(records.filter(record => record.revoked).length)],
            ["Validity unavailable", String(records.filter(record => !record.issued || !record.expires).length)],
          ])}
          <ul class="rows">${[...issuers.values()].map(({ name, key, count }) => `<li>
            <strong>${escapeHtml(name)}</strong> · ${count} ${count === 1 ? "certificate" : "certificates"}
            ${key ? `<p class="small">Issuer key SHA-256 <code>${escapeHtml(key)}</code></p>` : ""}
          </li>`).join("")}</ul>`}
    </div>
  </div>`;
}

function renderIpPki(result: IpRecon, observedAt: string): string {
  return `<section class="panel" aria-labelledby="ip-pki-title">
    <h2 id="ip-pki-title">CA and PKI analysis</h2>
    <p>Certificate log records for DNS names that reverse DNS lists and forward DNS confirms for this address.</p>
    ${result.pki.length ? result.pki.map(({ hostname, forward, caa, certificates }) => {
      if (forward !== "confirmed") return `<p><strong>${escapeHtml(hostname)}</strong> · ${forward === "unknown"
        ? "Forward DNS confirmation unavailable" : "Forward DNS returned another address"}</p>`;
      const reviewed = certificates?.records.filter(record => typeof record.matchesAddress === "boolean") ?? [];
      const matched = reviewed.filter(record => record.matchesAddress).length;
      return `<div class="pki-host">
        <h3><code>${escapeHtml(hostname)}</code></h3>
        <p>Forward DNS confirms this address.</p>
        ${reviewed.length ? `<p><strong>${matched} of ${reviewed.length} checked records list this exact IP.</strong></p>`
          : certificates?.records.length ? "<p>IP identities are unavailable in the returned log records.</p>" : ""}
        ${renderPkiFacts(caa, certificates, observedAt)}
        ${certificates?.records.length ? `<details>
          <summary>Logged certificate details</summary>${renderCertificateRows(certificates.records, observedAt)}
        </details>` : ""}
      </div>`;
    }).join("") : `<p>${!result.address.isPublic ? "Public DNS linkage applies to public unicast addresses."
      : result.names === null ? "Reverse DNS lookup unavailable." : "No public PTR hostname returned."}</p>`}
    ${result.names && result.names.length > result.pki.length ? '<p class="small">Checked the first two public PTR names.</p>' : ""}
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

const SEVERITY_LABELS: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
const RISKY_PORT_NAMES: Record<number, string> = {
  21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP", 135: "MS RPC", 139: "NetBIOS", 443: "HTTPS", 445: "SMB", 1433: "MS SQL",
  2375: "Docker API", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5984: "CouchDB", 6379: "Redis",
  9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
};

function severityBadge(severity: Severity): string {
  return `<span class="sev sev-${severity}">${SEVERITY_LABELS[severity]}</span>`;
}

function techniqueLink(id?: string): string {
  return id && /^T\d{4}(?:\.\d{3})?$/.test(id)
    ? `<span class="rt-tag"><a href="https://attack.mitre.org/techniques/${id.replace(".", "/")}/">${id}</a></span>` : "";
}

function renderFindingList(findings: RedAssessment["findings"]): string {
  return `<ol class="rt-list">${findings.map(item => `<li>
    ${severityBadge(item.severity)}<h3>${escapeHtml(item.title)}</h3><span class="rt-tag">${escapeHtml(item.category)}</span>${techniqueLink(item.technique)}
    <p>${escapeHtml(item.evidence)}</p>
    <p class="small"><strong>Fix</strong> · ${escapeHtml(item.action)}</p>
  </li>`).join("")}</ol>`;
}

function renderRedSummary(assessment: RedAssessment, subject: string): string {
  const { summary } = assessment;
  const value = (count: number | null) => count === null ? "Not run" : String(count);
  return `<section class="panel" aria-labelledby="rt-summary-title">
    <h2 id="rt-summary-title">Attack surface summary · <code>${escapeHtml(subject)}</code></h2>
    <p><span class="sev sev-${summary.worst}">${summary.worst === "none" ? "No actionable findings" : "Worst · " + SEVERITY_LABELS[summary.worst]}</span></p>
    <dl class="rt-metrics">
      <div><dt>Subdomains in CT logs</dt><dd>${value(summary.subdomains)}</dd></div>
      <div><dt>Open ports</dt><dd>${value(summary.openPorts)}</dd></div>
      <div><dt>Known CVEs</dt><dd>${value(summary.cves)}</dd></div>
      <div><dt>Takeover candidates</dt><dd>${value(summary.takeoverCandidates)}</dd></div>
      <div><dt>Critical / High</dt><dd>${summary.counts.critical} / ${summary.counts.high}</dd></div>
      <div><dt>Medium / Low</dt><dd>${summary.counts.medium} / ${summary.counts.low}</dd></div>
    </dl>
    <p class="small">Sources · Cloudflare Public DNS, Certificate Transparency (Cert Spotter), Shodan InternetDB. Open ports and CVEs come from Shodan's passive data and may be out of date.</p>
  </section>`;
}

function renderEntryPoints(assessment: RedAssessment): string {
  const rest = assessment.findings.filter(item => !assessment.entryPoints.includes(item));
  return `<section class="panel" aria-labelledby="rt-entry-title">
    <h2 id="rt-entry-title">Likely entry points</h2>
    <p class="small">Ranked by severity. These are the first places an attacker would look.</p>
    ${assessment.entryPoints.length ? renderFindingList(assessment.entryPoints)
      : "<p>No likely entry points were found in the public data checked.</p>"}
    ${rest.length ? `<details><summary>More findings (${rest.length})</summary>${renderFindingList(rest)}</details>` : ""}
  </section>`;
}

function portLabel(port: number): string {
  return RISKY_PORT_NAMES[port] ? `${port} ${RISKY_PORT_NAMES[port]}` : String(port);
}

function renderExposureHosts(hosts: ExposureHost[]): string {
  return `<ul class="rows">${hosts.map(host => `<li>
    <strong><code>${escapeHtml(host.address)}</code></strong>
    ${host.status === "unavailable" ? '<span class="status unknown">Lookup unavailable</span>'
      : host.status === "none" ? '<span class="status">No Shodan data</span>' : `
    <p>Ports · ${host.ports.length ? host.ports.map(port => `<code>${escapeHtml(portLabel(port))}</code>`).join(" ") : "none listed"}</p>
    <p>CVEs · ${host.vulns.length ? host.vulns.map(id => `<a href="https://nvd.nist.gov/vuln/detail/${escapeHtml(id)}"><code>${escapeHtml(id)}</code></a>`).join(" ") : "none listed"}</p>
    ${host.tags.length ? `<p class="small">Tags · ${host.tags.map(escapeHtml).join(", ")}</p>` : ""}
    ${host.hostnames.length ? `<p class="small">Hostnames · ${host.hostnames.map(escapeHtml).join(", ")}</p>` : ""}`}
  </li>`).join("")}</ul>`;
}

function renderLiveChecks(extras: RedExtras | undefined, snapshot: boolean): string {
  if (!extras) {
    return `<section class="panel" aria-labelledby="rt-live-title"><h2 id="rt-live-title">Live exposure checks</h2>
      <p>${snapshot ? "Saved snapshots hold DNS, certificate, and mail data only. Run recon again for ports, CVEs, takeover, and header checks."
        : "Run recon to check exposed ports, CVEs, and subdomain takeover."}</p></section>`;
  }
  const exposure = extras.exposure === undefined ? ""
    : `<h3>Exposed ports and CVEs · Shodan InternetDB</h3>${extras.exposure === null || !extras.exposure.length
      ? "<p>No public addresses to check, or the lookup is unavailable.</p>" : renderExposureHosts(extras.exposure)}`;
  const takeover = extras.takeover === undefined ? ""
    : `<h3>Subdomain takeover hints · DNS</h3>${extras.takeover === null ? "<p>Lookup unavailable.</p>"
      : `<p class="small">Checked ${extras.takeover.checked} logged subdomain${extras.takeover.checked === 1 ? "" : "s"} for CNAMEs.</p>
        ${extras.takeover.hints.length ? `<ul class="rows">${extras.takeover.hints.map(hint => `<li>
          ${hint.state === "dangling" ? '<span class="sev sev-high">Dangling</span>' : '<span class="sev sev-info">Delegated</span>'}
          <code>${escapeHtml(hint.name)}</code> → <code>${escapeHtml(hint.target)}</code>${hint.service ? " · " + escapeHtml(hint.service) : ""}
        </li>`).join("")}</ul>` : "<p>No dangling or third-party CNAMEs found among them.</p>"}`}`;
  const headers = extras.headers === undefined ? '<h3>Web headers</h3><p class="small">Not run. Tick the headers box to send one HTTPS request to the target.</p>'
    : `<h3>Web headers · one HTTPS request</h3>${extras.headers === null || extras.headers.status === "unreachable"
      ? "<p>The HTTPS site could not be fetched.</p>"
      : `<p class="small">HTTP status ${extras.headers.httpStatus}.</p>
        ${extras.headers.missing.length || extras.headers.weak.length ? `<ul class="rows">${[...extras.headers.missing.map(name => "Missing · " + name), ...extras.headers.weak].map(text => `<li>${escapeHtml(text)}</li>`).join("")}</ul>` : "<p>No header gaps found.</p>"}`}`;
  return `<section class="panel" aria-labelledby="rt-live-title"><h2 id="rt-live-title">Live exposure checks</h2>${exposure}${takeover}${headers}</section>`;
}

function renderExport(page: ReconPageData): string {
  if (!page.results && !page.ipResults) return "";
  const subject = escapeHtml(page.domain);
  const viaSnapshot = page.snapshot && !page.extras && page.results;
  const buttons = viaSnapshot
    ? `<a href="${snapshotLink(page.domain, page.snapshot!.id)}&amp;format=md">Download Markdown</a>
       <a href="${snapshotLink(page.domain, page.snapshot!.id)}&amp;format=json">Download JSON</a>`
    : `<form method="post" action="${RECON_PATH}" class="export-row">
         <input type="hidden" name="domain" value="${subject}">
         ${page.results?.mail ? '<input type="hidden" name="mail" value="1">' : ""}
         ${page.extras?.headers !== undefined ? '<input type="hidden" name="headers" value="1">' : ""}
         <button type="submit" name="format" value="md" class="secondary">Export Markdown</button>
         <button type="submit" name="format" value="json" class="secondary">Export JSON</button>
       </form>`;
  return `<section class="panel" aria-labelledby="rt-export-title">
    <h2 id="rt-export-title">Export findings</h2>
    <p class="small">${viaSnapshot ? "Exports this saved snapshot." : "Exporting runs the same lookups again and downloads the report."}</p>
    <div class="export-row">${buttons}</div>
  </section>`;
}

const AUTHORIZED_NOTICE = `<section class="panel authorized" role="note" aria-labelledby="authorized-title">
  <h2 id="authorized-title">Authorized targets only</h2>
  <p><strong>Only assess domains and addresses you own or have written permission to test.</strong>
  This page uses passive public lookups: DNS, Certificate Transparency, and Shodan InternetDB. The optional headers check sends one ordinary HTTPS request.
  It never scans ports, guesses passwords, or exploits anything.</p>
</section>`;

export function reconPage(page: ReconPageData, applySecurityHeaders: (headers: Headers) => void): Response {
  const observedAt = page.snapshot?.at ?? new Date().toISOString();
  const subject = page.domain;
  const redAssessment = page.results ? assessRed(subject, page.results, page.extras ?? {}, observedAt)
    : page.ipResults ? assessRed(subject, undefined, page.extras ?? {}, observedAt) : null;
  const redResults = redAssessment
    ? renderRedSummary(redAssessment, subject) + renderEntryPoints(redAssessment) + renderLiveChecks(page.extras, Boolean(page.snapshot)) + renderExport(page)
    : "";
  const downloadRed = redAssessment ? renderRedSummary(redAssessment, subject) + renderEntryPoints(redAssessment) : "";
  const results = page.results
    ? `${page.snapshot ? `<section class="panel"><h2>${escapeHtml(page.domain)}</h2>
      <p class="small">Saved ${snapshotTime(page.snapshot.at)}</p>
      ${!page.download ? `<a href="${snapshotLink(page.domain, page.snapshot.id)}&amp;download=1">Download report</a>` : ""}
    </section>` : ""}
    ${page.download ? downloadRed : redResults}
    <section class="panel" aria-labelledby="pki-title">
      <h2 id="pki-title">CA and PKI analysis</h2>
      ${renderPkiFacts(page.results.dns.find(record => record.label === "CAA") ?? null, page.results.certificates, observedAt)}
    </section>
    <div class="recon-results">${renderDns(page.results.dns)}${renderCertificateLog(page.results.certificates, observedAt)}</div>
    ${page.results.mail ? renderMail(page.results.mail) : ""}
    ${page.previous ? renderComparison(page.results, page.previous) : ""}`
    : "";
  const form = `<section class="panel">
    <form class="domain-form" method="post" action="${RECON_PATH}" aria-describedby="recon-help">
      <label for="domain">Authorized target · public domain or IP address</label>
      <div class="query">
        <input id="domain" name="domain" type="text" inputmode="url" placeholder="example.com" value="${escapeHtml(page.domain)}"
          maxlength="254" autocomplete="off" autocapitalize="none" spellcheck="false" required>
        <button type="submit">Run red team recon</button>
      </div>
      <label class="save-option"><input name="save" value="1" type="checkbox"> Save domain snapshot</label>
      <label class="save-option"><input name="headers" value="1" type="checkbox"${page.extras?.headers !== undefined ? " checked" : ""}> Also check web security headers (sends one HTTPS request to the target)</label>
      <details class="mail-options"${page.results?.mail ? " open" : ""}>
        <summary>Email policy details</summary>
        <label class="save-option"><input name="mail" value="1" type="checkbox"${page.results?.mail ? " checked" : ""}> Review mail policy details</label>
        <label for="selector">DKIM selector (optional)</label>
        <div class="query"><input id="selector" name="selector" value="${escapeHtml(page.results?.mail?.dkim?.selector ?? "")}"
          maxlength="63" placeholder="selector1" autocomplete="off" spellcheck="false"></div>
      </details>
      <p id="recon-help" class="small">Passive attacker\u2019s-eye recon: public DNS, certificate log subdomains, Shodan InternetDB ports and CVEs, takeover hints, and email spoofability.</p>
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
    title: page.download ? "Red Team Recon report" : "Red Team Recon",
    theme: "red",
    navigation: page.download ? "" : `
      ${page.domain ? `<a href="${RECON_PATH}">Recon home</a>` : ""}
      <a href="${RECON_CERTIFICATE_PATH}">Certificate inspector</a><a href="${OPERATIONS_PATH}">Globe operations</a>
      <a href="${PURPLE_TEAM_ROOT}">Purple Team Recon (original)</a>`,
    content: page.download ? results : AUTHORIZED_NOTICE + notice +
      `<div class="recon-toolbar">${form}${page.ownConnection ? renderOwnConnection(page.ownConnection) : ""}</div>` +
      (page.ipResults ? redResults + renderIpPki(page.ipResults, observedAt) + renderIpResults(page.ipResults) : "") + results + history + savedDomains,
    status: page.status,
  }, applySecurityHeaders);
  if (page.download) response.headers.set("Content-Disposition", `attachment; filename="globe-recon-${page.domain}.html"`);
  return response;
}
