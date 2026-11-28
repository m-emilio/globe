import { parseReconAddress } from "../reconAddress";
import { readBoundedText } from "./boundedBody";
import { readReconDns, type DnsRecordGroup, type ReconResults } from "./purpleTeamRecon";

// Red Team Recon: an attacker's-eye view built only from public lookups (Cloudflare DNS, Certificate
// Transparency, Shodan InternetDB) plus one optional HTTPS request to the target. Nothing here probes
// ports, guesses passwords, or exploits anything. For authorized assessments only.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export type RedFinding = {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  evidence: string;
  action: string;
  technique?: string;
};

export type ExposureHost = {
  address: string;
  status: "ok" | "none" | "unavailable";
  ports: number[];
  vulns: string[];
  hostnames: string[];
  tags: string[];
};

export type TakeoverHint = {
  name: string;
  target: string;
  service: string | null;
  state: "dangling" | "delegated";
};

export type HeaderCheck =
  | { status: "ok"; httpStatus: number; missing: string[]; weak: string[]; disclosure: string[]; downgrade: boolean }
  | { status: "unreachable" };

export type RedExtras = {
  exposure?: ExposureHost[] | null;
  takeover?: { checked: number; hints: TakeoverHint[] } | null;
  headers?: HeaderCheck | null;
};

export type RedSummary = {
  worst: Severity | "none";
  counts: Record<Severity, number>;
  subdomains: number | null;
  addressesChecked: number | null;
  openPorts: number | null;
  cves: number | null;
  takeoverCandidates: number | null;
};

export type RedAssessment = { findings: RedFinding[]; summary: RedSummary; entryPoints: RedFinding[] };

const rank = (severity: Severity) => SEVERITIES.indexOf(severity);
const worstOf = (...values: Severity[]) => values.reduce((a, b) => (rank(b) < rank(a) ? b : a));

// ---------- Shodan InternetDB (passive, no key) ----------

async function lookupInternetDb(address: string): Promise<ExposureHost> {
  const empty = { address, ports: [], vulns: [], hostnames: [], tags: [] };
  const ctl = new AbortController();
  const timeout = setTimeout(() => ctl.abort(), 3500);
  try {
    const response = await fetch("https://internetdb.shodan.io/" + encodeURIComponent(address), {
      headers: { accept: "application/json" }, redirect: "manual", signal: ctl.signal,
    });
    if (response.status === 404) {
      await response.body?.cancel();
      return { ...empty, status: "none" };
    }
    if (!response.ok) {
      await response.body?.cancel();
      return { ...empty, status: "unavailable" };
    }
    const body = JSON.parse(await readBoundedText(response.body, 262_144)) as Record<string, unknown>;
    const list = (value: unknown) => (Array.isArray(value) ? value : []);
    return {
      address,
      status: "ok",
      ports: [...new Set(list(body.ports).filter((port): port is number => Number.isInteger(port) && port > 0 && port < 65536))]
        .sort((a, b) => a - b).slice(0, 100),
      vulns: [...new Set(list(body.vulns).filter((id): id is string => typeof id === "string" && /^CVE-\d{4}-\d{4,7}$/i.test(id))
        .map(id => id.toUpperCase()))].slice(0, 40),
      hostnames: [...new Set(list(body.hostnames).filter((name): name is string => typeof name === "string")
        .map(name => name.toLowerCase().slice(0, 253)))].slice(0, 10),
      tags: list(body.tags).filter((tag): tag is string => typeof tag === "string" && /^[a-z0-9-]{1,32}$/.test(tag)).slice(0, 12),
    };
  } catch {
    return { ...empty, status: "unavailable" };
  } finally {
    clearTimeout(timeout);
  }
}

export function exposureTargets(dns: DnsRecordGroup[]): string[] {
  const values = ["A", "AAAA"].flatMap(label => dns.find(group => group.label === label)?.values ?? []);
  const addresses = values.flatMap(value => {
    const address = parseReconAddress(value);
    return address?.isPublic ? [address.value] : [];
  });
  return [...new Set(addresses)].slice(0, 3);
}

export async function lookupExposure(addresses: string[]): Promise<ExposureHost[]> {
  return Promise.all(addresses.slice(0, 3).map(lookupInternetDb));
}

// ---------- Subdomain takeover hints (DNS only) ----------

const TAKEOVER_SERVICES: [RegExp, string][] = [
  [/\.github\.io$/, "GitHub Pages"],
  [/\.herokuapp\.com$|\.herokudns\.com$/, "Heroku"],
  [/\.s3(?:[.-][a-z0-9-]+)*\.amazonaws\.com$|\.s3-website[.-][a-z0-9.-]+\.amazonaws\.com$/, "Amazon S3"],
  [/\.elasticbeanstalk\.com$/, "AWS Elastic Beanstalk"],
  [/\.azurewebsites\.net$|\.cloudapp\.net$|\.cloudapp\.azure\.com$|\.trafficmanager\.net$|\.blob\.core\.windows\.net$|\.azureedge\.net$/, "Microsoft Azure"],
  [/\.surge\.sh$/, "Surge"],
  [/\.bitbucket\.io$/, "Bitbucket Pages"],
  [/\.pantheonsite\.io$/, "Pantheon"],
  [/\.readme\.io$/, "Readme"],
  [/\.ghost\.io$/, "Ghost"],
  [/\.helpjuice\.com$|\.helpscoutdocs\.com$|\.zendesk\.com$|\.uservoice\.com$/, "Help-desk platform"],
  [/\.statuspage\.io$/, "Statuspage"],
  [/\.wordpress\.com$|\.tumblr\.com$/, "Blog platform"],
  [/\.myshopify\.com$/, "Shopify"],
  [/\.cargocollective\.com$/, "Cargo"],
  [/\.unbouncepages\.com$/, "Unbounce"],
  [/\.fly\.dev$/, "Fly.io"],
  [/\.webflow\.io$|proxy\.webflow\.com$/, "Webflow"],
  [/\.strikinglydns\.com$/, "Strikingly"],
];

function takeoverService(target: string): string | null {
  return TAKEOVER_SERVICES.find(([pattern]) => pattern.test(target))?.[1] ?? null;
}

export async function lookupTakeoverHints(domain: string, names: string[]): Promise<{ checked: number; hints: TakeoverHint[] }> {
  const candidates = names.filter(name => !name.startsWith("*.") && name !== domain && name !== "www." + domain).slice(0, 12);
  const hints: TakeoverHint[] = [];
  for (let index = 0; index < candidates.length; index += 6) {
    await Promise.all(candidates.slice(index, index + 6).map(async name => {
      try {
        const response = await readReconDns(name, "A", { timeoutMs: 3000 });
        const targets = response.answer.flatMap(answer =>
          answer?.type === 5 && typeof answer.data === "string" ? [answer.data.toLowerCase().replace(/\.$/, "").slice(0, 253)] : []);
        const target = targets.at(-1);
        if (!target) return;
        const service = takeoverService(target);
        if (response.status === 3) hints.push({ name, target, service, state: "dangling" });
        else if (service) hints.push({ name, target, service, state: "delegated" });
      } catch {
        // An unavailable lookup is simply not reported.
      }
    }));
  }
  hints.sort((a, b) => a.name.localeCompare(b.name));
  return { checked: candidates.length, hints };
}

// ---------- Web headers (opt-in, one HTTPS request to the target) ----------

export async function inspectWebHeaders(domain: string): Promise<HeaderCheck> {
  const ctl = new AbortController();
  const timeout = setTimeout(() => ctl.abort(), 4500);
  try {
    const response = await fetch("https://" + domain + "/", {
      redirect: "manual", signal: ctl.signal, headers: { "user-agent": "Globe-RedTeamRecon/1 (authorized assessment)" },
    });
    await response.body?.cancel();
    const get = (name: string) => (response.headers.get(name) ?? "").slice(0, 300);
    const redirected = response.status >= 300 && response.status < 400;
    const downgrade = redirected && /^http:\/\//i.test(get("location"));
    const missing: string[] = [];
    const weak: string[] = [];
    const hsts = get("strict-transport-security");
    if (!hsts) missing.push("Strict-Transport-Security");
    else {
      const age = Number(/max-age\s*=\s*"?(\d+)/i.exec(hsts)?.[1] ?? 0);
      if (age < 15_552_000) weak.push("Strict-Transport-Security max-age is under 180 days");
    }
    const csp = get("content-security-policy");
    if (!csp) missing.push("Content-Security-Policy");
    else if (/'unsafe-inline'|'unsafe-eval'/i.test(csp) && /script-src|default-src/i.test(csp)) {
      weak.push("Content-Security-Policy allows unsafe script sources");
    }
    if (!get("x-frame-options") && !/frame-ancestors/i.test(csp)) missing.push("X-Frame-Options or frame-ancestors");
    if (!/nosniff/i.test(get("x-content-type-options"))) missing.push("X-Content-Type-Options");
    if (!get("referrer-policy")) missing.push("Referrer-Policy");
    if (!get("permissions-policy")) missing.push("Permissions-Policy");
    const disclosure = [["server", get("server")], ["x-powered-by", get("x-powered-by")]]
      .filter(([, value]) => /\d/.test(value)).map(([name, value]) => `${name}: ${value.slice(0, 80)}`);
    return { status: "ok", httpStatus: response.status, missing, weak, disclosure, downgrade };
  } catch {
    return { status: "unreachable" };
  } finally {
    clearTimeout(timeout);
  }
}

// ---------- Findings ----------

const quoted = (value: string) => value.trim().replace(/"\s*"/g, "").replace(/^"|"$/g, "");

type SpfState = "none" | "multiple" | "open" | "neutral" | "soft" | "hard" | "noall" | "redirect";
type DmarcState = "none" | "multiple" | "monitor" | "quarantine" | "reject";

function spfState(values: string[]): SpfState {
  const records = values.map(quoted).filter(value => /^v=spf1(?:\s|$)/i.test(value));
  if (!records.length) return "none";
  if (records.length > 1) return "multiple";
  const all = /(?:^|\s)([+\-~?]?)all(?:\s|$)/i.exec(records[0]);
  if (!all) return /(?:^|\s)redirect=/i.test(records[0]) ? "redirect" : "noall";
  return ({ "": "open", "+": "open", "?": "neutral", "~": "soft", "-": "hard" } as Record<string, SpfState>)[all[1]];
}

function dmarcPolicy(values: string[]): { state: DmarcState; pct: number; subdomain: string | null } {
  const records = values.map(quoted).filter(value => /^v=dmarc1(?:[\s;]|$)/i.test(value));
  if (!records.length) return { state: "none", pct: 100, subdomain: null };
  if (records.length > 1) return { state: "multiple", pct: 100, subdomain: null };
  const tags = new Map(records[0].split(";").flatMap(part => {
    const [key, ...rest] = part.trim().split("=");
    return key && rest.length ? [[key.trim().toLowerCase(), rest.join("=").trim().toLowerCase()] as [string, string]] : [];
  }));
  const policy = tags.get("p");
  const state: DmarcState = policy === "reject" ? "reject" : policy === "quarantine" ? "quarantine" : "monitor";
  const pct = Number(tags.get("pct") ?? 100);
  return { state, pct: Number.isFinite(pct) ? Math.min(100, Math.max(0, pct)) : 100, subdomain: tags.get("sp") ?? null };
}

function emailFinding(dns: DnsRecordGroup[]): RedFinding[] {
  const spfGroup = dns.find(group => group.label === "SPF");
  const dmarcGroup = dns.find(group => group.label === "DMARC");
  if (!spfGroup?.values || !dmarcGroup?.values) return [];
  const spf = spfState(spfGroup.values);
  const dmarc = dmarcPolicy(dmarcGroup.values);
  const spfWeak = spf === "none" || spf === "open" || spf === "neutral" || spf === "noall" || spf === "multiple";
  const spfText = ({
    none: "no SPF record", multiple: "more than one SPF record (invalid, receivers may ignore it)", open: "SPF ends in +all (anyone may send)",
    neutral: "SPF ends in ?all (no protection)", soft: "SPF ends in ~all (soft fail)", hard: "SPF ends in -all (hard fail)",
    noall: "SPF has no all mechanism", redirect: "SPF redirects to another domain's policy",
  } as Record<SpfState, string>)[spf];
  const dmarcText = ({
    none: "no DMARC record", multiple: "more than one DMARC record (invalid)", monitor: "DMARC p=none (monitor only)",
    quarantine: "DMARC p=quarantine", reject: "DMARC p=reject",
  } as Record<DmarcState, string>)[dmarc.state];
  let severity: Severity;
  if (spf === "open") severity = "critical";
  else if (dmarc.state === "none" || dmarc.state === "multiple") severity = spfWeak ? "critical" : "high";
  else if (dmarc.state === "monitor") severity = spfWeak ? "high" : "medium";
  else if (dmarc.state === "quarantine") severity = "low";
  else severity = dmarc.pct < 100 ? "low" : dmarc.subdomain === "none" ? "medium" : "info";
  const notes = [
    dmarc.pct < 100 && (dmarc.state === "quarantine" || dmarc.state === "reject") ? `Policy applies to only ${dmarc.pct}% of mail.` : "",
    dmarc.subdomain === "none" && dmarc.state !== "none" ? "Subdomain policy sp=none leaves subdomains spoofable." : "",
  ].filter(Boolean).join(" ");
  const strong = severity === "info";
  return [{
    id: "email-spoofing",
    severity,
    category: "Email / phishing",
    title: strong ? "Email spoofing path is closed" : "Email spoofing attack path",
    evidence: `${spfText[0].toUpperCase()}${spfText.slice(1)}; ${dmarcText}. ${notes}`.trim(),
    action: strong ? "Keep SPF -all and DMARC p=reject; review rua reports."
      : "Publish SPF ending in -all, sign mail with DKIM, and move DMARC to p=quarantine then p=reject (also set sp=reject).",
    technique: "T1566",
  }];
}

const HIGH_VALUE_HOST = /(^|[.-])(admin|vpn|jenkins|gitlab|git|sso|rdp|remote|owa|webmail|phpmyadmin|grafana|kibana|jira|confluence|bastion|citrix|ssh|ftp|sftp|db|sql|intranet|internal|portal)(\d*)([.-]|$)/;
const PRE_PROD_HOST = /(^|[.-])(dev|stage|staging|test|uat|qa|beta|old|backup|demo|sandbox|preprod|preview)(\d*)([.-]|$)/;

function certificateFindings(results: ReconResults, observedAt: string, domain: string): RedFinding[] {
  const certificates = results.certificates;
  if (!certificates) return [];
  const findings: RedFinding[] = [];
  const hosts = certificates.names.filter(name => !name.startsWith("*."));
  const labelOf = (name: string) => name === domain ? "" : name.slice(0, -(domain.length + 1));
  const valuable = hosts.filter(name => labelOf(name) && HIGH_VALUE_HOST.test(labelOf(name)));
  const preProd = hosts.filter(name => labelOf(name) && !valuable.includes(name) && PRE_PROD_HOST.test(labelOf(name)));
  if (valuable.length || preProd.length) {
    findings.push({
      id: "interesting-hosts",
      severity: valuable.length ? "medium" : "low",
      category: "Subdomain exposure",
      title: valuable.length ? "Admin, remote-access or internal-looking hostnames are public"
        : "Staging, test or legacy hostnames are public",
      evidence: [...valuable, ...preProd].slice(0, 12).join(", ") + ([...valuable, ...preProd].length > 12 ? ", …" : "") +
        " appear in public certificate logs, so an attacker finds them without touching the target.",
      action: "Confirm each is intended to be internet-facing, patched, behind SSO or an allowlist, and covered by monitoring.",
      technique: "T1596.003",
    });
  }
  if (certificates.names.some(name => name.startsWith("*."))) {
    findings.push({
      id: "wildcard-cert", severity: "info", category: "TLS / PKI", title: "Wildcard certificate in use",
      evidence: "A wildcard certificate covers every subdomain, so new hostnames never show up in certificate logs.",
      action: "Inventory subdomains from DNS zone data rather than relying on certificate logs.", technique: "T1596.003",
    });
  }
  const newest = certificates.records[0];
  const days = newest?.expires ? (Date.parse(newest.expires) - Date.parse(observedAt.slice(0, 10))) / 86_400_000 : NaN;
  if (Number.isFinite(days) && days < 0) {
    findings.push({
      id: "cert-expired", severity: "medium", category: "TLS / PKI", title: "Newest logged certificate is expired",
      evidence: `Latest logged certificate expired on ${newest.expires}. Clients may see TLS errors or users may be trained to click through warnings.`,
      action: "Renew and deploy a valid certificate, then automate renewal.", technique: "T1588.004",
    });
  } else if (Number.isFinite(days) && days <= 30) {
    findings.push({
      id: "cert-expiring", severity: "low", category: "TLS / PKI", title: "Certificate expires within 30 days",
      evidence: `Latest logged certificate expires on ${newest.expires}.`, action: "Confirm automatic renewal is working.", technique: "T1588.004",
    });
  }
  return findings;
}

const RISKY_PORTS: Record<number, [string, Severity]> = {
  21: ["FTP", "medium"], 23: ["Telnet", "high"], 135: ["MS RPC", "high"], 139: ["NetBIOS", "high"], 445: ["SMB", "high"],
  1433: ["MS SQL", "high"], 2375: ["Docker API", "high"], 3306: ["MySQL", "high"], 3389: ["RDP", "high"], 5432: ["PostgreSQL", "high"],
  5900: ["VNC", "high"], 5984: ["CouchDB", "high"], 6379: ["Redis", "high"], 9200: ["Elasticsearch", "high"], 11211: ["Memcached", "high"],
  27017: ["MongoDB", "high"], 22: ["SSH", "low"], 25: ["SMTP", "info"], 5985: ["WinRM", "high"],
};

function exposureFindings(hosts: ExposureHost[]): RedFinding[] {
  const findings: RedFinding[] = [];
  for (const host of hosts) {
    if (host.status !== "ok") continue;
    const cdn = host.tags.includes("cdn");
    const labelled = host.ports.map(port => (RISKY_PORTS[port] ? `${port} ${RISKY_PORTS[port][0]}` : String(port)));
    const risky = host.ports.filter(port => RISKY_PORTS[port] && RISKY_PORTS[port][1] !== "info");
    if (host.ports.length) {
      const severity = cdn ? "info" : risky.length ? worstOf(...risky.map(port => RISKY_PORTS[port][1])) : "info";
      findings.push({
        id: "ports-" + host.address,
        severity,
        category: "Exposed service",
        title: `${host.address}: ${host.ports.length} open port${host.ports.length === 1 ? "" : "s"} seen by Shodan`,
        evidence: `Ports ${labelled.join(", ")}.${cdn ? " This address is a CDN edge, so ports describe the CDN rather than the origin server." : ""}`,
        action: risky.length && !cdn ? "Close or firewall administrative and database ports; require VPN or an IP allowlist."
          : "Confirm each listed service is intended to be public.",
        technique: risky.some(port => [3389, 5900, 5985, 22, 23].includes(port)) ? "T1133" : "T1190",
      });
    }
    if (host.vulns.length) {
      findings.push({
        id: "cves-" + host.address,
        severity: host.vulns.length >= 10 ? "critical" : "high",
        category: "Known CVEs",
        title: `${host.address}: ${host.vulns.length} CVE${host.vulns.length === 1 ? "" : "s"} reported`,
        evidence: `${host.vulns.slice(0, 10).join(", ")}${host.vulns.length > 10 ? ", …" : ""}. Shodan infers these from service banners, so confirm each against the real software version.`,
        action: "Patch or upgrade the exposed software, then verify which CVEs actually apply.",
        technique: "T1190",
      });
    }
    const badTags = host.tags.filter(tag => ["compromised", "malware"].includes(tag));
    if (badTags.length) {
      findings.push({
        id: "tags-bad-" + host.address, severity: "high", category: "Reputation", title: `${host.address} is tagged ${badTags.join(", ")}`,
        evidence: "Shodan InternetDB labels this address with threat-related tags.", action: "Investigate the host for compromise.",
      });
    }
    const weakTags = host.tags.filter(tag => ["eol-os", "eol-product", "self-signed"].includes(tag));
    if (weakTags.length) {
      findings.push({
        id: "tags-weak-" + host.address, severity: weakTags.some(tag => tag.startsWith("eol")) ? "medium" : "low", category: "Exposed service",
        title: `${host.address}: ${weakTags.join(", ").replace(/-/g, " ")}`,
        evidence: "Shodan tags indicate end-of-life software or a self-signed certificate on a public service.",
        action: "Upgrade unsupported software and use a certificate from a trusted CA.", technique: "T1190",
      });
    }
  }
  return findings;
}

function takeoverFindings(result: { checked: number; hints: TakeoverHint[] }): RedFinding[] {
  const findings: RedFinding[] = [];
  for (const hint of result.hints.filter(item => item.state === "dangling")) {
    findings.push({
      id: "takeover-" + hint.name,
      severity: hint.service ? "high" : "medium",
      category: "Subdomain takeover",
      title: `Dangling CNAME on ${hint.name}`,
      evidence: `${hint.name} is a CNAME to ${hint.target}${hint.service ? ` (${hint.service})` : ""}, and that name no longer resolves${
        hint.service ? ", so an attacker may be able to claim the resource and serve content on your domain" : ""}.`,
      action: "Delete the CNAME, or recreate the resource at the provider. Then audit DNS for other stale records.",
      technique: "T1584.001",
    });
  }
  const delegated = result.hints.filter(item => item.state === "delegated");
  if (delegated.length) {
    findings.push({
      id: "takeover-delegated", severity: "info", category: "Subdomain takeover",
      title: `${delegated.length} subdomain${delegated.length === 1 ? "" : "s"} delegated to third-party hosting`,
      evidence: delegated.slice(0, 8).map(item => `${item.name} → ${item.service}`).join("; ") + (delegated.length > 8 ? "; …" : ""),
      action: "Confirm the provider account and resource behind each name still exist.", technique: "T1584.001",
    });
  }
  return findings;
}

function headerFindings(check: HeaderCheck): RedFinding[] {
  if (check.status === "unreachable") {
    return [{
      id: "headers-unreachable", severity: "medium", category: "TLS / PKI", title: "HTTPS site could not be fetched",
      evidence: "One HTTPS request from Globe failed or timed out. The cause may be no HTTPS service, an invalid or expired certificate, or a blocked request.",
      action: "Verify the HTTPS endpoint, certificate chain, and expiry from another network.",
    }];
  }
  const findings: RedFinding[] = [];
  const gaps = [...check.missing, ...check.weak];
  if (gaps.length) {
    const important = check.missing.some(name => name.startsWith("Strict-Transport") || name.startsWith("Content-Security")) ||
      check.weak.some(text => text.startsWith("Content-Security"));
    findings.push({
      id: "headers-missing", severity: important ? "medium" : "low", category: "Web hardening",
      title: "Web security header gaps", evidence: gaps.join("; ") + ".",
      action: "Add HSTS (with includeSubDomains), a strict Content-Security-Policy, frame-ancestors, nosniff, and Referrer-Policy.",
      technique: "T1189",
    });
  }
  if (check.downgrade) {
    findings.push({
      id: "headers-downgrade", severity: "medium", category: "Web hardening", title: "HTTPS redirects to plain HTTP",
      evidence: "The HTTPS response redirected to an http:// URL, which lets a network attacker intercept traffic.",
      action: "Redirect only to https:// URLs and enable HSTS.", technique: "T1557",
    });
  }
  if (check.disclosure.length) {
    findings.push({
      id: "headers-disclosure", severity: "low", category: "Web hardening", title: "Server software version disclosed",
      evidence: check.disclosure.join("; "), action: "Remove version details from Server and X-Powered-By headers.", technique: "T1592.002",
    });
  }
  return findings;
}

export function assessRed(
  subject: string,
  results: ReconResults | undefined,
  extras: RedExtras,
  observedAt = new Date().toISOString(),
): RedAssessment {
  const findings: RedFinding[] = [];
  if (results) {
    findings.push(...emailFinding(results.dns));
    for (const finding of results.purpleFindings ?? []) {
      if (finding.status !== "low") continue;
      const detail = ({
        CAA: ["No CAA record: any public CA may issue certificates", "low", "Publish CAA records naming only the CAs you use."],
        DNSSEC: ["DNSSEC is not enabled", "low", "Sign the zone and publish the DS record at the registrar."],
        DKIM: ["No DKIM key found at checked selectors", "info", "Confirm DKIM signing and check the real selector."],
      } as const)[finding.control];
      findings.push({
        id: "purple-" + finding.control.toLowerCase(), severity: detail[1], category: finding.control === "DKIM" ? "Email / phishing" : "DNS / PKI",
        title: detail[0], evidence: finding.red, action: detail[2], technique: finding.technique,
      });
    }
    findings.push(...certificateFindings(results, observedAt, subject));
  }
  if (extras.takeover) findings.push(...takeoverFindings(extras.takeover));
  if (extras.exposure) findings.push(...exposureFindings(extras.exposure));
  if (extras.headers) findings.push(...headerFindings(extras.headers));
  findings.sort((a, b) => rank(a.severity) - rank(b.severity));
  const counts = Object.fromEntries(SEVERITIES.map(level => [level, findings.filter(item => item.severity === level).length])) as Record<Severity, number>;
  const okHosts = extras.exposure?.filter(host => host.status === "ok") ?? [];
  const entryPoints = findings.filter(item => item.severity !== "info").slice(0, 8);
  return {
    findings,
    entryPoints,
    summary: {
      worst: findings.find(item => item.severity !== "info")?.severity ?? "none",
      counts,
      subdomains: results?.certificates ? results.certificates.nameCount : null,
      addressesChecked: extras.exposure ? extras.exposure.length : null,
      openPorts: extras.exposure ? okHosts.reduce((total, host) => total + host.ports.length, 0) : null,
      cves: extras.exposure ? okHosts.reduce((total, host) => total + host.vulns.length, 0) : null,
      takeoverCandidates: extras.takeover ? extras.takeover.hints.filter(item => item.state === "dangling").length : null,
    },
  };
}

// ---------- Export ----------

const cell = (value: string) => value.replace(/[\r\n|]+/g, " ").replace(/</g, "&lt;");

export function redReportMarkdown(subject: string, assessment: RedAssessment, results: ReconResults | undefined, extras: RedExtras, at: string): string {
  const { summary } = assessment;
  const lines = [
    `# Red Team Recon report: ${cell(subject)}`,
    "",
    `Generated ${at} by Globe. Passive public lookups only. Use for authorized assessments of systems you own or have permission to test.`,
    "",
    "## Summary",
    "",
    `- Highest severity: ${summary.worst}`,
    ...SEVERITIES.map(level => `- ${level}: ${summary.counts[level]}`),
    `- Subdomains in certificate logs: ${summary.subdomains ?? "n/a"}`,
    `- Open ports seen by Shodan InternetDB: ${summary.openPorts ?? "not checked"}`,
    `- CVEs reported by Shodan InternetDB: ${summary.cves ?? "not checked"}`,
    `- Takeover candidates: ${summary.takeoverCandidates ?? "not checked"}`,
    "",
    "## Findings",
    "",
    assessment.findings.length ? "| Severity | Category | Finding | Evidence | Fix |\n|---|---|---|---|---|" : "No findings.",
    ...assessment.findings.map(item => `| ${item.severity} | ${cell(item.category)} | ${cell(item.title)} | ${cell(item.evidence)} | ${cell(item.action)} |`),
  ];
  if (results?.certificates?.names.length) {
    lines.push("", "## Subdomains seen in certificate logs", "", ...results.certificates.names.map(name => `- ${cell(name)}`));
  }
  if (extras.exposure?.length) {
    lines.push("", "## Exposure (Shodan InternetDB)", "", ...extras.exposure.map(host =>
      `- ${cell(host.address)}: ${host.status === "ok" ? `ports ${host.ports.join(", ") || "none"}; CVEs ${host.vulns.join(", ") || "none"}` : host.status === "none" ? "no data" : "lookup unavailable"}`));
  }
  return lines.join("\n") + "\n";
}

export function redReportJson(subject: string, assessment: RedAssessment, results: ReconResults | undefined, extras: RedExtras, at: string): string {
  return JSON.stringify({
    tool: "Globe Red Team Recon",
    notice: "Passive public lookups only. Authorized assessments only.",
    subject,
    generatedAt: at,
    summary: assessment.summary,
    findings: assessment.findings,
    subdomains: results?.certificates?.names ?? [],
    exposure: extras.exposure ?? null,
    takeover: extras.takeover ?? null,
    headers: extras.headers ?? null,
  }, null, 2) + "\n";
}

export function redReportResponse(
  format: "md" | "json", subject: string, assessment: RedAssessment, results: ReconResults | undefined, extras: RedExtras,
  applySecurityHeaders: (headers: Headers) => void,
): Response {
  const at = new Date().toISOString();
  const safe = subject.replace(/[^a-z0-9.-]/gi, "_").slice(0, 80);
  const headers = new Headers({
    "content-type": format === "md" ? "text/markdown; charset=utf-8" : "application/json; charset=utf-8",
    "content-disposition": `attachment; filename="red-team-recon-${safe}.${format}"`,
    "cache-control": "private, no-store",
    "x-content-type-options": "nosniff",
    "content-security-policy": "default-src 'none'; sandbox",
  });
  applySecurityHeaders(headers);
  return new Response(
    format === "md" ? redReportMarkdown(subject, assessment, results, extras, at) : redReportJson(subject, assessment, results, extras, at),
    { headers },
  );
}
