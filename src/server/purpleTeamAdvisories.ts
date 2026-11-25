import { BodyLimitError, readBoundedText } from "./boundedBody";

type SecurityHeaders = (headers: Headers) => void;

const ECOSYSTEMS = ["npm", "PyPI", "Go", "Maven", "crates.io", "NuGet"];
const REPORT_TOOLS = [
  "amass", "nuclei", "trivy", "syft", "grype", "sslyze", "testssl", "zeek",
  "suricata", "sigma", "yara", "atomic-red-team", "openscap",
];

type Advisory = {
  id: string;
  aliases?: string[];
  summary?: string;
  severity?: { type: string; score: string }[];
  modified?: string;
  withdrawn?: string;
};

type OsvResponse = {
  vulns?: Advisory[];
  next_page_token?: string;
};

type LookupResult =
  | { status: 400 | 502; data: { error: string } }
  | { status: 200; data: {
      source: "OSV";
      name: string;
      version: string;
      ecosystem: string;
      partial: boolean;
      findings: Advisory[];
    } };

function escapeHtml(value: unknown): string {
  return String(value ?? "").replace(/[&<>"']/g, (character) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character] ?? character,
  );
}

function reportPage(title: string, content: string, applySecurityHeaders?: SecurityHeaders) {
  const headers = new Headers({
    "content-type": "text/html; charset=utf-8",
    "cache-control": "private, no-store",
    vary: "Cookie",
    "x-robots-tag": "noindex, nofollow",
    "referrer-policy": "same-origin",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  });
  applySecurityHeaders?.(headers);
  return new Response(`<!doctype html><html lang="en"><head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>${escapeHtml(title)}</title>
    <style>
      body{background:#0d0a14;color:#e9e3f7;font:16px system-ui;max-width:960px;margin:30px auto;padding:16px}
      a,h1,h2{color:#b58aff}
      form,article{background:#171124;border:1px solid #392952;padding:18px;border-radius:12px;margin:12px 0}
      label{display:block;margin:10px 0}
      input,select,button,textarea{font:inherit;color:inherit;background:#211734;border:1px solid #684b90;padding:10px;border-radius:7px;max-width:100%;box-sizing:border-box}
      textarea{width:100%;min-height:160px} button{cursor:pointer}
      pre{white-space:pre-wrap;overflow-wrap:anywhere}
      table{width:100%;border-collapse:collapse;overflow-wrap:anywhere}
      td,th{padding:8px;border-bottom:1px solid #392952;text-align:left}
    </style></head><body><main>
    <a href="/admin/purple-team">Back to Purple Team</a>
    <h1>${escapeHtml(title)}</h1>${content}
    </main></body></html>`, { headers });
}

function reportSection(title: string, content: string): string {
  return `<article><h2>${escapeHtml(title)}</h2>${content}</article>`;
}

function reportJson(data: unknown): string {
  return `<pre>${escapeHtml(JSON.stringify(data, null, 2))}</pre>`;
}

async function fetchJson<T>(url: string, limit: number, body?: unknown, timeout = 8000): Promise<T> {
  const headers = new Headers({ accept: "application/json" });
  if (body !== undefined) headers.set("content-type", "application/json");
  const response = await fetch(url, {
    method: body === undefined ? "GET" : "POST",
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "manual",
    headers,
    signal: AbortSignal.timeout(timeout),
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error("Upstream unavailable: HTTP " + response.status);
  }
  return JSON.parse(await readBoundedText(response.body, limit)) as T;
}

export async function lookupPackageAdvisories(params: URLSearchParams): Promise<LookupResult> {
  const name = params.get("package") ?? "";
  const version = params.get("version") ?? "";
  const ecosystem = params.get("ecosystem") || "npm";
  if (!ECOSYSTEMS.includes(ecosystem) || !/^[A-Za-z0-9@._/+:-]{1,180}$/.test(name) ||
      !/^[vV]?\d/.test(version) || !/^[A-Za-z0-9._+:-]{1,100}$/.test(version)) {
    return { status: 400, data: { error: "invalid_package_or_version" } };
  }
  try {
    const data = await fetchJson<OsvResponse>("https://api.osv.dev/v1/query", 1_048_576, {
      package: { name, ecosystem }, version,
    });
    const advisories = Array.isArray(data.vulns) ? data.vulns : [];
    const findings = advisories.filter((entry) => entry && typeof entry.id === "string" && !entry.withdrawn)
      .slice(0, 100)
      .map(({ id, aliases, summary, severity, modified }) => ({
        id, aliases: Array.isArray(aliases) ? aliases : undefined, summary, severity, modified,
      }));
    return {
      status: 200,
      data: { source: "OSV", name, version, ecosystem, partial: Boolean(data.next_page_token) || advisories.length > 100, findings },
    };
  } catch (error) {
    return {
      status: 502,
      data: { error: error instanceof BodyLimitError ? "upstream_response_too_large" : "upstream_unavailable" },
    };
  }
}

export async function packageAdvisoriesPage(params: URLSearchParams, applySecurityHeaders?: SecurityHeaders) {
  const options = ECOSYSTEMS.map((item) =>
    `<option${params.get("ecosystem") === item ? " selected" : ""}>${item}</option>`,
  ).join("");
  let result = "";
  if (params.has("package")) {
    const lookup = await lookupPackageAdvisories(params);
    if (lookup.status === 200) {
      const { name, version, partial, findings } = lookup.data;
      result = `<h2>${escapeHtml(name)} ${escapeHtml(version)} · ${findings.length} advisories</h2>
        <p>${partial ? "Partial results. " : ""}Review affected versions before treating a package as clear.</p>
        ${findings.map((entry) => reportSection(entry.id, `<p>${escapeHtml(entry.summary || "No summary supplied")}</p>
          <p>${escapeHtml(entry.aliases?.join(", "))}</p>${reportJson(entry.severity ?? [])}`)).join("")}`;
    } else {
      result = `<p>Lookup failed: ${escapeHtml(lookup.data.error)}</p>`;
    }
  }
  return reportPage("Software vulnerability intelligence", `<p>OSV advisory lookup for exact installed versions.</p>
    <form method="get" action="/admin/purple-team/vulnerabilities">
      <label>Ecosystem <select name="ecosystem">${options}</select></label>
      <label>Package <input required maxlength="180" name="package" value="${escapeHtml(params.get("package"))}" placeholder="react"></label>
      <label>Installed version <input required maxlength="100" name="version" value="${escapeHtml(params.get("version"))}" placeholder="18.3.1"></label>
      <button>Check vulnerabilities</button>
    </form>${result}`, applySecurityHeaders);
}

type ImportedRecord = {
  VulnerabilityID?: unknown;
  Severity?: unknown;
  severity?: unknown;
  id?: unknown;
  "template-id"?: unknown;
  name?: unknown;
  signature_id?: unknown;
  Title?: unknown;
  PkgName?: unknown;
  InstalledVersion?: unknown;
  version?: unknown;
  FixedVersion?: unknown;
  cve?: unknown;
  info?: { name?: unknown; severity?: unknown; classification?: { "cve-id"?: unknown } };
  vulnerability?: { id?: unknown; severity?: unknown; description?: unknown };
  artifact?: { name?: unknown; version?: unknown };
  alert?: { signature?: unknown };
};

function reportRecords(source: string, tool: string): unknown[] {
  let data: unknown;
  try {
    data = JSON.parse(source);
  } catch {
    const lines = source.trim().split(/\r?\n/).filter((line) => line.trim());
    if (lines.length > 1000) throw new Error("Maximum 1000 JSONL records.");
    data = lines.map((line) => JSON.parse(line));
  }
  if (Array.isArray(data)) return data;
  if (!data || typeof data !== "object") return [data];
  const wrapper = data as { Results?: { Vulnerabilities?: unknown[] }[]; matches?: unknown[]; artifacts?: unknown[] };
  if (tool === "trivy") {
    return Array.isArray(wrapper.Results) ? wrapper.Results.flatMap((result) =>
      Array.isArray(result?.Vulnerabilities) ? result.Vulnerabilities : [],
    ) : [];
  }
  if (tool === "grype") return Array.isArray(wrapper.matches) ? wrapper.matches : [];
  if (tool === "syft") return Array.isArray(wrapper.artifacts) ? wrapper.artifacts : [];
  return [data];
}

async function importedAssessment(request: Request): Promise<string> {
  try {
    const form = new URLSearchParams(await readBoundedText(request.body, 524_288));
    const tool = form.get("tool") ?? "";
    const source = form.get("report") ?? "";
    if (!REPORT_TOOLS.includes(tool) || !source.trim() || source.length > 160_000) {
      throw new Error("Choose a supported tool and paste a report up to 160,000 characters.");
    }
    const records = reportRecords(source, tool);
    if (records.length > 5000) throw new Error("Report exceeds 5000 records.");

    const severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
    const cveIds = new Set<string>();
    const samples: object[] = [];
    for (const value of records) {
      if (!value || typeof value !== "object") {
        severity.unknown++;
        if (samples.length < 100) samples.push({ record: "invalid" });
        continue;
      }
      const record = value as ImportedRecord;
      const info = record.info;
      const vulnerability = record.vulnerability;
      const level = String(record.Severity || record.severity || info?.severity || vulnerability?.severity || "unknown").toLowerCase();
      severity[Object.hasOwn(severity, level) ? level as keyof typeof severity : "unknown"]++;
      const ids = JSON.stringify([record.VulnerabilityID, vulnerability?.id, info?.classification?.["cve-id"], record.cve]);
      for (const id of ids.match(/CVE-\d{4}-\d{4,}/gi) ?? []) {
        if (cveIds.size === 500) break;
        cveIds.add(id.toUpperCase());
      }
      if (samples.length < 100) {
        samples.push({
          id: String(record.VulnerabilityID || vulnerability?.id || record["template-id"] || record.id || record.name || record.signature_id || "").slice(0, 180),
          severity: level,
          title: String(info?.name || record.Title || vulnerability?.description || record.name || record.alert?.signature || "").slice(0, 240),
          package: String(record.PkgName || record.artifact?.name || "").slice(0, 180),
          version: String(record.InstalledVersion || record.artifact?.version || record.version || "").slice(0, 120),
          fixedVersion: String(record.FixedVersion || "").slice(0, 120),
        });
      }
    }
    return reportSection("Imported report · " + tool, `<p>Imported findings are unverified and may need manual review. Reports are processed in memory.</p>
      ${reportJson({ records: records.length, severity, cveIds: [...cveIds], sampleLimit: 100, samples })}`);
  } catch (error) {
    return reportSection("Import failed", `<p>${escapeHtml(error instanceof SyntaxError ? "Enter valid JSON or JSONL." : (error as Error).message)}</p>`);
  }
}

async function cveReview(input: string): Promise<string> {
  const id = input.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,12}$/.test(id)) return reportSection("Invalid CVE", "<p>Enter a valid CVE identifier.</p>");

  type Epss = { epss: string; percentile: string; date: string };
  type Kev = { cveID: string; dateAdded: string; dueDate: string; requiredAction: string };
  type Cve = { cveMetadata?: { state?: string }; containers?: { cna?: { descriptions?: { lang: string; value: string }[] } } };
  const [epss, kev, cve] = await Promise.allSettled([
    fetchJson<{ data?: Epss[] }>("https://api.first.org/data/v1/epss?cve=" + encodeURIComponent(id), 65_536),
    fetchJson<{ vulnerabilities?: Kev[] }>("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", 4_194_304),
    fetchJson<Cve>("https://cveawg.mitre.org/api/cve/" + encodeURIComponent(id), 1_048_576),
  ]);
  const score = epss.status === "fulfilled" ? epss.value.data?.[0] : undefined;
  const listing = kev.status === "fulfilled" ? kev.value.vulnerabilities?.find((entry) => entry.cveID === id) : undefined;
  const record = cve.status === "fulfilled" ? cve.value : undefined;
  const summary = {
    cveState: record?.cveMetadata?.state ?? "unavailable",
    description: record?.containers?.cna?.descriptions?.find((entry) => entry.lang === "en")?.value ?? "unavailable",
    epss: score ? { probability: score.epss, percentile: score.percentile, date: score.date } : "unavailable",
    cisaKev: kev.status === "rejected" || !Array.isArray(kev.value.vulnerabilities) ? "unavailable" : listing
      ? { listed: true, dateAdded: listing.dateAdded, dueDate: listing.dueDate, requiredAction: listing.requiredAction }
      : { listed: false },
  };
  return reportSection(id, reportJson(summary) +
    "<p>EPSS estimates likelihood of exploitation. Validate affected versions and use KEV listings to prioritize remediation.</p>");
}

export async function assessmentPage(request: Request, params: URLSearchParams, applySecurityHeaders?: SecurityHeaders) {
  const cve = params.get("cve");
  const result = request.method === "POST" ? await importedAssessment(request)
    : cve !== null ? await cveReview(cve) : "";
  return reportPage("Assessment & Risk Center", `
    <p><a href="/admin/purple-team/vulnerabilities">Package checks</a></p>
    <form method="get"><h2>CVE prioritization</h2><p>MITRE CVE record, FIRST EPSS and CISA KEV.</p>
      <label>CVE <input name="cve" required placeholder="CVE-2024-12345" maxlength="25"></label><button>Check CVE</button>
    </form>
    <form method="post"><h2>Assessment evidence</h2>
      <p>Paste JSON or JSONL from authorized assessments. Reports are processed in memory.</p>
      <label>Tool <select name="tool">${REPORT_TOOLS.map((tool) => `<option>${tool}</option>`).join("")}</select></label>
      <label>Report <textarea name="report" required maxlength="160000"></textarea></label><button>Analyze report</button>
    </form>${result}
    <article><h2>Detection and compliance review</h2>
      <p>Review imported lab evidence against ATT&amp;CK, NIST 800-53, NIST 800-171, CIS and HIPAA.
        Record expected telemetry, observed detection, gaps, owner and retest date.</p>
    </article>`, applySecurityHeaders);
}

type Dependency = { name: string; version: string; dev: boolean };

async function auditDependencies(): Promise<string> {
  const limit = 2_097_152;
  const lock = await fetchJson<{ packages?: Record<string, { version?: string; dev?: boolean; link?: boolean } | null> }>(
    "https://raw.githubusercontent.com/m-emilio/globe/main/package-lock.json", limit,
  );
  if (!lock.packages || !Object.hasOwn(lock.packages, "")) throw new Error("Unsupported lockfile.");

  const packages = new Map<string, Dependency>();
  let skipped = 0;
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (!path) continue;
    const name = path.includes("node_modules/") ? path.split("node_modules/").at(-1) ?? "" : "";
    const version = entry?.version;
    if (entry?.link || !/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(name) ||
        typeof version !== "string" || !/^\d+\.\d+\.\d+(?:[-+][a-z0-9.+-]+)?$/i.test(version)) {
      skipped++;
      continue;
    }
    const key = name + "@" + version;
    packages.set(key, { name, version, dev: Boolean(entry?.dev && packages.get(key)?.dev !== false) });
  }
  const all = [...packages.values()].sort((a, b) => Number(a.dev) - Number(b.dev) || a.name.localeCompare(b.name));
  const selected = all.slice(0, 300);
  if (!selected.length) throw new Error("No exact npm package versions found.");

  const findings: (Dependency & { ids: string[] })[] = [];
  let checked = 0;
  let incomplete = 0;
  for (let start = 0; start < selected.length; start += 100) {
    const batch = selected.slice(start, start + 100);
    try {
      const data = await fetchJson<{ results?: (OsvResponse | null)[] }>(
        "https://api.osv.dev/v1/querybatch", limit,
        { queries: batch.map(({ name, version }) => ({ package: { ecosystem: "npm", name }, version })) },
        20_000,
      );
      if (!Array.isArray(data.results) || data.results.length !== batch.length) throw new Error("Unexpected OSV response.");
      for (const [index, result] of data.results.entries()) {
        if (!result || typeof result !== "object") {
          incomplete++;
          continue;
        }
        if (result.next_page_token) incomplete++;
        else checked++;
        const ids = (Array.isArray(result.vulns) ? result.vulns : []).map((entry) => entry?.id)
          .filter((id): id is string => typeof id === "string").slice(0, 100);
        if (ids.length) findings.push({ ...batch[index], ids });
      }
    } catch {
      incomplete += batch.length;
    }
  }
  const partial = Boolean(skipped || incomplete || all.length > selected.length);
  const rows = findings.map(({ name, version, dev, ids }) => `<tr>
    <td>${escapeHtml(name)}</td><td>${escapeHtml(version)}</td><td>${dev ? "Development" : "Runtime / optional"}</td>
    <td>${ids.map((id) => `<a rel="noreferrer" href="https://osv.dev/vulnerability/${encodeURIComponent(id)}">${escapeHtml(id)}</a>`).join(" · ")}</td>
    </tr>`).join("");
  return reportSection("Audit results", `
    <p>${partial ? "Partial audit. " : ""}Completed package queries: ${checked} / ${all.length}.
      Skipped lockfile entries: ${skipped}. Incomplete queries: ${incomplete}.
      Packages with advisory matches: ${findings.length}.</p>
    <p>Source: GitHub main lockfile. Results include development dependencies and describe published advisories.</p>
    ${rows ? `<table><thead><tr><th>Package</th><th>Version</th><th>Scope</th><th>Advisories</th></tr></thead><tbody>${rows}</tbody></table>`
      : `<p>${partial ? "No matches returned by completed queries. Results are incomplete." : "No known advisories returned by OSV for checked versions."}</p>`}`);
}

export async function dependencyAuditPage(request: Request, applySecurityHeaders?: SecurityHeaders) {
  let report = "";
  if (request.method === "POST") {
    try {
      report = await auditDependencies();
    } catch (error) {
      report = reportSection("Audit unavailable", `<p>${escapeHtml((error as Error).message)}</p>`);
    }
  }
  return reportPage("Globe dependency audit", `<p>Check exact npm versions from the public Globe lockfile against OSV.</p>
    <form method="post"><button type="submit">Run dependency audit</button></form>${report}`, applySecurityHeaders);
}
