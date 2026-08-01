/**
 * PKI / TLS / certificate-related vulnerability hotspots for the globe.
 * Sources: CISA KEV (known exploited) + NVD keyword samples (cached at edge/KV).
 * Geography is a vendor→country signal map for visualization (not a claim of exploit location).
 */

import type {
  PkiCountryHotspot,
  PkiVulnCategory,
  PkiVulnCve,
  PkiVulnSeverity,
  PkiVulnsPreview,
} from "../shared";

const CISA_KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const CISA_KEV_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";
const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_CVE_URL = (id: string) => `https://nvd.nist.gov/vuln/detail/${id}`;

const CACHE_SECONDS = 6 * 60 * 60;
const BROWSER_CACHE =
  "public, max-age=1800, s-maxage=21600, stale-while-revalidate=86400";
const KV_KEY = "pki-vulns-preview:v2";
export const PKI_EDGE_CACHE_VERSION = "v2";

const CENTROIDS_URL =
  "https://gist.githubusercontent.com/tadast/8827699/raw/" +
  "f5cac3d42d16b78348610fc4ec301e9234f82821/countries_codes_and_coordinates.csv";

const PKI_TEXT_RE =
  /\b(certificate|x\.?509|pki|openssl|tls\b|ssl\b|cryptograph|s\/?mime|cng key|public.?key|private.?key|hard-?coded crypt|signature verif|certificate valid|trust store|root ca|intermediate ca|ssl\/?tls|tls handshake|ocsp|acme|subject.?public.?key|spki|cryptographic key|elliptic curve|rsa key|curveball|heartbleed|robot attack|beast attack|poodle|freak|logjam)\b/i;

const NVD_QUERIES = [
  "certificate validation",
  "openssl",
  "x.509",
  "hard-coded cryptographic key",
  "TLS certificate",
];

/** Vendor / product keywords → ISO3 deployment/HQ signal weights for map intensity. */
const VENDOR_COUNTRY_WEIGHTS: Array<{
  match: RegExp;
  countries: Array<{ iso3: string; weight: number }>;
}> = [
  {
    match: /microsoft|windows|active directory|cng/i,
    countries: [
      { iso3: "USA", weight: 1 },
      { iso3: "GBR", weight: 0.35 },
      { iso3: "DEU", weight: 0.3 },
      { iso3: "CAN", weight: 0.28 },
      { iso3: "AUS", weight: 0.25 },
      { iso3: "IND", weight: 0.22 },
      { iso3: "JPN", weight: 0.2 },
      { iso3: "NLD", weight: 0.18 },
      { iso3: "FRA", weight: 0.18 },
      { iso3: "SGP", weight: 0.15 },
    ],
  },
  {
    match: /apple|ios|macos|safari/i,
    countries: [
      { iso3: "USA", weight: 1 },
      { iso3: "GBR", weight: 0.28 },
      { iso3: "JPN", weight: 0.3 },
      { iso3: "DEU", weight: 0.22 },
      { iso3: "AUS", weight: 0.2 },
      { iso3: "CAN", weight: 0.2 },
      { iso3: "KOR", weight: 0.18 },
      { iso3: "FRA", weight: 0.16 },
    ],
  },
  {
    match: /openssl|heartbleed/i,
    countries: [
      { iso3: "USA", weight: 0.9 },
      { iso3: "DEU", weight: 0.75 },
      { iso3: "GBR", weight: 0.7 },
      { iso3: "NLD", weight: 0.65 },
      { iso3: "FRA", weight: 0.6 },
      { iso3: "JPN", weight: 0.55 },
      { iso3: "SGP", weight: 0.55 },
      { iso3: "IRL", weight: 0.5 },
      { iso3: "SWE", weight: 0.45 },
      { iso3: "BRA", weight: 0.4 },
      { iso3: "IND", weight: 0.45 },
      { iso3: "AUS", weight: 0.42 },
      { iso3: "CAN", weight: 0.42 },
      { iso3: "KOR", weight: 0.4 },
      { iso3: "CHN", weight: 0.38 },
    ],
  },
  {
    match: /fortinet|fortios|fortiproxy/i,
    countries: [
      { iso3: "USA", weight: 0.85 },
      { iso3: "CAN", weight: 0.7 },
      { iso3: "GBR", weight: 0.45 },
      { iso3: "DEU", weight: 0.4 },
      { iso3: "AUS", weight: 0.35 },
      { iso3: "SGP", weight: 0.35 },
      { iso3: "JPN", weight: 0.3 },
      { iso3: "ARE", weight: 0.28 },
      { iso3: "BRA", weight: 0.28 },
      { iso3: "IND", weight: 0.3 },
    ],
  },
  {
    match: /cisco|asa|firepower/i,
    countries: [
      { iso3: "USA", weight: 1 },
      { iso3: "GBR", weight: 0.4 },
      { iso3: "DEU", weight: 0.35 },
      { iso3: "JPN", weight: 0.32 },
      { iso3: "IND", weight: 0.3 },
      { iso3: "AUS", weight: 0.28 },
      { iso3: "SGP", weight: 0.28 },
      { iso3: "CAN", weight: 0.28 },
      { iso3: "BRA", weight: 0.25 },
    ],
  },
  {
    match: /sonicwall/i,
    countries: [
      { iso3: "USA", weight: 0.9 },
      { iso3: "GBR", weight: 0.35 },
      { iso3: "DEU", weight: 0.3 },
      { iso3: "AUS", weight: 0.28 },
      { iso3: "IND", weight: 0.25 },
      { iso3: "CAN", weight: 0.25 },
    ],
  },
  {
    match: /ivanti|pulse secure|connect secure/i,
    countries: [
      { iso3: "USA", weight: 0.9 },
      { iso3: "GBR", weight: 0.4 },
      { iso3: "DEU", weight: 0.35 },
      { iso3: "NLD", weight: 0.3 },
      { iso3: "AUS", weight: 0.28 },
      { iso3: "JPN", weight: 0.25 },
    ],
  },
  {
    match: /array networks/i,
    countries: [
      { iso3: "USA", weight: 0.7 },
      { iso3: "CHN", weight: 0.55 },
      { iso3: "SGP", weight: 0.35 },
      { iso3: "JPN", weight: 0.3 },
      { iso3: "IND", weight: 0.28 },
    ],
  },
  {
    match: /igel/i,
    countries: [
      { iso3: "DEU", weight: 0.9 },
      { iso3: "USA", weight: 0.45 },
      { iso3: "GBR", weight: 0.35 },
      { iso3: "NLD", weight: 0.3 },
      { iso3: "FRA", weight: 0.28 },
    ],
  },
  {
    match: /gladinet|centrestack|triofox/i,
    countries: [
      { iso3: "USA", weight: 0.75 },
      { iso3: "GBR", weight: 0.3 },
      { iso3: "DEU", weight: 0.28 },
      { iso3: "AUS", weight: 0.25 },
    ],
  },
];

/** Digital-economy countries that receive residual global OpenSSL/TLS signal. */
const GLOBAL_TLS_BASE: Array<{ iso3: string; weight: number }> = [
  { iso3: "USA", weight: 0.22 },
  { iso3: "CHN", weight: 0.18 },
  { iso3: "IND", weight: 0.16 },
  { iso3: "DEU", weight: 0.14 },
  { iso3: "GBR", weight: 0.14 },
  { iso3: "JPN", weight: 0.13 },
  { iso3: "BRA", weight: 0.12 },
  { iso3: "FRA", weight: 0.12 },
  { iso3: "KOR", weight: 0.11 },
  { iso3: "CAN", weight: 0.11 },
  { iso3: "AUS", weight: 0.1 },
  { iso3: "NLD", weight: 0.1 },
  { iso3: "SGP", weight: 0.1 },
  { iso3: "RUS", weight: 0.1 },
  { iso3: "ITA", weight: 0.09 },
  { iso3: "ESP", weight: 0.09 },
  { iso3: "IDN", weight: 0.09 },
  { iso3: "MEX", weight: 0.08 },
  { iso3: "TUR", weight: 0.08 },
  { iso3: "POL", weight: 0.08 },
  { iso3: "SWE", weight: 0.08 },
  { iso3: "CHE", weight: 0.08 },
  { iso3: "IRL", weight: 0.08 },
  { iso3: "ARE", weight: 0.07 },
  { iso3: "ZAF", weight: 0.07 },
  { iso3: "SAU", weight: 0.07 },
  { iso3: "ISR", weight: 0.07 },
  { iso3: "NOR", weight: 0.06 },
  { iso3: "FIN", weight: 0.06 },
  { iso3: "DNK", weight: 0.06 },
];

type Centroid = { iso3: string; name: string; lat: number; lng: number };

type KevEntry = {
  cveID?: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  shortDescription?: string;
  dateAdded?: string;
  requiredAction?: string;
  notes?: string;
};

type NvdCveItem = {
  cve?: {
    id?: string;
    published?: string;
    descriptions?: Array<{ lang?: string; value?: string }>;
    metrics?: {
      cvssMetricV31?: Array<{ cvssData?: { baseScore?: number; baseSeverity?: string } }>;
      cvssMetricV30?: Array<{ cvssData?: { baseScore?: number; baseSeverity?: string } }>;
      cvssMetricV2?: Array<{ cvssData?: { baseScore?: number }; baseSeverity?: string }>;
    };
    references?: Array<{ url?: string }>;
  };
};

type PkiKvEnv = { BILLING_KV?: KVNamespace };

let memoryCache: { at: number; payload: PkiVulnsPreview } | null = null;
const MEMORY_TTL_MS = CACHE_SECONDS * 1000;

function parseCsvLine(line: string): string[] {
  const columns: string[] = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    const next = line[i + 1];
    if (char === '"' && next === '"') {
      current += '"';
      i += 1;
    } else if (char === '"') {
      inQuotes = !inQuotes;
    } else if (char === "," && !inQuotes) {
      columns.push(current.trim().replace(/^"|"$/g, ""));
      current = "";
    } else {
      current += char;
    }
  }
  columns.push(current.trim().replace(/^"|"$/g, ""));
  return columns;
}

function parseNumber(raw: string | undefined): number | null {
  if (raw === undefined || raw === "" || raw === "NA") return null;
  const n = Number(String(raw).replace(/,/g, ""));
  return Number.isFinite(n) ? n : null;
}

async function fetchText(url: string): Promise<string | null> {
  try {
    const response = await fetch(url, {
      headers: { accept: "text/csv,application/json,*/*" },
      cf: { cacheEverything: true, cacheTtl: CACHE_SECONDS },
    });
    if (!response.ok) return null;
    return response.text();
  } catch {
    return null;
  }
}

async function fetchJson(url: string): Promise<unknown | null> {
  try {
    const response = await fetch(url, {
      headers: {
        accept: "application/json",
        "user-agent": "federalkey-globe-pki-preview/1.0",
      },
      cf: { cacheEverything: true, cacheTtl: CACHE_SECONDS },
    });
    if (!response.ok) return null;
    return response.json();
  } catch {
    return null;
  }
}

function loadCentroids(csv: string | null): Map<string, Centroid> {
  const map = new Map<string, Centroid>();
  if (!csv) return map;
  for (const line of csv.split(/\r?\n/).slice(1)) {
    if (!line.trim()) continue;
    const [name, , alpha3, , latText, lngText] = parseCsvLine(line);
    const lat = parseNumber(latText);
    const lng = parseNumber(lngText);
    const iso3 = (alpha3 || "").replace(/"/g, "").trim().toUpperCase();
    if (!iso3 || iso3.length !== 3 || lat === null || lng === null) continue;
    map.set(iso3, {
      iso3,
      name: (name || iso3).replace(/"/g, "").trim(),
      lat,
      lng,
    });
  }
  return map;
}

function isPkiRelated(text: string): boolean {
  return PKI_TEXT_RE.test(text);
}

function categorize(text: string): PkiVulnCategory[] {
  const cats = new Set<PkiVulnCategory>();
  if (/\b(certificate|x\.?509|pki|ocsp|acme|trust store|root ca)\b/i.test(text)) {
    cats.add("certificate");
  }
  if (/\b(tls|ssl|ssl\/?tls|handshake)\b/i.test(text)) {
    cats.add("tls-ssl");
  }
  if (/\bopenssl|heartbleed\b/i.test(text)) {
    cats.add("openssl");
  }
  if (
    /\b(hard-?coded crypt|cryptographic key|cng key|private.?key|public.?key|rsa key|elliptic)\b/i.test(
      text,
    )
  ) {
    cats.add("crypto-key");
  }
  if (/\b(auth|certificate dialog|signature verif|certificate valid)\b/i.test(text)) {
    cats.add("pki-auth");
  }
  if (cats.size === 0) cats.add("other-pki");
  return [...cats];
}

function severityFromCvss(score: number | null | undefined, label?: string | null): PkiVulnSeverity {
  if (label) {
    const s = label.toUpperCase();
    if (s.includes("CRITICAL")) return "critical";
    if (s.includes("HIGH")) return "high";
    if (s.includes("MEDIUM")) return "medium";
    if (s.includes("LOW")) return "low";
  }
  if (score == null || !Number.isFinite(score)) return "unknown";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

function severityWeight(sev: PkiVulnSeverity): number {
  switch (sev) {
    case "critical":
      return 4.5;
    case "high":
      return 3;
    case "medium":
      return 1.6;
    case "low":
      return 0.8;
    default:
      return 1.2;
  }
}

function normalizeCveId(raw: string | undefined | null): string | null {
  const id = (raw || "").trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(id)) return null;
  return id;
}

function fromKev(entry: KevEntry): PkiVulnCve | null {
  const id = normalizeCveId(entry.cveID);
  if (!id) return null;
  const blob = [
    entry.cveID,
    entry.vendorProject,
    entry.product,
    entry.vulnerabilityName,
    entry.shortDescription,
    entry.notes,
  ]
    .filter(Boolean)
    .join(" ");
  if (!isPkiRelated(blob)) return null;

  const title =
    (entry.vulnerabilityName || "").trim() ||
    `${entry.vendorProject || "Vendor"} ${entry.product || ""}`.trim() ||
    id;

  return {
    id,
    title,
    severity: "high", // KEV implies real-world exploitation priority
    cvss: null,
    description: (entry.shortDescription || title).trim(),
    vendor: entry.vendorProject?.trim() || null,
    product: entry.product?.trim() || null,
    categories: categorize(blob),
    knownExploited: true,
    publishedAt: null,
    kevDateAdded: entry.dateAdded || null,
    nvdUrl: NVD_CVE_URL(id),
    cisaUrl: CISA_KEV_PAGE,
  };
}

function fromNvd(item: NvdCveItem): PkiVulnCve | null {
  const cve = item.cve;
  const id = normalizeCveId(cve?.id);
  if (!id || !cve) return null;

  const desc =
    cve.descriptions?.find((d) => d.lang === "en")?.value ||
    cve.descriptions?.[0]?.value ||
    "";
  const blob = `${id} ${desc}`;
  if (!isPkiRelated(blob)) return null;

  const m31 = cve.metrics?.cvssMetricV31?.[0];
  const m30 = cve.metrics?.cvssMetricV30?.[0];
  const m2 = cve.metrics?.cvssMetricV2?.[0];
  const score =
    m31?.cvssData?.baseScore ??
    m30?.cvssData?.baseScore ??
    m2?.cvssData?.baseScore ??
    null;
  const sevLabel =
    m31?.cvssData?.baseSeverity ||
    m30?.cvssData?.baseSeverity ||
    m2?.baseSeverity ||
    null;

  return {
    id,
    title: desc.slice(0, 140) || id,
    severity: severityFromCvss(score, sevLabel),
    cvss: score,
    description: desc.slice(0, 600),
    vendor: null,
    product: null,
    categories: categorize(blob),
    knownExploited: false,
    publishedAt: cve.published || null,
    kevDateAdded: null,
    nvdUrl: NVD_CVE_URL(id),
    cisaUrl: null,
  };
}

async function fetchNvdKeyword(query: string): Promise<PkiVulnCve[]> {
  const url =
    `${NVD_API}?keywordSearch=${encodeURIComponent(query)}` +
    `&resultsPerPage=25`;
  const raw = await fetchJson(url);
  const payload = raw as { vulnerabilities?: Array<{ cve?: NvdCveItem["cve"] }> } | null;
  if (!payload?.vulnerabilities?.length) return [];
  const out: PkiVulnCve[] = [];
  for (const row of payload.vulnerabilities) {
    const cve = fromNvd({ cve: row.cve });
    if (cve) out.push(cve);
  }
  return out;
}

function mergeCves(lists: PkiVulnCve[][]): PkiVulnCve[] {
  const byId = new Map<string, PkiVulnCve>();
  for (const list of lists) {
    for (const cve of list) {
      const prev = byId.get(cve.id);
      if (!prev) {
        byId.set(cve.id, cve);
        continue;
      }
      // Prefer KEV flags + richer CVSS.
      byId.set(cve.id, {
        ...prev,
        ...cve,
        knownExploited: prev.knownExploited || cve.knownExploited,
        kevDateAdded: prev.kevDateAdded || cve.kevDateAdded,
        cisaUrl: prev.cisaUrl || cve.cisaUrl,
        cvss: prev.cvss ?? cve.cvss,
        severity:
          severityWeight(cve.severity) > severityWeight(prev.severity)
            ? cve.severity
            : prev.severity,
        categories: [...new Set([...prev.categories, ...cve.categories])],
        title:
          prev.knownExploited && prev.title.length < cve.title.length
            ? prev.title
            : cve.title.length >= prev.title.length
              ? cve.title
              : prev.title,
        description:
          cve.description.length > prev.description.length
            ? cve.description
            : prev.description,
        vendor: prev.vendor || cve.vendor,
        product: prev.product || cve.product,
      });
    }
  }
  return [...byId.values()].sort((a, b) => {
    if (a.knownExploited !== b.knownExploited) return a.knownExploited ? -1 : 1;
    const sw = severityWeight(b.severity) - severityWeight(a.severity);
    if (sw !== 0) return sw;
    return (b.cvss || 0) - (a.cvss || 0);
  });
}

function vendorWeights(cve: PkiVulnCve): Array<{ iso3: string; weight: number }> {
  const blob = `${cve.vendor || ""} ${cve.product || ""} ${cve.title} ${cve.description}`;
  const weights = new Map<string, number>();

  for (const rule of VENDOR_COUNTRY_WEIGHTS) {
    if (!rule.match.test(blob)) continue;
    for (const c of rule.countries) {
      weights.set(c.iso3, Math.max(weights.get(c.iso3) || 0, c.weight));
    }
  }

  // Global TLS/OpenSSL residual if no specific vendor match or openssl category.
  const needsGlobal =
    weights.size === 0 ||
    cve.categories.includes("openssl") ||
    cve.categories.includes("tls-ssl");
  if (needsGlobal) {
    for (const c of GLOBAL_TLS_BASE) {
      weights.set(c.iso3, (weights.get(c.iso3) || 0) + c.weight * 0.55);
    }
  }

  return [...weights.entries()].map(([iso3, weight]) => ({ iso3, weight }));
}

/** Attach origin + full exposure ISO3 list for client arc fan-out. */
function annotateCveGeography(cves: PkiVulnCve[]): PkiVulnCve[] {
  return cves.map((cve) => {
    const points = vendorWeights(cve)
      .slice()
      .sort((a, b) => b.weight - a.weight);
    if (points.length === 0) {
      return {
        ...cve,
        originIso3: "USA",
        exposureIso3s: GLOBAL_TLS_BASE.map((c) => c.iso3).filter(
          (iso) => iso !== "USA",
        ),
      };
    }
    const originIso3 = points[0].iso3;
    let exposureIso3s = points
      .filter((p) => p.iso3 !== originIso3)
      .map((p) => p.iso3);
    // Single-country vendor still gets residual global TLS destinations
    if (exposureIso3s.length === 0) {
      exposureIso3s = GLOBAL_TLS_BASE.map((c) => c.iso3).filter(
        (iso) => iso !== originIso3,
      );
    }
    return { ...cve, originIso3, exposureIso3s };
  });
}

function buildHotspots(
  cves: PkiVulnCve[],
  centroids: Map<string, Centroid>,
): PkiCountryHotspot[] {
  type Acc = {
    score: number;
    cveIds: Set<string>;
    critical: number;
    high: number;
    kev: number;
    categories: Set<PkiVulnCategory>;
  };
  const byIso = new Map<string, Acc>();
  const cveById = new Map(cves.map((c) => [c.id, c] as const));

  for (const cve of cves) {
    const base = severityWeight(cve.severity) * (cve.knownExploited ? 1.75 : 1);
    const cvssBoost = cve.cvss != null ? 0.15 * cve.cvss : 0.5;
    const points = vendorWeights(cve);
    for (const { iso3, weight } of points) {
      if (!centroids.has(iso3)) continue;
      let acc = byIso.get(iso3);
      if (!acc) {
        acc = {
          score: 0,
          cveIds: new Set(),
          critical: 0,
          high: 0,
          kev: 0,
          categories: new Set(),
        };
        byIso.set(iso3, acc);
      }
      acc.score += (base + cvssBoost) * weight;
      acc.cveIds.add(cve.id);
      if (cve.severity === "critical") acc.critical += 1;
      if (cve.severity === "high") acc.high += 1;
      if (cve.knownExploited) acc.kev += 1;
      for (const cat of cve.categories) acc.categories.add(cat);
    }
  }

  const rows = [...byIso.entries()]
    .map(([iso3, acc]) => {
      const c = centroids.get(iso3)!;
      // Rank linked CVEs by exploit status + severity (not insertion order)
      const rankedIds = [...acc.cveIds].sort((a, b) => {
        const ca = cveById.get(a);
        const cb = cveById.get(b);
        if (!ca || !cb) return 0;
        if (ca.knownExploited !== cb.knownExploited) {
          return ca.knownExploited ? -1 : 1;
        }
        const sw = severityWeight(cb.severity) - severityWeight(ca.severity);
        if (sw !== 0) return sw;
        return (cb.cvss || 0) - (ca.cvss || 0);
      });
      return {
        iso3,
        name: c.name,
        lat: c.lat,
        lng: c.lng,
        score: acc.score,
        cveCount: acc.cveIds.size,
        criticalCount: acc.critical,
        highCount: acc.high,
        kevCount: acc.kev,
        topCves: rankedIds.slice(0, 48),
        categories: [...acc.categories],
      };
    })
    .sort((a, b) => b.score - a.score)
    .slice(0, 72);

  if (rows.length === 0) return [];

  const scores = rows.map((r) => r.score).sort((a, b) => a - b);
  const p90 = scores[Math.min(scores.length - 1, Math.floor(scores.length * 0.9))] || 1;
  const minS = scores[0] || 0;

  return rows.map((r) => {
    const t =
      p90 > minS
        ? (Math.log1p(r.score - minS) - Math.log1p(0)) /
          Math.log1p(Math.max(1e-9, p90 - minS))
        : 0.5;
    const intensity = Math.max(0.22, Math.min(1, 0.25 + t * 0.75));
    return {
      id: `pki-${r.iso3}`,
      iso3: r.iso3,
      name: r.name,
      lat: r.lat,
      lng: r.lng,
      intensity,
      score: Math.round(r.score * 100) / 100,
      cveCount: r.cveCount,
      criticalCount: r.criticalCount,
      highCount: r.highCount,
      kevCount: r.kevCount,
      topCves: r.topCves,
      categories: r.categories,
    };
  });
}

async function readKv(
  env: PkiKvEnv | undefined,
): Promise<{ at: number; payload: PkiVulnsPreview } | null> {
  if (!env?.BILLING_KV) return null;
  try {
    const raw = await env.BILLING_KV.get(KV_KEY, "json");
    if (!raw || typeof raw !== "object") return null;
    const entry = raw as { at?: number; payload?: PkiVulnsPreview };
    if (
      typeof entry.at !== "number" ||
      !entry.payload ||
      !Array.isArray(entry.payload.cves) ||
      !Array.isArray(entry.payload.hotspots)
    ) {
      return null;
    }
    return { at: entry.at, payload: entry.payload };
  } catch {
    return null;
  }
}

async function writeKv(
  env: PkiKvEnv | undefined,
  entry: { at: number; payload: PkiVulnsPreview },
): Promise<void> {
  if (!env?.BILLING_KV) return;
  try {
    await env.BILLING_KV.put(KV_KEY, JSON.stringify(entry), {
      expirationTtl: CACHE_SECONDS,
    });
  } catch {
    // non-fatal
  }
}

function jsonResponse(data: unknown, init?: ResponseInit) {
  const headers = new Headers(init?.headers);
  headers.set("content-type", "application/json; charset=utf-8");
  if (!headers.has("cache-control")) {
    headers.set("cache-control", BROWSER_CACHE);
  }
  return new Response(JSON.stringify(data), { ...init, headers });
}

export async function getPkiVulnsPreview(env?: PkiKvEnv): Promise<Response> {
  const now = Date.now();
  if (memoryCache && now - memoryCache.at < MEMORY_TTL_MS) {
    return jsonResponse(memoryCache.payload, {
      headers: {
        "cache-control": BROWSER_CACHE,
        "x-pki-vulns-cache": "memory",
      },
    });
  }

  const kvHit = await readKv(env);
  if (kvHit && now - kvHit.at < MEMORY_TTL_MS) {
    memoryCache = kvHit;
    return jsonResponse(kvHit.payload, {
      headers: {
        "cache-control": BROWSER_CACHE,
        "x-pki-vulns-cache": "kv",
      },
    });
  }

  const [centroidCsv, kevRaw, ...nvdLists] = await Promise.all([
    fetchText(CENTROIDS_URL),
    fetchJson(CISA_KEV_URL),
    ...NVD_QUERIES.map((q) => fetchNvdKeyword(q)),
  ]);

  const centroids = loadCentroids(centroidCsv);
  const kevPayload = kevRaw as { vulnerabilities?: KevEntry[] } | null;
  const kevCves: PkiVulnCve[] = [];
  for (const entry of kevPayload?.vulnerabilities || []) {
    const cve = fromKev(entry);
    if (cve) kevCves.push(cve);
  }

  const cves = annotateCveGeography(
    mergeCves([kevCves, ...nvdLists]).slice(0, 120),
  );
  const hotspots = buildHotspots(cves, centroids);
  const kevCount = cves.filter((c) => c.knownExploited).length;
  const arcCount = cves.reduce(
    (n, c) => n + (c.exposureIso3s?.length || 0),
    0,
  );
  const dataMode: PkiVulnsPreview["dataMode"] =
    cves.length === 0
      ? "unavailable"
      : kevCves.length === 0 || nvdLists.every((l) => l.length === 0)
        ? "partial"
        : "live";

  const payload: PkiVulnsPreview = {
    source: "CISA KEV + NVD · certificate, TLS & crypto-key filter",
    sourceUrl: CISA_KEV_PAGE,
    cisaKevUrl: CISA_KEV_PAGE,
    nvdUrl: "https://nvd.nist.gov/",
    updatedAt: new Date().toISOString(),
    queryLabel: `${cves.length} CVEs · ${kevCount} known-exploited · ${arcCount} exposure arcs · ${hotspots.length} countries`,
    dataMode,
    cveCount: cves.length,
    hotspotCount: hotspots.length,
    cves,
    hotspots,
    notes: [
      "Each arc runs from the vendor’s primary origin country to deployment/exposure countries weighted by product footprint.",
      "Solid arcs = CISA Known Exploited Vulnerabilities (KEV). Dashed arcs = NVD catalog entries matching the PKI/TLS filter.",
      "Color encodes severity (critical → low). This is a signal map for situational awareness — not exploit geolocation or attribution.",
      "Filter keywords: certificate, X.509, OpenSSL, TLS/SSL, hard-coded crypto keys, CNG / public-key issues.",
    ],
  };

  const entry = { at: now, payload };
  memoryCache = entry;
  await writeKv(env, entry);

  return jsonResponse(payload, {
    headers: {
      "cache-control": BROWSER_CACHE,
      "x-pki-vulns-cache": "miss",
    },
  });
}
