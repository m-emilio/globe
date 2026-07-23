/**
 * UNODC Data Portal theme hotspots for the globe.
 * Themes mirror https://data.unodc.org/ and https://data.unodc.org/datasearch.
 * Country series hydrate from open UNODC-sourced CSVs (OWID) + UNSD SDG API.
 */

import type {
  UnodcHotspotPoint,
  UnodcHotspotsPreview,
  UnodcThemeId,
  UnodcThemePreview,
} from "../shared";

const UNODC_SOURCE = "UNODC Data Portal";
const UNODC_SOURCE_URL = "https://data.unodc.org/";
const UNODC_DATASEARCH_URL = "https://data.unodc.org/datasearch";
const UNODC_CACHE_SECONDS = 6 * 60 * 60;
/** More countries → better relative scale; still capped for client path budget. */
const HOTSPOT_LIMIT = 90;
/** Prefer recent observations for “current” accuracy. */
const MIN_YEAR = 2015;
const SDG_API = "https://unstats.un.org/sdgapi/v1/sdg";
const OWID_CSV = (slug: string) =>
  `https://ourworldindata.org/grapher/${slug}.csv?v=1&csvType=full&useColumnShortNames=true`;
const OWID_INDICATOR_DATA = (id: number) =>
  `https://api.ourworldindata.org/v1/indicators/${id}.data.json`;
const OWID_INDICATOR_META = (id: number) =>
  `https://api.ourworldindata.org/v1/indicators/${id}.metadata.json`;
const OWID_COVID_LATEST =
  "https://raw.githubusercontent.com/owid/covid-19-data/master/public/data/latest/owid-covid-latest.csv";
const CENTROIDS_URL =
  "https://gist.githubusercontent.com/tadast/8827699/raw/" +
  "f5cac3d42d16b78348610fc4ec301e9234f82821/countries_codes_and_coordinates.csv";

type Centroid = { iso3: string; name: string; lat: number; lng: number; m49: string };

type ThemeSource =
  | {
      kind: "owid";
      slug: string;
      /** Invert so higher = worse (e.g. CPI). */
      invertFrom?: number;
      minYear?: number;
      maxYear?: number;
    }
  | {
      kind: "owid-indicator";
      /** OWID numeric indicator id (avoids CSV 403s on some charts). */
      variableId: number;
      invertFrom?: number;
      minYear?: number;
      maxYear?: number;
    }
  | {
      kind: "sdg";
      seriesCode: string;
      /** Require these dimension values (e.g. Sex: BOTHSEX). */
      dimensions?: Record<string, string>;
      invertFrom?: number;
      minYear?: number;
    }
  | {
      kind: "covid-latest";
      metric: "total_deaths_per_million" | "total_cases_per_million";
    }
  | {
      kind: "portal-only";
    };

type ThemeDef = {
  id: UnodcThemeId;
  label: string;
  portalPath: string;
  unit: string;
  seriesLabel: string;
  source: ThemeSource;
  note?: string;
};

/** All research themes listed on the UNODC Data Portal home / datasearch. */
const UNODC_THEME_DEFS: ThemeDef[] = [
  {
    id: "drug-seizure",
    label: "Individual Drugs Seizure",
    portalPath: "https://dmp.unodc.org/",
    unit: "% gap",
    seriesLabel: "Opioid treatment coverage gap (SDG SH_SUD_TREAT) — DMP seizure proxy",
    source: {
      kind: "sdg",
      seriesCode: "SH_SUD_TREAT",
      dimensions: {
        Sex: "BOTHSEX",
        "Substance use disorders": "OPIOIDS",
      },
      invertFrom: 100,
      minYear: MIN_YEAR,
    },
    note: "Open SDG treatment-gap proxy (higher = weaker opioid treatment coverage). Full Individual Drug Seizure events remain on the UNODC DMP.",
  },
  {
    id: "drug-use",
    label: "Drug Use & Treatment",
    portalPath: "https://data.unodc.org/datareport/druguse",
    unit: "per 100 people",
    seriesLabel: "Drug use disorder prevalence (OWID / IHME GBD)",
    source: {
      kind: "owid-indicator",
      variableId: 1188097,
      minYear: MIN_YEAR,
    },
    note: "Country prevalence of drug use disorders (all illicit drugs). Portal tables have additional UNODC detail.",
  },
  {
    id: "drug-trafficking",
    label: "Drug Trafficking & Cultivation",
    portalPath: "https://data.unodc.org/datareport/drug-seizure",
    unit: "per 100,000",
    seriesLabel: "Deaths from drug use disorders (OWID / IHME GBD) — market-harm proxy",
    source: {
      kind: "owid-indicator",
      variableId: 1165048,
      minYear: MIN_YEAR,
    },
    note: "Age-standardized drug-use death rates as open proxy for trafficking/market intensity. Cultivation & seizure tables on UNODC portal.",
  },
  {
    id: "homicide",
    label: "Intentional Homicide",
    portalPath: "https://data.unodc.org/datareport/hom-victim",
    unit: "per 100,000",
    seriesLabel: "UNODC intentional homicide rate (via OWID)",
    source: { kind: "owid", slug: "homicide-rate-unodc" },
  },
  {
    id: "violent-crime",
    label: "Violent & Sexual Crime",
    portalPath: "https://data.unodc.org/datareport/violent-offences",
    unit: "% population",
    seriesLabel: "SDG physical violence prevalence (VC_VOV_PHYL)",
    source: { kind: "sdg", seriesCode: "VC_VOV_PHYL" },
  },
  {
    id: "corruption",
    label: "Corruption, Environmental, & Other Crime",
    portalPath: "https://data.unodc.org/datareport/econ-corruption",
    unit: "% population",
    seriesLabel: "Bribery prevalence (UNODC / SDG 16.5.1 via OWID)",
    source: { kind: "owid", slug: "bribery-prevalence-un" },
    note: "Share who paid or were asked for a bribe (UNODC). Environmental crime tables remain on the portal.",
  },
  {
    id: "prisons",
    label: "Prisons & Prisoners",
    portalPath: "https://data.unodc.org/datareport/prison-held",
    unit: "per 100,000",
    seriesLabel: "Prison population rate (OWID / UNODC-linked)",
    source: { kind: "owid", slug: "prison-population-rate" },
  },
  {
    id: "justice",
    label: "Access & Functioning of Justice",
    portalPath: "https://data.unodc.org/datareport/cjs-arrested",
    unit: "% of prison pop.",
    seriesLabel: "Unsentenced detainees share (SDG 16.3.2 / OWID)",
    source: {
      kind: "owid",
      slug: "unsentenced-detainees-as-proportion-of-prison-population",
    },
  },
  {
    id: "firearms",
    label: "Firearms Trafficking",
    portalPath: "https://data.unodc.org/datareport/firearm-seizures",
    unit: "per 100,000",
    seriesLabel: "Firearm homicide rate (UNODC via OWID) — related hotspot proxy",
    source: { kind: "owid", slug: "homicide-rates-from-firearms" },
    note: "Proxy intensity from firearm homicide rates; seizure tables on portal.",
  },
  {
    id: "trafficking-persons",
    label: "Trafficking in Persons",
    portalPath: "https://data.unodc.org/datareport/tip-victims",
    unit: "per 100,000",
    seriesLabel: "Detected TIP victims rate (SDG VC_HTF_DETVR)",
    source: { kind: "sdg", seriesCode: "VC_HTF_DETVR" },
  },
  {
    id: "wildlife",
    label: "Wildlife Trafficking",
    portalPath: "https://data.unodc.org/datareport/wildlife-seizures",
    unit: "share illicit",
    seriesLabel: "Illicit wildlife trade share (SDG ER_WLD_TRPOACH)",
    source: { kind: "sdg", seriesCode: "ER_WLD_TRPOACH" },
  },
  {
    id: "covid",
    label: "COVID-19",
    portalPath: "https://data.unodc.org/datareport/covid-homicide",
    unit: "deaths / million",
    seriesLabel: "Cumulative COVID-19 deaths per million (OWID)",
    source: { kind: "covid-latest", metric: "total_deaths_per_million" },
    note: "Pandemic mortality intensity by country. UNODC COVID-crime dashboards remain on the portal.",
  },
];

let previewCache: { at: number; payload: UnodcHotspotsPreview } | null = null;
const PREVIEW_TTL_MS = UNODC_CACHE_SECONDS * 1000;
/** Browser + CDN TTL. Rate limits apply only on edge/KV miss (see withPublicEdgeCache). */
const UNODC_BROWSER_CACHE =
  "public, max-age=3600, s-maxage=21600, stale-while-revalidate=86400";
/** Persist across cold isolates so OWID/SDG hydrate is rare. Bump on theme source changes. */
const UNODC_KV_KEY = "unodc:hotspots-preview:v3";
/** Edge Cache API key version — bump when payload schema/sources change. */
export const UNODC_EDGE_CACHE_VERSION = "v3";
// Bump when intensity / filter logic changes so stale in-memory payloads are dropped after redeploy.

type UnodcKvEnv = {
  BILLING_KV?: KVNamespace;
};

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
  if (raw === undefined || raw === "" || raw === "NA" || raw === "nan") return null;
  const n = Number(String(raw).replace(/,/g, ""));
  return Number.isFinite(n) ? n : null;
}

async function fetchText(url: string): Promise<string | null> {
  try {
    const response = await fetch(url, {
      headers: { accept: "text/csv,application/json,*/*" },
      cf: { cacheEverything: true, cacheTtl: UNODC_CACHE_SECONDS },
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
      headers: { accept: "application/json" },
      cf: { cacheEverything: true, cacheTtl: UNODC_CACHE_SECONDS },
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
    const [name, , alpha3, numeric, latText, lngText] = parseCsvLine(line);
    const lat = parseNumber(latText);
    const lng = parseNumber(lngText);
    const iso3 = (alpha3 || "").replace(/"/g, "").trim().toUpperCase();
    const m49 = (numeric || "").replace(/"/g, "").trim().replace(/^0+/, "") || "";
    if (!iso3 || iso3.length !== 3 || lat === null || lng === null) continue;
    map.set(iso3, {
      iso3,
      name: (name || iso3).replace(/"/g, "").trim(),
      lat,
      lng,
      m49,
    });
  }
  return map;
}

function m49Index(centroids: Map<string, Centroid>): Map<string, Centroid> {
  const byM49 = new Map<string, Centroid>();
  for (const c of centroids.values()) {
    if (c.m49) byM49.set(c.m49, c);
  }
  return byM49;
}

type LatestPoint = { iso3: string; name: string; year: number; value: number };

function applyInvert(value: number, invertFrom?: number): number {
  if (invertFrom === undefined) return value;
  return Math.max(0, invertFrom - value);
}

function latestFromOwidCsv(
  csv: string | null,
  options?: { minYear?: number; maxYear?: number; invertFrom?: number },
): LatestPoint[] {
  if (!csv) return [];
  const minYear = options?.minYear ?? MIN_YEAR;
  const maxYear = options?.maxYear;
  const lines = csv.split(/\r?\n/).filter((l) => l.trim());
  if (lines.length < 2) return [];
  const header = parseCsvLine(lines[0]);
  const codeIdx = header.findIndex((h) => /^code$/i.test(h) || /^iso_code$/i.test(h));
  const entityIdx = header.findIndex(
    (h) => /^entity$/i.test(h) || /^location$/i.test(h),
  );
  const yearIdx = header.findIndex((h) => /^year$/i.test(h));
  // Value: first non-meta numeric column after year, or last column.
  let valueIdx = header.findIndex(
    (h, i) =>
      i > Math.max(yearIdx, 0) &&
      !/^(entity|code|year|owid_region|continent|iso_code|location)$/i.test(h),
  );
  if (valueIdx < 0) valueIdx = header.length - 1;

  const latest = new Map<string, LatestPoint>();
  for (const line of lines.slice(1)) {
    const cols = parseCsvLine(line);
    const iso3 = (cols[codeIdx] || "").toUpperCase();
    // Skip aggregates / non-countries (OWID region rows often lack a real ISO3).
    if (!iso3 || iso3.length !== 3 || !/^[A-Z]{3}$/.test(iso3)) continue;
    if (iso3.startsWith("OWID")) continue;
    const year =
      yearIdx >= 0 ? parseNumber(cols[yearIdx]) : new Date().getUTCFullYear();
    let value = parseNumber(cols[valueIdx]);
    if (year === null || value === null || value < 0) continue;
    if (year < minYear) continue;
    if (maxYear !== undefined && year > maxYear) continue;
    value = applyInvert(value, options?.invertFrom);
    const name = cols[entityIdx] || iso3;
    const prev = latest.get(iso3);
    if (!prev || year > prev.year) {
      latest.set(iso3, { iso3, name, year, value });
    }
  }
  return [...latest.values()];
}

async function latestFromOwidIndicator(
  variableId: number,
  options?: { minYear?: number; maxYear?: number; invertFrom?: number },
): Promise<LatestPoint[]> {
  const minYear = options?.minYear ?? MIN_YEAR;
  const maxYear = options?.maxYear;
  const [dataRaw, metaRaw] = await Promise.all([
    fetchJson(OWID_INDICATOR_DATA(variableId)),
    fetchJson(OWID_INDICATOR_META(variableId)),
  ]);
  if (!dataRaw || !metaRaw) return [];

  const data = dataRaw as {
    values?: number[];
    years?: number[];
    entities?: number[];
  };
  const meta = metaRaw as {
    dimensions?: {
      entities?: {
        values?: Array<{ id: number; name?: string; code?: string }>;
      };
    };
  };

  const entityById = new Map<number, { iso3: string; name: string }>();
  for (const ent of meta.dimensions?.entities?.values || []) {
    const code = (ent.code || "").toUpperCase();
    if (!code || code.length !== 3 || !/^[A-Z]{3}$/.test(code)) continue;
    if (code.startsWith("OWID") || code.startsWith("WB_") || code.startsWith("WHO_")) {
      continue;
    }
    entityById.set(ent.id, { iso3: code, name: ent.name || code });
  }

  const values = data.values || [];
  const years = data.years || [];
  const entities = data.entities || [];
  const n = Math.min(values.length, years.length, entities.length);
  const latest = new Map<string, LatestPoint>();

  for (let i = 0; i < n; i += 1) {
    const year = years[i];
    const ent = entityById.get(entities[i]);
    if (!ent || !Number.isFinite(year)) continue;
    if (year < minYear) continue;
    if (maxYear !== undefined && year > maxYear) continue;
    let value = values[i];
    if (!Number.isFinite(value) || value < 0) continue;
    value = applyInvert(value, options?.invertFrom);
    const prev = latest.get(ent.iso3);
    if (!prev || year > prev.year) {
      latest.set(ent.iso3, {
        iso3: ent.iso3,
        name: ent.name,
        year,
        value,
      });
    }
  }
  return [...latest.values()];
}

function latestFromCovidLatest(
  csv: string | null,
  metric: "total_deaths_per_million" | "total_cases_per_million",
): LatestPoint[] {
  if (!csv) return [];
  const lines = csv.split(/\r?\n/).filter((l) => l.trim());
  if (lines.length < 2) return [];
  const header = parseCsvLine(lines[0]);
  const codeIdx = header.findIndex((h) => /^iso_code$/i.test(h));
  const nameIdx = header.findIndex((h) => /^location$/i.test(h));
  const dateIdx = header.findIndex((h) => /^last_updated_date$/i.test(h));
  const valueIdx = header.findIndex((h) => h === metric);
  if (codeIdx < 0 || valueIdx < 0) return [];

  const out: LatestPoint[] = [];
  for (const line of lines.slice(1)) {
    const cols = parseCsvLine(line);
    const iso3 = (cols[codeIdx] || "").toUpperCase();
    if (!iso3 || iso3.length !== 3 || !/^[A-Z]{3}$/.test(iso3)) continue;
    if (iso3.startsWith("OWID")) continue;
    const value = parseNumber(cols[valueIdx]);
    if (value === null || value < 0) continue;
    const dateRaw = cols[dateIdx] || "";
    const year =
      parseNumber(dateRaw.slice(0, 4)) ?? new Date().getUTCFullYear();
    out.push({
      iso3,
      name: cols[nameIdx] || iso3,
      year,
      value,
    });
  }
  return out;
}

async function latestFromSdg(
  seriesCode: string,
  byM49: Map<string, Centroid>,
  options?: {
    dimensions?: Record<string, string>;
    invertFrom?: number;
    minYear?: number;
  },
): Promise<LatestPoint[]> {
  const minYear = options?.minYear ?? MIN_YEAR;
  const requiredDims = options?.dimensions || {};
  const latest = new Map<string, LatestPoint>();
  // Three pages cover SH_SUD_TREAT (2507) and denser series.
  const pageUrls = [1, 2, 3].map(
    (page) =>
      `${SDG_API}/Series/Data?seriesCode=${encodeURIComponent(seriesCode)}` +
      `&pageSize=900&pageNumber=${page}`,
  );
  const payloads = await Promise.all(pageUrls.map((url) => fetchJson(url)));

  for (const raw of payloads) {
    const payload = raw as {
      data?: Array<Record<string, unknown>>;
    } | null;
    if (!payload?.data?.length) continue;

    for (const row of payload.data) {
      const m49 = String(row.geoAreaCode ?? "").replace(/^0+/, "");
      // Skip world / region aggregates (M49 countries are typically 3-digit).
      if (!m49 || m49.length > 3) continue;
      const centroid = byM49.get(m49);
      if (!centroid) continue;
      const year = parseNumber(String(row.timePeriodStart ?? ""));
      let value = parseNumber(String(row.value ?? ""));
      if (year === null || value === null || value < 0) continue;
      if (year < minYear) continue;

      const dims = (row.dimensions || {}) as Record<string, string>;
      // Strict: only both-sex / total when Sex dimension is present and not required.
      if (!requiredDims.Sex && !requiredDims.sex) {
        const sex = (dims.Sex || dims.sex || "").toUpperCase();
        if (sex && sex !== "BOTHSEX" && sex !== "TOTAL" && sex !== "ALL") {
          continue;
        }
      }
      let dimsOk = true;
      for (const [key, want] of Object.entries(requiredDims)) {
        const got = String(dims[key] ?? "").toUpperCase();
        if (got !== want.toUpperCase()) {
          dimsOk = false;
          break;
        }
      }
      if (!dimsOk) continue;

      value = applyInvert(value, options?.invertFrom);
      const prev = latest.get(centroid.iso3);
      if (!prev || year > prev.year) {
        latest.set(centroid.iso3, {
          iso3: centroid.iso3,
          name: String(row.geoAreaName || centroid.name),
          year,
          value,
        });
      }
    }
  }
  return [...latest.values()];
}

/**
 * Continuous intensity from full distribution (log scale vs p90).
 * Avoids “everything looks max red” when a few outliers dominate max().
 */
function intensityFromValues(value: number, p90: number, minV: number): number {
  if (!(p90 > minV)) {
    return 0.35;
  }
  // Normalize on log1p so mid-tier countries stay distinguishable.
  const t =
    (Math.log1p(Math.max(0, value - minV)) -
      Math.log1p(0)) /
    Math.log1p(Math.max(1e-9, p90 - minV));
  // Wider range so low vs high countries separate clearly on the globe.
  return Math.max(0.2, Math.min(1, 0.22 + t * 0.78));
}

function toHotspots(
  points: LatestPoint[],
  centroids: Map<string, Centroid>,
  themeId: string,
): UnodcHotspotPoint[] {
  const eligible = points.filter(
    (p) => centroids.has(p.iso3) && Number.isFinite(p.value) && p.value >= 0,
  );
  if (eligible.length === 0) return [];

  const sortedVals = eligible.map((p) => p.value).sort((a, b) => a - b);
  const minV = sortedVals[0] ?? 0;
  const p90 =
    sortedVals[Math.min(sortedVals.length - 1, Math.floor(sortedVals.length * 0.9))] ??
    sortedVals[sortedVals.length - 1] ??
    1;

  // Include broad set; rank by value for stable ordering, intensity is scale-based.
  const ranked = [...eligible].sort((a, b) => b.value - a.value).slice(0, HOTSPOT_LIMIT);

  return ranked.map((p) => {
    const c = centroids.get(p.iso3)!;
    return {
      id: `${themeId}-${p.iso3}`,
      iso3: p.iso3,
      name: p.name || c.name,
      lat: c.lat,
      lng: c.lng,
      value: Math.round(p.value * 1000) / 1000,
      year: p.year,
      intensity: intensityFromValues(p.value, p90, minV),
    };
  });
}

async function buildTheme(
  def: ThemeDef,
  centroids: Map<string, Centroid>,
  byM49: Map<string, Centroid>,
): Promise<UnodcThemePreview> {
  let points: LatestPoint[] = [];
  try {
    if (def.source.kind === "owid") {
      const csv = await fetchText(OWID_CSV(def.source.slug));
      points = latestFromOwidCsv(csv, {
        minYear: def.source.minYear,
        maxYear: def.source.maxYear,
        invertFrom: def.source.invertFrom,
      });
    } else if (def.source.kind === "owid-indicator") {
      points = await latestFromOwidIndicator(def.source.variableId, {
        minYear: def.source.minYear,
        maxYear: def.source.maxYear,
        invertFrom: def.source.invertFrom,
      });
    } else if (def.source.kind === "sdg") {
      points = await latestFromSdg(def.source.seriesCode, byM49, {
        dimensions: def.source.dimensions,
        invertFrom: def.source.invertFrom,
        minYear: def.source.minYear,
      });
    } else if (def.source.kind === "covid-latest") {
      const csv = await fetchText(OWID_COVID_LATEST);
      points = latestFromCovidLatest(csv, def.source.metric);
    }
  } catch {
    points = [];
  }

  const hotspots = toHotspots(points, centroids, def.id);
  const years = hotspots.map((h) => h.year);
  const period =
    years.length > 0
      ? `${Math.min(...years)}–${Math.max(...years)}`
      : null;

  return {
    id: def.id,
    label: def.label,
    portalUrl: def.portalPath,
    unit: def.unit,
    seriesLabel: def.seriesLabel,
    dataMode: hotspots.length > 0 ? "live" : "unavailable",
    period,
    hotspotCount: hotspots.length,
    hotspots,
    note: def.note,
  };
}

function isValidUnodcPayload(value: unknown): value is UnodcHotspotsPreview {
  if (!value || typeof value !== "object") return false;
  const p = value as UnodcHotspotsPreview;
  return Array.isArray(p.themes) && typeof p.source === "string";
}

async function readUnodcKv(
  env: UnodcKvEnv | undefined,
): Promise<{ at: number; payload: UnodcHotspotsPreview } | null> {
  if (!env?.BILLING_KV) return null;
  try {
    const raw = await env.BILLING_KV.get(UNODC_KV_KEY, "json");
    if (!raw || typeof raw !== "object") return null;
    const entry = raw as { at?: number; payload?: unknown };
    if (
      typeof entry.at !== "number" ||
      !isValidUnodcPayload(entry.payload)
    ) {
      return null;
    }
    return { at: entry.at, payload: entry.payload };
  } catch {
    return null;
  }
}

async function writeUnodcKv(
  env: UnodcKvEnv | undefined,
  entry: { at: number; payload: UnodcHotspotsPreview },
): Promise<void> {
  if (!env?.BILLING_KV) return;
  try {
    await env.BILLING_KV.put(UNODC_KV_KEY, JSON.stringify(entry), {
      expirationTtl: UNODC_CACHE_SECONDS,
    });
  } catch {
    // non-fatal
  }
}

export async function getUnodcHotspotsPreview(
  env?: UnodcKvEnv,
): Promise<Response> {
  const now = Date.now();
  if (previewCache && now - previewCache.at < PREVIEW_TTL_MS) {
    return jsonResponse(previewCache.payload, {
      headers: {
        "cache-control": UNODC_BROWSER_CACHE,
        "x-unodc-cache": "memory",
      },
    });
  }

  const kvHit = await readUnodcKv(env);
  if (kvHit && now - kvHit.at < PREVIEW_TTL_MS) {
    previewCache = kvHit;
    return jsonResponse(kvHit.payload, {
      headers: {
        "cache-control": UNODC_BROWSER_CACHE,
        "x-unodc-cache": "kv",
      },
    });
  }

  const centroidCsv = await fetchText(CENTROIDS_URL);
  const centroids = loadCentroids(centroidCsv);
  const byM49 = m49Index(centroids);

  // Parallel theme hydration (portal-only is instant).
  const themes = await Promise.all(
    UNODC_THEME_DEFS.map((def) => buildTheme(def, centroids, byM49)),
  );

  const liveCount = themes.filter((t) => t.dataMode === "live").length;
  const payload: UnodcHotspotsPreview = {
    source: UNODC_SOURCE,
    sourceUrl: UNODC_SOURCE_URL,
    datasearchUrl: UNODC_DATASEARCH_URL,
    updatedAt: new Date().toISOString(),
    queryLabel: `UNODC themes · ${liveCount}/${themes.length} with country hotspots`,
    themes,
    notes: [
      "Themes match the UNODC Data Portal (data.unodc.org).",
      "Hotspots use open country series (UNODC via OWID / UNSD SDG). Portal-only themes link to full UNODC tables.",
      "Marker size reflects relative intensity within each theme (not absolute global ranking across themes).",
    ],
  };

  const entry = { at: now, payload };
  previewCache = entry;
  // Await so the next isolate can hit KV even if edge put is still in flight.
  await writeUnodcKv(env, entry);

  return jsonResponse(payload, {
    headers: {
      "cache-control": UNODC_BROWSER_CACHE,
      "x-unodc-cache": "miss",
    },
  });
}

function jsonResponse(data: unknown, init?: ResponseInit) {
  const headers = new Headers(init?.headers);
  headers.set("content-type", "application/json; charset=utf-8");
  if (!headers.has("cache-control")) {
    headers.set("cache-control", "public, max-age=120");
  }
  // Security headers applied by caller path via applySecurityHeaders in index if needed —
  // index wraps with withoutResponseBodyForHead which preserves headers; main path applies CSP on HTML.
  return new Response(JSON.stringify(data), { ...init, headers });
}
