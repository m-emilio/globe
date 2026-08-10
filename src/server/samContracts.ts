/**
 * SAM.gov Opportunities Public API proxy for FederalKey Globe.
 *
 * Security:
 * - API key only from Worker secret SAM_API_KEY (never client / git / responses)
 * - HTTPS host allowlist: api.sam.gov only; no redirects
 * - Query params allowlisted; secrets redacted from errors
 * - Edge + memory cache never stores the key
 */

import type {
  SamContractMarker,
  SamContractsPreview,
  SamOpportunityPreview,
  SamSetAsideCode,
} from "../shared";

const SAM_API_HOST = "api.sam.gov";
const SAM_API_PATH = "/opportunities/v2/search";
const SAM_SOURCE = "SAM.gov Opportunities Public API v2";
const SAM_SOURCE_URL = "https://open.gsa.gov/api/get-opportunities-public-api/";
const SAM_UI = "https://sam.gov";

export const SAM_EDGE_CACHE_VERSION = "v1";
const CACHE_SECONDS = 30 * 60;
/** Paid feature: never public CDN cache; server memory/KV still OK for SAM quota. */
const BROWSER_CACHE = "private, no-store";
const KV_KEY_PREFIX = "sam-contracts-preview:v1:";
const MAX_RESULTS = 60;
const MAX_REMOTE_QUERIES = 5;
const MAX_LIMIT = 40;
const REQUEST_TIMEOUT_MS = 18_000;

/** FederalKey / PKI-aligned NAICS (6-digit). */
export const SAM_NAICS_CATALOG: Record<string, string> = {
  "541511": "Custom Computer Programming Services",
  "541512": "Computer Systems Design Services",
  "541513": "Computer Facilities Management Services",
  "541519": "Other Computer Related Services",
  "541330": "Engineering Services",
  "541715": "R&D in Physical, Engineering & Life Sciences",
  "518210": "Computing Infrastructure / Data Processing / Hosting",
  "541690": "Other Scientific & Technical Consulting Services",
  "541611": "Admin Management & General Management Consulting",
  "561621": "Security Systems Services (except Locksmiths)",
  "561612": "Security Guards & Patrol Services",
  "334111": "Electronic Computer Manufacturing",
  "334118": "Computer Terminal & Other Computer Peripheral Equipment Mfg",
  "334419": "Other Electronic Component Manufacturing",
  "517111": "Wired Telecommunications Carriers",
  "517810": "All Other Telecommunications",
  "611420": "Computer Training",
  "561210": "Facilities Support Services",
};

export const SAM_NAICS_GROUPS: Record<
  string,
  { label: string; codes: string[] }
> = {
  fk_pki: {
    label: "PKI / identity / cyber",
    codes: ["541512", "541519", "541690", "541611"],
  },
  fk_core: {
    label: "Software & systems design",
    codes: ["541511", "541512", "541519"],
  },
  fk_pacs: {
    label: "Physical access / security systems",
    codes: ["561621", "561612", "561210"],
  },
  fk_hw: {
    label: "Smart card / endpoint hardware",
    codes: ["334111", "334118", "334419"],
  },
  fk_infra: {
    label: "Hosting / telecom / facilities IT",
    codes: ["518210", "517111", "517810", "541513"],
  },
  fk_all: {
    label: "All FederalKey-relevant NAICS",
    codes: Object.keys(SAM_NAICS_CATALOG),
  },
};

export const SAM_SET_ASIDE_OPTIONS: Record<string, string> = {
  any: "Any (no set-aside filter)",
  ANY_SB: "Any small business set-aside",
  SBA: "Total Small Business Set-Aside (SBA)",
  SBP: "Partial Small Business Set-Aside (SBP)",
  "8A": "8(a) Set-Aside",
  "8AN": "8(a) Sole Source",
  HZC: "HUBZone Set-Aside",
  HZS: "HUBZone Sole Source",
  SDVOSBC: "SDVOSB Set-Aside",
  SDVOSBS: "SDVOSB Sole Source",
  WOSB: "Women-Owned Small Business (WOSB)",
  EDWOSB: "EDWOSB Set-Aside",
  VSA: "Veteran-Owned Small Business (VSA)",
  VSS: "VOSB Sole Source",
};

const ANY_SB_CODES = new Set([
  "SBA",
  "SBP",
  "8A",
  "8AN",
  "HZC",
  "HZS",
  "SDVOSBC",
  "SDVOSBS",
  "WOSB",
  "EDWOSB",
  "VSA",
  "VSS",
]);

const PRESETS: Record<
  string,
  { label: string; keywords: string[]; naics: string[] }
> = {
  pki: {
    label: "Public Key Infrastructure (PKI)",
    keywords: [
      "Public Key Infrastructure",
      "PKI",
      "certificate authority",
      "hardware security module",
      "PIV CAC",
      "digital certificate",
    ],
    naics: ["541512", "541519", "541511"],
  },
  cyber: {
    label: "Cybersecurity & zero trust",
    keywords: [
      "cybersecurity",
      "zero trust",
      "identity and access management",
      "ICAM",
      "information assurance",
    ],
    naics: ["541512", "541519", "541690"],
  },
  software: {
    label: "Software design & engineering",
    keywords: [
      "software development",
      "software design",
      "application development",
      "DevSecOps",
    ],
    naics: ["541511", "541512", "541519"],
  },
  awards: {
    label: "Awards & small business notices",
    keywords: ["award", "PKI", "cybersecurity", "identity"],
    naics: ["541512", "541519", "541511"],
  },
};

/** US state / territory approximate centroids for place-of-performance mapping. */
const US_STATE_CENTROIDS: Record<string, { lat: number; lng: number; name: string }> =
  {
    AL: { lat: 32.8, lng: -86.8, name: "Alabama" },
    AK: { lat: 64.2, lng: -152.5, name: "Alaska" },
    AZ: { lat: 34.3, lng: -111.7, name: "Arizona" },
    AR: { lat: 34.9, lng: -92.4, name: "Arkansas" },
    CA: { lat: 37.2, lng: -119.5, name: "California" },
    CO: { lat: 39.0, lng: -105.5, name: "Colorado" },
    CT: { lat: 41.6, lng: -72.7, name: "Connecticut" },
    DE: { lat: 39.0, lng: -75.5, name: "Delaware" },
    DC: { lat: 38.9, lng: -77.0, name: "District of Columbia" },
    FL: { lat: 28.1, lng: -81.7, name: "Florida" },
    GA: { lat: 32.7, lng: -83.4, name: "Georgia" },
    HI: { lat: 20.3, lng: -156.4, name: "Hawaii" },
    ID: { lat: 44.4, lng: -114.6, name: "Idaho" },
    IL: { lat: 40.0, lng: -89.2, name: "Illinois" },
    IN: { lat: 39.9, lng: -86.3, name: "Indiana" },
    IA: { lat: 42.0, lng: -93.5, name: "Iowa" },
    KS: { lat: 38.5, lng: -98.3, name: "Kansas" },
    KY: { lat: 37.5, lng: -85.3, name: "Kentucky" },
    LA: { lat: 31.0, lng: -92.0, name: "Louisiana" },
    ME: { lat: 45.3, lng: -69.2, name: "Maine" },
    MD: { lat: 39.0, lng: -76.8, name: "Maryland" },
    MA: { lat: 42.3, lng: -71.8, name: "Massachusetts" },
    MI: { lat: 44.3, lng: -85.4, name: "Michigan" },
    MN: { lat: 46.3, lng: -94.3, name: "Minnesota" },
    MS: { lat: 32.7, lng: -89.7, name: "Mississippi" },
    MO: { lat: 38.4, lng: -92.5, name: "Missouri" },
    MT: { lat: 47.0, lng: -109.6, name: "Montana" },
    NE: { lat: 41.5, lng: -99.8, name: "Nebraska" },
    NV: { lat: 39.3, lng: -116.6, name: "Nevada" },
    NH: { lat: 43.7, lng: -71.6, name: "New Hampshire" },
    NJ: { lat: 40.1, lng: -74.5, name: "New Jersey" },
    NM: { lat: 34.4, lng: -106.1, name: "New Mexico" },
    NY: { lat: 42.9, lng: -75.5, name: "New York" },
    NC: { lat: 35.6, lng: -79.4, name: "North Carolina" },
    ND: { lat: 47.5, lng: -100.5, name: "North Dakota" },
    OH: { lat: 40.3, lng: -82.8, name: "Ohio" },
    OK: { lat: 35.6, lng: -97.5, name: "Oklahoma" },
    OR: { lat: 44.0, lng: -120.5, name: "Oregon" },
    PA: { lat: 40.9, lng: -77.8, name: "Pennsylvania" },
    RI: { lat: 41.7, lng: -71.5, name: "Rhode Island" },
    SC: { lat: 33.9, lng: -80.9, name: "South Carolina" },
    SD: { lat: 44.4, lng: -100.2, name: "South Dakota" },
    TN: { lat: 35.9, lng: -86.4, name: "Tennessee" },
    TX: { lat: 31.5, lng: -99.3, name: "Texas" },
    UT: { lat: 39.3, lng: -111.7, name: "Utah" },
    VT: { lat: 44.1, lng: -72.7, name: "Vermont" },
    VA: { lat: 37.5, lng: -78.9, name: "Virginia" },
    WA: { lat: 47.4, lng: -120.5, name: "Washington" },
    WV: { lat: 38.6, lng: -80.6, name: "West Virginia" },
    WI: { lat: 44.6, lng: -89.7, name: "Wisconsin" },
    WY: { lat: 43.0, lng: -107.6, name: "Wyoming" },
    PR: { lat: 18.2, lng: -66.5, name: "Puerto Rico" },
    GU: { lat: 13.4, lng: 144.8, name: "Guam" },
    VI: { lat: 18.3, lng: -64.9, name: "U.S. Virgin Islands" },
  };

/** Major city nudges so multiple contracts in one state do not stack exactly. */
const CITY_NUDGES: Record<string, { lat: number; lng: number }> = {
  "washington|dc": { lat: 38.9072, lng: -77.0369 },
  "arlington|va": { lat: 38.8816, lng: -77.091 },
  "alexandria|va": { lat: 38.8048, lng: -77.0469 },
  "reston|va": { lat: 38.9586, lng: -77.357 },
  "fairfax|va": { lat: 38.8462, lng: -77.3064 },
  "norfolk|va": { lat: 36.8508, lng: -76.2859 },
  "richmond|va": { lat: 37.5407, lng: -77.436 },
  "new york|ny": { lat: 40.7128, lng: -74.006 },
  "boston|ma": { lat: 42.3601, lng: -71.0589 },
  "philadelphia|pa": { lat: 39.9526, lng: -75.1652 },
  "atlanta|ga": { lat: 33.749, lng: -84.388 },
  "miami|fl": { lat: 25.7617, lng: -80.1918 },
  "tampa|fl": { lat: 27.9506, lng: -82.4572 },
  "orlando|fl": { lat: 28.5383, lng: -81.3792 },
  "chicago|il": { lat: 41.8781, lng: -87.6298 },
  "detroit|mi": { lat: 42.3314, lng: -83.0458 },
  "dallas|tx": { lat: 32.7767, lng: -96.797 },
  "houston|tx": { lat: 29.7604, lng: -95.3698 },
  "san antonio|tx": { lat: 29.4241, lng: -98.4936 },
  "austin|tx": { lat: 30.2672, lng: -97.7431 },
  "denver|co": { lat: 39.7392, lng: -104.9903 },
  "phoenix|az": { lat: 33.4484, lng: -112.074 },
  "los angeles|ca": { lat: 34.0522, lng: -118.2437 },
  "san diego|ca": { lat: 32.7157, lng: -117.1611 },
  "san francisco|ca": { lat: 37.7749, lng: -122.4194 },
  "sacramento|ca": { lat: 38.5816, lng: -121.4944 },
  "seattle|wa": { lat: 47.6062, lng: -122.3321 },
  "portland|or": { lat: 45.5152, lng: -122.6784 },
  "huntsville|al": { lat: 34.7304, lng: -86.5861 },
  "colorado springs|co": { lat: 38.8339, lng: -104.8214 },
  "dayton|oh": { lat: 39.7589, lng: -84.1916 },
  "ogden|ut": { lat: 41.223, lng: -111.9738 },
  "omaha|ne": { lat: 41.2565, lng: -95.9345 },
};

type SamEnv = {
  SAM_API_KEY?: string;
  BILLING_KV?: KVNamespace;
};

type SearchQuery = {
  preset: string;
  q: string;
  days: number;
  limit: number;
  setAside: string;
  ptype: string;
  naics: string[];
  naicsGroup: string;
  activeOnly: boolean;
  includeAwards: boolean;
};

type MemoryEntry = { at: number; body: string; status: number };
const memoryCache = new Map<string, MemoryEntry>();
const MEMORY_TTL_MS = 8 * 60_000;

function redact(text: string, secret = ""): string {
  let out = text;
  if (secret.length >= 8) {
    out = out.split(secret).join("[redacted]");
  }
  return out
    .replace(/([?&]api_key=)[^&\s]+/gi, "$1[redacted]")
    .replace(/\bSAM-[A-Fa-f0-9-]{20,}\b/gi, "[redacted]")
    .replace(/\b[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\b/gi, "[redacted]")
    .slice(0, 400);
}

function validateApiKey(key: string): boolean {
  const k = key.trim();
  if (k.length < 16 || k.length > 256) return false;
  return /^[A-Za-z0-9._\-]+$/.test(k);
}

function sanitizeQuery(raw: string, max = 120): string {
  return raw
    .replace(/[\x00-\x1F\x7F]/g, "")
    .replace(/[<>]/g, "")
    .trim()
    .slice(0, max);
}

function sanitizeSetAside(code: string): string {
  const raw = code.trim();
  if (!raw || raw.toLowerCase() === "any") return "";
  const c = raw.toUpperCase();
  if (c === "ANY_SB") return "ANY_SB";
  if (c in SAM_SET_ASIDE_OPTIONS) return c;
  return "";
}

function sanitizePtype(p: string): string {
  const v = p.trim().toLowerCase();
  // o=sol, p=pre, k=combined, r=sources sought, a=award, s=special, u=J&A
  if (/^[opkrgasuij]$/.test(v)) return v;
  return "";
}

function sanitizeNaicsList(raw: string[]): string[] {
  const out: string[] = [];
  for (const item of raw) {
    const digits = String(item).replace(/\D/g, "");
    if (digits.length >= 2 && digits.length <= 6 && SAM_NAICS_CATALOG[digits]) {
      if (!out.includes(digits)) out.push(digits);
    }
  }
  return out.slice(0, 4);
}

function parseSearchQuery(url: URL): SearchQuery {
  const presetRaw = (url.searchParams.get("preset") || "pki").toLowerCase();
  const preset = PRESETS[presetRaw] ? presetRaw : "pki";
  const q = sanitizeQuery(url.searchParams.get("q") || "");
  let days = Number.parseInt(url.searchParams.get("days") || "30", 10);
  if (!Number.isFinite(days)) days = 30;
  days = Math.max(1, Math.min(180, days));
  let limit = Number.parseInt(url.searchParams.get("limit") || "25", 10);
  if (!Number.isFinite(limit)) limit = 25;
  limit = Math.max(5, Math.min(MAX_LIMIT, limit));
  const setAside = sanitizeSetAside(url.searchParams.get("set_aside") || "");
  const ptype = sanitizePtype(url.searchParams.get("ptype") || "");
  const naicsGroup = (url.searchParams.get("naics_group") || "").trim();
  const naicsParam = url.searchParams.getAll("naics");
  let naics = sanitizeNaicsList(naicsParam);
  if (naics.length === 0 && naicsGroup && SAM_NAICS_GROUPS[naicsGroup]) {
    naics = sanitizeNaicsList(SAM_NAICS_GROUPS[naicsGroup].codes);
  }
  const activeOnly =
    url.searchParams.get("active") === "1" ||
    url.searchParams.get("active_only") === "1";
  const includeAwards =
    url.searchParams.get("awards") === "1" ||
    preset === "awards" ||
    ptype === "a";

  return {
    preset,
    q,
    days,
    limit,
    setAside,
    ptype,
    naics,
    naicsGroup,
    activeOnly,
    includeAwards,
  };
}

function dateRange(days: number): { from: string; to: string } {
  const to = new Date();
  const from = new Date(to.getTime() - days * 86_400_000);
  const fmt = (d: Date) => {
    const mm = String(d.getUTCMonth() + 1).padStart(2, "0");
    const dd = String(d.getUTCDate()).padStart(2, "0");
    const yyyy = d.getUTCFullYear();
    return `${mm}/${dd}/${yyyy}`;
  };
  return { from: fmt(from), to: fmt(to) };
}

function cacheKey(q: SearchQuery): string {
  return KV_KEY_PREFIX + JSON.stringify(q);
}

function stateCodeFromPop(pop: unknown): string {
  if (!pop || typeof pop !== "object") return "";
  const p = pop as Record<string, unknown>;
  const state = p.state;
  if (state && typeof state === "object") {
    const s = state as Record<string, unknown>;
    const code = String(s.code || s.name || "")
      .trim()
      .toUpperCase();
    if (/^[A-Z]{2}$/.test(code) && US_STATE_CENTROIDS[code]) return code;
    // Full name match
    for (const [k, v] of Object.entries(US_STATE_CENTROIDS)) {
      if (v.name.toUpperCase() === code) return k;
    }
  }
  if (typeof state === "string") {
    const code = state.trim().toUpperCase();
    if (/^[A-Z]{2}$/.test(code) && US_STATE_CENTROIDS[code]) return code;
  }
  return "";
}

function cityNameFromPop(pop: unknown): string {
  if (!pop || typeof pop !== "object") return "";
  const p = pop as Record<string, unknown>;
  const city = p.city;
  let name = "";
  if (city && typeof city === "object") {
    name = String((city as Record<string, unknown>).name || "").trim();
  } else if (typeof city === "string") {
    name = city.trim();
  }
  // SAM sometimes puts zip/city codes in name — ignore pure digits
  if (/^\d{3,}$/.test(name)) return "";
  return name;
}

function resolveLocation(
  pop: unknown,
  seed: string,
): { lat: number; lng: number; label: string; state: string; city: string } | null {
  const state = stateCodeFromPop(pop);
  const city = cityNameFromPop(pop);
  if (!state && !city) return null;

  const nudgeKey = `${city.toLowerCase()}|${state.toLowerCase()}`;
  const cityHit = CITY_NUDGES[nudgeKey];
  if (cityHit) {
    return {
      lat: cityHit.lat,
      lng: cityHit.lng,
      label: city && state ? `${city}, ${state}` : city || state,
      state,
      city,
    };
  }

  const centroid = state ? US_STATE_CENTROIDS[state] : null;
  if (!centroid) {
    // CONUS fallback for unknown
    return {
      lat: 39.5,
      lng: -98.35,
      label: city || "United States",
      state: state || "US",
      city,
    };
  }

  // Deterministic micro-jitter so co-located notices separate slightly
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) | 0;
  const jLat = ((h % 1000) / 1000 - 0.5) * 0.35;
  const jLng = ((((h / 1000) | 0) % 1000) / 1000 - 0.5) * 0.45;

  return {
    lat: centroid.lat + jLat,
    lng: centroid.lng + jLng,
    label: city ? `${city}, ${state}` : `${centroid.name} (${state})`,
    state,
    city,
  };
}

function normalizeOpportunity(row: Record<string, unknown>): SamOpportunityPreview | null {
  const title = String(row.title || row.opportunityTitle || "").trim();
  if (!title) return null;

  const noticeId = String(row.noticeId || row.noticeID || row.opportunityId || "")
    .replace(/[^A-Za-z0-9._-]/g, "")
    .slice(0, 80);
  const sol = String(row.solicitationNumber || row.solicitation_number || "").slice(
    0,
    64,
  );
  const type = String(row.type || row.baseType || row.opportunityType || "").slice(
    0,
    80,
  );
  const posted = String(row.postedDate || row.publishDate || "").slice(0, 40);
  const response = String(
    row.responseDeadLine || row.responseDeadline || row.archiveDate || "",
  ).slice(0, 40);
  const department = String(
    row.fullParentPathName || row.department || row.organizationName || "",
  ).slice(0, 300);
  let naics = String(row.naicsCode || row.naics || "").replace(/\D/g, "");
  if (naics.length > 6) naics = naics.slice(0, 6);
  if (naics.length < 2) naics = "";

  let setAsideCode = String(
    row.typeOfSetAside || row.setAside || row.setAsideCode || "",
  )
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "")
    .slice(0, 16) as SamSetAsideCode | string;
  let setAside = String(
    row.typeOfSetAsideDescription || row.setAsideDescription || "",
  ).slice(0, 120);
  if (!setAside && setAsideCode) {
    setAside = SAM_SET_ASIDE_OPTIONS[setAsideCode] || setAsideCode;
  }

  let uiLink = String(row.uiLink || row.additionalInfoLink || "");
  if (!uiLink && noticeId) {
    uiLink = `${SAM_UI}/opp/${encodeURIComponent(noticeId)}/view`;
  }
  if (uiLink && !/^https:\/\/(www\.)?sam\.gov\//i.test(uiLink)) {
    uiLink = "";
  }

  let desc = String(row.description || row.additionalInfoText || "");
  desc = desc
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 400);

  const pop = row.placeOfPerformance;
  const loc = resolveLocation(pop, noticeId || sol || title);
  const active = String(row.active || "").slice(0, 16);

  return {
    id: noticeId || sol || hashId(title + posted),
    noticeId,
    solicitationNumber: sol,
    title: title.slice(0, 500),
    type,
    postedDate: posted,
    responseDeadline: response,
    department,
    naics,
    naicsLabel: naics && SAM_NAICS_CATALOG[naics] ? SAM_NAICS_CATALOG[naics] : "",
    setAside,
    setAsideCode: String(setAsideCode),
    url: uiLink,
    descriptionExcerpt: desc,
    active,
    placeLabel: loc?.label || "",
    state: loc?.state || "",
    city: loc?.city || "",
    lat: loc?.lat ?? null,
    lng: loc?.lng ?? null,
  };
}

function hashId(s: string): string {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return `h${(h >>> 0).toString(16)}`;
}

async function samHttpGet(
  params: Record<string, string>,
  apiKey: string,
): Promise<{ ok: boolean; http: number; body: string; error: string }> {
  const safe: Record<string, string> = {};
  const allowed = [
    "title",
    "ncode",
    "postedFrom",
    "postedTo",
    "limit",
    "offset",
    "ptype",
    "status",
    "solnum",
    "typeOfSetAside",
  ];
  for (const k of allowed) {
    if (params[k] == null) continue;
    const v = String(params[k]).trim();
    if (!v || v.length > 200) continue;
    if (k === "ncode" && !/^\d{2,6}$/.test(v)) continue;
    if (
      (k === "postedFrom" || k === "postedTo") &&
      !/^\d{2}\/\d{2}\/\d{4}$/.test(v)
    ) {
      continue;
    }
    if ((k === "limit" || k === "offset") && !/^\d{1,4}$/.test(v)) continue;
    if (k === "typeOfSetAside") {
      const sa = sanitizeSetAside(v);
      if (!sa || sa === "ANY_SB") continue;
      safe[k] = sa;
      continue;
    }
    if (k === "ptype") {
      const pt = sanitizePtype(v);
      if (!pt) continue;
      safe[k] = pt;
      continue;
    }
    safe[k] = v;
  }
  if (!safe.postedFrom || !safe.postedTo) {
    return { ok: false, http: 0, body: "", error: "Date range required" };
  }

  // api_key is required by SAM as a query param — never log this URL
  safe.api_key = apiKey;
  const qs = new URLSearchParams(safe);
  const url = `https://${SAM_API_HOST}${SAM_API_PATH}?${qs.toString()}`;
  // Clear key from local map ASAP after building URL
  delete safe.api_key;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    // Workers only support redirect "follow" | "manual" (not "error").
    // Use manual + reject 3xx so we never follow off allowlisted host.
    const response = await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: controller.signal,
      headers: {
        accept: "application/json",
        "user-agent": "FederalKey-Globe/1.0 (defense contracting research)",
      },
    });
    clearTimeout(timer);
    if (response.status >= 300 && response.status < 400) {
      return {
        ok: false,
        http: response.status,
        body: "",
        error: "Blocked redirect from SAM.gov (SSRF guard)",
      };
    }
    const body = await response.text();
    if (!response.ok) {
      return {
        ok: false,
        http: response.status,
        body: "",
        error: redact(
          `SAM.gov HTTP ${response.status}: ${body.slice(0, 200)}`,
          apiKey,
        ),
      };
    }
    // Defense: never return body containing the key to callers that might log it
    if (body.includes(apiKey)) {
      return {
        ok: false,
        http: response.status,
        body: "",
        error: "Upstream response blocked (credential leakage guard)",
      };
    }
    return { ok: true, http: response.status, body, error: "" };
  } catch (err) {
    const msg = err instanceof Error ? err.message : "sam_upstream_error";
    return {
      ok: false,
      http: 0,
      body: "",
      error: redact(msg, apiKey),
    };
  }
}

function parseOpportunities(body: string): SamOpportunityPreview[] {
  let decoded: unknown;
  try {
    decoded = JSON.parse(body);
  } catch {
    return [];
  }
  if (!decoded || typeof decoded !== "object") return [];
  const root = decoded as Record<string, unknown>;
  if (root.error || root.errorMessage) return [];

  const rows =
    root.opportunitiesData ||
    root.opportunityData ||
    root.data ||
    root.opportunities ||
    [];
  if (!Array.isArray(rows)) return [];

  const out: SamOpportunityPreview[] = [];
  for (const row of rows) {
    if (!row || typeof row !== "object") continue;
    const n = normalizeOpportunity(row as Record<string, unknown>);
    if (n) out.push(n);
  }
  return out;
}

function matchesSetAsideLocal(
  opp: SamOpportunityPreview,
  setAside: string,
): boolean {
  if (!setAside) return true;
  const code = (opp.setAsideCode || "").toUpperCase();
  if (setAside === "ANY_SB") return ANY_SB_CODES.has(code);
  return code === setAside;
}

function matchesNaicsLocal(opp: SamOpportunityPreview, naics: string[]): boolean {
  if (naics.length === 0) return true;
  if (!opp.naics) return true; // keep if remote already filtered / missing field
  return naics.some(
    (c) => opp.naics === c || opp.naics.startsWith(c.slice(0, 4)),
  );
}

function buildMarkers(opps: SamOpportunityPreview[]): SamContractMarker[] {
  const markers: SamContractMarker[] = [];
  for (const o of opps) {
    if (o.lat == null || o.lng == null) continue;
    if (!Number.isFinite(o.lat) || !Number.isFinite(o.lng)) continue;
    if (o.lat < -90 || o.lat > 90 || o.lng < -180 || o.lng > 180) continue;
    markers.push({
      id: o.id,
      lat: o.lat,
      lng: o.lng,
      title: o.title,
      setAsideCode: o.setAsideCode,
      naics: o.naics,
      placeLabel: o.placeLabel,
      size: o.setAsideCode && ANY_SB_CODES.has(o.setAsideCode) ? 0.08 : 0.06,
    });
  }
  return markers;
}

async function pullLive(
  env: SamEnv,
  query: SearchQuery,
): Promise<SamContractsPreview> {
  const apiKey = (env.SAM_API_KEY || "").trim();
  const pulledAt = new Date().toISOString();
  const preset = PRESETS[query.preset] || PRESETS.pki;
  const dates = dateRange(query.days);

  const baseMeta = {
    source: SAM_SOURCE,
    sourceUrl: SAM_SOURCE_URL,
    updatedAt: pulledAt,
    queryLabel: "",
    preset: query.preset,
    presetLabel: preset.label,
    dataMode: "live" as const,
    opportunityCount: 0,
    markerCount: 0,
    opportunities: [] as SamOpportunityPreview[],
    markers: [] as SamContractMarker[],
    notes: [] as string[],
    filters: {
      q: query.q,
      days: query.days,
      setAside: query.setAside,
      setAsideLabel: SAM_SET_ASIDE_OPTIONS[query.setAside] || "",
      ptype: query.ptype,
      naics: query.naics,
      naicsGroup: query.naicsGroup,
      activeOnly: query.activeOnly,
      includeAwards: query.includeAwards,
    },
    catalog: {
      naics: SAM_NAICS_CATALOG,
      groups: Object.fromEntries(
        Object.entries(SAM_NAICS_GROUPS).map(([id, g]) => [
          id,
          { label: g.label, codes: g.codes },
        ]),
      ),
      setAsides: SAM_SET_ASIDE_OPTIONS,
      presets: Object.fromEntries(
        Object.entries(PRESETS).map(([id, p]) => [id, p.label]),
      ),
    },
  };

  if (!apiKey || !validateApiKey(apiKey)) {
    return {
      ...baseMeta,
      dataMode: "unavailable",
      queryLabel: "SAM.gov API key not configured",
      notes: [
        "Set Worker secret SAM_API_KEY (Cloudflare Secrets) — never commit keys.",
        "Create a free key at sam.gov → Account Details → Public API Key.",
      ],
      error: "sam_api_key_missing",
    };
  }

  const keywords: string[] = [];
  if (query.q) keywords.push(query.q);
  for (const kw of preset.keywords) {
    if (!keywords.includes(kw)) keywords.push(kw);
  }
  const kwCap =
    query.naics.length > 0
      ? Math.max(2, MAX_REMOTE_QUERIES - Math.min(query.naics.length, 2))
      : MAX_REMOTE_QUERIES;
  const useKeywords = keywords.slice(0, kwCap);

  const naicsRemote =
    query.naics.length > 0
      ? query.naics
      : sanitizeNaicsList(preset.naics).slice(0, 2);

  const remoteSetAside =
    query.setAside && query.setAside !== "ANY_SB" ? query.setAside : "";
  const remotePtype = query.ptype || (query.includeAwards ? "" : "");

  const merged = new Map<string, SamOpportunityPreview>();
  const notes: string[] = [];
  const errors: string[] = [];

  const runSearch = async (params: Record<string, string>, label: string) => {
    if (merged.size >= MAX_RESULTS) return;
    const res = await samHttpGet(
      {
        ...params,
        postedFrom: dates.from,
        postedTo: dates.to,
        limit: String(Math.min(25, query.limit)),
        offset: "0",
        ...(remoteSetAside ? { typeOfSetAside: remoteSetAside } : {}),
        ...(remotePtype ? { ptype: remotePtype } : {}),
      },
      apiKey,
    );
    if (!res.ok) {
      errors.push(`${label}: ${res.error}`);
      if (
        res.http === 401 ||
        res.http === 403 ||
        /api key|unauthorized/i.test(res.error)
      ) {
        throw new Error("auth_failed");
      }
      return;
    }
    const opps = parseOpportunities(res.body);
    let added = 0;
    for (const o of opps) {
      if (!merged.has(o.id)) {
        merged.set(o.id, o);
        added += 1;
      }
      if (merged.size >= MAX_RESULTS) break;
    }
    notes.push(`${label}: ${opps.length} hit(s), ${added} new`);
  };

  try {
    for (const kw of useKeywords) {
      await runSearch({ title: kw }, `Keyword "${kw}"`);
    }
    for (const ncode of naicsRemote.slice(0, 3)) {
      await runSearch({ ncode }, `NAICS ${ncode}`);
    }
    // Extra pass for award notices when requested and no explicit ptype
    if (query.includeAwards && !query.ptype) {
      await runSearch(
        { title: query.q || "PKI", ptype: "a" },
        "Awards (ptype=a)",
      );
    }
  } catch (e) {
    if (e instanceof Error && e.message === "auth_failed") {
      return {
        ...baseMeta,
        dataMode: "unavailable",
        queryLabel: preset.label,
        notes: [
          "SAM.gov rejected the API key. Rotate the key at sam.gov and update Cloudflare secret SAM_API_KEY.",
        ],
        error: "sam_unauthorized",
      };
    }
  }

  let list = Array.from(merged.values());
  list = list.filter((o) => matchesSetAsideLocal(o, query.setAside));
  list = list.filter((o) => matchesNaicsLocal(o, query.naics));
  if (query.activeOnly) {
    list = list.filter((o) => {
      const a = (o.active || "").toLowerCase();
      return a === "" || a === "yes" || a === "true" || a === "1" || a === "active";
    });
  }
  // Prefer items with location for globe, then newest-ish title order
  list.sort((a, b) => {
    const al = a.lat != null ? 1 : 0;
    const bl = b.lat != null ? 1 : 0;
    if (bl !== al) return bl - al;
    return (b.postedDate || "").localeCompare(a.postedDate || "");
  });
  list = list.slice(0, MAX_RESULTS);

  const markers = buildMarkers(list);
  const queryLabel = [
    preset.label,
    query.q ? `“${query.q}”` : "",
    query.setAside
      ? SAM_SET_ASIDE_OPTIONS[query.setAside] || query.setAside
      : "",
    query.naics.length ? `NAICS ${query.naics.join(",")}` : "",
    `${query.days}d`,
  ]
    .filter(Boolean)
    .join(" · ");

  if (errors.length) {
    notes.push(
      "Partial errors: " + errors.slice(0, 3).map((e) => redact(e, apiKey)).join("; "),
    );
  }
  notes.push(
    "API key is held only in Cloudflare Worker secrets and never sent to the browser.",
  );
  notes.push(
    "Map pins use place-of-performance city/state centroids (approximate).",
  );
  notes.push(
    "FederalKey Contracting is a paid app feature (login + Stripe when enforced). Opportunity data remains public on SAM.gov.",
  );

  return {
    ...baseMeta,
    queryLabel,
    dataMode: list.length ? "live" : errors.length ? "partial" : "live",
    opportunityCount: list.length,
    markerCount: markers.length,
    opportunities: list,
    markers,
    notes,
    error: list.length === 0 && errors.length ? redact(errors[0], apiKey) : undefined,
  };
}

/**
 * Authenticated GET handler for /api/sam-contracts-preview
 * (caller must enforce login + paid gate; never edge-cache publicly).
 */
export async function getSamContractsPreview(
  request: Request,
  env: SamEnv,
): Promise<Response> {
  const url = new URL(request.url);
  const query = parseSearchQuery(url);
  const key = cacheKey(query);
  const force = url.searchParams.get("force") === "1";

  if (!force) {
    const mem = memoryCache.get(key);
    if (mem && Date.now() - mem.at < MEMORY_TTL_MS) {
      return new Response(mem.body, {
        status: mem.status,
        headers: {
          "content-type": "application/json; charset=utf-8",
          "cache-control": BROWSER_CACHE,
          "x-sam-cache": "memory",
        },
      });
    }
    if (env.BILLING_KV) {
      try {
        const cached = await env.BILLING_KV.get(key, "text");
        if (cached) {
          memoryCache.set(key, {
            at: Date.now(),
            body: cached,
            status: 200,
          });
          return new Response(cached, {
            status: 200,
            headers: {
              "content-type": "application/json; charset=utf-8",
              "cache-control": BROWSER_CACHE,
              "x-sam-cache": "kv",
            },
          });
        }
      } catch {
        // ignore KV errors
      }
    }
  }

  const preview = await pullLive(env, query);
  // Hard scrub: ensure key never appears in JSON
  const apiKey = (env.SAM_API_KEY || "").trim();
  let json = JSON.stringify(preview);
  if (apiKey && json.includes(apiKey)) {
    json = json.split(apiKey).join("[redacted]");
  }

  const status =
    preview.dataMode === "unavailable" && preview.error === "sam_api_key_missing"
      ? 503
      : preview.error === "sam_unauthorized"
        ? 502
        : 200;

  memoryCache.set(key, { at: Date.now(), body: json, status });
  if (env.BILLING_KV && status === 200 && preview.opportunityCount > 0) {
    try {
      await env.BILLING_KV.put(key, json, {
        expirationTtl: CACHE_SECONDS,
      });
    } catch {
      // ignore
    }
  }

  return new Response(json, {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control":
        status === 200 ? BROWSER_CACHE : "no-store",
      "x-sam-cache": "miss",
      "x-sam-mode": preview.dataMode,
    },
  });
}
