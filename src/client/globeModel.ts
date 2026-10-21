import { type GlobeArc, type GlobeHeatZone } from "./CobeGlobe";
import type { OutgoingMessage, NearbyPathsPreview, PkiCountryHotspot, PkiVulnCve, PkiVulnSeverity, PkiVulnsPreview, TradePulseLayer, TradePulsePreview, TradePulseRoutePreview, UnodcHotspotsPreview, UnodcThemeId } from "../shared";
import { fallbackChatDisplayName, sanitizeChatDisplayName, sanitizeChatText } from "../shared";

export type WeatherStatus = "idle" | "loading" | "ready" | "error";

export type NearbyStatus = "idle" | "loading" | "ready" | "error";

export type TransitStatus = "idle" | "loading" | "ready" | "error";


export type ForecastView = "daily" | "hourly";

export type ComtradeStatus = "idle" | "loading" | "ready" | "error";

export type ComtradeSection = "records" | "availability" | "references" | "reporters";

export type ComtradeValueMode = "compact" | "full";

export type UnGlobalStatus = "idle" | "loading" | "ready" | "error";

export type TradePulseStatus = "idle" | "loading" | "ready" | "error";

export type UnGlobalSection =
  | "offices"
  | "activeMissions"
  | "pastMissions"
  | "memberStates"
  | "affiliates"
  | "embassies";


export const DEFAULT_COMTRADE_SECTIONS: Record<ComtradeSection, boolean> = {
  records: true,
  availability: true,
  references: true,
  reporters: true,
};


export const COMTRADE_SECTION_LABELS: Record<ComtradeSection, string> = {
  records: "Trade rows",
  availability: "Availability",
  references: "References",
  reporters: "Reporters",
};


export const COMTRADE_SECTION_DESCRIPTIONS: Record<ComtradeSection, string> = {
  records: "sample export/import rows with partner, commodity, and value",
  availability: "dataset coverage, release windows, and total record counts",
  references: "API reference tables that explain Comtrade variables",
  reporters: "reporting economies available through Comtrade+ metadata",
};


export const COMTRADE_SECTIONS: ComtradeSection[] = [
  "records",
  "availability",
  "references",
  "reporters",
];


export const DEFAULT_UN_GLOBAL_SECTIONS: Record<UnGlobalSection, boolean> = {
  offices: true,
  activeMissions: true,
  pastMissions: true,
  memberStates: true,
  affiliates: true,
  embassies: true,
};


export const UN_GLOBAL_SECTION_LABELS: Record<UnGlobalSection, string> = {
  offices: "HQ offices",
  activeMissions: "Active missions",
  pastMissions: "Past missions",
  memberStates: "Member states",
  affiliates: "Affiliates",
  embassies: "Embassies",
};


export type UnodcStatus = "idle" | "loading" | "ready" | "error";

export type PkiVulnsStatus = "idle" | "loading" | "ready" | "error";


export const PKI_PREVIEW_URL = "/api/pki-vulns-preview?v=2";

export const SAM_CONTRACTS_PREVIEW_URL = "/api/sam-contracts-preview";


export const PKI_SEVERITY_COLORS: Record<PkiVulnSeverity, string> = {
  critical: "#ff2d55",
  high: "#ff9f0a",
  medium: "#ffd60a",
  low: "#30d158",
  unknown: "#8e8e93",
};


export const PKI_CATEGORY_LABELS: Record<string, string> = {
  certificate: "Certificate",
  "tls-ssl": "TLS / SSL",
  openssl: "OpenSSL",
  "crypto-key": "Crypto key",
  "pki-auth": "PKI auth",
  "other-pki": "Other PKI",
};


/** Heat color by severity for PKI arcs. */
export function pkiSeverityColor(severity: PkiVulnSeverity): string {
  return PKI_SEVERITY_COLORS[severity] || PKI_SEVERITY_COLORS.unknown;
}


/** Fallback country centers when hotspot list omits an origin/exposure ISO3. */
export const PKI_COUNTRY_CENTERS: Record<
  string,
  { name: string; lat: number; lng: number }
> = {
  USA: { name: "United States", lat: 39.83, lng: -98.58 },
  CAN: { name: "Canada", lat: 56.13, lng: -106.35 },
  GBR: { name: "United Kingdom", lat: 55.38, lng: -3.44 },
  DEU: { name: "Germany", lat: 51.17, lng: 10.45 },
  FRA: { name: "France", lat: 46.23, lng: 2.21 },
  NLD: { name: "Netherlands", lat: 52.13, lng: 5.29 },
  IRL: { name: "Ireland", lat: 53.14, lng: -7.69 },
  SWE: { name: "Sweden", lat: 60.13, lng: 18.64 },
  CHE: { name: "Switzerland", lat: 46.82, lng: 8.23 },
  JPN: { name: "Japan", lat: 36.2, lng: 138.25 },
  KOR: { name: "South Korea", lat: 35.91, lng: 127.77 },
  CHN: { name: "China", lat: 35.86, lng: 104.2 },
  SGP: { name: "Singapore", lat: 1.35, lng: 103.82 },
  AUS: { name: "Australia", lat: -25.27, lng: 133.78 },
  IND: { name: "India", lat: 20.59, lng: 78.96 },
  BRA: { name: "Brazil", lat: -14.24, lng: -51.93 },
  ARE: { name: "United Arab Emirates", lat: 23.42, lng: 53.85 },
  ISR: { name: "Israel", lat: 31.05, lng: 34.85 },
  RUS: { name: "Russia", lat: 61.52, lng: 105.32 },
  ZAF: { name: "South Africa", lat: -30.56, lng: 22.94 },
  ITA: { name: "Italy", lat: 41.87, lng: 12.57 },
  ESP: { name: "Spain", lat: 40.46, lng: -3.75 },
  IDN: { name: "Indonesia", lat: -0.79, lng: 113.92 },
  MEX: { name: "Mexico", lat: 23.63, lng: -102.55 },
  TUR: { name: "Turkey", lat: 38.96, lng: 35.24 },
  POL: { name: "Poland", lat: 51.92, lng: 19.15 },
  SAU: { name: "Saudi Arabia", lat: 23.89, lng: 45.08 },
  NOR: { name: "Norway", lat: 60.47, lng: 8.47 },
  FIN: { name: "Finland", lat: 61.92, lng: 25.75 },
  DNK: { name: "Denmark", lat: 56.26, lng: 9.5 },
};


export type PkiGeoPoint = {
  iso3: string;
  name: string;
  lat: number;
  lng: number;
};


export function pkiResolvePoint(
  iso3: string,
  hotspotByIso: Map<string, PkiCountryHotspot>,
): PkiGeoPoint | null {
  const h = hotspotByIso.get(iso3);
  if (h) {
    return { iso3: h.iso3, name: h.name, lat: h.lat, lng: h.lng };
  }
  const fb = PKI_COUNTRY_CENTERS[iso3];
  if (!fb) return null;
  return { iso3, name: fb.name, lat: fb.lat, lng: fb.lng };
}


export function pkiVendorOriginIso3(cve: PkiVulnCve): string {
  if (cve.originIso3) return cve.originIso3;
  const blob = `${cve.vendor || ""} ${cve.product || ""} ${cve.title}`;
  if (/igel/i.test(blob)) return "DEU";
  if (/array networks/i.test(blob)) return "USA";
  if (/fortinet/i.test(blob)) return "CAN";
  return "USA";
}


export function pkiSeverityRank(s: string): number {
  return s === "critical" ? 0 : s === "high" ? 1 : s === "medium" ? 2 : 3;
}


/** Count hotspot countries that list this CVE when exposureIso3s is missing. */
export function previewHotspotLinks(
  preview: PkiVulnsPreview,
  cveId: string,
): number {
  return preview.hotspots.filter((h) => h.topCves.includes(cveId)).length;
}


/** Catalog filter: solid KEV vs dotted NVD catalog arcs. */
export type PkiCatalogFilter = "all" | "kev" | "nvd";

export type PkiSortMode =
  | "priority"
  | "severity"
  | "cvss"
  | "newest"
  | "vendor"
  | "cve";

/** Visible arc budget — sparse default keeps the globe smooth. */
export type PkiDensity = "sparse" | "balanced" | "dense";


export const PKI_DENSITY_LIMITS: Record<PkiDensity, number> = {
  sparse: 8,
  balanced: 14,
  dense: 22,
};

export const PKI_DESTS_PER_CVE: Record<PkiDensity, number> = {
  sparse: 3,
  balanced: 5,
  dense: 8,
};

export const PKI_SORT_LABELS: Record<PkiSortMode, string> = {
  priority: "Priority",
  severity: "Severity",
  cvss: "CVSS",
  newest: "Newest",
  vendor: "Vendor",
  cve: "CVE ID",
};

export const DEFAULT_PKI_SEVERITIES: PkiVulnSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "unknown",
];


export type PkiArcBuildOptions = {
  catalog: PkiCatalogFilter;
  severities: Set<PkiVulnSeverity>;
  category: string | "all";
  focusCve: string | null;
  sort: PkiSortMode;
  density: PkiDensity;
  page: number;
};


export type PkiArcSelection = {
  arcs: GlobeArc[];
  total: number;
  page: number;
  pageCount: number;
  pageSize: number;
  kevCount: number;
  nvdCount: number;
};


export function pkiArcDateMs(cve: PkiVulnCve): number {
  const raw = cve.kevDateAdded || cve.publishedAt || "";
  const t = Date.parse(raw);
  return Number.isFinite(t) ? t : 0;
}


export function sortPkiCves(list: PkiVulnCve[], sort: PkiSortMode): PkiVulnCve[] {
  const out = list.slice();
  out.sort((a, b) => {
    switch (sort) {
      case "severity": {
        const sr = pkiSeverityRank(a.severity) - pkiSeverityRank(b.severity);
        if (sr !== 0) return sr;
        return (b.cvss || 0) - (a.cvss || 0);
      }
      case "cvss":
        return (b.cvss || 0) - (a.cvss || 0);
      case "newest":
        return pkiArcDateMs(b) - pkiArcDateMs(a);
      case "vendor":
        return (a.vendor || "zzz").localeCompare(b.vendor || "zzz");
      case "cve":
        return a.id.localeCompare(b.id);
      case "priority":
      default: {
        if (a.knownExploited !== b.knownExploited) {
          return a.knownExploited ? -1 : 1;
        }
        const sr = pkiSeverityRank(a.severity) - pkiSeverityRank(b.severity);
        if (sr !== 0) return sr;
        return (b.cvss || 0) - (a.cvss || 0);
      }
    }
  });
  return out;
}


export function sortPkiArcs(arcs: GlobeArc[], sort: PkiSortMode): GlobeArc[] {
  const out = arcs.slice();
  out.sort((a, b) => {
    const ac = a.comtrade;
    const bc = b.comtrade;
    switch (sort) {
      case "severity": {
        const sr =
          pkiSeverityRank(ac?.severity || "unknown") -
          pkiSeverityRank(bc?.severity || "unknown");
        if (sr !== 0) return sr;
        return (bc?.confidencePct || 0) - (ac?.confidencePct || 0);
      }
      case "cvss":
        return (bc?.confidencePct || 0) - (ac?.confidencePct || 0);
      case "newest":
        return (bc?.period || "").localeCompare(ac?.period || "");
      case "vendor":
        return (ac?.originName || "").localeCompare(bc?.originName || "");
      case "cve":
        return (ac?.commodityCode || "").localeCompare(bc?.commodityCode || "");
      case "priority":
      default: {
        const aKev = ac?.quantity === "CISA KEV" ? 0 : 1;
        const bKev = bc?.quantity === "CISA KEV" ? 0 : 1;
        if (aKev !== bKev) return aKev - bKev;
        const sr =
          pkiSeverityRank(ac?.severity || "unknown") -
          pkiSeverityRank(bc?.severity || "unknown");
        if (sr !== 0) return sr;
        return (bc?.confidencePct || 0) - (ac?.confidencePct || 0);
      }
    }
  });
  return out;
}


/**
 * Build filtered PKI arcs with paging + fair KEV (solid) / NVD (dotted) mix.
 * Keeps visible set small so globe projection stays smooth.
 */
export function buildPkiGlobeArcs(
  preview: PkiVulnsPreview,
  options: PkiArcBuildOptions,
): PkiArcSelection {
  const pageSize = PKI_DENSITY_LIMITS[options.density];
  const maxDests = options.focusCve
    ? 24
    : PKI_DESTS_PER_CVE[options.density];

  let cves = preview.cves.slice();
  if (options.focusCve) {
    cves = cves.filter((c) => c.id === options.focusCve);
  } else {
    if (options.catalog === "kev") {
      cves = cves.filter((c) => c.knownExploited);
    } else if (options.catalog === "nvd") {
      cves = cves.filter((c) => !c.knownExploited);
    }
    if (options.severities.size < DEFAULT_PKI_SEVERITIES.length) {
      cves = cves.filter((c) => options.severities.has(c.severity));
    }
    if (options.category !== "all") {
      cves = cves.filter((c) => c.categories.includes(options.category as never));
    }
  }
  cves = sortPkiCves(cves, options.sort);

  const hotspotByIso = new Map(
    preview.hotspots.map((h) => [h.iso3, h] as const),
  );
  const candidates: GlobeArc[] = [];

  for (const cve of cves) {
    const originIso = pkiVendorOriginIso3(cve);
    const originCenter = pkiResolvePoint(originIso, hotspotByIso);
    if (!originCenter) continue;

    const exposureIsos =
      cve.exposureIso3s && cve.exposureIso3s.length > 0
        ? cve.exposureIso3s
        : preview.hotspots
            .filter((h) => h.topCves.includes(cve.id) && h.iso3 !== originIso)
            .map((h) => h.iso3);

    const dests: PkiGeoPoint[] = [];
    const seen = new Set<string>();
    for (const iso of exposureIsos) {
      if (iso === originIso || seen.has(iso)) continue;
      const pt = pkiResolvePoint(iso, hotspotByIso);
      if (!pt) continue;
      seen.add(iso);
      dests.push(pt);
      if (dests.length >= maxDests) break;
    }

    if (dests.length === 0 && !options.focusCve) {
      for (const h of preview.hotspots) {
        if (h.iso3 === originIso || seen.has(h.iso3)) continue;
        dests.push({
          iso3: h.iso3,
          name: h.name,
          lat: h.lat,
          lng: h.lng,
        });
        if (dests.length >= Math.min(3, maxDests)) break;
      }
    }

    const color = pkiSeverityColor(cve.severity);
    const width =
      cve.severity === "critical"
        ? 2.6
        : cve.severity === "high"
          ? 2.1
          : cve.severity === "medium"
            ? 1.6
            : 1.3;
    const period =
      cve.kevDateAdded ||
      (cve.publishedAt ? cve.publishedAt.slice(0, 10) : "n/a");
    const product = cve.product || "—";
    const vendor = cve.vendor || "Unknown vendor";
    const cats =
      cve.categories
        .map((c) => PKI_CATEGORY_LABELS[c] || c)
        .join(" · ") || "PKI / TLS";
    const isKev = cve.knownExploited;
    const catalog = isKev ? "CISA KEV" : "NVD catalog";
    // KEV = solid; NVD = dotted (short dashes). Never use "0".
    const dash = isKev ? "none" : "2.5 3.5";

    for (const dest of dests) {
      candidates.push({
        id: `pki-${cve.id}-${dest.iso3}`,
        from: [originCenter.lat, originCenter.lng],
        to: [dest.lat, dest.lng],
        fromLabel: `${vendor} · ${originCenter.name}`,
        toLabel: `${dest.name} · exposure`,
        color,
        width,
        dash,
        severity: cve.severity === "unknown" ? "elevated" : cve.severity,
        comtrade: {
          kind: "pki",
          routeId: cve.id,
          commodity: cve.title.slice(0, 200),
          commodityCode: cve.id,
          period,
          originName: `${vendor} · ${originCenter.name}`,
          originIso3: originIso,
          destName: dest.name,
          destIso3: dest.iso3,
          hubName: null,
          hubIso3: null,
          transportMode: cats,
          customsProcedure: product,
          valueUsd: 0,
          quantity: catalog,
          supplierSharePct: 0,
          exportValueUsd: 0,
          importValueUsd: 0,
          asymmetryPct: 0,
          fobValueUsd: 0,
          cifValueUsd: 0,
          frictionPct: 0,
          reExportSharePct: 0,
          confidencePct: cve.cvss ?? 0,
          severity: cve.severity,
          layers: cve.categories.map((c) => PKI_CATEGORY_LABELS[c] || c),
          insight: cve.description.slice(0, 520),
          referenceUrl: cve.nvdUrl,
        },
      });
    }
  }

  const sorted = sortPkiArcs(candidates, options.sort);
  const kevPool = sorted.filter((a) => a.comtrade?.quantity === "CISA KEV");
  const nvdPool = sorted.filter((a) => a.comtrade?.quantity !== "CISA KEV");

  // Fair mix so dotted NVD arcs are not starved when KEV dominates priority sort.
  let ordered: GlobeArc[];
  if (options.catalog === "all" && !options.focusCve) {
    ordered = [];
    let i = 0;
    let j = 0;
    while (i < kevPool.length || j < nvdPool.length) {
      // Prefer 1 KEV solid then 1 NVD dotted when both remain
      if (i < kevPool.length) ordered.push(kevPool[i++]);
      if (j < nvdPool.length) ordered.push(nvdPool[j++]);
    }
  } else {
    ordered = sorted;
  }

  const total = ordered.length;
  const pageCount = Math.max(1, Math.ceil(total / pageSize) || 1);
  const page = Math.min(Math.max(0, options.page), pageCount - 1);
  const start = page * pageSize;
  const arcs = ordered.slice(start, start + pageSize);

  return {
    arcs,
    total,
    page,
    pageCount,
    pageSize,
    kevCount: kevPool.length,
    nvdCount: nvdPool.length,
  };
}


export const UNODC_THEME_IDS /*sec-pass*/: UnodcThemeId[] = [
  "homicide",
  "firearms",
  "trafficking-persons",
  "wildlife",
  "violent-crime",
  "prisons",
  "justice",
  "drug-trafficking",
  "drug-use",
  "drug-seizure",
  "corruption",
  "covid",
];


/** Default ON: high-signal themes only (less globe clutter). */
export const DEFAULT_UNODC_THEMES: Record<UnodcThemeId, boolean> = {
  homicide: true,
  firearms: true,
  "trafficking-persons": true,
  wildlife: false,
  "violent-crime": false,
  prisons: false,
  justice: false,
  "drug-trafficking": false,
  "drug-use": false,
  "drug-seizure": false,
  corruption: false,
  covid: false,
};


/** Themes auto-enabled after data load if they have live hotspots. */
export const UNODC_FOCUS_THEMES: UnodcThemeId[] = [
  "homicide",
  "firearms",
  "trafficking-persons",
];


/** Versioned URL busts browser HTTP cache when server theme sources change. */
export const UNODC_PREVIEW_URL = "/api/unodc-hotspots-preview?v=3";


export function countLiveUnodcThemes(data: UnodcHotspotsPreview | null | undefined) {
  if (!data?.themes?.length) return 0;
  return data.themes.filter(
    (t) => t.dataMode === "live" && t.hotspotCount > 0,
  ).length;
}


/** Reject stale session/HTTP payloads that still only have the old 7 live themes. */
export function isCompleteUnodcPreview(data: UnodcHotspotsPreview | null | undefined) {
  return Boolean(
    data &&
      Array.isArray(data.themes) &&
      data.themes.length >= UNODC_THEME_IDS.length &&
      countLiveUnodcThemes(data) >= UNODC_THEME_IDS.length,
  );
}


/** Vivid theme fills for choropleth (no heat glow; opacity scaled by intensity). */
export const UNODC_THEME_CSS: Record<UnodcThemeId, string> = {
  homicide: "#ff3b30",
  firearms: "#ff9500",
  "trafficking-persons": "#ff2d95",
  wildlife: "#34c759",
  "violent-crime": "#ff453a",
  prisons: "#bf5af2",
  justice: "#0a84ff",
  "drug-trafficking": "#ffd60a",
  "drug-use": "#a8e10c",
  "drug-seizure": "#64d2ff",
  corruption: "#ff9f0a",
  covid: "#8e8e93",
};


/** Approx distance between two lat/lng points (km). */
export function haversineKm(
  lat1: number,
  lng1: number,
  lat2: number,
  lng2: number,
): number {
  const toRad = (d: number) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return 6371 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}


export type UnodcHotspotLike = {
  id: string;
  iso3: string;
  name: string;
  lat: number;
  lng: number;
  value: number;
  year: number;
  intensity: number;
};


/**
 * Greedy geographic clustering: nearby high-intensity countries collapse into
 * larger regional heat zones (clearer than many small dots).
 */
export function clusterUnodcHotspots(
  spots: UnodcHotspotLike[],
  radiusKm = 1400,
): Array<{
  members: UnodcHotspotLike[];
  lat: number;
  lng: number;
  intensity: number;
  valuePeak: number;
}> {
  const ordered = [...spots].sort((a, b) => b.intensity - a.intensity);
  const used = new Set<string>();
  const clusters: Array<{
    members: UnodcHotspotLike[];
    lat: number;
    lng: number;
    intensity: number;
    valuePeak: number;
  }> = [];

  for (const seed of ordered) {
    if (used.has(seed.iso3)) continue;
    const members = [seed];
    used.add(seed.iso3);
    for (const candidate of ordered) {
      if (used.has(candidate.iso3)) continue;
      if (haversineKm(seed.lat, seed.lng, candidate.lat, candidate.lng) <= radiusKm) {
        members.push(candidate);
        used.add(candidate.iso3);
      }
    }
    const weightSum = members.reduce((s, m) => s + m.intensity + 0.15, 0);
    const lat =
      members.reduce((s, m) => s + m.lat * (m.intensity + 0.15), 0) / weightSum;
    const lng =
      members.reduce((s, m) => s + m.lng * (m.intensity + 0.15), 0) / weightSum;
    const valuePeak = Math.max(...members.map((m) => m.value));
    const intensity = Math.min(
      1,
      Math.max(...members.map((m) => m.intensity)) +
        Math.min(0.35, (members.length - 1) * 0.08),
    );
    clusters.push({ members, lat, lng, intensity, valuePeak });
  }

  return clusters;
}


export function buildUnodcThemeHeatZones(
  theme: { id: UnodcThemeId; label: string; hotspots: UnodcHotspotLike[] },
  color: string,
): GlobeHeatZone[] {
  const clusters = clusterUnodcHotspots(theme.hotspots);
  return clusters.map((cluster, index) => {
    const isCluster = cluster.members.length >= 2;
    const names = cluster.members
      .slice(0, 4)
      .map((m) => m.iso3)
      .join(", ");
    const more =
      cluster.members.length > 4 ? ` +${cluster.members.length - 4}` : "";
    return {
      id: `unodc-${theme.id}-c${index}`,
      location: [cluster.lat, cluster.lng] as [number, number],
      intensity: cluster.intensity,
      color,
      themeId: theme.id,
      kind: isCluster ? "cluster" : "point",
      radiusScale: isCluster
        ? 1.15 + Math.min(0.9, (cluster.members.length - 1) * 0.14)
        : 1,
      label: isCluster
        ? `${theme.label} region (${cluster.members.length}): ${names}${more} · peak ${cluster.valuePeak}`
        : `${theme.label}: ${cluster.members[0].name} · ${cluster.members[0].value} (${cluster.members[0].year})`,
    };
  });
}


export const TRADE_PULSE_LAYERS: TradePulseLayer[] = [
  "dependency",
  "lifelines",
  "asymmetry",
  "intermediary",
  "transport",
  "friction",
  "hubs",
  "confidence",
];


export const DEFAULT_TRADE_PULSE_LAYERS: Record<TradePulseLayer, boolean> = {
  dependency: true,
  lifelines: true,
  asymmetry: true,
  intermediary: true,
  transport: true,
  friction: true,
  hubs: true,
  confidence: true,
};


export const TRADE_PULSE_LAYER_LABELS: Record<TradePulseLayer, string> = {
  dependency: "Single supplier dependency",
  lifelines: "Commodity lifelines",
  asymmetry: "Bilateral asymmetry alerts",
  intermediary: "Hidden intermediary signal",
  transport: "Transport mode skin",
  friction: "CIF/FOB friction",
  hubs: "Re-export hubs",
  confidence: "Data confidence",
};


export const TRADE_PULSE_LAYER_SHORT_LABELS: Record<TradePulseLayer, string> = {
  dependency: "Dependency",
  lifelines: "Lifelines",
  asymmetry: "Asymmetry",
  intermediary: "Intermediary",
  transport: "Transport",
  friction: "Friction",
  hubs: "Hubs",
  confidence: "Confidence",
};


export const TRADE_PULSE_LAYER_COLORS: Record<TradePulseLayer, string> = {
  dependency: "#ff3b3b",
  lifelines: "#ffd166",
  asymmetry: "#ff2fb3",
  intermediary: "#7c5cff",
  transport: "#00d9ff",
  friction: "#ff8a00",
  hubs: "#00ff88",
  confidence: "#8f99a2",
};


export const TRADE_PULSE_TRANSPORT_DASHES: Record<
  TradePulseRoutePreview["transportMode"],
  string
> = {
  // "none" = solid stroke. Never use "0" — SVG stroke-dasharray:0 can hide arcs.
  sea: "none",
  air: "4 7",
  rail: "10 5 2 5",
  road: "2 5",
  mixed: "12 5 4 5",
};


export interface WeatherForecastDay {
  date: string;
  condition: string;
  highF: number;
  lowF: number;
  precipitationChancePct: number;
  precipitationIn: number;
  windMph: number;
  gustMph: number;
  uvIndex: number;
}


export interface WeatherForecastHour {
  time: string;
  condition: string;
  tempF: number;
  feelsLikeF: number;
  humidityPct: number;
  precipitationChancePct: number;
  precipitationIn: number;
  windMph: number;
  gustMph: number;
  cloudCoverPct: number;
}


export interface WeatherFeed {
  tempF: number;
  humidityPct: number;
  windMph: number;
  weatherCode: number;
  condition: string;
  hasLightning: boolean;
  locationLabel: string;
  updatedAt: string;
  dailyForecast: WeatherForecastDay[];
  hourlyForecast: WeatherForecastHour[];
}


export type OpenMeteoForecastResponse = {
  current?: {
    time?: string;
    temperature_2m?: number;
    relative_humidity_2m?: number;
    wind_speed_10m?: number;
    weather_code?: number;
  };
  daily?: {
    time?: string[];
    weather_code?: number[];
    temperature_2m_max?: number[];
    temperature_2m_min?: number[];
    precipitation_probability_max?: number[];
    precipitation_sum?: number[];
    wind_speed_10m_max?: number[];
    wind_gusts_10m_max?: number[];
    uv_index_max?: number[];
  };
  hourly?: {
    time?: string[];
    weather_code?: number[];
    temperature_2m?: number[];
    apparent_temperature?: number[];
    relative_humidity_2m?: number[];
    precipitation_probability?: number[];
    precipitation?: number[];
    wind_speed_10m?: number[];
    wind_gusts_10m?: number[];
    cloud_cover?: number[];
  };
};


export const DEFAULT_WEATHER_LOCATION = {
  latitude: 40.7128,
  longitude: -74.006,
  label: "New York, NY",
};


/** v2: hardened parse (plain object only, capped payload, strong label sanitize). */
export const LOCATION_PREF_KEY = "globe:location-pref:v2";

export const LOCATION_PREF_LEGACY_KEY = "globe:location-pref:v1";

export const LOCATION_PREF_MAX_BYTES = 512;

/** Min interval between browser geolocation prompts/calls (anti-spam / battery). */
export const GEO_REQUEST_MIN_MS = 4_000;

export const NEARBY_SESSION_MAX_PATHS = 400;

export const NEARBY_SESSION_MAX_POINTS = 80;

export const NEARBY_SESSION_MAX_RAW = 450_000;


export type LocationMode = "browser" | "manual" | "address";


export type LocationPreference = {
  mode: LocationMode;
  latitude: number;
  longitude: number;
  label: string;
};


/** Fixed Open-Meteo geocoder host — never build from user input. */
export const GEOCODE_API_ORIGIN = "https://geocoding-api.open-meteo.com";

export const GEOCODE_PATH = "/v1/search";

export const GEOCODE_MAX_QUERY = 120;

export const GEOCODE_MIN_MS = 2_500;

export const GEOCODE_TIMEOUT_MS = 10_000;


export const DEFAULT_LOCATION_PREF: LocationPreference = {
  mode: "browser",
  latitude: DEFAULT_WEATHER_LOCATION.latitude,
  longitude: DEFAULT_WEATHER_LOCATION.longitude,
  label: DEFAULT_WEATHER_LOCATION.label,
};


export function clampCoord(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, value));
}


/**
 * Display-only location label. Strip controls, bidi spoofing, and zero-widths
 * (same class of issues as chat display names).
 */
export function sanitizeLocationLabel(raw: unknown): string {
  if (typeof raw !== "string") return "";
  return raw
    // eslint-disable-next-line no-control-regex
    .replace(
      /[\u0000-\u001F\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u2028-\u202F\u2060-\u2064\u2066-\u206F\uFEFF\uFFF9-\uFFFB]/g,
      "",
    )
    .replace(/[<>`"\\]/g, "")
    .trim()
    .slice(0, 64);
}


export function parseFiniteCoord(raw: unknown, min: number, max: number): number | null {
  // Numbers only from storage — reject objects/arrays that Number() coerces to NaN/0
  if (typeof raw === "number" && Number.isFinite(raw)) {
    if (raw < min || raw > max) return null;
    return raw;
  }
  if (typeof raw === "string" && raw.trim().length > 0 && raw.trim().length <= 24) {
    const n = Number(raw);
    if (!Number.isFinite(n) || n < min || n > max) return null;
    return n;
  }
  return null;
}


export function isPlainLocationObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}


export function normalizeLocationPreference(
  raw: unknown,
): LocationPreference {
  if (!isPlainLocationObject(raw)) return { ...DEFAULT_LOCATION_PREF };
  const mode: LocationMode =
    raw.mode === "manual"
      ? "manual"
      : raw.mode === "address"
        ? "address"
        : "browser";
  const latitude =
    parseFiniteCoord(raw.latitude, -90, 90) ??
    DEFAULT_WEATHER_LOCATION.latitude;
  const longitude =
    parseFiniteCoord(raw.longitude, -180, 180) ??
    DEFAULT_WEATHER_LOCATION.longitude;
  const label =
    sanitizeLocationLabel(raw.label) ||
    (mode === "manual"
      ? "Custom location"
      : mode === "address"
        ? "Address location"
        : DEFAULT_WEATHER_LOCATION.label);
  return { mode, latitude, longitude, label };
}


/** Sanitize free-text address before sending as a query parameter. */
export function sanitizeAddressQuery(raw: unknown): string {
  if (typeof raw !== "string") return "";
  return raw
    // eslint-disable-next-line no-control-regex
    .replace(
      /[\u0000-\u001F\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u2028-\u202F\u2060-\u2064\u2066-\u206F\uFEFF\uFFF9-\uFFFB]/g,
      "",
    )
    .replace(/[<>`"'\\]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, GEOCODE_MAX_QUERY);
}


export function buildGeocodeLabel(result: Record<string, unknown>): string {
  const name = sanitizeLocationLabel(result.name);
  const admin1 = sanitizeLocationLabel(result.admin1);
  const country = sanitizeLocationLabel(result.country);
  const bits = [name, admin1, country].filter(Boolean);
  const joined = bits.join(", ").slice(0, 64);
  return sanitizeLocationLabel(joined) || "Address location";
}


/**
 * Resolve a place name via Open-Meteo geocoding (HTTPS, fixed host, no credentials).
 * Returns validated WGS84 coordinates only — never follows redirects to other hosts.
 */
export async function geocodeAddressQuery(
  query: string,
): Promise<{ latitude: number; longitude: number; label: string }> {
  const name = sanitizeAddressQuery(query);
  if (name.length < 2) {
    throw new Error("Enter at least 2 characters for an address or place.");
  }

  const params = new URLSearchParams({
    name,
    count: "1",
    language: "en",
    format: "json",
  });
  // Host is constant; query is URLSearchParams-encoded only
  const url = `${GEOCODE_API_ORIGIN}${GEOCODE_PATH}?${params.toString()}`;

  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), GEOCODE_TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      signal: controller.signal,
      headers: { accept: "application/json" },
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new Error("Address lookup timed out. Try a simpler query.");
    }
    throw new Error("Address lookup failed. Check your network and try again.");
  } finally {
    window.clearTimeout(timer);
  }

  if (!response.ok) {
    throw new Error(`Address lookup failed (${response.status}).`);
  }

  const contentType = response.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("json")) {
    throw new Error("Unexpected address lookup response.");
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new Error("Could not parse address lookup response.");
  }
  if (!isPlainLocationObject(payload)) {
    throw new Error("Invalid address lookup response.");
  }
  const results = payload.results;
  if (!Array.isArray(results) || results.length === 0) {
    throw new Error("No places found for that address. Try another query.");
  }
  const first = results[0];
  if (!isPlainLocationObject(first)) {
    throw new Error("Invalid place result.");
  }
  const latitude = parseFiniteCoord(first.latitude, -90, 90);
  const longitude = parseFiniteCoord(first.longitude, -180, 180);
  if (latitude === null || longitude === null) {
    throw new Error("Place result had invalid coordinates.");
  }
  return {
    latitude,
    longitude,
    label: buildGeocodeLabel(first),
  };
}


export function loadLocationPreference(): LocationPreference {
  try {
    let raw = localStorage.getItem(LOCATION_PREF_KEY);
    if (!raw) {
      raw = localStorage.getItem(LOCATION_PREF_LEGACY_KEY);
    }
    if (!raw || raw.length > LOCATION_PREF_MAX_BYTES) {
      return { ...DEFAULT_LOCATION_PREF };
    }
    const parsed: unknown = JSON.parse(raw);
    const pref = normalizeLocationPreference(parsed);
    // Migrate legacy key to v2 once
    if (localStorage.getItem(LOCATION_PREF_LEGACY_KEY)) {
      saveLocationPreference(pref);
      try {
        localStorage.removeItem(LOCATION_PREF_LEGACY_KEY);
      } catch {
        // ignore
      }
    }
    return pref;
  } catch {
    return { ...DEFAULT_LOCATION_PREF };
  }
}


export function saveLocationPreference(pref: LocationPreference): void {
  try {
    const safe = normalizeLocationPreference(pref);
    const payload = JSON.stringify({
      mode: safe.mode,
      latitude: safe.latitude,
      longitude: safe.longitude,
      label: safe.label,
    });
    if (payload.length > LOCATION_PREF_MAX_BYTES) return;
    localStorage.setItem(LOCATION_PREF_KEY, payload);
  } catch {
    // private mode / blocked storage
  }
}


export function formatCoordPair(lat: number, lng: number): string {
  const safeLat = clampCoord(lat, -90, 90);
  const safeLng = clampCoord(lng, -180, 180);
  const ns = safeLat >= 0 ? "N" : "S";
  const ew = safeLng >= 0 ? "E" : "W";
  return `${Math.abs(safeLat).toFixed(4)}°${ns}, ${Math.abs(safeLng).toFixed(4)}°${ew}`;
}


/** Validate a nearby-paths session cache blob before trusting geometry. */
export function isValidNearbyPathsCache(data: unknown): data is NearbyPathsPreview {
  if (!isPlainLocationObject(data)) return false;
  if (data.stale === true) return false;
  if (typeof data.lat !== "number" || !Number.isFinite(data.lat)) return false;
  if (typeof data.lng !== "number" || !Number.isFinite(data.lng)) return false;
  if (data.lat < -90 || data.lat > 90 || data.lng < -180 || data.lng > 180) {
    return false;
  }
  if (typeof data.radiusM !== "number" || !Number.isFinite(data.radiusM)) {
    return false;
  }
  if (data.radiusM < 50 || data.radiusM > 5000) return false;
  if (!Array.isArray(data.paths) || data.paths.length === 0) return false;
  if (data.paths.length > NEARBY_SESSION_MAX_PATHS) return false;
  // Spot-check structure without walking every point on huge valid caches
  const sample = data.paths.slice(0, 8);
  for (const path of sample) {
    if (!isPlainLocationObject(path)) return false;
    if (typeof path.id !== "string" || path.id.length > 80) return false;
    if (!Array.isArray(path.points) || path.points.length < 2) return false;
    if (path.points.length > NEARBY_SESSION_MAX_POINTS * 4) return false;
    const p0 = path.points[0];
    if (!isPlainLocationObject(p0)) return false;
    if (typeof p0.lat !== "number" || typeof p0.lng !== "number") return false;
  }
  return true;
}


export const WEATHER_CODE_LABELS: Record<number, string> = {
  0: "Clear",
  1: "Mostly clear",
  2: "Partly cloudy",
  3: "Overcast",
  45: "Fog",
  48: "Freezing fog",
  51: "Light drizzle",
  53: "Drizzle",
  55: "Heavy drizzle",
  56: "Freezing drizzle",
  57: "Heavy freezing drizzle",
  61: "Light rain",
  63: "Rain",
  65: "Heavy rain",
  66: "Freezing rain",
  67: "Heavy freezing rain",
  71: "Light snow",
  73: "Snow",
  75: "Heavy snow",
  77: "Snow grains",
  80: "Light showers",
  81: "Showers",
  82: "Heavy showers",
  85: "Snow showers",
  86: "Heavy snow showers",
  95: "Thunderstorm",
  96: "Thunderstorm with hail",
  99: "Severe thunderstorm",
};


export const LIGHTNING_WEATHER_CODES = new Set([95, 96, 99]);

export const BUTTON_RATE_LIMIT_MS = 500;

export const SOCKET_MESSAGE_MAX_CHARS = 4096;


export function getBoundedNumber(value: unknown, min: number, max: number) {
  const number = Number(value);
  return Number.isFinite(number) && number >= min && number <= max ? number : null;
}


export function getLimitedString(value: unknown, maxLength: number) {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : undefined;
}


export function parseSocketMessage(data: unknown): OutgoingMessage | null {
  if (typeof data !== "string" || data.length > SOCKET_MESSAGE_MAX_CHARS) {
    return null;
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(data);
  } catch {
    return null;
  }

  if (!parsed || typeof parsed !== "object") {
    return null;
  }

  const message = parsed as Record<string, unknown>;

  if (message.type === "remove-marker") {
    const id = getLimitedString(message.id, 128);
    return id ? { type: "remove-marker", id } : null;
  }

  if (message.type === "feed-access") {
    return {
      type: "feed-access",
      paid: Boolean(message.paid),
    };
  }

  if (message.type === "feed-join" && message.meta && typeof message.meta === "object") {
    const meta = message.meta as Record<string, unknown>;
    const id = getLimitedString(meta.id, 128);
    if (!id) return null;
    return {
      type: "feed-join",
      meta: {
        id,
        city: getLimitedString(meta.city, 80),
        country: getLimitedString(meta.country, 4),
        org: getLimitedString(meta.org, 120),
        ipMasked: getLimitedString(meta.ipMasked, 45),
      },
    };
  }

  if (message.type === "feed-leave") {
    const id = getLimitedString(message.id, 128);
    if (!id) return null;
    const sessionMs =
      typeof message.sessionMs === "number" && Number.isFinite(message.sessionMs)
        ? Math.max(0, Math.min(message.sessionMs, 7 * 24 * 60 * 60 * 1000))
        : undefined;
    let meta:
      | {
          id: string;
          city?: string;
          country?: string;
          org?: string;
          ipMasked?: string;
        }
      | undefined;
    if (message.meta && typeof message.meta === "object") {
      const m = message.meta as Record<string, unknown>;
      const mid = getLimitedString(m.id, 128) || id;
      meta = {
        id: mid,
        city: getLimitedString(m.city, 80),
        country: getLimitedString(m.country, 4),
        org: getLimitedString(m.org, 120),
        ipMasked: getLimitedString(m.ipMasked, 45),
      };
    }
    return { type: "feed-leave", id, sessionMs, meta };
  }

  if (message.type === "chat") {
    // Re-sanitize on receive — never trust fields for display
    try {
      const id =
        typeof message.id === "string" ? message.id.slice(0, 128) : "";
      const fromId =
        typeof message.fromId === "string" ? message.fromId.slice(0, 128) : "";
      if (!id || !fromId) return null;
      if (/[\u0000-\u001F\u007F<>]/.test(id) || /[\u0000-\u001F\u007F<>]/.test(fromId)) {
        return null;
      }
      const text = sanitizeChatText(message.text);
      if (!text) return null;
      let displayName = "";
      try {
        displayName = sanitizeChatDisplayName(message.displayName);
      } catch {
        displayName = "";
      }
      if (!displayName) displayName = fallbackChatDisplayName(fromId);
      const ts =
        typeof message.ts === "number" &&
        Number.isFinite(message.ts) &&
        message.ts > 0 &&
        message.ts < Date.now() + 120_000
          ? message.ts
          : Date.now();
      return {
        type: "chat",
        id,
        fromId,
        text,
        displayName,
        ts,
      };
    } catch {
      return null;
    }
  }

  if (message.type !== "add-marker" || !message.position || typeof message.position !== "object") {
    return null;
  }

  const position = message.position as Record<string, unknown>;
  const lat = getBoundedNumber(position.lat, -90, 90);
  const lng = getBoundedNumber(position.lng, -180, 180);
  const id = getLimitedString(position.id, 128);

  if (lat === null || lng === null || !id) {
    return null;
  }

  // Public markers only — ignore any legacy ip/org fields
  return {
    type: "add-marker",
    position: {
      lat,
      lng,
      id,
      country: getLimitedString(position.country, 4),
    },
  };
}


export function describeWeatherCode(code: number) {
  return WEATHER_CODE_LABELS[code] ?? `Weather code ${code}`;
}


/** Shared throttle so UI + automatic resolve cannot spam the Geolocation API. */
export let lastGeoRequestAt = 0;


export function getBrowserPosition(timeoutMs = 5000) {
  return new Promise<GeolocationPosition>((resolve, reject) => {
    if (!navigator.geolocation) {
      reject(new Error("Geolocation unavailable"));
      return;
    }
    const now = Date.now();
    if (now - lastGeoRequestAt < GEO_REQUEST_MIN_MS) {
      reject(new Error("Location request throttled — try again in a moment."));
      return;
    }
    lastGeoRequestAt = now;

    navigator.geolocation.getCurrentPosition(resolve, reject, {
      enableHighAccuracy: false,
      timeout: Math.min(Math.max(timeoutMs, 1_000), 15_000),
      // Prefer a recent cached fix to reduce permission churn / battery
      maximumAge: 10 * 60 * 1000,
    });
  });
}


export function buildWeatherUrl(latitude: number, longitude: number) {
  const lat = clampCoord(latitude, -90, 90);
  const lng = clampCoord(longitude, -180, 180);
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
    throw new Error("Invalid weather coordinates");
  }
  const params = new URLSearchParams({
    // Fixed precision — no raw untrusted strings in query
    latitude: lat.toFixed(5),
    longitude: lng.toFixed(5),
    current: "temperature_2m,relative_humidity_2m,wind_speed_10m,weather_code",
    daily:
      "weather_code,temperature_2m_max,temperature_2m_min,precipitation_probability_max,precipitation_sum,wind_speed_10m_max,wind_gusts_10m_max,uv_index_max",
    hourly:
      "weather_code,temperature_2m,apparent_temperature,relative_humidity_2m,precipitation_probability,precipitation,wind_speed_10m,wind_gusts_10m,cloud_cover",
    forecast_days: "7",
    temperature_unit: "fahrenheit",
    wind_speed_unit: "mph",
    precipitation_unit: "inch",
    timezone: "auto",
  });

  return `https://api.open-meteo.com/v1/forecast?${params.toString()}`;
}


export function formatWeatherTime(time: string) {
  return time.replace("T", " ");
}


export function getForecastNumber(values: number[] | undefined, index: number) {
  const value = Number(values?.[index]);
  return Number.isFinite(value) ? value : 0;
}


export function formatForecastDay(date: string) {
  return new Intl.DateTimeFormat(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
  }).format(new Date(`${date}T12:00:00`));
}


export function formatForecastHour(time: string) {
  return new Intl.DateTimeFormat(undefined, {
    weekday: "short",
    hour: "numeric",
  }).format(new Date(time));
}


export function formatPreviewNumber(value: number, stale?: boolean) {
  if (stale && value === 0) {
    return "n/a";
  }

  return value.toLocaleString();
}


export function formatUsd(
  value: number,
  stale?: boolean,
  valueMode: ComtradeValueMode = "compact",
) {
  if (stale && value === 0) {
    return "n/a";
  }

  return new Intl.NumberFormat(undefined, {
    style: "currency",
    currency: "USD",
    notation: valueMode === "compact" ? "compact" : "standard",
    maximumFractionDigits: valueMode === "compact" ? 2 : 0,
  }).format(value);
}


export function formatSignedUsd(
  value: number,
  stale?: boolean,
  valueMode: ComtradeValueMode = "compact",
) {
  const formatted = formatUsd(Math.abs(value), stale, valueMode);

  if (formatted === "n/a" || value === 0) {
    return formatted;
  }

  return `${value > 0 ? "+" : "-"}${formatted}`;
}


export function formatNullableUsd(
  value: number | null,
  stale?: boolean,
  valueMode: ComtradeValueMode = "compact",
) {
  return value === null ? "n/a" : formatUsd(value, stale, valueMode);
}


export function formatPreviewDate(time: string) {
  const date = new Date(time);

  if (Number.isNaN(date.getTime())) {
    return "unknown";
  }

  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(date);
}


export function formatPercent(value: number) {
  return `${Math.round(value)}%`;
}


export function getIsTradePulsePreview() {
  const url = new URL(window.location.href);
  return (
    url.pathname === "/preview/trade-pulse" ||
    url.searchParams.get("preview") === "trade-pulse"
  );
}


/** Dedicated mobile UN hub page: /un, #un, or ?view=un */
export function getIsUnHubRoute() {
  if (typeof window === "undefined") return false;
  const url = new URL(window.location.href);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  return (
    path === "/un" ||
    url.hash === "#un" ||
    url.hash === "#/un" ||
    url.searchParams.get("view") === "un"
  );
}


export function openUnHubRoute() {
  const url = new URL(window.location.href);
  url.pathname = "/un";
  url.hash = "";
  url.searchParams.delete("view");
  window.history.pushState({ unHub: true }, "", url.toString());
}


export function closeUnHubRoute() {
  const url = new URL(window.location.href);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  if (path === "/un") {
    url.pathname = "/";
  }
  if (url.hash === "#un" || url.hash === "#/un") {
    url.hash = "";
  }
  url.searchParams.delete("view");
  window.history.pushState({ unHub: false }, "", url.toString());
}


/** Dedicated mobile PKI hub: /pki, #pki, or ?view=pki */
export function getIsPkiHubRoute() {
  if (typeof window === "undefined") return false;
  const url = new URL(window.location.href);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  return (
    path === "/pki" ||
    url.hash === "#pki" ||
    url.hash === "#/pki" ||
    url.searchParams.get("view") === "pki"
  );
}


export function openPkiHubRoute() {
  const url = new URL(window.location.href);
  url.pathname = "/pki";
  url.hash = "";
  url.searchParams.delete("view");
  window.history.pushState({ pkiHub: true }, "", url.toString());
}


export function closePkiHubRoute() {
  const url = new URL(window.location.href);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  if (path === "/pki") {
    url.pathname = "/";
  }
  if (url.hash === "#pki" || url.hash === "#/pki") {
    url.hash = "";
  }
  url.searchParams.delete("view");
  window.history.pushState({ pkiHub: false }, "", url.toString());
}


/** Dedicated mobile Contracting hub: /contracts, #contracts, or ?view=contracts */
export function getIsContractsHubRoute() {
  if (typeof window === "undefined") return false;
  const url = new URL(window.location.href);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  return (
    path === "/contracts" ||
    url.hash === "#contracts" ||
    url.hash === "#/contracts" ||
    url.searchParams.get("view") === "contracts"
  );
}


export function openContractsHubRoute() {
  const url = new URL(window.location.href);
  url.pathname = "/contracts";
  url.hash = "";
  url.searchParams.delete("view");
  window.history.pushState({ contractsHub: true }, "", url.toString());
}


export function closeContractsHubRoute() {
  const url = new URL(window.location.href);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  if (path === "/contracts") {
    url.pathname = "/";
  }
  if (url.hash === "#contracts" || url.hash === "#/contracts") {
    url.hash = "";
  }
  url.searchParams.delete("view");
  window.history.pushState({ contractsHub: false }, "", url.toString());
}


export function getRoutePulseLayer(
  route: TradePulseRoutePreview,
  layers: Record<TradePulseLayer, boolean>,
) {
  return route.layers.find((layer) => layers[layer]) ?? route.layers[0] ?? "dependency";
}


export function getVisibleTradePulseRoutes(
  preview: TradePulsePreview | null,
  layers: Record<TradePulseLayer, boolean>,
) {
  if (!preview) {
    return [];
  }

  return preview.routes.filter((route) => route.layers.some((layer) => layers[layer]));
}


export function buildTradePulsePoints(
  routes: TradePulseRoutePreview[],
  layers: Record<TradePulseLayer, boolean>,
) {
  const points = new Map<
    string,
    {
      key: string;
      name: string;
      iso3: string;
      lat: number;
      lng: number;
      size: number;
      color: string;
      label: string;
      severity: string;
    }
  >();

  const addPoint = (
    route: TradePulseRoutePreview,
    country: TradePulseRoutePreview["origin"],
    role: string,
  ) => {
    const layer = getRoutePulseLayer(route, layers);
    const existing = points.get(`${country.iso3}-${role}`);
    const size =
      role === "hub"
        ? 18
        : 10 + Math.min(12, Math.max(route.supplierSharePct, route.asymmetryPct) / 8);

    if (existing && existing.size >= size) {
      return;
    }

    points.set(`${country.iso3}-${role}`, {
      key: `${country.iso3}-${role}`,
      name: country.name,
      iso3: country.iso3,
      lat: country.lat,
      lng: country.lng,
      size,
      color: TRADE_PULSE_LAYER_COLORS[layer],
      label: role === "hub" ? "Hub" : TRADE_PULSE_LAYER_SHORT_LABELS[layer],
      severity: route.severity,
    });
  };

  for (const route of routes) {
    addPoint(route, route.destination, "destination");

    if (layers.lifelines || layers.transport) {
      addPoint(route, route.origin, "origin");
    }

    if (route.intermediary && (layers.intermediary || layers.hubs)) {
      addPoint(route, route.intermediary, "hub");
    }
  }

  return Array.from(points.values());
}


export function getTradePulseGlobeMarkers(
  preview: TradePulsePreview | null,
  layers: Record<TradePulseLayer, boolean>,
) {
  return buildTradePulsePoints(getVisibleTradePulseRoutes(preview, layers), layers)
    .slice(0, 28)
    .map((point) => ({
      location: [point.lat, point.lng] as [number, number],
      size: point.severity === "critical" ? 0.09 : point.severity === "high" ? 0.07 : 0.05,
    }));
}


export function buildDailyForecast(data: OpenMeteoForecastResponse): WeatherForecastDay[] {
  const daily = data.daily;

  return (daily?.time ?? []).slice(0, 7).map((date, index) => {
    const weatherCode = Math.round(getForecastNumber(daily?.weather_code, index));

    return {
      date,
      condition: describeWeatherCode(weatherCode),
      highF: Math.round(getForecastNumber(daily?.temperature_2m_max, index)),
      lowF: Math.round(getForecastNumber(daily?.temperature_2m_min, index)),
      precipitationChancePct: Math.round(
        getForecastNumber(daily?.precipitation_probability_max, index),
      ),
      precipitationIn: getForecastNumber(daily?.precipitation_sum, index),
      windMph: Math.round(getForecastNumber(daily?.wind_speed_10m_max, index)),
      gustMph: Math.round(getForecastNumber(daily?.wind_gusts_10m_max, index)),
      uvIndex: Math.round(getForecastNumber(daily?.uv_index_max, index)),
    };
  });
}


export function buildHourlyForecast(data: OpenMeteoForecastResponse): WeatherForecastHour[] {
  const hourly = data.hourly;
  const times = hourly?.time ?? [];
  const currentTime = data.current?.time;
  const currentHourIndex = currentTime
    ? times.findIndex((time) => time >= currentTime)
    : 0;
  const startIndex = currentHourIndex >= 0 ? currentHourIndex : 0;

  return times.slice(startIndex, startIndex + 7).map((time, offset) => {
    const index = startIndex + offset;
    const weatherCode = Math.round(getForecastNumber(hourly?.weather_code, index));

    return {
      time,
      condition: describeWeatherCode(weatherCode),
      tempF: Math.round(getForecastNumber(hourly?.temperature_2m, index)),
      feelsLikeF: Math.round(getForecastNumber(hourly?.apparent_temperature, index)),
      humidityPct: Math.round(getForecastNumber(hourly?.relative_humidity_2m, index)),
      precipitationChancePct: Math.round(
        getForecastNumber(hourly?.precipitation_probability, index),
      ),
      precipitationIn: getForecastNumber(hourly?.precipitation, index),
      windMph: Math.round(getForecastNumber(hourly?.wind_speed_10m, index)),
      gustMph: Math.round(getForecastNumber(hourly?.wind_gusts_10m, index)),
      cloudCoverPct: Math.round(getForecastNumber(hourly?.cloud_cover, index)),
    };
  });
}


/** Globe outline glow + matching solid text color for weather condition UI. */
export function getWeatherGlow(weather: WeatherFeed | null): {
  color: [number, number, number];
  css: string;
  text: string;
} {
  if (!weather) {
    return {
      color: [0.18, 0.55, 0.8],
      css: "rgba(0, 217, 255, 0.35)",
      text: "#00d9ff",
    };
  }

  if (weather.hasLightning) {
    return {
      color: [0.78, 0.7, 1],
      css: "rgba(170, 145, 255, 0.55)",
      text: "#aa91ff",
    };
  }

  if (weather.weatherCode === 0 || weather.weatherCode === 1) {
    return {
      color: [1, 0.72, 0.18],
      css: "rgba(255, 184, 46, 0.46)",
      text: "#ffb82e",
    };
  }

  if ([2, 3, 45, 48].includes(weather.weatherCode)) {
    return {
      color: [0.52, 0.64, 0.76],
      css: "rgba(150, 178, 210, 0.38)",
      text: "#96b2d2",
    };
  }

  if (
    [
      51, 53, 55, 56, 57, 61, 63, 65, 66, 67, 80, 81, 82,
    ].includes(weather.weatherCode)
  ) {
    return {
      color: [0.1, 0.45, 0.95],
      css: "rgba(35, 126, 255, 0.48)",
      text: "#237eff",
    };
  }

  if ([71, 73, 75, 77, 85, 86].includes(weather.weatherCode)) {
    return {
      color: [0.72, 0.9, 1],
      css: "rgba(190, 232, 255, 0.5)",
      text: "#bee8ff",
    };
  }

  return {
    color: [0.18, 0.55, 0.8],
    css: "rgba(0, 217, 255, 0.35)",
    text: "#00d9ff",
  };
}
