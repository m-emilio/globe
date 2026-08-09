// Messages that we'll send to the client

/**
 * Public globe marker — no raw IP / ASN / org (privacy).
 * Coarse country may be included for map context only.
 */
export type Position = {
  lat: number;
  lng: number;
  id: string;
  /** ISO country code only (optional, coarse) */
  country?: string;
};

/**
 * Paid Live Feed enrichment (server sends only to transitPaid sessions).
 * Never includes full IP — only a privacy-masked form when present.
 */
export type FeedVisitorMeta = {
  id: string;
  city?: string;
  country?: string;
  org?: string;
  /** Masked IP only (e.g. 1.2.x.x) — never full address */
  ipMasked?: string;
};

/**
 * Client → server web-support chat (relay only).
 * Paid: server accepts only transitPaid (Live Feed) sessions.
 * Never persisted on the server.
 */
export type IncomingMessage = {
  type: "chat";
  /** Plain chat body (server strips control chars, max length) */
  text: string;
  /** Optional display label (not a verified identity) */
  displayName?: string;
};

export type ChatMessage = {
  type: "chat";
  /** Server-assigned message id for UI keys */
  id: string;
  /** Sender connection id (always server-set) */
  fromId: string;
  text: string;
  displayName: string;
  /** Server clock ms */
  ts: number;
};

/** Wire / display limits for paid Live Feed web-support chat */
export const CHAT_MAX_TEXT = 200;
export const CHAT_MAX_NAME = 24;
/** Max raw JSON frame size we accept on the socket */
export const CHAT_MAX_WIRE_BYTES = 800;
export const CHAT_RATE_WINDOW_MS = 8_000;
export const CHAT_MAX_PER_WINDOW = 5;
/** Client-side pre-send throttle (server still enforces) */
export const CHAT_CLIENT_MAX_PER_WINDOW = 4;

/**
 * Invisible / control / bidi / zero-width characters that enable spoofing
 * or terminal/log injection if ever logged.
 */
const CHAT_STRIP_RE =
  // eslint-disable-next-line no-control-regex
  /[\u0000-\u001F\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u2028-\u202F\u2060-\u2064\u2066-\u206F\uFEFF\uFFF9-\uFFFB]/g;

/** Connection / message ids — no spaces, controls, or HTML meta */
const CHAT_ID_RE = /^[\w.:-]{2,128}$/;

function nfkc(raw: string): string {
  try {
    return raw.normalize("NFKC");
  } catch {
    return raw;
  }
}

/**
 * Sanitize chat body for relay + display.
 * - NFKC normalize
 * - Strip controls / bidi / zero-width
 * - Collapse whitespace
 * - Cap length
 * React text nodes escape HTML; we never inject as HTML.
 */
export function sanitizeChatText(raw: unknown): string {
  if (typeof raw !== "string") return "";
  let s = nfkc(raw);
  s = s.replace(CHAT_STRIP_RE, "");
  // No HTML tags or angle-bracket spoofing in plain text
  s = s.replace(/[<>]/g, "");
  s = s.replace(/\s+/g, " ").trim();
  if (s.length > CHAT_MAX_TEXT) s = s.slice(0, CHAT_MAX_TEXT);
  // Reject empty / whitespace-only after cleanup
  if (!s || /^\s*$/.test(s)) return "";
  return s;
}

/**
 * Display name is cosmetic only — not auth.
 * Letters, numbers, spaces, limited punctuation; no brackets/quotes/slashes.
 */
export function sanitizeChatDisplayName(raw: unknown): string {
  if (typeof raw !== "string") return "";
  let s = nfkc(raw);
  s = s.replace(CHAT_STRIP_RE, "");
  try {
    // Prefer Unicode-aware allowlist when available
    s = s.replace(/[^\p{L}\p{N}\s._\-]/gu, "");
  } catch {
    // Fallback if runtime lacks Unicode property escapes
    s = s.replace(/[^a-zA-Z0-9\s._\-]/g, "");
  }
  s = s.replace(/\s+/g, " ").trim();
  if (s.length > CHAT_MAX_NAME) s = s.slice(0, CHAT_MAX_NAME);
  return s;
}

export function isValidChatId(id: unknown): id is string {
  if (typeof id !== "string") return false;
  if (id.length < 2 || id.length > 128) return false;
  // Allow Party/nanoid/UUID-style ids; block controls and HTML meta
  if (/[\u0000-\u001F\u007F<>"'`\\]/.test(id)) return false;
  // Prefer strict charset when it matches; otherwise accept printable safe ids
  if (CHAT_ID_RE.test(id)) return true;
  return /^[\x20-\x7E]+$/.test(id) && !/[<>"'`]/.test(id);
}

export function fallbackChatDisplayName(connectionId: string): string {
  const safe = (connectionId || "user")
    .replace(/[^a-zA-Z0-9]/g, "")
    .slice(0, 6);
  return `User ${safe || "anon"}`;
}

export type OutgoingMessage =
  | {
      type: "add-marker";
      position: Position;
    }
  | {
      type: "remove-marker";
      id: string;
    }
  | {
      type: "feed-join";
      meta: FeedVisitorMeta;
    }
  | {
      type: "feed-leave";
      id: string;
      sessionMs?: number;
      meta?: FeedVisitorMeta;
    }
  | {
      /** Whether this connection receives paid feed events */
      type: "feed-access";
      paid: boolean;
    }
  | ChatMessage;

export type ComtradeTradeRecordPreview = {
  flow: string;
  reporter: string;
  partner: string;
  period: string;
  commodityCode: string;
  commodity: string;
  primaryValueUsd: number;
  cifValueUsd: number | null;
  fobValueUsd: number | null;
  isAggregate: boolean;
};

export type ComtradeAvailabilityPreview = {
  datasetCode: string;
  reporter: string;
  period: string;
  classification: string;
  totalRecords: number;
  firstReleased: string | null;
  lastReleased: string | null;
};

export type ComtradeReferencePreview = {
  category: string;
  variable: string;
  description: string;
};

export type ComtradeReporterPreview = {
  code: string;
  iso3: string;
  name: string;
};

export type ComtradePreview = {
  source: string;
  sourceUrl: string;
  apiUrl: string;
  updatedAt: string;
  queryLabel: string;
  reporter: string;
  period: string;
  exportsUsd: number;
  importsUsd: number;
  tradeBalanceUsd: number;
  availabilityTotalRecords: number;
  latestRelease: string | null;
  referenceTablesTotal: number;
  reportersTotal: number;
  tradeRecords: ComtradeTradeRecordPreview[];
  availability: ComtradeAvailabilityPreview[];
  references: ComtradeReferencePreview[];
  reporters: ComtradeReporterPreview[];
  /**
   * public-preview: unauthenticated /public/v1 sample.
   * free-subscription: Worker-held Free API key → /data/v1 (key never sent to client).
   */
  dataMode: "public-preview" | "free-subscription";
  /** Path A: free public viz; Transit/Live Feed remain the paid product. */
  accessTier: "free-public";
  sampleLimit: number;
  complianceNotes: string[];
  /** True when Worker has COMTRADE_SUBSCRIPTION_KEY and used Free /data/v1 for trade rows. */
  subscriptionBacked?: boolean;
  stale?: boolean;
};

export type UnMissionLocationPreview = {
  id: string;
  acronym: string;
  name: string;
  active: boolean;
  location: string;
  lat: number;
  lng: number;
  startDate: string | null;
  endDate: string | null;
  lastUpdate: string | null;
};

export type UnGeoAreaPreview = {
  code: string;
  name: string;
  category: "member-state" | "observer" | "affiliate" | "embassy";
  lat: number;
  lng: number;
};

export type UnOfficeLocationPreview = {
  id: string;
  name: string;
  category: "headquarters" | "office" | "principal-organ";
  city: string;
  country: string;
  lat: number;
  lng: number;
};

export type UnGlobalPreview = {
  source: string;
  sourceUrl: string;
  apiUrl: string;
  updatedAt: string;
  queryLabel: string;
  missionsTotal: number;
  activeMissionsTotal: number;
  missionCoordinateTotal: number;
  memberStatesTotal: number;
  geoAreasTotal: number;
  affiliatesTotal: number;
  officesTotal: number;
  embassiesTotal: number;
  latestMissionUpdate: string | null;
  missionLocations: UnMissionLocationPreview[];
  offices: UnOfficeLocationPreview[];
  memberStates: UnGeoAreaPreview[];
  affiliates: UnGeoAreaPreview[];
  embassies: UnGeoAreaPreview[];
  stale?: boolean;
};

/** UNODC Data Portal research themes (data.unodc.org). */
export type UnodcThemeId =
  | "drug-seizure"
  | "drug-use"
  | "drug-trafficking"
  | "homicide"
  | "violent-crime"
  | "corruption"
  | "prisons"
  | "justice"
  | "firearms"
  | "trafficking-persons"
  | "wildlife"
  | "covid";

export type UnodcHotspotPoint = {
  id: string;
  iso3: string;
  name: string;
  lat: number;
  lng: number;
  value: number;
  year: number;
  /** 0–1 relative intensity within theme for marker size. */
  intensity: number;
};

export type UnodcThemePreview = {
  id: UnodcThemeId;
  label: string;
  portalUrl: string;
  unit: string;
  seriesLabel: string;
  dataMode: "live" | "unavailable";
  period: string | null;
  hotspotCount: number;
  hotspots: UnodcHotspotPoint[];
  note?: string;
};

export type UnodcHotspotsPreview = {
  source: string;
  sourceUrl: string;
  datasearchUrl: string;
  updatedAt: string;
  queryLabel: string;
  themes: UnodcThemePreview[];
  notes: string[];
};

/** PKI / TLS / certificate-related vulnerability layer for the globe. */
export type PkiVulnSeverity = "critical" | "high" | "medium" | "low" | "unknown";

export type PkiVulnCategory =
  | "certificate"
  | "tls-ssl"
  | "openssl"
  | "crypto-key"
  | "pki-auth"
  | "other-pki";

export type PkiVulnCve = {
  id: string;
  title: string;
  severity: PkiVulnSeverity;
  /** 0–10 when known */
  cvss?: number | null;
  description: string;
  vendor?: string | null;
  product?: string | null;
  categories: PkiVulnCategory[];
  knownExploited: boolean;
  publishedAt?: string | null;
  kevDateAdded?: string | null;
  nvdUrl: string;
  cisaUrl?: string | null;
  /**
   * Vendor HQ / primary origin country for map arcs (ISO3).
   * Signal map only — not where the exploit occurred.
   */
  originIso3?: string | null;
  /**
   * Deployment / exposure countries for map arcs (ISO3).
   * Derived from vendor footprint + TLS residual signal.
   */
  exposureIso3s?: string[];
};

export type PkiCountryHotspot = {
  id: string;
  iso3: string;
  name: string;
  lat: number;
  lng: number;
  /** Relative 0–1 for marker / heat size */
  intensity: number;
  /** Aggregate risk score (higher = more relevant PKI exposure signal) */
  score: number;
  cveCount: number;
  criticalCount: number;
  highCount: number;
  kevCount: number;
  topCves: string[];
  categories: PkiVulnCategory[];
};

export type PkiVulnsPreview = {
  source: string;
  sourceUrl: string;
  cisaKevUrl: string;
  nvdUrl: string;
  updatedAt: string;
  queryLabel: string;
  dataMode: "live" | "partial" | "unavailable";
  cveCount: number;
  hotspotCount: number;
  cves: PkiVulnCve[];
  hotspots: PkiCountryHotspot[];
  notes: string[];
};

export type TradePulseLayer =
  | "dependency"
  | "lifelines"
  | "asymmetry"
  | "intermediary"
  | "transport"
  | "friction"
  | "hubs"
  | "confidence";

export type TradePulseSeverity = "watch" | "elevated" | "high" | "critical";

export type TradePulseCountryPreview = {
  iso3: string;
  name: string;
  lat: number;
  lng: number;
};

export type TradePulseRoutePreview = {
  id: string;
  commodityCode: string;
  commodity: string;
  origin: TradePulseCountryPreview;
  destination: TradePulseCountryPreview;
  intermediary: TradePulseCountryPreview | null;
  transportMode: "sea" | "air" | "rail" | "road" | "mixed";
  customsProcedure: string;
  period: string;
  valueUsd: number;
  quantity: string;
  supplierSharePct: number;
  exportValueUsd: number;
  importValueUsd: number;
  asymmetryPct: number;
  fobValueUsd: number;
  cifValueUsd: number;
  frictionPct: number;
  reExportSharePct: number;
  confidencePct: number;
  layers: TradePulseLayer[];
  severity: TradePulseSeverity;
  insight: string;
};

export type TradePulseMetricPreview = {
  label: string;
  value: string;
};

export type TradePulsePreview = {
  source: string;
  sourceUrl: string;
  apiUrl: string;
  updatedAt: string;
  queryLabel: string;
  period: string;
  /**
   * derived-preview: synthetic scenario routes.
   * free-subscription: route values hydrated from Free /data/v1 (Worker key only).
   */
  dataMode: "derived-preview" | "free-subscription";
  /** Path A: free public UI; not gated by Stripe Transit. */
  accessTier: "free-public";
  /** True only when Free API successfully hydrated route values (still not a bulk dump). */
  isOfficialLiveStats: boolean;
  /** True when Worker Free API key backed the trade values. */
  subscriptionBacked?: boolean;
  /** How many template routes got at least one live Free API row. */
  liveRouteCount?: number;
  /** Annual periods selectable in the UI (Free API). */
  availablePeriods?: string[];
  routes: TradePulseRoutePreview[];
  metrics: TradePulseMetricPreview[];
  notes: string[];
  complianceNotes: string[];
};

export type NearbyPathKind = "road" | "path" | "cycle" | "service" | "park";

export type NearbyPathPoint = {
  lat: number;
  lng: number;
};

export type NearbyPathSegment = {
  id: string;
  name: string;
  /** highway=* or leisure/landuse tag for parks */
  highway: string;
  kind: NearbyPathKind;
  points: NearbyPathPoint[];
};

export type NearbyPathsPreview = {
  source: string;
  sourceUrl: string;
  lat: number;
  lng: number;
  radiusM: number;
  updatedAt: string;
  pathCount: number;
  roadCount: number;
  footCount: number;
  /** Park / green area polygons when present */
  parkCount?: number;
  paths: NearbyPathSegment[];
  stale?: boolean;
  note?: string;
};

export type TransitModePreview = {
  modeName: string;
  count: number;
};

export type TransitRoutePreview = {
  id: string;
  shortName: string;
  longName: string;
  modeName: string;
  networkName: string;
  color: string;
  textColor: string;
  closestStopName: string;
  closestStopDistanceM: number | null;
  nextDepartures: string[];
  alertCount: number;
};

export type TransitStopPreview = {
  id: string;
  name: string;
  code: string;
  distanceM: number | null;
  lat: number | null;
  lng: number | null;
  routeType: number | null;
};

export type TransitNearbyPreview = {
  source: string;
  sourceUrl: string;
  lat: number;
  lng: number;
  maxDistanceM: number;
  updatedAt: string;
  routeCount: number;
  stopCount: number;
  modes: TransitModePreview[];
  routes: TransitRoutePreview[];
  stops: TransitStopPreview[];
  note?: string;
};

/** SAM.gov set-aside code (subset used by FederalKey filters). */
export type SamSetAsideCode = string;

/** Normalized contract opportunity for Contracts hub + globe pins. */
export type SamOpportunityPreview = {
  id: string;
  noticeId: string;
  solicitationNumber: string;
  title: string;
  type: string;
  postedDate: string;
  responseDeadline: string;
  department: string;
  naics: string;
  naicsLabel: string;
  setAside: string;
  setAsideCode: string;
  url: string;
  descriptionExcerpt: string;
  active: string;
  placeLabel: string;
  state: string;
  city: string;
  /** Approximate place-of-performance coordinates (null if unknown). */
  lat: number | null;
  lng: number | null;
};

export type SamContractMarker = {
  id: string;
  lat: number;
  lng: number;
  title: string;
  setAsideCode: string;
  naics: string;
  placeLabel: string;
  size: number;
};

export type SamContractsPreview = {
  source: string;
  sourceUrl: string;
  updatedAt: string;
  queryLabel: string;
  preset: string;
  presetLabel: string;
  dataMode: "live" | "partial" | "unavailable";
  opportunityCount: number;
  markerCount: number;
  opportunities: SamOpportunityPreview[];
  markers: SamContractMarker[];
  notes: string[];
  filters: {
    q: string;
    days: number;
    setAside: string;
    setAsideLabel: string;
    ptype: string;
    naics: string[];
    naicsGroup: string;
    activeOnly: boolean;
    includeAwards: boolean;
  };
  catalog: {
    naics: Record<string, string>;
    groups: Record<string, { label: string; codes: string[] }>;
    setAsides: Record<string, string>;
    presets: Record<string, string>;
  };
  error?: string;
};
