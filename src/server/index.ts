import { routePartykitRequest, Server } from "partyserver";
import {
  adoptSessionToken,
  createAuthChallenge,
  getMe,
  getSessionUser,
  loginUser,
  logoutUser,
  rateLimitDurable,
  rateLimitOrNull,
  registerUser,
  requireTransitAccess,
  type AuthEnv,
} from "./auth";
import {
  adminClaimSession,
  adminDeleteUser,
  adminElevate,
  adminElevateChallenge,
  adminGrantTransit,
  adminListAudit,
  adminListUsers,
  adminLookupUser,
  adminRevokeTransit,
  adminStatus,
} from "./admin";
import {
  claimCheckoutSession,
  ensureBillingCatalog,
  getAccessStatus,
  getPaymentLink,
  getPaymentStatus,
  handleStripeWebhook,
} from "./billing";
import {
  getUnodcHotspotsPreview,
  UNODC_EDGE_CACHE_VERSION,
} from "./unodcHotspots";

import type {
  ComtradeAvailabilityPreview,
  ComtradePreview,
  ComtradeReferencePreview,
  ComtradeReporterPreview,
  ComtradeTradeRecordPreview,
  NearbyPathKind,
  NearbyPathSegment,
  NearbyPathsPreview,
  OutgoingMessage,
  FeedVisitorMeta,
  Position,
  TransitModePreview,
  TransitNearbyPreview,
  TransitRoutePreview,
  TransitStopPreview,
  TradePulseCountryPreview,
  TradePulseMetricPreview,
  TradePulsePreview,
  TradePulseRoutePreview,
  UnGeoAreaPreview,
  UnGlobalPreview,
  UnMissionLocationPreview,
  UnOfficeLocationPreview,
} from "../shared";
import type { Connection, ConnectionContext } from "partyserver";

const MAX_ACTIVE_CONNECTIONS = 500;
const MAX_CONNECTIONS_PER_IP = 8;
const CONNECTION_RATE_WINDOW_MS = 10_000;
const MAX_CONNECTIONS_PER_WINDOW = 20;
const MAX_CONNECTION_ATTEMPT_BUCKETS = 1_000;
const MAX_REPLAY_MARKERS = MAX_ACTIVE_CONNECTIONS;
const CLOSE_POLICY_VIOLATION = 1008;
const CLOSE_TRY_AGAIN_LATER = 1013;
const COMTRADE_SOURCE = "UN Comtrade Plus";
const COMTRADE_SOURCE_URL = "https://comtradeplus.un.org/";
const COMTRADE_API_BASE = "https://comtradeapi.un.org";
const COMTRADE_REPORTER_CODE = "842";
const COMTRADE_REPORTER_LABEL = "USA";
const COMTRADE_PERIOD = "2023";
const COMTRADE_CACHE_SECONDS = 6 * 60 * 60;
const COMTRADE_PREVIEW_QUERY =
  "C/A/HS annual merchandise trade, USA, World, all commodities";
/** Unauthenticated public sample (no subscription key). */
const COMTRADE_PUBLIC_EXPORT_URL =
  `${COMTRADE_API_BASE}/public/v1/preview/C/A/HS?reporterCode=${COMTRADE_REPORTER_CODE}` +
  `&period=${COMTRADE_PERIOD}&cmdCode=TOTAL&flowCode=X&partnerCode=0` +
  "&maxRecords=10&format=JSON&includeDesc=true";
const COMTRADE_PUBLIC_IMPORT_URL =
  `${COMTRADE_API_BASE}/public/v1/preview/C/A/HS?reporterCode=${COMTRADE_REPORTER_CODE}` +
  `&period=${COMTRADE_PERIOD}&cmdCode=TOTAL&flowCode=M&partnerCode=0` +
  "&maxRecords=10&format=JSON&includeDesc=true";
const COMTRADE_PUBLIC_AVAILABILITY_URL =
  `${COMTRADE_API_BASE}/public/v1/getDa/C/A/HS?reporterCode=${COMTRADE_REPORTER_CODE}` +
  `&period=${COMTRADE_PERIOD}`;
/** Free APIs (comtrade - v1) — requires Ocp-Apim-Subscription-Key server-side only. */
const COMTRADE_FREE_EXPORT_URL =
  `${COMTRADE_API_BASE}/data/v1/get/C/A/HS?reporterCode=${COMTRADE_REPORTER_CODE}` +
  `&period=${COMTRADE_PERIOD}&cmdCode=TOTAL&flowCode=X&partnerCode=0` +
  "&maxRecords=10&format=JSON&includeDesc=true";
const COMTRADE_FREE_IMPORT_URL =
  `${COMTRADE_API_BASE}/data/v1/get/C/A/HS?reporterCode=${COMTRADE_REPORTER_CODE}` +
  `&period=${COMTRADE_PERIOD}&cmdCode=TOTAL&flowCode=M&partnerCode=0` +
  "&maxRecords=10&format=JSON&includeDesc=true";
const COMTRADE_FREE_AVAILABILITY_URL =
  `${COMTRADE_API_BASE}/data/v1/getDa/C/A/HS?reporterCode=${COMTRADE_REPORTER_CODE}` +
  `&period=${COMTRADE_PERIOD}`;
/** @deprecated alias — public preview export (kept for response.apiUrl fallbacks) */
const COMTRADE_EXPORT_URL = COMTRADE_PUBLIC_EXPORT_URL;
const COMTRADE_IMPORT_URL = COMTRADE_PUBLIC_IMPORT_URL;
const COMTRADE_AVAILABILITY_URL = COMTRADE_PUBLIC_AVAILABILITY_URL;
const COMTRADE_REFERENCES_URL =
  `${COMTRADE_API_BASE}/files/v1/app/reference/ListofReferences.json`;
const COMTRADE_REPORTERS_URL =
  `${COMTRADE_API_BASE}/files/v1/app/reference/Reporters.json`;
const COMTRADE_RETRY_DELAY_MS = 1_250;
const COMTRADE_PREVIEW_LIMIT = 5;
const TRADE_PULSE_SOURCE_DERIVED = "FederalKey derived dependency scenario";
const TRADE_PULSE_SOURCE_LIVE = "UN Comtrade Free API · dependency radar";
const TRADE_PULSE_API_URL = `${COMTRADE_API_BASE}/data/v1/get/C/A/HS`;
const TRADE_PULSE_QUERY_DERIVED =
  "Derived global dependency radar (scenario UI). Uses Comtrade-shaped fields; not a live official UN extract.";
const TRADE_PULSE_QUERY_LIVE =
  "Live Free API values for radar routes (HS annual). Indicators computed server-side; limited sample not bulk extract.";
const TRADE_PULSE_PERIODS = ["2022", "2023", "2024", "2025"] as const;
type TradePulsePeriod = (typeof TRADE_PULSE_PERIODS)[number];
const TRADE_PULSE_DEFAULT_PERIOD: TradePulsePeriod = "2023";
const TRADE_PULSE_PERIOD = TRADE_PULSE_DEFAULT_PERIOD;
/** Path A product policy: Comtrade surfaces stay free/public; never resell API keys. */
const COMTRADE_ACCESS_TIER = "free-public" as const;
const COMTRADE_COMPLIANCE_NOTES = [
  "Limited public preview sample from the UN Comtrade public API — not a bulk download or premium extract.",
  "Free on FederalKey. Transit maps and Live Feed are the paid product; this drawer is not sold as UN Comtrade access.",
  "Attribution: UN Comtrade Plus. FederalKey does not resell UN API keys or re-host bulk original datasets.",
] as const;
const COMTRADE_FREE_COMPLIANCE_NOTES = [
  "Limited sample via UN Comtrade Free APIs (comtrade - v1), fetched server-side only — not a bulk extract or premium product.",
  "Free on FederalKey. Subscription key stays in the Worker; never exposed to browsers or resold.",
  "Transit maps and Live Feed are the paid product; this drawer is not sold as UN Comtrade access.",
] as const;
const TRADE_PULSE_COMPLIANCE_NOTES = [
  "Derived dependency scenario / preview — not official live UN Comtrade statistics.",
  "Routes and indicators are FederalKey scenario data for UI and risk framing, not a literal shipment tracker.",
  "Free public surface (Path A). Paid Transit/Live Feed do not unlock or resell Comtrade raw data or API keys.",
] as const;
const TRADE_PULSE_LIVE_COMPLIANCE_NOTES = [
  "Route values hydrated from UN Comtrade Free APIs (server-side key only) for a small fixed route set.",
  "Radar indicators (share, asymmetry, friction) are FederalKey transforms — not a bulk original dump or key resale.",
  "Free on FederalKey; not unlocked by Transit payment.",
] as const;
/** iso3 → Comtrade reporter/partner numeric code */
const TRADE_PULSE_REPORTER_CODES: Record<string, string> = {
  BRA: "76",
  CHN: "156",
  COL: "170",
  DEU: "276",
  EGY: "818",
  IND: "699",
  IDN: "360",
  KAZ: "398",
  KEN: "404",
  MEX: "484",
  MYS: "458",
  NLD: "528",
  NOR: "579",
  PAN: "591",
  RUS: "643",
  SGP: "702",
  USA: "842",
  VNM: "704",
  ZAF: "710",
};
const TRADE_PULSE_LIVE_CACHE_TTL_MS = 60 * 60 * 1000;
/** Serve last good live payload a bit longer if Free API is rate-limited. */
const TRADE_PULSE_LIVE_STALE_TTL_MS = 24 * 60 * 60 * 1000;
const TRADE_PULSE_KV_CACHE_PREFIX = "comtrade:trade-pulse:live:v3:";
const tradePulseLiveCacheByPeriod = new Map<
  string,
  {
    at: number;
    preview: TradePulsePreview;
  }
>();

type TradePulseKvCache = {
  at: number;
  preview: TradePulsePreview;
};

function tradePulseKvCacheKey(period: string) {
  return `${TRADE_PULSE_KV_CACHE_PREFIX}${period}`;
}

function parseTradePulsePeriod(raw: string | null | undefined): TradePulsePeriod {
  const value = (raw || "").trim();
  if ((TRADE_PULSE_PERIODS as readonly string[]).includes(value)) {
    return value as TradePulsePeriod;
  }
  return TRADE_PULSE_DEFAULT_PERIOD;
}

async function readTradePulseKvCache(
  env: Env,
  period: string,
): Promise<TradePulseKvCache | null> {
  try {
    const raw = await env.BILLING_KV.get(tradePulseKvCacheKey(period), "json");
    if (!raw || typeof raw !== "object") return null;
    const parsed = raw as TradePulseKvCache;
    if (
      !parsed.preview ||
      parsed.preview.dataMode !== "free-subscription" ||
      !Array.isArray(parsed.preview.routes) ||
      parsed.preview.period !== period
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

async function writeTradePulseKvCache(
  env: Env,
  period: string,
  entry: TradePulseKvCache,
  secrets: string[] = [],
): Promise<void> {
  try {
    // Never persist raw secrets in KV — scrub before write.
    const scrubbed: TradePulseKvCache = {
      at: entry.at,
      preview: scrubComtradeClientPayload(entry.preview, secrets),
    };
    await env.BILLING_KV.put(tradePulseKvCacheKey(period), JSON.stringify(scrubbed), {
      expirationTtl: Math.ceil(TRADE_PULSE_LIVE_STALE_TTL_MS / 1000),
    });
  } catch (error) {
    safeWarn("Trade Pulse KV cache write failed", error, secrets);
  }
}
const UN_GLOBAL_SOURCE = "UN Peace & Security Data Hub / UNSD SDG API";
const UN_GLOBAL_SOURCE_URL = "https://psdata.un.org/dataset/DPPADPOSS-PKO";
const UN_GLOBAL_API_BASE = "https://api.psdata.un.org/public";
const UN_GLOBAL_SDG_API_BASE = "https://unstats.un.org/sdgapi/v1/sdg";
const UN_PKO_DATA_URL =
  `${UN_GLOBAL_API_BASE}/data/DPPADPOSS-PKO/json?page_num=1&per_page=100` +
  "&source=DataHub";
const UN_PKO_METADATA_URL = `${UN_GLOBAL_API_BASE}/metadata/DPPADPOSS-PKO`;
const UN_SDG_GEO_AREAS_URL = `${UN_GLOBAL_SDG_API_BASE}/GeoArea/List`;
const UN_MEMBER_STATUS_URL =
  "https://ourworldindata.org/grapher/united-nations-membership-status.csv" +
  "?v=1&csvType=full&useColumnShortNames=false";
const COUNTRY_CENTROIDS_URL =
  "https://gist.githubusercontent.com/tadast/8827699/raw/" +
  "f5cac3d42d16b78348610fc4ec301e9234f82821/countries_codes_and_coordinates.csv";
const UN_BLUE_BOOK_SOURCE_URL = "https://www.un.org/dgacm/en/content/protocol/blue-book";
const UN_GLOBAL_CACHE_SECONDS = 6 * 60 * 60;
const NEARBY_PATHS_SOURCE = "OpenStreetMap";
const NEARBY_PATHS_SOURCE_URL = "https://www.openstreetmap.org/copyright";
const TRANSIT_API_BASE = "https://external.transitapp.com";
const TRANSIT_SOURCE = "Transit App Public API v4";
const TRANSIT_SOURCE_URL = "https://api-doc.transitapp.com/v4.html";
const TRANSIT_DEFAULT_MAX_DISTANCE_M = 800;
const TRANSIT_MIN_MAX_DISTANCE_M = 150;
const TRANSIT_MAX_MAX_DISTANCE_M = 1500;
const TRANSIT_MAX_ROUTES = 40;
const TRANSIT_MAX_STOPS = 40;
const TRANSIT_CACHE_SECONDS = 60;
const TRANSIT_CACHE = new Map<
  string,
  { expiresAt: number; payload: TransitNearbyPreview }
>();
const OSM_MAP_API = "https://api.openstreetmap.org/api/0.6/map";
const OVERPASS_ENDPOINTS = [
  "https://overpass-api.de/api/interpreter",
  "https://overpass.kumi.systems/api/interpreter",
  "https://overpass.private.coffee/api/interpreter",
] as const;
/** OSM 500m cores usually return in 1–3s; keep abort tight for snappy maps */
const OSM_MAP_ATTEMPT_MS = 7_000;
/** Single-mirror budget — Overpass is fallback only */
const OVERPASS_ATTEMPT_MS = 5_000;
/** Soft cap: dense cities ~10–15MB; still parse when possible */
const OSM_MAP_MAX_XML_CHARS = 18_000_000;
const NEARBY_DEFAULT_RADIUS_M = 500;
const NEARBY_MIN_RADIUS_M = 250;
/** Match transit max so both maps can share the same accurate radius. */
const NEARBY_MAX_RADIUS_M = 1500;
/** Enough ways to fill large rings after tiling */
const NEARBY_MAX_WAYS = 200;
const NEARBY_MAX_POINTS_PER_WAY = 40;
/** OSM map API bbox half-size — must cover full user radius. */
const OSM_FETCH_RADIUS_CAP_M = NEARBY_MAX_RADIUS_M;
const NEARBY_CACHE_SECONDS = 15 * 60;
/** ~0.1 m at equator — keep geometry true for projection */
const NEARBY_COORD_DECIMALS = 6;
const HIGHWAY_ALLOW =
  /^(motorway|trunk|primary|secondary|tertiary|unclassified|residential|living_street|service|track|footway|path|cycleway|pedestrian|steps|bridleway)$/;
/** Park / green polygons (leisure + landuse) — must stay defined for classifyOsmTags */
const PARK_LEISURE =
  /^(park|garden|playground|pitch|nature_reserve|recreation_ground|common|dog_park|village_green)$/;
const PARK_LANDUSE =
  /^(grass|recreation_ground|meadow|forest|village_green|orchard|allotments)$/;
const NEARBY_CACHE = new Map<
  string,
  { expiresAt: number; payload: NearbyPathsPreview }
>();
const UN_MEMBER_STATES_TOTAL = 193;
const UN_GEO_AREAS_FALLBACK_TOTAL = 460;
const UN_GLOBAL_PREVIEW_LIMIT = 100;
/**
 * Browser security policy (XSS / supply-chain focused).
 * - No third-party scripts forever: script-src 'self' only (+ wasm for OpenPGP).
 * - connect-src: same-origin APIs/WebSocket + open-meteo (browser weather only).
 * - Upstream Stripe/OSM/Transit/Comtrade are server-side (Worker fetch), not browser connect.
 * Keep in sync with public/_headers.
 */
const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "base-uri 'none'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "frame-src 'none'",
  "child-src 'none'",
  "worker-src 'self' blob:",
  "manifest-src 'self'",
  // First-party JS only. 'wasm-unsafe-eval' required for OpenPGP Argon2 WASM.
  "script-src 'self' 'wasm-unsafe-eval'",
  "script-src-attr 'none'",
  // React style={{}} attributes; no external stylesheets.
  "style-src 'self' 'unsafe-inline'",
  "style-src-attr 'unsafe-inline'",
  // No remote images in-app (imagedelivery was template metadata only).
  "img-src 'self' data: blob:",
  "font-src 'self'",
  // 'self' covers same-origin fetch + WebSocket (PartyKit). No open ws:/wss: wildcards.
  "connect-src 'self' https://api.open-meteo.com",
  "form-action 'self'",
  // No upgrade-insecure-requests: breaks local http://127.0.0.1 wrangler dev.
  // Production is HTTPS at the edge.
].join("; ");

const SECURITY_HEADERS = {
  "content-security-policy": CONTENT_SECURITY_POLICY,
  "cross-origin-opener-policy": "same-origin",
  // CORP same-origin is fine for API JSON. Static /dist assets set
  // CORP cross-origin via public/_headers so SRI+crossorigin scripts load.
  "cross-origin-resource-policy": "same-origin",
  "origin-agent-cluster": "?1",
  "referrer-policy": "strict-origin-when-cross-origin",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "permissions-policy":
    "camera=(), microphone=(), geolocation=(self), payment=(), usb=(), interest-cohort=()",
  // Discourage MIME-based XSS / legacy plugins
  "x-permitted-cross-domain-policies": "none",
} satisfies Record<string, string>;

// Connection state: public marker + private feed meta (never fully broadcast)
type ConnectionState = {
  /** Public globe marker — no IP/org */
  position: Position;
  /** Internal rate-limit key (full IP kept server-side only) */
  clientKey: string;
  /** Paid Live Feed enrichment — only sent to transitPaid peers */
  feedMeta: FeedVisitorMeta;
  joinedAt: number;
  /** Whether this socket may receive feed-* messages */
  feedPaid: boolean;
};

/** Mask IPv4/IPv6 for paid feed only — never send full address on the wire. */
function maskIpForFeed(ip: string | undefined): string | undefined {
  if (!ip) return undefined;
  const value = ip.trim().slice(0, 64);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
    const [a, b] = value.split(".");
    return `${a}.${b}.x.x`;
  }
  if (value.includes(":")) {
    const groups = value.split(":").filter(Boolean).slice(0, 2);
    return groups.length ? `${groups.join(":")}:…` : "ipv6:…";
  }
  return "hidden";
}

function publicMarker(position: Position): Position {
  return {
    lat: position.lat,
    lng: position.lng,
    id: position.id,
    ...(position.country ? { country: position.country } : {}),
  };
}

type ConnectionAttemptBucket = {
  windowStart: number;
  count: number;
};

type ComtradeApiRecord = Record<string, unknown>;

type CountryCentroidRecord = {
  alpha3: string;
  code: string;
  name: string;
  lat: number;
  lng: number;
};

const FALLBACK_COMTRADE_RECORDS: ComtradeTradeRecordPreview[] = [
  {
    flow: "Export",
    reporter: "USA",
    partner: "World",
    period: COMTRADE_PERIOD,
    commodityCode: "TOTAL",
    commodity: "All Commodities",
    primaryValueUsd: 2_018_542_583_771,
    cifValueUsd: null,
    fobValueUsd: 2_018_542_583_771,
    isAggregate: true,
  },
  {
    flow: "Import",
    reporter: "USA",
    partner: "World",
    period: COMTRADE_PERIOD,
    commodityCode: "TOTAL",
    commodity: "All Commodities",
    primaryValueUsd: 3_168_471_121_076,
    cifValueUsd: 3_168_471_121_076,
    fobValueUsd: 3_080_052_528_515,
    isAggregate: true,
  },
];

const FALLBACK_COMTRADE_AVAILABILITY: ComtradeAvailabilityPreview[] = [
  {
    datasetCode: "20842202301202100",
    reporter: "USA",
    period: COMTRADE_PERIOD,
    classification: "H6",
    totalRecords: 1_204_648,
    firstReleased: "2024-02-11T05:48:29.3133333",
    lastReleased: "2024-02-11T05:48:29.3133333",
  },
];

const FALLBACK_COMTRADE_REFERENCES: ComtradeReferencePreview[] = [
  {
    category: "reporter",
    variable: "Reporter",
    description: "The reporting country or geographic area.",
  },
  {
    category: "partner",
    variable: "Partner country/area",
    description: "The partner country or geographic area for the trade flow.",
  },
  {
    category: "flow",
    variable: "Trade Flow",
    description: "Imports, exports, re-imports, re-exports, and related flows.",
  },
];

const FALLBACK_COMTRADE_REPORTERS: ComtradeReporterPreview[] = [
  {
    code: "842",
    iso3: "USA",
    name: "USA",
  },
  {
    code: "156",
    iso3: "CHN",
    name: "China",
  },
  {
    code: "276",
    iso3: "DEU",
    name: "Germany",
  },
  {
    code: "124",
    iso3: "CAN",
    name: "Canada",
  },
  {
    code: "484",
    iso3: "MEX",
    name: "Mexico",
  },
];

const TRADE_PULSE_COUNTRIES = {
  BRA: { iso3: "BRA", name: "Brazil", lat: -15.7939, lng: -47.8828 },
  CHN: { iso3: "CHN", name: "China", lat: 39.9042, lng: 116.4074 },
  COL: { iso3: "COL", name: "Colombia", lat: 4.711, lng: -74.0721 },
  DEU: { iso3: "DEU", name: "Germany", lat: 52.52, lng: 13.405 },
  EGY: { iso3: "EGY", name: "Egypt", lat: 30.0444, lng: 31.2357 },
  IND: { iso3: "IND", name: "India", lat: 28.6139, lng: 77.209 },
  IDN: { iso3: "IDN", name: "Indonesia", lat: -6.2088, lng: 106.8456 },
  KAZ: { iso3: "KAZ", name: "Kazakhstan", lat: 51.1694, lng: 71.4491 },
  KEN: { iso3: "KEN", name: "Kenya", lat: -1.2921, lng: 36.8219 },
  MEX: { iso3: "MEX", name: "Mexico", lat: 19.4326, lng: -99.1332 },
  MYS: { iso3: "MYS", name: "Malaysia", lat: 3.139, lng: 101.6869 },
  NLD: { iso3: "NLD", name: "Netherlands", lat: 52.3676, lng: 4.9041 },
  NOR: { iso3: "NOR", name: "Norway", lat: 59.9139, lng: 10.7522 },
  PAN: { iso3: "PAN", name: "Panama", lat: 8.9824, lng: -79.5199 },
  RUS: { iso3: "RUS", name: "Russian Federation", lat: 55.7558, lng: 37.6173 },
  SGP: { iso3: "SGP", name: "Singapore", lat: 1.3521, lng: 103.8198 },
  USA: { iso3: "USA", name: "United States", lat: 38.8977, lng: -77.0365 },
  VNM: { iso3: "VNM", name: "Viet Nam", lat: 21.0278, lng: 105.8342 },
  ZAF: { iso3: "ZAF", name: "South Africa", lat: -25.7479, lng: 28.2293 },
} satisfies Record<string, TradePulseCountryPreview>;

const TRADE_PULSE_ROUTES: TradePulseRoutePreview[] = [
  {
    id: "dependency-egy-rus-wheat",
    commodityCode: "100199",
    commodity: "Wheat and meslin",
    origin: TRADE_PULSE_COUNTRIES.RUS,
    destination: TRADE_PULSE_COUNTRIES.EGY,
    intermediary: null,
    transportMode: "sea",
    customsProcedure: "Import for domestic consumption",
    period: "2023",
    valueUsd: 2_480_000_000,
    quantity: "8.7M t",
    supplierSharePct: 72,
    exportValueUsd: 2_180_000_000,
    importValueUsd: 2_480_000_000,
    asymmetryPct: 12,
    fobValueUsd: 2_180_000_000,
    cifValueUsd: 2_480_000_000,
    frictionPct: 13.8,
    reExportSharePct: 2,
    confidencePct: 86,
    layers: ["dependency", "lifelines", "transport", "friction"],
    severity: "critical",
    insight:
      "Food security route with dominant supplier exposure and visible CIF/FOB transport friction.",
  },
  {
    id: "asymmetry-ken-ind-medicine",
    commodityCode: "300490",
    commodity: "Packaged medicaments",
    origin: TRADE_PULSE_COUNTRIES.IND,
    destination: TRADE_PULSE_COUNTRIES.KEN,
    intermediary: null,
    transportMode: "air",
    customsProcedure: "Import for domestic consumption",
    period: "2023",
    valueUsd: 610_000_000,
    quantity: "18.2K t",
    supplierSharePct: 58,
    exportValueUsd: 420_000_000,
    importValueUsd: 610_000_000,
    asymmetryPct: 31.1,
    fobValueUsd: 420_000_000,
    cifValueUsd: 610_000_000,
    frictionPct: 45.2,
    reExportSharePct: 6,
    confidencePct: 67,
    layers: ["lifelines", "asymmetry", "transport", "friction", "confidence"],
    severity: "high",
    insight:
      "Health-sector lifeline with a large bilateral mirror mismatch and low confidence score.",
  },
  {
    id: "intermediary-mex-chn-chips",
    commodityCode: "854231",
    commodity: "Electronic integrated circuits",
    origin: TRADE_PULSE_COUNTRIES.CHN,
    destination: TRADE_PULSE_COUNTRIES.MEX,
    intermediary: TRADE_PULSE_COUNTRIES.USA,
    transportMode: "air",
    customsProcedure: "Import after transit or processing",
    period: "2023",
    valueUsd: 5_900_000_000,
    quantity: "3.4B units",
    supplierSharePct: 66,
    exportValueUsd: 4_950_000_000,
    importValueUsd: 5_900_000_000,
    asymmetryPct: 16.1,
    fobValueUsd: 4_950_000_000,
    cifValueUsd: 5_900_000_000,
    frictionPct: 19.2,
    reExportSharePct: 38,
    confidencePct: 76,
    layers: ["dependency", "lifelines", "intermediary", "transport", "friction", "hubs"],
    severity: "critical",
    insight:
      "Electronics dependency with a second-partner relay signal through the United States.",
  },
  {
    id: "hub-pan-chn-col-electronics",
    commodityCode: "851762",
    commodity: "Data transmission apparatus",
    origin: TRADE_PULSE_COUNTRIES.CHN,
    destination: TRADE_PULSE_COUNTRIES.COL,
    intermediary: TRADE_PULSE_COUNTRIES.PAN,
    transportMode: "sea",
    customsProcedure: "Re-export via free zone",
    period: "2023",
    valueUsd: 1_140_000_000,
    quantity: "11.8M units",
    supplierSharePct: 44,
    exportValueUsd: 820_000_000,
    importValueUsd: 1_140_000_000,
    asymmetryPct: 28.1,
    fobValueUsd: 820_000_000,
    cifValueUsd: 1_140_000_000,
    frictionPct: 39,
    reExportSharePct: 73,
    confidencePct: 61,
    layers: ["asymmetry", "intermediary", "transport", "friction", "hubs", "confidence"],
    severity: "high",
    insight:
      "Re-export hub pattern where second-partner routing and mirror mismatch both light up.",
  },
  {
    id: "dependency-bra-rus-fertilizer",
    commodityCode: "310420",
    commodity: "Potassium chloride fertilizers",
    origin: TRADE_PULSE_COUNTRIES.RUS,
    destination: TRADE_PULSE_COUNTRIES.BRA,
    intermediary: TRADE_PULSE_COUNTRIES.NLD,
    transportMode: "sea",
    customsProcedure: "Import for agriculture inputs",
    period: "2023",
    valueUsd: 3_760_000_000,
    quantity: "7.9M t",
    supplierSharePct: 63,
    exportValueUsd: 3_120_000_000,
    importValueUsd: 3_760_000_000,
    asymmetryPct: 17,
    fobValueUsd: 3_120_000_000,
    cifValueUsd: 3_760_000_000,
    frictionPct: 20.5,
    reExportSharePct: 22,
    confidencePct: 79,
    layers: ["dependency", "lifelines", "intermediary", "transport", "friction"],
    severity: "critical",
    insight:
      "Agriculture input dependency with a northern European second-partner routing signal.",
  },
  {
    id: "hub-sgp-vnm-idn-refined-petroleum",
    commodityCode: "271019",
    commodity: "Refined petroleum oils",
    origin: TRADE_PULSE_COUNTRIES.VNM,
    destination: TRADE_PULSE_COUNTRIES.IDN,
    intermediary: TRADE_PULSE_COUNTRIES.SGP,
    transportMode: "sea",
    customsProcedure: "Re-export after storage",
    period: "2023",
    valueUsd: 4_420_000_000,
    quantity: "5.1M t",
    supplierSharePct: 36,
    exportValueUsd: 3_180_000_000,
    importValueUsd: 4_420_000_000,
    asymmetryPct: 28.1,
    fobValueUsd: 3_180_000_000,
    cifValueUsd: 4_420_000_000,
    frictionPct: 39,
    reExportSharePct: 61,
    confidencePct: 64,
    layers: ["lifelines", "asymmetry", "intermediary", "transport", "friction", "hubs", "confidence"],
    severity: "high",
    insight:
      "Energy route with hub behavior, low confidence, and a high CIF/FOB spread.",
  },
  {
    id: "confidence-deu-nor-gas",
    commodityCode: "271121",
    commodity: "Natural gas in gaseous state",
    origin: TRADE_PULSE_COUNTRIES.NOR,
    destination: TRADE_PULSE_COUNTRIES.DEU,
    intermediary: null,
    transportMode: "mixed",
    customsProcedure: "Pipeline and sea energy imports",
    period: "2023",
    valueUsd: 18_600_000_000,
    quantity: "44.5B m3",
    supplierSharePct: 47,
    exportValueUsd: 17_200_000_000,
    importValueUsd: 18_600_000_000,
    asymmetryPct: 7.5,
    fobValueUsd: 17_200_000_000,
    cifValueUsd: 18_600_000_000,
    frictionPct: 8.1,
    reExportSharePct: 4,
    confidencePct: 92,
    layers: ["lifelines", "transport"],
    severity: "elevated",
    insight:
      "High-value energy lifeline with stronger mirror agreement than other alert routes.",
  },
  {
    id: "asymmetry-zaf-chn-solar",
    commodityCode: "854143",
    commodity: "Photovoltaic cells and modules",
    origin: TRADE_PULSE_COUNTRIES.CHN,
    destination: TRADE_PULSE_COUNTRIES.ZAF,
    intermediary: TRADE_PULSE_COUNTRIES.SGP,
    transportMode: "sea",
    customsProcedure: "Import for renewable energy deployment",
    period: "2023",
    valueUsd: 1_020_000_000,
    quantity: "28.6M units",
    supplierSharePct: 79,
    exportValueUsd: 640_000_000,
    importValueUsd: 1_020_000_000,
    asymmetryPct: 37.3,
    fobValueUsd: 640_000_000,
    cifValueUsd: 1_020_000_000,
    frictionPct: 59.4,
    reExportSharePct: 34,
    confidencePct: 58,
    layers: ["dependency", "lifelines", "asymmetry", "intermediary", "transport", "friction", "hubs", "confidence"],
    severity: "critical",
    insight:
      "Transition-goods dependency where mirror mismatch, friction, and intermediary signals converge.",
  },
  {
    id: "intermediary-deu-kaz-uranium",
    commodityCode: "284410",
    commodity: "Natural uranium compounds",
    origin: TRADE_PULSE_COUNTRIES.KAZ,
    destination: TRADE_PULSE_COUNTRIES.DEU,
    intermediary: TRADE_PULSE_COUNTRIES.NLD,
    transportMode: "rail",
    customsProcedure: "Specialized industrial input transit",
    period: "2023",
    valueUsd: 730_000_000,
    quantity: "2.8K t",
    supplierSharePct: 52,
    exportValueUsd: 650_000_000,
    importValueUsd: 730_000_000,
    asymmetryPct: 11,
    fobValueUsd: 650_000_000,
    cifValueUsd: 730_000_000,
    frictionPct: 12.3,
    reExportSharePct: 29,
    confidencePct: 74,
    layers: ["lifelines", "intermediary", "transport", "friction", "confidence"],
    severity: "elevated",
    insight:
      "Strategic industrial input with a second-partner transit signal and moderate confidence.",
  },
];

const MEMBER_STATE_MARKER_SEEDS = [
  { code: "840", fallbackName: "United States of America", lat: 38.8977, lng: -77.0365 },
  { code: "124", fallbackName: "Canada", lat: 45.4215, lng: -75.6972 },
  { code: "484", fallbackName: "Mexico", lat: 19.4326, lng: -99.1332 },
  { code: "76", fallbackName: "Brazil", lat: -15.7939, lng: -47.8828 },
  {
    code: "826",
    fallbackName: "United Kingdom of Great Britain and Northern Ireland",
    lat: 51.5074,
    lng: -0.1278,
  },
  { code: "250", fallbackName: "France", lat: 48.8566, lng: 2.3522 },
  { code: "276", fallbackName: "Germany", lat: 52.52, lng: 13.405 },
  { code: "710", fallbackName: "South Africa", lat: -25.7479, lng: 28.2293 },
  { code: "356", fallbackName: "India", lat: 28.6139, lng: 77.209 },
  { code: "156", fallbackName: "China", lat: 39.9042, lng: 116.4074 },
  { code: "392", fallbackName: "Japan", lat: 35.6762, lng: 139.6503 },
  { code: "36", fallbackName: "Australia", lat: -35.2809, lng: 149.13 },
];

const UN_OFFICE_LOCATIONS: UnOfficeLocationPreview[] = [
  {
    id: "un-hq-new-york",
    name: "United Nations Headquarters",
    category: "headquarters",
    city: "New York",
    country: "United States",
    lat: 40.7499,
    lng: -73.968,
  },
  {
    id: "unog-geneva",
    name: "United Nations Office at Geneva",
    category: "office",
    city: "Geneva",
    country: "Switzerland",
    lat: 46.2266,
    lng: 6.1405,
  },
  {
    id: "unov-vienna",
    name: "United Nations Office at Vienna",
    category: "office",
    city: "Vienna",
    country: "Austria",
    lat: 48.2353,
    lng: 16.4167,
  },
  {
    id: "unon-nairobi",
    name: "United Nations Office at Nairobi",
    category: "office",
    city: "Nairobi",
    country: "Kenya",
    lat: -1.2344,
    lng: 36.8172,
  },
  {
    id: "icj-the-hague",
    name: "International Court of Justice",
    category: "principal-organ",
    city: "The Hague",
    country: "Netherlands",
    lat: 52.0866,
    lng: 4.2955,
  },
];

const PERMANENT_MISSION_MARKER_SEEDS = [
  {
    code: "US-PM",
    name: "United States Mission to the United Nations",
    lat: 40.7508,
    lng: -73.9678,
  },
  {
    code: "CA-PM",
    name: "Permanent Mission of Canada to the United Nations",
    lat: 40.7531,
    lng: -73.9746,
  },
  {
    code: "FR-PM",
    name: "Permanent Mission of France to the United Nations",
    lat: 40.753,
    lng: -73.9702,
  },
  {
    code: "DE-PM",
    name: "Permanent Mission of Germany to the United Nations",
    lat: 40.7515,
    lng: -73.969,
  },
  {
    code: "GB-PM",
    name: "Permanent Mission of the United Kingdom to the United Nations",
    lat: 40.7526,
    lng: -73.9695,
  },
  {
    code: "JP-PM",
    name: "Permanent Mission of Japan to the United Nations",
    lat: 40.7519,
    lng: -73.9692,
  },
  {
    code: "CN-PM",
    name: "Permanent Mission of China to the United Nations",
    lat: 40.7457,
    lng: -73.972,
  },
  {
    code: "IN-PM",
    name: "Permanent Mission of India to the United Nations",
    lat: 40.7512,
    lng: -73.9726,
  },
  {
    code: "BR-PM",
    name: "Permanent Mission of Brazil to the United Nations",
    lat: 40.754,
    lng: -73.9714,
  },
  {
    code: "ZA-PM",
    name: "Permanent Mission of South Africa to the United Nations",
    lat: 40.7476,
    lng: -73.9728,
  },
  {
    code: "MX-PM",
    name: "Permanent Mission of Mexico to the United Nations",
    lat: 40.75,
    lng: -73.9698,
  },
  {
    code: "PS-PM",
    name: "Permanent Observer Mission of the State of Palestine",
    lat: 40.7651,
    lng: -73.9654,
  },
] satisfies Array<{ code: string; name: string; lat: number; lng: number }>;

const AFFILIATE_MARKER_SEEDS = [
  {
    code: "336",
    fallbackName: "Holy See",
    category: "observer",
    lat: 41.9029,
    lng: 12.4534,
  },
  {
    code: "275",
    fallbackName: "State of Palestine",
    category: "observer",
    lat: 31.9522,
    lng: 35.2332,
  },
  {
    code: "412",
    fallbackName: "Kosovo",
    category: "affiliate",
    lat: 42.6629,
    lng: 21.1655,
  },
] satisfies Array<{
  code: string;
  fallbackName: string;
  category: UnGeoAreaPreview["category"];
  lat: number;
  lng: number;
}>;

const FALLBACK_UN_MISSIONS: UnMissionLocationPreview[] = [
  {
    id: "un-mission-MINURSO",
    acronym: "MINURSO",
    name: "United Nations Mission for the Referendum in Western Sahara",
    active: true,
    location: "Laayoune",
    lat: 27.1536,
    lng: -13.2033,
    startDate: "1991-05-01T00:00:00.000Z",
    endDate: null,
    lastUpdate: "2026-07-06T00:00:00.000Z",
  },
  {
    id: "un-mission-MINUSCA",
    acronym: "MINUSCA",
    name: "United Nations Multidimensional Integrated Stabilization Mission in the Central African Republic",
    active: true,
    location: "Bangui",
    lat: 4.3667,
    lng: 18.5833,
    startDate: "2014-04-10T00:00:00.000Z",
    endDate: null,
    lastUpdate: "2026-07-06T00:00:00.000Z",
  },
  {
    id: "un-mission-MONUSCO",
    acronym: "MONUSCO",
    name: "United Nations Organization Stabilization Mission in the Democratic Republic of the Congo",
    active: true,
    location: "Kinshasa",
    lat: -4.325,
    lng: 15.3222,
    startDate: "2010-07-01T00:00:00.000Z",
    endDate: null,
    lastUpdate: "2026-07-06T00:00:00.000Z",
  },
  {
    id: "un-mission-UNFICYP",
    acronym: "UNFICYP",
    name: "United Nations Peacekeeping Force in Cyprus",
    active: true,
    location: "Nicosia",
    lat: 35.1667,
    lng: 33.3667,
    startDate: "1964-03-27T00:00:00.000Z",
    endDate: null,
    lastUpdate: "2026-07-06T00:00:00.000Z",
  },
];

function parseBoundedCoordinate(
  value: string | undefined,
  min: number,
  max: number,
) {
  if (!value) {
    return null;
  }

  const coordinate = Number.parseFloat(value);

  if (!Number.isFinite(coordinate) || coordinate < min || coordinate > max) {
    return null;
  }

  return coordinate;
}

function limitText(value: string | undefined, maxLength: number) {
  return value ? value.trim().slice(0, maxLength) : undefined;
}

function getClientIp(request: Request) {
  return limitText(
    request.headers.get("cf-connecting-ip") ??
      (request.cf?.clientIp as string | undefined),
    45,
  );
}

/** Alias for rate-limit keys on public preview routes */
function clientIpFromRequest(request: Request): string {
  return getClientIp(request) || "unknown";
}

function limitApiText(value: unknown, maxLength: number) {
  if (typeof value === "string") {
    return value.trim().replace(/\s+/g, " ").slice(0, maxLength);
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return String(value).slice(0, maxLength);
  }

  return "";
}

function getApiNumber(value: unknown) {
  const number = Number(value);
  return Number.isFinite(number) ? number : 0;
}

function getNullableApiNumber(value: unknown) {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function getComtradeResults(payload: unknown, key: "data" | "results") {
  if (!payload || typeof payload !== "object") {
    return [];
  }

  const records = (payload as Record<string, unknown>)[key];
  return Array.isArray(records) ? records : [];
}

function normalizeComtradeTradeRecords(payload: unknown): ComtradeTradeRecordPreview[] {
  return getComtradeResults(payload, "data")
    .map((item) => {
      if (!item || typeof item !== "object") {
        return null;
      }

      const record = item as ComtradeApiRecord;
      const flow = limitApiText(record.flowDesc, 40);
      const reporter = limitApiText(record.reporterDesc, 80);
      const partner = limitApiText(record.partnerDesc, 80);
      const commodityCode = limitApiText(record.cmdCode, 24);
      const commodity = limitApiText(record.cmdDesc, 160);

      if (!flow || !reporter || !partner || !commodityCode || !commodity) {
        return null;
      }

      return {
        flow,
        reporter,
        partner,
        period: limitApiText(record.period, 12) || COMTRADE_PERIOD,
        commodityCode,
        commodity,
        primaryValueUsd: getApiNumber(record.primaryValue),
        cifValueUsd: getNullableApiNumber(record.cifvalue),
        fobValueUsd: getNullableApiNumber(record.fobvalue),
        isAggregate: Boolean(record.isAggregate),
      } satisfies ComtradeTradeRecordPreview;
    })
    .filter((record): record is ComtradeTradeRecordPreview => record !== null)
    .slice(0, COMTRADE_PREVIEW_LIMIT);
}

function normalizeComtradeAvailability(payload: unknown): ComtradeAvailabilityPreview[] {
  return getComtradeResults(payload, "data")
    .map((item) => {
      if (!item || typeof item !== "object") {
        return null;
      }

      const record = item as ComtradeApiRecord;
      const datasetCode = limitApiText(record.datasetCode, 32);
      const reporter = limitApiText(record.reporterDesc, 80);

      if (!datasetCode || !reporter) {
        return null;
      }

      return {
        datasetCode,
        reporter,
        period: limitApiText(record.period, 12) || COMTRADE_PERIOD,
        classification: limitApiText(record.classificationCode, 24),
        totalRecords: getApiNumber(record.totalRecords),
        firstReleased: limitApiText(record.firstReleased, 40) || null,
        lastReleased: limitApiText(record.lastReleased, 40) || null,
      } satisfies ComtradeAvailabilityPreview;
    })
    .filter((record): record is ComtradeAvailabilityPreview => record !== null)
    .slice(0, COMTRADE_PREVIEW_LIMIT);
}

function normalizeComtradeReferences(payload: unknown): ComtradeReferencePreview[] {
  return getComtradeResults(payload, "results")
    .map((item) => {
      if (!item || typeof item !== "object") {
        return null;
      }

      const record = item as ComtradeApiRecord;
      const category = limitApiText(record.category, 32);
      const variable = limitApiText(record.variable, 80);

      if (!category || !variable) {
        return null;
      }

      return {
        category,
        variable,
        description: limitApiText(record.description, 160),
      } satisfies ComtradeReferencePreview;
    })
    .filter((record): record is ComtradeReferencePreview => record !== null);
}

function normalizeComtradeReporters(payload: unknown): ComtradeReporterPreview[] {
  const preferredCodes = new Set(["842", "156", "276", "124", "484"]);
  const records = getComtradeResults(payload, "results")
    .map((item) => {
      if (!item || typeof item !== "object") {
        return null;
      }

      const record = item as ComtradeApiRecord;
      const code = limitApiText(record.reporterCode ?? record.id, 12);
      const name = limitApiText(record.reporterDesc ?? record.text, 80);
      const iso3 = limitApiText(record.reporterCodeIsoAlpha3, 8);

      if (!code || !name) {
        return null;
      }

      return {
        code,
        iso3,
        name,
      } satisfies ComtradeReporterPreview;
    })
    .filter((record): record is ComtradeReporterPreview => record !== null);

  const preferred = records.filter((record) => preferredCodes.has(record.code));
  return (preferred.length > 0 ? preferred : records).slice(0, COMTRADE_PREVIEW_LIMIT);
}

function getComtradeCount(payload: unknown, key: "data" | "results") {
  if (!payload || typeof payload !== "object") {
    return 0;
  }

  const count = getApiNumber((payload as Record<string, unknown>).count);
  return count || getComtradeResults(payload, key).length;
}

function getTradeValue(records: ComtradeTradeRecordPreview[], flow: string) {
  return records.find((record) => record.flow.toLowerCase() === flow)?.primaryValueUsd ?? 0;
}

function getLatestRelease(records: ComtradeAvailabilityPreview[]) {
  return (
    records
      .map((record) => record.lastReleased)
      .filter((date): date is string => Boolean(date))
      .sort()
      .at(-1) ?? null
  );
}

function parseApiCoordinate(value: unknown, min: number, max: number) {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  const coordinate =
    typeof value === "string"
      ? Number.parseFloat(value.replace(",", "."))
      : Number(value);

  if (!Number.isFinite(coordinate) || coordinate < min || coordinate > max) {
    return null;
  }

  return coordinate;
}

function normalizeApiDate(value: unknown) {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  const date =
    typeof value === "number" || /^\-?\d+$/.test(String(value))
      ? new Date(Number(value))
      : new Date(String(value));

  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date.toISOString();
}

function normalizeAreaCode(value: unknown) {
  const code = limitApiText(value, 12);
  const number = Number(code);
  return Number.isFinite(number) ? String(number) : code;
}

function getApiArray(payload: unknown) {
  return Array.isArray(payload) ? payload : [];
}

function normalizeUnMissionLocations(payload: unknown): UnMissionLocationPreview[] {
  return getApiArray(payload)
    .map((item) => {
      if (!item || typeof item !== "object") {
        return null;
      }

      const record = item as Record<string, unknown>;
      const acronym = limitApiText(record.mission_acronym, 32);
      const name = limitApiText(record.mission_name, 180);
      const location = limitApiText(record.mission_location, 100);
      const lat = parseApiCoordinate(record.mission_latitude, -90, 90);
      const lng = parseApiCoordinate(record.mission_longitude, -180, 180);

      if (!acronym || !name || !location || lat === null || lng === null) {
        return null;
      }

      return {
        id: `un-mission-${acronym.replace(/\s+/g, "-")}`,
        acronym,
        name,
        active: /^yes$/i.test(limitApiText(record.mission_isactive, 12)),
        location,
        lat,
        lng,
        startDate: normalizeApiDate(record.start_date),
        endDate: normalizeApiDate(record.end_date),
        lastUpdate: normalizeApiDate(record.last_update),
      } satisfies UnMissionLocationPreview;
    })
    .filter((record): record is UnMissionLocationPreview => record !== null);
}

function getUnMissionRecordCount(payload: unknown) {
  return getApiArray(payload).length;
}

function getUnActiveMissionRecordCount(payload: unknown) {
  return getApiArray(payload).filter((item) => {
    if (!item || typeof item !== "object") {
      return false;
    }

    return /^yes$/i.test(limitApiText((item as Record<string, unknown>).mission_isactive, 12));
  }).length;
}

function getLatestMissionUpdate(missions: UnMissionLocationPreview[]) {
  return (
    missions
      .map((mission) => mission.lastUpdate)
      .filter((date): date is string => Boolean(date))
      .sort()
      .at(-1) ?? null
  );
}

function rankMissionLocations(missions: UnMissionLocationPreview[]) {
  const active = missions
    .filter((mission) => mission.active)
    .sort((a, b) => a.acronym.localeCompare(b.acronym));
  const historic = missions
    .filter((mission) => !mission.active)
    .sort((a, b) => b.startDate?.localeCompare(a.startDate ?? "") ?? 0);

  return [...active, ...historic].slice(0, UN_GLOBAL_PREVIEW_LIMIT);
}

function normalizeGeoAreas(payload: unknown) {
  return getApiArray(payload)
    .map((item) => {
      if (!item || typeof item !== "object") {
        return null;
      }

      const record = item as Record<string, unknown>;
      const code = normalizeAreaCode(record.geoAreaCode);
      const name = limitApiText(record.geoAreaName, 120);

      return code && name ? { code, name } : null;
    })
    .filter((record): record is { code: string; name: string } => record !== null);
}

function buildGeoAreaLookup(geoAreas: Array<{ code: string; name: string }>) {
  return new Map(geoAreas.map((area) => [area.code, area.name]));
}

function parseCsvLine(line: string) {
  const columns: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    const next = line[index + 1];

    if (char === '"' && next === '"') {
      current += '"';
      index += 1;
    } else if (char === '"') {
      inQuotes = !inQuotes;
    } else if (char === "," && !inQuotes) {
      columns.push(current.trim());
      current = "";
    } else {
      current += char;
    }
  }

  columns.push(current.trim());
  return columns.map((column) => column.replace(/^"|"$/g, "").trim());
}

function normalizeCountryCentroids(csv: string | null): CountryCentroidRecord[] {
  if (!csv) {
    return [];
  }

  const seenCodes = new Set<string>();

  return csv
    .split(/\r?\n/)
    .slice(1)
    .map((line) => {
      if (!line.trim()) {
        return null;
      }

      const [name, , alpha3, numericCode, latitude, longitude] = parseCsvLine(line);
      const code = normalizeAreaCode(numericCode);
      const lat = parseApiCoordinate(latitude, -90, 90);
      const lng = parseApiCoordinate(longitude, -180, 180);

      if (!name || !alpha3 || !code || lat === null || lng === null || seenCodes.has(code)) {
        return null;
      }

      seenCodes.add(code);

      return {
        alpha3,
        code,
        name,
        lat,
        lng,
      } satisfies CountryCentroidRecord;
    })
    .filter((record): record is CountryCentroidRecord => record !== null);
}

function normalizeUnMemberAlpha3Codes(csv: string | null) {
  if (!csv) {
    return new Set<string>();
  }

  const latestByCode = new Map<string, { year: number; status: string }>();

  for (const line of csv.split(/\r?\n/).slice(1)) {
    if (!line.trim()) {
      continue;
    }

    const [, alpha3, yearText, status] = parseCsvLine(line);
    const year = Number(yearText);

    if (!alpha3 || !Number.isFinite(year)) {
      continue;
    }

    const current = latestByCode.get(alpha3);
    if (!current || year > current.year) {
      latestByCode.set(alpha3, { year, status });
    }
  }

  return new Set(
    Array.from(latestByCode.entries())
      .filter(([, record]) => record.status === "Member")
      .map(([alpha3]) => alpha3),
  );
}

function buildMemberStateMarkers(
  areaLookup: Map<string, string>,
  centroids: CountryCentroidRecord[],
  memberAlpha3Codes: Set<string>,
): UnGeoAreaPreview[] {
  const joinedMarkers = centroids
    .filter((centroid) => memberAlpha3Codes.has(centroid.alpha3))
    .map((centroid) => ({
      code: centroid.code,
      name: areaLookup.get(centroid.code) ?? centroid.name,
      category: "member-state",
      lat: centroid.lat,
      lng: centroid.lng,
    }) satisfies UnGeoAreaPreview)
    .sort((a, b) => a.name.localeCompare(b.name));

  if (joinedMarkers.length >= 150) {
    return joinedMarkers;
  }

  return MEMBER_STATE_MARKER_SEEDS.map((seed) => ({
    code: seed.code,
    name: areaLookup.get(seed.code) ?? seed.fallbackName,
    category: "member-state",
    lat: seed.lat,
    lng: seed.lng,
  }));
}

function buildAffiliateMarkers(areaLookup: Map<string, string>): UnGeoAreaPreview[] {
  return AFFILIATE_MARKER_SEEDS.map((seed) => ({
    code: seed.code,
    name: areaLookup.get(seed.code) ?? seed.fallbackName,
    category: seed.category,
    lat: seed.lat,
    lng: seed.lng,
  }));
}

function buildPermanentMissionMarkers(): UnGeoAreaPreview[] {
  return PERMANENT_MISSION_MARKER_SEEDS.map((seed) => ({
    code: seed.code,
    name: seed.name,
    category: "embassy",
    lat: seed.lat,
    lng: seed.lng,
  }));
}

function buildComtradePreview({
  tradeRecords,
  availability,
  references,
  reporters,
  referenceTablesTotal,
  reportersTotal,
  stale = false,
  dataMode = "public-preview",
  apiUrl = COMTRADE_PUBLIC_EXPORT_URL,
}: {
  tradeRecords: ComtradeTradeRecordPreview[];
  availability: ComtradeAvailabilityPreview[];
  references: ComtradeReferencePreview[];
  reporters: ComtradeReporterPreview[];
  referenceTablesTotal: number;
  reportersTotal: number;
  stale?: boolean;
  dataMode?: ComtradePreview["dataMode"];
  apiUrl?: string;
}): ComtradePreview {
  const exportsUsd = getTradeValue(tradeRecords, "export");
  const importsUsd = getTradeValue(tradeRecords, "import");
  const subscriptionBacked = dataMode === "free-subscription";

  return {
    source: COMTRADE_SOURCE,
    sourceUrl: COMTRADE_SOURCE_URL,
    // Public catalog URL only — never a key-bearing URL
    apiUrl,
    updatedAt: new Date().toISOString(),
    queryLabel: COMTRADE_PREVIEW_QUERY,
    reporter: COMTRADE_REPORTER_LABEL,
    period: COMTRADE_PERIOD,
    exportsUsd,
    importsUsd,
    tradeBalanceUsd: exportsUsd - importsUsd,
    availabilityTotalRecords: availability.reduce(
      (total, record) => total + record.totalRecords,
      0,
    ),
    latestRelease: getLatestRelease(availability),
    referenceTablesTotal,
    reportersTotal,
    tradeRecords: tradeRecords.slice(0, COMTRADE_PREVIEW_LIMIT),
    availability: availability.slice(0, COMTRADE_PREVIEW_LIMIT),
    references: references.slice(0, COMTRADE_PREVIEW_LIMIT),
    reporters: reporters.slice(0, COMTRADE_PREVIEW_LIMIT),
    dataMode,
    accessTier: COMTRADE_ACCESS_TIER,
    sampleLimit: COMTRADE_PREVIEW_LIMIT,
    complianceNotes: subscriptionBacked
      ? [...COMTRADE_FREE_COMPLIANCE_NOTES]
      : [...COMTRADE_COMPLIANCE_NOTES],
    subscriptionBacked,
    stale,
  };
}

/** Worker secret only; never log or return this value. */
function resolveComtradeSubscriptionKey(env: Env): string | null {
  const raw = env.COMTRADE_SUBSCRIPTION_KEY?.trim();
  if (!raw || raw.length < 16) {
    return null;
  }
  return raw;
}

/** Collect all Worker secrets that must never appear in logs or client JSON. */
function collectWorkerSecrets(env: Env): string[] {
  const candidates = [
    env.COMTRADE_SUBSCRIPTION_KEY,
    env.STRIPE_SECRET_KEY,
    env.STRIPE_WEBHOOK_SECRET,
    env.ADMIN_ACTION_SECRET,
    env.TRANSIT_PUBLICAPI_V4,
  ];
  const out: string[] = [];
  for (const raw of candidates) {
    const value = raw?.trim();
    if (value && value.length >= 8 && !out.includes(value)) {
      out.push(value);
    }
  }
  return out;
}

/** Property names that must never appear on Comtrade client payloads. */
const COMTRADE_SECRET_PROPERTY_RE =
  /^(ocp-?apim-?subscription-?key|subscription[-_]?key|api[-_]?key|apikey|comtrade[-_]?subscription[-_]?key|primary[-_]?key|secondary[-_]?key|access[-_]?token|bearer|authorization|stripe[-_]?secret|webhook[-_]?secret|admin[-_]?action[-_]?secret)$/i;

const COMTRADE_REDACTED = "[redacted]";

/** Redact secrets and credential-shaped substrings from log/response text. */
function redactSensitiveText(text: string, secrets: string[] = []): string {
  let out = text;
  for (const secret of secrets) {
    if (secret.length >= 8 && out.includes(secret)) {
      out = out.split(secret).join(COMTRADE_REDACTED);
    }
  }
  return out
    .replace(/([?&](?:subscription-?key|api-?key|access_token)=)[^&\s]+/gi, `$1${COMTRADE_REDACTED}`)
    .replace(/(Ocp-Apim-Subscription-Key\s*[:=]\s*)\S+/gi, `$1${COMTRADE_REDACTED}`)
    .replace(/\b(sk_(?:live|test)_[A-Za-z0-9]+)\b/g, COMTRADE_REDACTED)
    .replace(/\b(pk_(?:live|test)_[A-Za-z0-9]+)\b/g, COMTRADE_REDACTED)
    .replace(/\b(whsec_[A-Za-z0-9]+)\b/g, COMTRADE_REDACTED)
    .replace(/\b(rk_live_[A-Za-z0-9]+)\b/g, COMTRADE_REDACTED)
    .slice(0, 400);
}

/**
 * Strip secret-shaped keys and redact known secret substrings from any value
 * before it is serialized to the browser. Defense-in-depth for Free API path.
 */
function scrubComtradeClientPayload<T>(payload: T, secrets: string[] = []): T {
  const scrub = (value: unknown, depth: number): unknown => {
    if (depth > 12 || value === null || value === undefined) {
      return value;
    }

    if (typeof value === "string") {
      return redactSensitiveText(value, secrets);
    }

    if (typeof value === "number" || typeof value === "boolean") {
      return value;
    }

    if (Array.isArray(value)) {
      return value.map((item) => scrub(item, depth + 1));
    }

    if (typeof value === "object") {
      const out: Record<string, unknown> = {};
      for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
        if (COMTRADE_SECRET_PROPERTY_RE.test(key)) {
          // Drop entirely — do not even send redacted secret field names to clients.
          continue;
        }
        out[key] = scrub(child, depth + 1);
      }
      return out;
    }

    return value;
  };

  return scrub(payload, 0) as T;
}

/** Safe log text: never includes secrets even if Error.message was poisoned. */
function safeComtradeLogMessage(
  error: unknown,
  knownSecret?: string | null,
  extraSecrets: string[] = [],
): string {
  const secrets = [
    ...extraSecrets,
    ...(knownSecret?.trim() ? [knownSecret.trim()] : []),
  ];
  const text =
    error instanceof Error
      ? error.message
      : typeof error === "string"
        ? error
        : "unknown_error";
  return redactSensitiveText(text, secrets).slice(0, 240);
}

/** Never log raw Error objects (stack/message may contain request headers/URLs). */
function safeWarn(message: string, error?: unknown, secrets: string[] = []) {
  if (error === undefined) {
    console.warn(redactSensitiveText(message, secrets));
    return;
  }
  console.warn(
    `${redactSensitiveText(message, secrets)}: ${safeComtradeLogMessage(error, null, secrets)}`,
  );
}

function responseBodyContainsSecret(serialized: string, secrets: string[]): boolean {
  for (const secret of secrets) {
    if (secret.length >= 8 && serialized.includes(secret)) {
      return true;
    }
  }
  // Credential-shaped tokens that must never ship to browsers.
  if (
    /\bsk_(?:live|test)_[A-Za-z0-9]{10,}\b/.test(serialized) ||
    /\bwhsec_[A-Za-z0-9]{10,}\b/.test(serialized) ||
    /Ocp-Apim-Subscription-Key/i.test(serialized)
  ) {
    return true;
  }
  return false;
}

/**
 * Build a Comtrade JSON response that cannot carry Worker secrets.
 * Scrubs body + forbids secret-bearing response headers + hard block if still present.
 */
function comtradeJsonResponse(
  data: unknown,
  knownSecret: string | null | undefined,
  init?: ResponseInit,
  allSecrets: string[] = [],
) {
  const secrets = [
    ...allSecrets,
    ...(knownSecret?.trim() ? [knownSecret.trim()] : []),
  ];
  const scrubbed = scrubComtradeClientPayload(data, secrets);
  const serialized = JSON.stringify(scrubbed);

  if (responseBodyContainsSecret(serialized, secrets)) {
    safeWarn("Comtrade response blocked: secret would have leaked in JSON body", undefined, secrets);
    return jsonResponse(
      {
        error: "comtrade_response_blocked",
        message: "Preview unavailable (safety filter).",
      },
      {
        status: 500,
        headers: {
          "cache-control": "no-store",
          "x-comtrade-mode": "blocked",
        },
      },
    );
  }

  const headers = new Headers(init?.headers);
  // Never forward APIM / key headers to browsers.
  for (const name of [
    "ocp-apim-subscription-key",
    "Ocp-Apim-Subscription-Key",
    "subscription-key",
    "x-api-key",
    "authorization",
    "cookie",
    "set-cookie",
  ]) {
    headers.delete(name);
  }

  return jsonResponse(scrubbed, { ...init, headers });
}

function buildUnGlobalPreview({
  missions,
  missionsTotal,
  activeMissionsTotal,
  geoAreasTotal,
  offices,
  memberStates,
  affiliates,
  embassies,
  stale = false,
}: {
  missions: UnMissionLocationPreview[];
  missionsTotal: number;
  activeMissionsTotal: number;
  geoAreasTotal: number;
  offices: UnOfficeLocationPreview[];
  memberStates: UnGeoAreaPreview[];
  affiliates: UnGeoAreaPreview[];
  embassies: UnGeoAreaPreview[];
  stale?: boolean;
}): UnGlobalPreview {
  return {
    source: UN_GLOBAL_SOURCE,
    sourceUrl: UN_GLOBAL_SOURCE_URL,
    apiUrl: UN_PKO_DATA_URL,
    updatedAt: new Date().toISOString(),
    queryLabel: "UN HQ offices, mission HQ coordinates, member states, affiliates, and permanent missions",
    missionsTotal,
    activeMissionsTotal,
    missionCoordinateTotal: missions.length,
    memberStatesTotal: memberStates.length || UN_MEMBER_STATES_TOTAL,
    geoAreasTotal,
    affiliatesTotal: affiliates.length,
    officesTotal: offices.length,
    embassiesTotal: embassies.length,
    latestMissionUpdate: getLatestMissionUpdate(missions),
    missionLocations: rankMissionLocations(missions),
    offices,
    memberStates,
    affiliates,
    embassies,
    stale,
  };
}

function formatCompactUsd(value: number) {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    notation: "compact",
    maximumFractionDigits: 1,
  }).format(value);
}

function formatMetricPercent(value: number) {
  return `${Math.round(value)}%`;
}

function buildTradePulseMetrics(routes: TradePulseRoutePreview[]): TradePulseMetricPreview[] {
  const totalValue = routes.reduce((total, route) => total + route.valueUsd, 0);
  const dependencies = routes.filter((route) => route.layers.includes("dependency"));
  const asymmetries = routes.filter((route) => route.layers.includes("asymmetry"));
  const hubs = routes.filter((route) => route.layers.includes("hubs"));
  const lowConfidence = routes.filter((route) => route.layers.includes("confidence"));
  const highestDependency = Math.max(...routes.map((route) => route.supplierSharePct));
  const highestAsymmetry = Math.max(...routes.map((route) => route.asymmetryPct));

  return [
    { label: "Routes", value: String(routes.length) },
    { label: "Value", value: formatCompactUsd(totalValue) },
    { label: "Single supplier", value: String(dependencies.length) },
    { label: "Mirror alerts", value: String(asymmetries.length) },
    { label: "Hub signals", value: String(hubs.length) },
    { label: "Low confidence", value: String(lowConfidence.length) },
    { label: "Peak dependency", value: formatMetricPercent(highestDependency) },
    { label: "Peak asymmetry", value: formatMetricPercent(highestAsymmetry) },
  ];
}

function buildTradePulseDerivedPreview(period: TradePulsePeriod): TradePulsePreview {
  const routes = TRADE_PULSE_ROUTES.map((route) => ({ ...route, period }));
  return {
    source: "Trade Pulse",
    sourceUrl: COMTRADE_SOURCE_URL,
    apiUrl: `${COMTRADE_API_BASE}/public/v1/preview/C/A/HS`,
    updatedAt: new Date().toISOString(),
    queryLabel: `Annual HS radar · ${period}`,
    period,
    dataMode: "derived-preview",
    accessTier: COMTRADE_ACCESS_TIER,
    isOfficialLiveStats: false,
    subscriptionBacked: false,
    liveRouteCount: 0,
    availablePeriods: [...TRADE_PULSE_PERIODS],
    routes,
    metrics: buildTradePulseMetrics(routes),
    notes: [],
    complianceNotes: [],
  };
}

function pickPrimaryComtradeValue(payload: unknown): {
  primary: number;
  cif: number | null;
  fob: number | null;
  qty: string;
  commodity: string;
  period: string;
} | null {
  const records = getComtradeResults(payload, "data");
  for (const item of records) {
    if (!item || typeof item !== "object") continue;
    const record = item as ComtradeApiRecord;
    const primary = getApiNumber(record.primaryValue);
    if (!(primary > 0)) continue;
    const qty = getApiNumber(record.qty);
    const unit = limitApiText(record.qtyUnitAbbr, 12);
    return {
      primary,
      cif: getNullableApiNumber(record.cifvalue),
      fob: getNullableApiNumber(record.fobvalue),
      qty: qty > 0 ? `${formatCompactNumber(qty)}${unit ? ` ${unit}` : ""}` : "",
      commodity: limitApiText(record.cmdDesc, 160) || "",
      period: limitApiText(record.period, 12) || "",
    };
  }
  return null;
}

function formatCompactNumber(value: number) {
  return new Intl.NumberFormat("en-US", {
    notation: "compact",
    maximumFractionDigits: 1,
  }).format(value);
}

function pctDelta(a: number, b: number): number {
  const base = Math.max(a, b, 1);
  return Math.round((Math.abs(a - b) / base) * 1000) / 10;
}

function frictionPct(cif: number | null, fob: number | null, fallback: number): number {
  if (cif != null && fob != null && fob > 0 && cif >= fob) {
    return Math.round(((cif - fob) / fob) * 1000) / 10;
  }
  return fallback;
}

function freeTradeUrl(params: {
  reporterCode: string;
  partnerCode: string;
  flowCode: "X" | "M";
  cmdCode: string;
  period: string;
}): string {
  return (
    `${COMTRADE_API_BASE}/data/v1/get/C/A/HS` +
    `?reporterCode=${encodeURIComponent(params.reporterCode)}` +
    `&period=${encodeURIComponent(params.period)}` +
    `&partnerCode=${encodeURIComponent(params.partnerCode)}` +
    `&cmdCode=${encodeURIComponent(params.cmdCode)}` +
    `&flowCode=${params.flowCode}` +
    // Single row is enough for radar metrics — faster Free API responses.
    "&maxRecords=1&format=JSON&includeDesc=true"
  );
}

/** Fast Free API fetch: no retry sleep (fail soft for pulse hydrate). */
async function fetchComtradeJsonFast(
  url: string,
  subscriptionKey: string,
): Promise<unknown | null> {
  try {
    const response = await fetch(url, {
      headers: {
        accept: "application/json",
        "Ocp-Apim-Subscription-Key": subscriptionKey,
      },
    });
    if (!response.ok) {
      return null;
    }
    return response.json();
  } catch {
    return null;
  }
}

/**
 * Hydrate template routes with Free /data/v1 bilateral values.
 * Returns null if key missing or too few routes hydrate (caller falls back to derived).
 */
async function hydrateOneTradePulseRoute(
  template: TradePulseRoutePreview,
  subscriptionKey: string,
  period: TradePulsePeriod,
): Promise<{ route: TradePulseRoutePreview; live: boolean }> {
  const originCode = TRADE_PULSE_REPORTER_CODES[template.origin.iso3];
  const destCode = TRADE_PULSE_REPORTER_CODES[template.destination.iso3];
  if (!originCode || !destCode) {
    return { route: { ...template, period }, live: false };
  }

  // Single import call per route (parallelized across routes) — main speed win.
  const importPayload = await fetchComtradeJsonFast(
    freeTradeUrl({
      reporterCode: destCode,
      partnerCode: originCode,
      flowCode: "M",
      cmdCode: template.commodityCode,
      period,
    }),
    subscriptionKey,
  );
  const importRow = pickPrimaryComtradeValue(importPayload);

  if (!importRow) {
    return { route: { ...template, period }, live: false };
  }

  const importValueUsd = importRow.primary;
  const exportValueUsd = importRow.primary;
  const valueUsd = importValueUsd;
  const cifValueUsd = importRow.cif ?? importValueUsd;
  const fobValueUsd = importRow.fob ?? exportValueUsd;
  const asymmetry = pctDelta(exportValueUsd, importValueUsd);
  const friction = frictionPct(
    typeof cifValueUsd === "number" ? cifValueUsd : null,
    typeof fobValueUsd === "number" ? fobValueUsd : null,
    template.frictionPct,
  );

  let severity = template.severity;
  if (asymmetry >= 30 || friction >= 40) severity = "critical";
  else if (asymmetry >= 18 || friction >= 25) severity = "high";
  else if (asymmetry >= 10 || friction >= 12) severity = "elevated";

  const resolvedPeriod = importRow.period || period;

  return {
    live: true,
    route: {
      ...template,
      commodity: importRow.commodity || template.commodity,
      period: resolvedPeriod,
      valueUsd,
      quantity: importRow.qty || template.quantity,
      exportValueUsd,
      importValueUsd,
      asymmetryPct: asymmetry,
      fobValueUsd: typeof fobValueUsd === "number" ? fobValueUsd : template.fobValueUsd,
      cifValueUsd: typeof cifValueUsd === "number" ? cifValueUsd : template.cifValueUsd,
      frictionPct: friction,
      severity,
      insight: `${resolvedPeriod} · ${template.origin.iso3}->${template.destination.iso3} · HS ${template.commodityCode} · friction ${friction}%`,
    },
  };
}

async function hydrateTradePulseRoutesFromFreeApi(
  subscriptionKey: string,
  period: TradePulsePeriod,
): Promise<{ routes: TradePulseRoutePreview[]; liveCount: number } | null> {
  // Parallel with a small concurrency cap — full fan-out trips Free API rate limits.
  const batchSize = 4;
  const results: { route: TradePulseRoutePreview; live: boolean }[] = [];
  for (let i = 0; i < TRADE_PULSE_ROUTES.length; i += batchSize) {
    const batch = TRADE_PULSE_ROUTES.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map((template) =>
        hydrateOneTradePulseRoute(template, subscriptionKey, period),
      ),
    );
    results.push(...batchResults);
  }

  const liveCount = results.filter((r) => r.live).length;
  if (liveCount < 1) {
    return null;
  }

  return {
    routes: results.map((r) => r.route),
    liveCount,
  };
}

/** Background-warm neighboring years so year buttons feel instant. */
async function warmTradePulsePeriods(
  env: Env,
  subscriptionKey: string,
  skipPeriod: TradePulsePeriod,
) {
  const secrets = collectWorkerSecrets(env);
  for (const period of TRADE_PULSE_PERIODS) {
    if (period === skipPeriod) continue;
    const memory = tradePulseLiveCacheByPeriod.get(period);
    if (memory && Date.now() - memory.at < TRADE_PULSE_LIVE_CACHE_TTL_MS) {
      continue;
    }
    const kv = await readTradePulseKvCache(env, period);
    if (kv && Date.now() - kv.at < TRADE_PULSE_LIVE_CACHE_TTL_MS) {
      tradePulseLiveCacheByPeriod.set(period, kv);
      continue;
    }
    try {
      const live = await hydrateTradePulseRoutesFromFreeApi(subscriptionKey, period);
      if (!live) continue;
      const preview = buildTradePulseLivePreview(live.routes, live.liveCount, period);
      const entry = { at: Date.now(), preview };
      tradePulseLiveCacheByPeriod.set(period, entry);
      await writeTradePulseKvCache(env, period, entry, secrets);
    } catch {
      // Best-effort warm only — never log raw errors (may hold headers).
    }
  }
}

function buildTradePulseLivePreview(
  routes: TradePulseRoutePreview[],
  liveCount: number,
  period: TradePulsePeriod,
): TradePulsePreview {
  return {
    source: "UN Comtrade",
    sourceUrl: COMTRADE_SOURCE_URL,
    apiUrl: TRADE_PULSE_API_URL,
    updatedAt: new Date().toISOString(),
    queryLabel: `Annual HS radar · ${period}`,
    period,
    dataMode: "free-subscription",
    accessTier: COMTRADE_ACCESS_TIER,
    isOfficialLiveStats: true,
    subscriptionBacked: true,
    liveRouteCount: liveCount,
    availablePeriods: [...TRADE_PULSE_PERIODS],
    routes,
    metrics: buildTradePulseMetrics(routes),
    notes: [],
    complianceNotes: [],
  };
}

async function getTradePulsePreview(
  env: Env,
  period: TradePulsePeriod,
  ctx?: ExecutionContext,
) {
  const subscriptionKey = resolveComtradeSubscriptionKey(env);
  const secrets = collectWorkerSecrets(env);
  const pulseJson = (
    preview: TradePulsePreview,
    headers: Record<string, string>,
  ) => comtradeJsonResponse(preview, subscriptionKey, { headers }, secrets);

  if (subscriptionKey) {
    const now = Date.now();
    const memory = tradePulseLiveCacheByPeriod.get(period);
    if (
      memory &&
      now - memory.at < TRADE_PULSE_LIVE_CACHE_TTL_MS &&
      memory.preview.dataMode === "free-subscription" &&
      memory.preview.period === period
    ) {
      ctx?.waitUntil(warmTradePulsePeriods(env, subscriptionKey, period));
      return pulseJson(memory.preview, {
        // Public: body is scrubbed; key never leaves the Worker. Edge/browser must cache.
        "cache-control":
          "public, max-age=600, s-maxage=3600, stale-while-revalidate=86400",
        "x-comtrade-mode": "free-subscription",
        "x-trade-pulse-cache": "memory",
        "x-trade-pulse-period": period,
      });
    }

    const kvFresh = await readTradePulseKvCache(env, period);
    if (kvFresh && now - kvFresh.at < TRADE_PULSE_LIVE_CACHE_TTL_MS) {
      tradePulseLiveCacheByPeriod.set(period, kvFresh);
      ctx?.waitUntil(warmTradePulsePeriods(env, subscriptionKey, period));
      return pulseJson(kvFresh.preview, {
        "cache-control":
          "public, max-age=600, s-maxage=3600, stale-while-revalidate=86400",
        "x-comtrade-mode": "free-subscription",
        "x-trade-pulse-cache": "kv",
        "x-trade-pulse-period": period,
      });
    }

    try {
      const live = await hydrateTradePulseRoutesFromFreeApi(subscriptionKey, period);
      if (live) {
        const preview = buildTradePulseLivePreview(live.routes, live.liveCount, period);
        const entry = { at: now, preview };
        tradePulseLiveCacheByPeriod.set(period, entry);
        void writeTradePulseKvCache(env, period, entry, secrets);
        // Prefetch other years after response so year buttons are cache hits.
        ctx?.waitUntil(warmTradePulsePeriods(env, subscriptionKey, period));
        return pulseJson(preview, {
          "cache-control":
            "public, max-age=900, s-maxage=3600, stale-while-revalidate=86400",
          "x-comtrade-mode": "free-subscription",
          "x-trade-pulse-cache": "miss",
          "x-trade-pulse-period": period,
        });
      }
      safeWarn(
        `Trade Pulse Free API hydrate incomplete for ${period}; trying stale cache or derived`,
        undefined,
        secrets,
      );
    } catch (error) {
      safeWarn("Trade Pulse Free API hydrate failed", error, secrets);
    }

    if (
      memory &&
      now - memory.at < TRADE_PULSE_LIVE_STALE_TTL_MS &&
      memory.preview.dataMode === "free-subscription"
    ) {
      return pulseJson(memory.preview, {
        "cache-control":
          "public, max-age=300, s-maxage=900, stale-while-revalidate=86400",
        "x-comtrade-mode": "free-subscription",
        "x-trade-pulse-cache": "stale-memory",
        "x-trade-pulse-period": period,
      });
    }

    const kvStale = kvFresh ?? (await readTradePulseKvCache(env, period));
    if (
      kvStale &&
      now - kvStale.at < TRADE_PULSE_LIVE_STALE_TTL_MS &&
      kvStale.preview.dataMode === "free-subscription"
    ) {
      tradePulseLiveCacheByPeriod.set(period, kvStale);
      return pulseJson(kvStale.preview, {
        "cache-control":
          "public, max-age=300, s-maxage=900, stale-while-revalidate=86400",
        "x-comtrade-mode": "free-subscription",
        "x-trade-pulse-cache": "stale-kv",
        "x-trade-pulse-period": period,
      });
    }
  }

  const derived = buildTradePulseDerivedPreview(period);
  return pulseJson(derived, {
    "cache-control":
      "public, max-age=120, s-maxage=600, stale-while-revalidate=3600",
    "x-comtrade-mode": "derived-preview",
    "x-trade-pulse-period": period,
  });
}

function classifyHighway(highway: string): NearbyPathKind {
  if (
    highway === "footway" ||
    highway === "path" ||
    highway === "steps" ||
    highway === "pedestrian" ||
    highway === "bridleway"
  ) {
    return "path";
  }
  if (highway === "cycleway") {
    return "cycle";
  }
  if (highway === "service" || highway === "track" || highway === "living_street") {
    return "service";
  }
  if (highway === "park" || highway.startsWith("leisure:") || highway.startsWith("landuse:")) {
    return "park";
  }
  return "road";
}

function classifyOsmTags(tags: Record<string, string>): {
  kind: NearbyPathKind;
  tag: string;
  name: string;
} | null {
  const highway = tags.highway;
  if (highway && HIGHWAY_ALLOW.test(highway)) {
    return {
      kind: classifyHighway(highway),
      tag: highway,
      name: (tags.name || tags.ref || highway).slice(0, 80),
    };
  }
  const leisure = tags.leisure || "";
  const landuse = tags.landuse || "";
  if (PARK_LEISURE.test(leisure) || PARK_LANDUSE.test(landuse)) {
    const tag = leisure || landuse;
    return {
      kind: "park",
      tag: leisure ? `leisure:${leisure}` : `landuse:${landuse}`,
      name: (tags.name || tag || "Park").slice(0, 80),
    };
  }
  return null;
}

/** Keep roads, foot/cycle paths, and parks all represented (not roads-only). */
function selectBalancedPaths(
  paths: NearbyPathSegment[],
  maxTotal: number,
): NearbyPathSegment[] {
  const rank = (p: NearbyPathSegment) => {
    let score = 0;
    if (p.name && p.name !== p.highway) score += 3;
    if (p.kind === "road") score += 2;
    if (p.kind === "path" || p.kind === "cycle") score += 4; // prefer keeping trails
    if (p.kind === "park") score += 3;
    if (p.kind === "service") score += 1;
    if (
      p.highway === "primary" ||
      p.highway === "secondary" ||
      p.highway === "tertiary"
    ) {
      score += 2;
    }
    return score;
  };
  const sortRank = (a: NearbyPathSegment, b: NearbyPathSegment) =>
    rank(b) - rank(a);

  const parks = paths.filter((p) => p.kind === "park").sort(sortRank);
  const foots = paths
    .filter((p) => p.kind === "path" || p.kind === "cycle")
    .sort(sortRank);
  const roads = paths
    .filter((p) => p.kind === "road" || p.kind === "service")
    .sort(sortRank);

  // Reserve slots so parks + foot/cycle paths never get crowded out by roads
  const parkN = Math.min(
    parks.length,
    Math.max(28, Math.floor(maxTotal * 0.24)),
  );
  const footN = Math.min(
    foots.length,
    Math.max(40, Math.floor(maxTotal * 0.3)),
  );
  const roadN = Math.max(36, maxTotal - parkN - footN);

  return [
    ...roads.slice(0, roadN),
    ...foots.slice(0, footN),
    ...parks.slice(0, parkN),
  ].slice(0, maxTotal);
}

function roundCoord(value: number, decimals = NEARBY_COORD_DECIMALS): number {
  const f = 10 ** decimals;
  return Math.round(value * f) / f;
}

function perpendicularDistance(
  point: { lat: number; lng: number },
  start: { lat: number; lng: number },
  end: { lat: number; lng: number },
): number {
  const x = point.lng;
  const y = point.lat;
  const x1 = start.lng;
  const y1 = start.lat;
  const x2 = end.lng;
  const y2 = end.lat;
  const dx = x2 - x1;
  const dy = y2 - y1;
  if (dx === 0 && dy === 0) {
    return Math.hypot(x - x1, y - y1);
  }
  const t = ((x - x1) * dx + (y - y1) * dy) / (dx * dx + dy * dy);
  const clamped = Math.max(0, Math.min(1, t));
  return Math.hypot(x - (x1 + clamped * dx), y - (y1 + clamped * dy));
}

function douglasPeucker(
  points: Array<{ lat: number; lng: number }>,
  epsilon: number,
): Array<{ lat: number; lng: number }> {
  if (points.length <= 2) {
    return points;
  }

  let maxDist = 0;
  let index = 0;
  const end = points.length - 1;
  for (let i = 1; i < end; i++) {
    const dist = perpendicularDistance(points[i], points[0], points[end]);
    if (dist > maxDist) {
      index = i;
      maxDist = dist;
    }
  }

  if (maxDist > epsilon) {
    const left = douglasPeucker(points.slice(0, index + 1), epsilon);
    const right = douglasPeucker(points.slice(index), epsilon);
    return left.slice(0, -1).concat(right);
  }

  return [points[0], points[end]];
}

function simplifyGeometry(
  geometry: Array<{ lat?: number; lon?: number }>,
  maxPoints: number,
): Array<{ lat: number; lng: number }> {
  const cleaned = geometry
    .map((point) => {
      const lat = Number(point.lat);
      const lng = Number(point.lon);
      if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
        return null;
      }
      if (lat < -90 || lat > 90 || lng < -180 || lng > 180) {
        return null;
      }
      return {
        lat: roundCoord(lat),
        lng: roundCoord(lng),
      };
    })
    .filter((point): point is { lat: number; lng: number } => point !== null);

  if (cleaned.length <= 2) {
    return cleaned;
  }

  // ~1–1.5 m tolerance — tighter than before so bends stay accurate
  let simplified = douglasPeucker(cleaned, 0.000012);
  if (simplified.length > maxPoints) {
    const step = Math.ceil(simplified.length / maxPoints);
    const reduced: Array<{ lat: number; lng: number }> = [];
    for (let i = 0; i < simplified.length; i += step) {
      reduced.push(simplified[i]);
    }
    const last = simplified[simplified.length - 1];
    const prev = reduced[reduced.length - 1];
    if (!prev || prev.lat !== last.lat || prev.lng !== last.lng) {
      reduced.push(last);
    }
    simplified = reduced;
  }

  return simplified;
}

/** Shrink JSON for the wire without changing client semantics. */
function compactNearbyPayload(payload: NearbyPathsPreview): NearbyPathsPreview {
  const paths = payload.paths.map((path) => {
    const points = path.points.map((p) => ({
      lat: roundCoord(p.lat),
      lng: roundCoord(p.lng),
    }));
    // Drop redundant name when it only repeats the highway tag
    const name =
      path.name && path.name !== path.highway ? path.name.slice(0, 48) : path.highway;
    return {
      id: path.id,
      name,
      highway: path.highway,
      kind: path.kind,
      points,
    };
  });

  return {
    source: payload.source,
    sourceUrl: payload.sourceUrl,
    lat: roundCoord(payload.lat, 5),
    lng: roundCoord(payload.lng, 5),
    radiusM: payload.radiusM,
    updatedAt: payload.updatedAt,
    pathCount: paths.length,
    roadCount: paths.filter((p) => p.kind === "road" || p.kind === "service")
      .length,
    footCount: paths.filter((p) => p.kind === "path" || p.kind === "cycle")
      .length,
    parkCount: paths.filter((p) => p.kind === "park").length,
    paths,
    ...(payload.stale ? { stale: true } : {}),
    ...(payload.note ? { note: payload.note.slice(0, 120) } : {}),
  };
}

function buildFallbackNearbyPaths(
  lat: number,
  lng: number,
  radiusM: number,
): NearbyPathsPreview {
  // Never invent fake streets — empty accurate frame only.
  return {
    source: NEARBY_PATHS_SOURCE,
    sourceUrl: NEARBY_PATHS_SOURCE_URL,
    lat,
    lng,
    radiusM,
    updatedAt: new Date().toISOString(),
    pathCount: 0,
    roadCount: 0,
    footCount: 0,
    paths: [],
    stale: true,
    note: `Live street data unavailable at ${lat.toFixed(4)}, ${lng.toFixed(4)} (${radiusM}m). OSM/Overpass failed or blocked — retry, check network, or allow location.`,
  };
}

function parseNearbyQuery(url: URL): {
  lat: number;
  lng: number;
  radiusM: number;
} | null {
  const lat = Number(url.searchParams.get("lat"));
  const lng = Number(url.searchParams.get("lng"));
  const radiusRaw = Number(url.searchParams.get("radius") ?? NEARBY_DEFAULT_RADIUS_M);

  if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
    return null;
  }
  if (lat < -90 || lat > 90 || lng < -180 || lng > 180) {
    return null;
  }

  const radiusM = Math.min(
    NEARBY_MAX_RADIUS_M,
    Math.max(
      NEARBY_MIN_RADIUS_M,
      Number.isFinite(radiusRaw) ? Math.round(radiusRaw) : NEARBY_DEFAULT_RADIUS_M,
    ),
  );

  return { lat, lng, radiusM };
}

function parseXmlAttrs(tagInner: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  const re = /([A-Za-z_:][\w:.-]*)\s*=\s*["']([^"']*)["']/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(tagInner)) !== null) {
    attrs[match[1]] = match[2];
  }
  return attrs;
}

function haversineMeters(
  lat1: number,
  lng1: number,
  lat2: number,
  lng2: number,
): number {
  const toRad = (d: number) => (d * Math.PI) / 180;
  const r = 6_371_000;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return 2 * r * Math.asin(Math.min(1, Math.sqrt(a)));
}

/**
 * Keep continuous road geometry that intersects the search circle.
 * Old filter dropped exterior vertices and *broke* roads that crossed the ring
 * (sketchy mid-block cuts). Instead: keep the span from first near point to last,
 * plus one exterior vertex on each end for exit direction.
 */
function clipPathToRadius(
  points: Array<{ lat: number; lng: number }>,
  lat: number,
  lng: number,
  radiusM: number,
  kind?: NearbyPathKind,
): Array<{ lat: number; lng: number }> {
  if (points.length < 2) return [];
  // Slightly larger than UI ring so edges don't vanish at the dashed circle
  const keepR = radiusM * 1.12;

  // Parks are closed polygons — keep the full ring if any vertex is in range
  // (continuous-span clipping shreds green areas).
  if (kind === "park") {
    if (points.length < 3) return [];
    const hits = points.some(
      (p) => haversineMeters(lat, lng, p.lat, p.lng) <= keepR,
    );
    if (!hits) return [];
    return points;
  }

  let first = -1;
  let last = -1;
  for (let i = 0; i < points.length; i++) {
    const p = points[i];
    if (haversineMeters(lat, lng, p.lat, p.lng) <= keepR) {
      if (first < 0) first = i;
      last = i;
    }
  }
  if (first < 0) return [];
  const start = Math.max(0, first - 1);
  const end = Math.min(points.length - 1, last + 1);
  const slice = points.slice(start, end + 1);
  return slice.length >= 2 ? slice : [];
}

function buildPreviewFromPaths(
  lat: number,
  lng: number,
  radiusM: number,
  paths: NearbyPathSegment[],
  note: string,
  stale = false,
): NearbyPathsPreview {
  const balanced = selectBalancedPaths(paths, NEARBY_MAX_WAYS);
  return {
    source: NEARBY_PATHS_SOURCE,
    sourceUrl: NEARBY_PATHS_SOURCE_URL,
    lat,
    lng,
    radiusM,
    updatedAt: new Date().toISOString(),
    pathCount: balanced.length,
    roadCount: balanced.filter((p) => p.kind === "road" || p.kind === "service")
      .length,
    footCount: balanced.filter((p) => p.kind === "path" || p.kind === "cycle")
      .length,
    parkCount: balanced.filter((p) => p.kind === "park").length,
    paths: balanced,
    stale,
    note,
  };
}

function parseOsmMapXml(
  xml: string,
  lat: number,
  lng: number,
  radiusM: number,
): NearbyPathSegment[] {
  const nodes = new Map<string, { lat: number; lng: number }>();
  // Self-closing and open node tags (OSM uses both forms)
  const nodeTagRe = /<node\b([^>/]*)(?:\/>|>)/g;
  let nodeMatch: RegExpExecArray | null;
  while ((nodeMatch = nodeTagRe.exec(xml)) !== null) {
    const attrs = parseXmlAttrs(nodeMatch[1]);
    const id = attrs.id;
    const nLat = Number(attrs.lat);
    const nLng = Number(attrs.lon);
    if (!id || !Number.isFinite(nLat) || !Number.isFinite(nLng)) continue;
    nodes.set(id, { lat: nLat, lng: nLng });
  }

  const paths: NearbyPathSegment[] = [];
  // Collect more than max so balanced selection can keep paths + parks
  const collectCap = NEARBY_MAX_WAYS * 3;
  const wayRe = /<way\b([^>]*)>([\s\S]*?)<\/way>/g;
  let wayMatch: RegExpExecArray | null;
  while ((wayMatch = wayRe.exec(xml)) !== null) {
    if (paths.length >= collectCap) break;

    const wayAttrs = parseXmlAttrs(wayMatch[1]);
    const body = wayMatch[2];
    const tags: Record<string, string> = {};
    const tagRe = /<tag\b([^>]*?)\/>/g;
    let tagMatch: RegExpExecArray | null;
    while ((tagMatch = tagRe.exec(body)) !== null) {
      const t = parseXmlAttrs(tagMatch[1]);
      if (t.k && t.v) tags[t.k] = t.v;
    }

    const classified = classifyOsmTags(tags);
    if (!classified) continue;

    const pts: Array<{ lat: number; lng: number }> = [];
    const ndRe = /<nd\b([^>]*?)\/>/g;
    let ndMatch: RegExpExecArray | null;
    while ((ndMatch = ndRe.exec(body)) !== null) {
      const ref = parseXmlAttrs(ndMatch[1]).ref;
      if (!ref) continue;
      const node = nodes.get(ref);
      if (node) pts.push(node);
    }

    // Parks need closed rings; paths/roads need ≥2 points
    if (classified.kind === "park") {
      if (pts.length < 3) continue;
      // Close ring if needed
      const first = pts[0];
      const last = pts[pts.length - 1];
      if (first && last && (first.lat !== last.lat || first.lng !== last.lng)) {
        pts.push({ ...first });
      }
    }

    const clipped = clipPathToRadius(
      pts,
      lat,
      lng,
      radiusM,
      classified.kind,
    );
    const simplified = simplifyGeometry(
      clipped.map((p) => ({ lat: p.lat, lon: p.lng })),
      classified.kind === "park"
        ? Math.min(NEARBY_MAX_POINTS_PER_WAY, 28)
        : NEARBY_MAX_POINTS_PER_WAY,
    );
    if (simplified.length < (classified.kind === "park" ? 3 : 2)) continue;

    paths.push({
      id: `w${wayAttrs.id ?? paths.length}`,
      name: classified.name,
      highway: classified.tag.slice(0, 40),
      kind: classified.kind,
      points: simplified,
    });
  }

  // Defer balanced trim to merge step so multi-tile + Overpass keep parks/paths
  return paths;
}

function parseOverpassElements(
  payload: {
    elements?: Array<{
      type?: string;
      id?: number;
      tags?: Record<string, string>;
      geometry?: Array<{ lat?: number; lon?: number }>;
    }>;
  },
  lat: number,
  lng: number,
  radiusM: number,
): NearbyPathSegment[] {
  const paths: NearbyPathSegment[] = [];
  const collectCap = NEARBY_MAX_WAYS * 3;
  for (const element of payload.elements ?? []) {
    if (element.type !== "way" || !element.geometry || !element.id) {
      continue;
    }
    if (paths.length >= collectCap) break;

    const classified = classifyOsmTags(element.tags || {});
    if (!classified) continue;

    const raw = element.geometry
      .map((p) => ({ lat: Number(p.lat), lng: Number(p.lon) }))
      .filter((p) => Number.isFinite(p.lat) && Number.isFinite(p.lng));
    if (classified.kind === "park" && raw.length >= 3) {
      const first = raw[0];
      const last = raw[raw.length - 1];
      if (first && last && (first.lat !== last.lat || first.lng !== last.lng)) {
        raw.push({ ...first });
      }
    }
    const clipped = clipPathToRadius(
      raw,
      lat,
      lng,
      radiusM,
      classified.kind,
    );
    const points = simplifyGeometry(
      clipped.map((p) => ({ lat: p.lat, lon: p.lng })),
      classified.kind === "park"
        ? Math.min(NEARBY_MAX_POINTS_PER_WAY, 28)
        : NEARBY_MAX_POINTS_PER_WAY,
    );
    if (points.length < (classified.kind === "park" ? 3 : 2)) continue;

    paths.push({
      id: `w${element.id}`,
      name: classified.name,
      highway: classified.tag.slice(0, 40),
      kind: classified.kind,
      points,
    });
  }
  // Defer balanced trim so OSM+Overpass merge can preserve all feature types
  return paths;
}

/**
 * OSM /api/0.6/map rejects dense bboxes with HTTP 400
 * ("too many nodes", limit 50k). Tile larger radii with safe tiles.
 */
const OSM_MAP_SAFE_RADIUS_M = 500;
/** Spacing between tile centers when covering large rings (meters). */
const OSM_TILE_STEP_M = 650;

/** Fetch one OSM bbox centered on (lat,lng) with bboxRadiusM, clip to clip*. */
async function fetchOsmTilePaths(
  tileLat: number,
  tileLng: number,
  bboxRadiusM: number,
  clipLat: number,
  clipLng: number,
  clipRadiusM: number,
): Promise<NearbyPathSegment[]> {
  const metersPerDegLat = 111_320;
  const metersPerDegLng =
    111_320 * Math.cos((tileLat * Math.PI) / 180) || 1;
  const fetchRadius = Math.min(
    Math.max(bboxRadiusM, NEARBY_MIN_RADIUS_M),
    OSM_MAP_SAFE_RADIUS_M,
  );
  const dLat = fetchRadius / metersPerDegLat;
  const dLng = fetchRadius / metersPerDegLng;
  const bbox = `${(tileLng - dLng).toFixed(6)},${(tileLat - dLat).toFixed(6)},${(tileLng + dLng).toFixed(6)},${(tileLat + dLat).toFixed(6)}`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), OSM_MAP_ATTEMPT_MS);
  try {
    const response = await fetch(`${OSM_MAP_API}?bbox=${bbox}`, {
      headers: {
        accept: "application/xml, text/xml, */*",
        "user-agent":
          "Mozilla/5.0 (compatible; GlobeNearby/1.3; +https://github.com/m-emilio/globe)",
      },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!response.ok) return [];

    const xml = await response.text();
    if (!xml.includes("<osm") || xml.length < 200) return [];
    if (xml.length > OSM_MAP_MAX_XML_CHARS) return [];

    // Parse/clip against the *search* center so the full ring is populated
    return parseOsmMapXml(xml, clipLat, clipLng, clipRadiusM);
  } catch {
    clearTimeout(timer);
    return [];
  }
}

function osmTileCenters(
  lat: number,
  lng: number,
  radiusM: number,
): Array<{ lat: number; lng: number }> {
  const metersPerDegLat = 111_320;
  const metersPerDegLng = 111_320 * Math.cos((lat * Math.PI) / 180) || 1;
  const centers: Array<{ lat: number; lng: number }> = [{ lat, lng }];
  if (radiusM <= OSM_MAP_SAFE_RADIUS_M) return centers;

  const step = OSM_TILE_STEP_M;
  for (let east = -radiusM; east <= radiusM + 1; east += step) {
    for (let north = -radiusM; north <= radiusM + 1; north += step) {
      if (east * east + north * north > radiusM * radiusM * 1.05) continue;
      if (Math.abs(east) < 80 && Math.abs(north) < 80) continue;
      centers.push({
        lat: lat + north / metersPerDegLat,
        lng: lng + east / metersPerDegLng,
      });
    }
  }
  // Cap concurrent tiles (9 covers 1500m well with 650m step)
  return centers.slice(0, 9);
}

async function fetchNearbyPathsFromOsmMapApi(
  lat: number,
  lng: number,
  radiusM: number,
): Promise<NearbyPathsPreview | null> {
  const tileCenters = osmTileCenters(lat, lng, radiusM);
  const byId = new Map<string, NearbyPathSegment>();

  // All tiles in parallel (max 9) — faster than sequential batches
  const results = await Promise.all(
    tileCenters.map((c) =>
      fetchOsmTilePaths(
        c.lat,
        c.lng,
        OSM_MAP_SAFE_RADIUS_M,
        lat,
        lng,
        radiusM,
      ),
    ),
  );
  for (const tilePaths of results) {
    for (const p of tilePaths) {
      if (!byId.has(p.id)) byId.set(p.id, p);
    }
  }

  const paths = [...byId.values()];
  if (paths.length < 1) return null;

  const tileNote =
    tileCenters.length > 1
      ? `Live OSM map (${tileCenters.length} tiles · ${radiusM}m · roads/paths/parks)`
      : "Live OpenStreetMap streets, paths & parks";

  return buildPreviewFromPaths(lat, lng, radiusM, paths, tileNote, false);
}

async function fetchNearbyPathsFromOverpass(
  lat: number,
  lng: number,
  radiusM: number,
): Promise<NearbyPathsPreview | null> {
  // Overpass is preferred for Workers: compact JSON + out geom (not multi‑MB OSM XML).
  const aroundM = Math.min(
    Math.max(radiusM, NEARBY_MIN_RADIUS_M),
    NEARBY_MAX_RADIUS_M,
  );
  // Highways + parks/greenways in one query
  const query = `
[out:json][timeout:20];
(
  way["highway"~"^(motorway|trunk|primary|secondary|tertiary|unclassified|residential|living_street|service|footway|path|cycleway|pedestrian|track|steps|bridleway)$"](around:${aroundM},${lat},${lng});
  way["leisure"~"^(park|garden|playground|pitch|nature_reserve|recreation_ground|common)$"](around:${aroundM},${lat},${lng});
  way["landuse"~"^(grass|recreation_ground|meadow|forest|village_green)$"](around:${aroundM},${lat},${lng});
);
out geom;
`.trim();

  const body = `data=${encodeURIComponent(query)}`;

  // One mirror only — cycling all three cost 15–40s when they 504
  const endpoint = OVERPASS_ENDPOINTS[0];
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), OVERPASS_ATTEMPT_MS);
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded;charset=UTF-8",
        accept: "application/json",
        "user-agent":
          "Mozilla/5.0 (compatible; GlobeNearby/1.2; +https://github.com/m-emilio/globe)",
      },
      body,
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (!response.ok) return null;

    const text = await response.text();
    if (!text || text.length < 20) return null;
    let payload: {
      elements?: Array<{
        type?: string;
        id?: number;
        tags?: Record<string, string>;
        geometry?: Array<{ lat?: number; lon?: number }>;
      }>;
      remark?: string;
    };
    try {
      payload = JSON.parse(text) as typeof payload;
    } catch {
      return null;
    }

    const paths = parseOverpassElements(payload, lat, lng, radiusM);
    if (paths.length < 1) return null;

    return buildPreviewFromPaths(
      lat,
      lng,
      radiusM,
      paths,
      "Live Overpass streets, paths & parks",
      false,
    );
  } catch {
    return null;
  }
}

/**
 * Full-radius coverage + speed:
 * - OSM tiles and Overpass run in parallel (not sequential fallback)
 * - Merge by way id so parks/paths from either source are kept
 * - Single balanced trim at the end
 */
async function fetchLiveNearbyPaths(
  lat: number,
  lng: number,
  radiusM: number,
): Promise<NearbyPathsPreview | null> {
  const [osmResult, overpassResult] = await Promise.all([
    fetchNearbyPathsFromOsmMapApi(lat, lng, radiusM).catch(() => null),
    fetchNearbyPathsFromOverpass(lat, lng, radiusM).catch(() => null),
  ]);

  const byId = new Map<string, NearbyPathSegment>();
  for (const preview of [osmResult, overpassResult]) {
    if (!preview?.paths?.length) continue;
    for (const p of preview.paths) {
      if (!byId.has(p.id)) byId.set(p.id, p);
    }
  }

  if (byId.size < 1) return null;

  const sources: string[] = [];
  if (osmResult?.paths?.length) sources.push("OSM");
  if (overpassResult?.paths?.length) sources.push("Overpass");
  const note =
    sources.length > 1
      ? `Live ${sources.join("+")} · ${radiusM}m · roads/paths/parks`
      : osmResult?.note ||
        overpassResult?.note ||
        "Live streets, paths & parks";

  return buildPreviewFromPaths(
    lat,
    lng,
    radiusM,
    [...byId.values()],
    note,
    false,
  );
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object"
    ? (value as Record<string, unknown>)
    : null;
}

function asString(value: unknown, max = 120): string {
  if (typeof value === "string") {
    return value.trim().slice(0, max);
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return String(value).slice(0, max);
  }
  const rec = asRecord(value);
  if (rec) {
    const nested =
      rec.id ?? rec.global_id ?? rec.value ?? rec.text ?? rec.name;
    if (typeof nested === "string" || typeof nested === "number") {
      return String(nested).trim().slice(0, max);
    }
  }
  return "";
}

function asNumber(value: unknown): number | null {
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function formatTransitDeparture(value: unknown): string | null {
  const epoch = asNumber(value);
  if (epoch === null) return null;
  // Transit may return seconds or milliseconds
  const ms = epoch > 1e12 ? epoch : epoch * 1000;
  try {
    return new Date(ms).toLocaleTimeString([], {
      hour: "numeric",
      minute: "2-digit",
    });
  } catch {
    return null;
  }
}

function parseTransitRoutes(raw: unknown): TransitRoutePreview[] {
  const root = asRecord(raw);
  const list = Array.isArray(root?.nearby_routes)
    ? root.nearby_routes
    : Array.isArray(raw)
      ? raw
      : [];

  const routes: TransitRoutePreview[] = [];
  for (const item of list) {
    if (routes.length >= TRANSIT_MAX_ROUTES) break;
    const route = asRecord(item);
    if (!route) continue;

    const shortName =
      asString(route.route_short_name, 24) ||
      asString(asRecord(route.route_display_short_name)?.text, 24) ||
      asString(route.mode_name, 24) ||
      "—";
    const longName = asString(route.route_long_name, 100);
    const id =
      asString(route.global_route_id, 80) ||
      asString(route.real_time_route_id, 80) ||
      `${shortName}-${routes.length}`;

    let closestStopName = "";
    let closestStopDistanceM: number | null = null;
    const nextDepartures: string[] = [];

    const merged = Array.isArray(route.merged_itineraries)
      ? route.merged_itineraries
      : [];
    for (const mergedItem of merged) {
      const mi = asRecord(mergedItem);
      if (!mi) continue;
      const stop = asRecord(mi.closest_stop);
      if (stop && !closestStopName) {
        closestStopName = asString(stop.stop_name, 80);
        closestStopDistanceM = asNumber(stop.distance);
      }
      const schedule = Array.isArray(mi.schedule_items) ? mi.schedule_items : [];
      for (const scheduleItem of schedule) {
        if (nextDepartures.length >= 3) break;
        const si = asRecord(scheduleItem);
        if (!si) continue;
        const label =
          formatTransitDeparture(si.departure_time) ||
          formatTransitDeparture(si.departure_time_seconds) ||
          asString(si.departure_time_str, 16);
        if (label && !nextDepartures.includes(label)) {
          nextDepartures.push(label);
        }
      }
      if (closestStopName && nextDepartures.length >= 3) break;
    }

    const alerts = Array.isArray(route.alerts) ? route.alerts.length : 0;
    const color = asString(route.route_color, 12).replace(/^#/, "") || "00d9ff";
    const textColor =
      asString(route.route_text_color, 12).replace(/^#/, "") || "0a0e27";

    routes.push({
      id,
      shortName,
      longName,
      modeName: asString(route.mode_name, 40) || "Transit",
      networkName: asString(route.route_network_name, 60),
      color,
      textColor,
      closestStopName,
      closestStopDistanceM,
      nextDepartures,
      alertCount: alerts,
    });
  }

  return routes;
}

function parseTransitStops(raw: unknown): TransitStopPreview[] {
  const root = asRecord(raw);
  const list = Array.isArray(root?.stops)
    ? root.stops
    : Array.isArray(raw)
      ? raw
      : [];

  const stops: TransitStopPreview[] = [];
  for (const item of list) {
    if (stops.length >= TRANSIT_MAX_STOPS) break;
    const stop = asRecord(item);
    if (!stop) continue;
    const name = asString(stop.stop_name, 80);
    if (!name) continue;
    stops.push({
      id: asString(stop.global_stop_id, 80) || `stop-${stops.length}`,
      name,
      code: asString(stop.stop_code, 24),
      distanceM: asNumber(stop.distance),
      lat: asNumber(stop.stop_lat),
      lng: asNumber(stop.stop_lon),
      routeType: asNumber(stop.route_type),
    });
  }
  return stops;
}

function buildTransitModes(routes: TransitRoutePreview[]): TransitModePreview[] {
  const counts = new Map<string, number>();
  for (const route of routes) {
    const key = route.modeName || "Transit";
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([modeName, count]) => ({ modeName, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 12);
}

async function fetchTransitJson(
  path: string,
  params: URLSearchParams,
  apiKey: string,
): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12_000);
  try {
    const response = await fetch(`${TRANSIT_API_BASE}${path}?${params}`, {
      headers: {
        accept: "application/json",
        apiKey,
        "user-agent": "GlobeOps/1.0 (local transit preview)",
      },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!response.ok) {
      throw new Error(`transit_upstream_${response.status}`);
    }
    return await response.json();
  } catch (error) {
    clearTimeout(timer);
    throw error;
  }
}

async function getTransitNearbyPreview(request: Request, url: URL, env: Env) {
  const gate = await requireTransitAccess(request, env, applySecurityHeaders);
  if (gate) {
    return gate;
  }

  const apiKey = env.TRANSIT_PUBLICAPI_V4?.trim();
  if (!apiKey) {
    return jsonResponse(
      {
        error: "transit_api_key_missing",
        message:
          "Set TRANSIT_PUBLICAPI_V4 (GitHub secret / wrangler secret / .dev.vars) to enable local transit.",
      },
      {
        status: 503,
        headers: { "cache-control": "no-store" },
      },
    );
  }

  const lat = Number(url.searchParams.get("lat"));
  const lon = Number(
    url.searchParams.get("lon") ?? url.searchParams.get("lng"),
  );
  const maxDistanceRaw = Number(
    url.searchParams.get("max_distance") ?? TRANSIT_DEFAULT_MAX_DISTANCE_M,
  );

  if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
    return jsonResponse(
      { error: "invalid_coordinates" },
      { status: 400, headers: { "cache-control": "no-store" } },
    );
  }
  if (lat < -90 || lat > 90 || lon < -180 || lon > 180) {
    return jsonResponse(
      { error: "invalid_coordinates" },
      { status: 400, headers: { "cache-control": "no-store" } },
    );
  }

  const maxDistanceM = Math.min(
    TRANSIT_MAX_MAX_DISTANCE_M,
    Math.max(
      TRANSIT_MIN_MAX_DISTANCE_M,
      Number.isFinite(maxDistanceRaw)
        ? Math.round(maxDistanceRaw)
        : TRANSIT_DEFAULT_MAX_DISTANCE_M,
    ),
  );

  const cacheKey = `${lat.toFixed(4)}:${lon.toFixed(4)}:${maxDistanceM}`;
  const cached = TRANSIT_CACHE.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return jsonResponse(cached.payload, {
      headers: {
        "cache-control": `public, max-age=${TRANSIT_CACHE_SECONDS}`,
      },
    });
  }

  const shared = new URLSearchParams({
    lat: String(lat),
    lon: String(lon),
    max_distance: String(maxDistanceM),
  });

  const routesParams = new URLSearchParams(shared);
  routesParams.set("should_update_realtime", "true");
  routesParams.set("max_num_departures", "3");
  routesParams.set("include_stops_and_shapes", "false");

  const stopsParams = new URLSearchParams(shared);
  stopsParams.set("stop_filter", "Routable");
  stopsParams.set("stop_detailed", "false");

  try {
    const [routesRaw, stopsRaw] = await Promise.all([
      fetchTransitJson("/v4/public/nearby_routes", routesParams, apiKey),
      fetchTransitJson("/v4/public/nearby_stops", stopsParams, apiKey),
    ]);

    const routes = parseTransitRoutes(routesRaw);
    const stops = parseTransitStops(stopsRaw);
    const payload: TransitNearbyPreview = {
      source: TRANSIT_SOURCE,
      sourceUrl: TRANSIT_SOURCE_URL,
      lat: Math.round(lat * 1e5) / 1e5,
      lng: Math.round(lon * 1e5) / 1e5,
      maxDistanceM,
      updatedAt: new Date().toISOString(),
      routeCount: routes.length,
      stopCount: stops.length,
      modes: buildTransitModes(routes),
      routes,
      stops,
      note:
        routes.length || stops.length
          ? "Live local transit from Transit App"
          : "No routes or stops found for this location",
    };

    TRANSIT_CACHE.set(cacheKey, {
      expiresAt: Date.now() + TRANSIT_CACHE_SECONDS * 1000,
      payload,
    });
    if (TRANSIT_CACHE.size > 48) {
      const first = TRANSIT_CACHE.keys().next().value;
      if (first) TRANSIT_CACHE.delete(first);
    }

    return jsonResponse(payload, {
      headers: {
        "cache-control": `public, max-age=${TRANSIT_CACHE_SECONDS}`,
      },
    });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "transit_upstream_error";
    return jsonResponse(
      {
        error: "transit_upstream_error",
        message: "Transit upstream unavailable. Try again shortly.",
        code: message.startsWith("transit_upstream_")
          ? message
          : "transit_upstream_error",
      },
      {
        status: 502,
        headers: { "cache-control": "no-store" },
      },
    );
  }
}

async function getNearbyPathsPreview(request: Request, url: URL, env: Env) {
  // Same gate as Transit when payment enforced; always requires login
  const gate = await requireTransitAccess(
    request,
    env,
    applySecurityHeaders,
    {
      rateKey: "nearby",
      rateLimit: 20,
      featureName: "Nearby maps",
    },
  );
  if (gate) return gate;

  const query = parseNearbyQuery(url);
  if (!query) {
    return jsonResponse(
      { error: "invalid_coordinates" },
      {
        status: 400,
        headers: { "cache-control": "no-store" },
      },
    );
  }

  const { lat, lng, radiusM } = query;
  // Higher precision cache key so small moves update geometry
  const cacheKey = `${lat.toFixed(4)}:${lng.toFixed(4)}:${radiusM}`;
  const cached = NEARBY_CACHE.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return jsonResponse(cached.payload, {
      headers: {
        "cache-control": `public, max-age=${NEARBY_CACHE_SECONDS}`,
      },
    });
  }

  // Parallel Overpass (primary for Workers) + OSM map API; pick denser result
  let payload: NearbyPathsPreview | null = null;
  try {
    payload = await fetchLiveNearbyPaths(lat, lng, radiusM);
  } catch {
    payload = null;
  }

  // Empty accurate frame only if live data unavailable (no invented streets)
  if (!payload || payload.paths.length === 0) {
    payload = buildFallbackNearbyPaths(lat, lng, radiusM);
  }

  // Never cache empty/stale failures for long — that trapped users after one outage
  if (!payload.stale && payload.paths.length > 0) {
    NEARBY_CACHE.set(cacheKey, {
      expiresAt: Date.now() + NEARBY_CACHE_SECONDS * 1000,
      payload,
    });
  } else {
    // Brief negative cache so we don't hammer upstream while still allowing quick retry
    NEARBY_CACHE.set(cacheKey, {
      expiresAt: Date.now() + 15_000,
      payload,
    });
  }

  if (NEARBY_CACHE.size > 64) {
    const first = NEARBY_CACHE.keys().next().value;
    if (first) NEARBY_CACHE.delete(first);
  }

  const compact = compactNearbyPayload(payload);

  return jsonResponse(compact, {
    headers: {
      "cache-control": compact.stale
        ? "no-store"
        : `public, max-age=${NEARBY_CACHE_SECONDS}`,
      vary: "accept-encoding",
    },
  });
}

function jsonResponse(data: unknown, init?: ResponseInit) {
  const headers = new Headers(init?.headers);
  headers.set("content-type", "application/json; charset=utf-8");
  if (!headers.has("vary")) {
    headers.set("vary", "accept-encoding");
  }
  applySecurityHeaders(headers);

  return new Response(JSON.stringify(data), {
    ...init,
    headers,
  });
}

function methodNotAllowedResponse() {
  return jsonResponse(
    { error: "method_not_allowed" },
    {
      status: 405,
      headers: {
        allow: "GET, HEAD",
        "cache-control": "no-store",
      },
    },
  );
}

function isReadApiMethod(request: Request) {
  return request.method === "GET" || request.method === "HEAD";
}

function withoutResponseBodyForHead(request: Request, response: Response) {
  if (request.method !== "HEAD") {
    return response;
  }

  return new Response(null, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

function applySecurityHeaders(headers: Headers, _request?: Request) {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    if (!headers.has(name)) {
      headers.set(name, value);
    }
  }
  // HSTS: browsers ignore over plain HTTP; safe to always emit for HTTPS prod
  if (!headers.has("strict-transport-security")) {
    headers.set(
      "strict-transport-security",
      "max-age=31536000; includeSubDomains; preload",
    );
  }
}

function withSecurityHeaders(response: Response, request?: Request) {
  const headers = new Headers(response.headers);
  applySecurityHeaders(headers, request);

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

/**
 * Serve public GET previews from the Cloudflare Cache API when possible.
 * Hits skip Durable rate limits and origin hydrate (main source of globe lag).
 * Only caches responses that are public and not no-store.
 */
async function withPublicEdgeCache(
  request: Request,
  ctx: ExecutionContext,
  generate: () => Promise<Response>,
  options?: { cacheVersion?: string },
): Promise<Response> {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return generate();
  }

  const cacheUrl = new URL(request.url);
  cacheUrl.searchParams.delete("_t");
  if (options?.cacheVersion) {
    cacheUrl.searchParams.set("_cv", options.cacheVersion);
  }
  // Stable key: method GET, no cookies (public data only).
  const cacheKey = new Request(cacheUrl.toString(), {
    method: "GET",
    headers: { accept: "application/json" },
  });

  try {
    const hit = await caches.default.match(cacheKey);
    if (hit) {
      const headers = new Headers(hit.headers);
      headers.set("x-edge-cache", "HIT");
      if (request.method === "HEAD") {
        return new Response(null, { status: hit.status, headers });
      }
      return new Response(hit.body, {
        status: hit.status,
        statusText: hit.statusText,
        headers,
      });
    }
  } catch {
    // Cache API unavailable — generate normally
  }

  const response = await generate();
  const cacheControl = response.headers.get("cache-control") || "";
  const canCache =
    response.ok &&
    response.status === 200 &&
    /public/i.test(cacheControl) &&
    !/no-store/i.test(cacheControl);

  if (canCache) {
    // Build a clean Response for Cache API (no transfer-encoding quirks).
    try {
      const body = await response.clone().arrayBuffer();
      const storeHeaders = new Headers(response.headers);
      storeHeaders.delete("set-cookie");
      // Prefer s-maxage for edge retention; keep body Cache-Control as-is.
      const storeResponse = new Response(body, {
        status: response.status,
        statusText: response.statusText,
        headers: storeHeaders,
      });
      ctx.waitUntil(
        caches.default.put(cacheKey, storeResponse).catch(() => {}),
      );
    } catch {
      // non-fatal — origin/KV still serve
    }
  }

  const headers = new Headers(response.headers);
  headers.set("x-edge-cache", canCache ? "MISS" : "BYPASS");
  if (request.method === "HEAD") {
    return new Response(null, { status: response.status, headers });
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function isWebSocketRequest(request: Request) {
  return request.headers.get("upgrade")?.toLowerCase() === "websocket";
}

function wait(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchComtradeJson(
  url: string,
  options?: { subscriptionKey?: string | null },
) {
  const subscriptionKey = options?.subscriptionKey?.trim() || null;
  const headers: Record<string, string> = {
    accept: "application/json",
  };
  // Free /data/v1 APIs require Azure APIM subscription key (server-side only).
  if (subscriptionKey) {
    headers["Ocp-Apim-Subscription-Key"] = subscriptionKey;
  }

  for (let attempt = 0; attempt < 2; attempt += 1) {
    const response = await fetch(url, {
      headers,
      cf: {
        // Do not put authenticated Free API responses in shared edge cache.
        cacheEverything: !subscriptionKey,
        cacheTtl: subscriptionKey ? 0 : COMTRADE_CACHE_SECONDS,
      },
    });

    if (response.ok) {
      return response.json();
    }

    if (response.status !== 429 || attempt === 1) {
      throw new Error(`Comtrade API returned ${response.status} for ${url}`);
    }

    await wait(COMTRADE_RETRY_DELAY_MS);
  }

  throw new Error(`Comtrade API request failed for ${url}`);
}

async function fetchOptionalComtradeJson(
  label: string,
  url: string,
  options?: { subscriptionKey?: string | null; secrets?: string[] },
) {
  try {
    return await fetchComtradeJson(url, options);
  } catch (error) {
    // Never log subscription keys or raw Error objects.
    const secrets = [
      ...(options?.secrets ?? []),
      ...(options?.subscriptionKey?.trim() ? [options.subscriptionKey.trim()] : []),
    ];
    safeWarn(`Comtrade ${label} request failed`, error, secrets);
    return null;
  }
}

/** Isolate memory for Comtrade preview — Free API hydrate is multi-second without this. */
let comtradePreviewMemory: {
  at: number;
  responseBody: string;
  headers: Record<string, string>;
} | null = null;
const COMTRADE_PREVIEW_MEMORY_TTL_MS = 30 * 60 * 1000;

/**
 * Prefer Free /data/v1 when COMTRADE_SUBSCRIPTION_KEY is set.
 * On missing key or Free API failure, fall back to public /public/v1 preview.
 * The subscription key is never returned to the client.
 */
async function getComtradePreview(env: Env) {
  const now = Date.now();
  if (
    comtradePreviewMemory &&
    now - comtradePreviewMemory.at < COMTRADE_PREVIEW_MEMORY_TTL_MS
  ) {
    const headers = new Headers(comtradePreviewMemory.headers);
    headers.set("x-comtrade-preview-cache", "memory");
    return new Response(comtradePreviewMemory.responseBody, {
      status: 200,
      headers,
    });
  }

  const subscriptionKey = resolveComtradeSubscriptionKey(env);
  const secrets = collectWorkerSecrets(env);
  let dataMode: ComtradePreview["dataMode"] = "public-preview";
  let apiUrl = COMTRADE_PUBLIC_EXPORT_URL;
  let usedFreeApi = false;

  let exportPayload: unknown = null;
  let importPayload: unknown = null;
  let availabilityPayload: unknown = null;

  if (subscriptionKey) {
    exportPayload = await fetchOptionalComtradeJson("exports-free", COMTRADE_FREE_EXPORT_URL, {
      subscriptionKey,
      secrets,
    });
    importPayload = await fetchOptionalComtradeJson("imports-free", COMTRADE_FREE_IMPORT_URL, {
      subscriptionKey,
      secrets,
    });
    availabilityPayload = await fetchOptionalComtradeJson(
      "availability-free",
      COMTRADE_FREE_AVAILABILITY_URL,
      { subscriptionKey, secrets },
    );

    const freeTradeRows =
      normalizeComtradeTradeRecords(exportPayload).length +
      normalizeComtradeTradeRecords(importPayload).length;

    if (freeTradeRows > 0) {
      usedFreeApi = true;
      dataMode = "free-subscription";
      apiUrl = COMTRADE_FREE_EXPORT_URL;
    } else {
      // Free path failed (401/429/empty) — public preview fallback.
      safeWarn(
        "Comtrade Free /data/v1 returned no trade rows; falling back to public preview",
        undefined,
        secrets,
      );
      exportPayload = null;
      importPayload = null;
      availabilityPayload = null;
    }
  }

  if (!usedFreeApi) {
    exportPayload = await fetchOptionalComtradeJson("exports", COMTRADE_PUBLIC_EXPORT_URL, {
      secrets,
    });
    importPayload = await fetchOptionalComtradeJson("imports", COMTRADE_PUBLIC_IMPORT_URL, {
      secrets,
    });
    availabilityPayload = await fetchOptionalComtradeJson(
      "availability",
      COMTRADE_PUBLIC_AVAILABILITY_URL,
      { secrets },
    );
    dataMode = "public-preview";
    apiUrl = COMTRADE_PUBLIC_EXPORT_URL;
  }

  // Reference metadata is public (no subscription key).
  const referencesPayload = await fetchOptionalComtradeJson(
    "references",
    COMTRADE_REFERENCES_URL,
    { secrets },
  );
  const reportersPayload = await fetchOptionalComtradeJson(
    "reporters",
    COMTRADE_REPORTERS_URL,
    { secrets },
  );

  let stale = false;
  let tradeRecords = [
    ...normalizeComtradeTradeRecords(exportPayload),
    ...normalizeComtradeTradeRecords(importPayload),
  ];
  let availability = normalizeComtradeAvailability(availabilityPayload);
  let references = normalizeComtradeReferences(referencesPayload);
  let reporters = normalizeComtradeReporters(reportersPayload);
  let referenceTablesTotal = getComtradeCount(referencesPayload, "results");
  let reportersTotal = getComtradeCount(reportersPayload, "results");

  if (tradeRecords.length === 0) {
    stale = true;
    tradeRecords = FALLBACK_COMTRADE_RECORDS;
  }

  if (availability.length === 0) {
    stale = true;
    availability = FALLBACK_COMTRADE_AVAILABILITY;
  }

  if (references.length === 0) {
    stale = true;
    references = FALLBACK_COMTRADE_REFERENCES;
    referenceTablesTotal = references.length;
  }

  if (reporters.length === 0) {
    stale = true;
    reporters = FALLBACK_COMTRADE_REPORTERS;
    reportersTotal = reporters.length;
  }

  const preview = buildComtradePreview({
    tradeRecords,
    availability,
    references,
    reporters,
    referenceTablesTotal,
    reportersTotal,
    stale,
    dataMode,
    apiUrl,
  });

  const response = comtradeJsonResponse(
    preview,
    subscriptionKey,
    {
      headers: {
        // Public + edge-cacheable: body is scrubbed; key never in response.
        "cache-control": stale
          ? "no-store"
          : usedFreeApi
            ? "public, max-age=600, s-maxage=3600, stale-while-revalidate=86400"
            : "public, max-age=300, s-maxage=1800, stale-while-revalidate=86400",
        "x-comtrade-mode": dataMode,
        "x-comtrade-preview-cache": "miss",
        ...(stale ? { "x-comtrade-preview": "partial-fallback" } : {}),
      },
    },
    secrets,
  );

  // Cache successful public bodies in isolate memory (edge Cache API is L1).
  if (response.ok && !stale) {
    try {
      const body = await response.clone().text();
      const headerObj: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        headerObj[key] = value;
      });
      comtradePreviewMemory = { at: Date.now(), responseBody: body, headers: headerObj };
    } catch {
      // non-fatal
    }
  }

  return response;
}

async function fetchUnGlobalJson(url: string) {
  const response = await fetch(url, {
    headers: {
      accept: "application/json",
    },
    cf: {
      cacheEverything: true,
      cacheTtl: UN_GLOBAL_CACHE_SECONDS,
    },
  });

  if (!response.ok) {
    throw new Error(`UN global API returned ${response.status} for ${url}`);
  }

  return response.json();
}

async function fetchOptionalUnGlobalJson(label: string, url: string) {
  try {
    return await fetchUnGlobalJson(url);
  } catch (error) {
    // Message only — never raw Error (may include headers/stack).
    safeWarn(`UN global ${label} request failed`, error);
    return null;
  }
}

async function fetchUnGlobalText(url: string) {
  const response = await fetch(url, {
    headers: {
      accept: "text/csv,text/plain,*/*",
      "user-agent": "globe-un-preview/1.0",
    },
    cf: {
      cacheEverything: true,
      cacheTtl: UN_GLOBAL_CACHE_SECONDS,
    },
  });

  if (!response.ok) {
    throw new Error(`UN global text source returned ${response.status} for ${url}`);
  }

  return response.text();
}

async function fetchOptionalUnGlobalText(label: string, url: string) {
  try {
    return await fetchUnGlobalText(url);
  } catch (error) {
    safeWarn(`UN global ${label} request failed`, error);
    return null;
  }
}

async function getUnGlobalPreview() {
  const missionPayload = await fetchOptionalUnGlobalJson("missions", UN_PKO_DATA_URL);
  const metadataPayload = await fetchOptionalUnGlobalJson("metadata", UN_PKO_METADATA_URL);
  const geoAreaPayload = await fetchOptionalUnGlobalJson("geo areas", UN_SDG_GEO_AREAS_URL);
  const memberStatusCsv = await fetchOptionalUnGlobalText(
    "member statuses",
    UN_MEMBER_STATUS_URL,
  );
  const countryCentroidsCsv = await fetchOptionalUnGlobalText(
    "country centroids",
    COUNTRY_CENTROIDS_URL,
  );

  let stale = false;
  let missions = normalizeUnMissionLocations(missionPayload);
  let missionsTotal = getUnMissionRecordCount(missionPayload);
  let activeMissionsTotal = getUnActiveMissionRecordCount(missionPayload);
  const geoAreas = normalizeGeoAreas(geoAreaPayload);
  let geoAreasTotal = geoAreas.length;
  const memberAlpha3Codes = normalizeUnMemberAlpha3Codes(memberStatusCsv);
  const countryCentroids = normalizeCountryCentroids(countryCentroidsCsv);

  if (missions.length === 0) {
    stale = true;
    missions = FALLBACK_UN_MISSIONS;
    missionsTotal = FALLBACK_UN_MISSIONS.length;
    activeMissionsTotal = FALLBACK_UN_MISSIONS.filter((mission) => mission.active).length;
  }

  if (metadataPayload === null) {
    stale = true;
  }

  if (geoAreas.length === 0) {
    stale = true;
    geoAreasTotal = UN_GEO_AREAS_FALLBACK_TOTAL;
  }

  const areaLookup = buildGeoAreaLookup(geoAreas);
  const memberStates = buildMemberStateMarkers(
    areaLookup,
    countryCentroids,
    memberAlpha3Codes,
  );

  if (memberStates.length < UN_MEMBER_STATES_TOTAL) {
    stale = true;
  }

  return jsonResponse(
    buildUnGlobalPreview({
      missions,
      missionsTotal,
      activeMissionsTotal,
      geoAreasTotal,
      offices: UN_OFFICE_LOCATIONS,
      memberStates,
      affiliates: buildAffiliateMarkers(areaLookup),
      embassies: buildPermanentMissionMarkers(),
      stale,
    }),
    {
      headers: {
        "cache-control": stale
          ? "no-store"
          : "public, max-age=3600, s-maxage=21600, stale-while-revalidate=86400",
        ...(stale ? { "x-un-global-preview": "partial-fallback" } : {}),
      },
    },
  );
}

export class Globe extends Server<Env> {
  private connectionAttempts = new Map<string, ConnectionAttemptBucket>();

  private getConnectionLimitReason(clientKey: string) {
    const now = Date.now();
    this.pruneConnectionAttempts(now);

    const bucket = this.connectionAttempts.get(clientKey);

    if (!bucket && this.connectionAttempts.size >= MAX_CONNECTION_ATTEMPT_BUCKETS) {
      return "server rate limit busy";
    }

    if (!bucket || now - bucket.windowStart >= CONNECTION_RATE_WINDOW_MS) {
      this.connectionAttempts.set(clientKey, {
        windowStart: now,
        count: 1,
      });
      return null;
    }

    bucket.count += 1;

    if (bucket.count > MAX_CONNECTIONS_PER_WINDOW) {
      return "too many connection attempts";
    }

    return null;
  }

  private pruneConnectionAttempts(now: number) {
    if (this.connectionAttempts.size < MAX_CONNECTION_ATTEMPT_BUCKETS) {
      return;
    }

    for (const [clientKey, bucket] of this.connectionAttempts) {
      if (now - bucket.windowStart >= CONNECTION_RATE_WINDOW_MS) {
        this.connectionAttempts.delete(clientKey);
      }
    }
  }

  private closeConnection(conn: Connection, code: number, reason: string) {
    try {
      conn.close(code, reason);
    } catch {
      // The connection may already be closing.
    }
  }

  private sendJson(conn: Connection, message: OutgoingMessage) {
    try {
      conn.send(JSON.stringify(message));
    } catch {
      // connection may be closing
    }
  }

  /** Deliver feed-* only to connections that proved transitPaid via session cookie */
  private broadcastFeed(message: OutgoingMessage, excludeId?: string) {
    for (const connection of this.getConnections<ConnectionState>()) {
      if (excludeId && connection.id === excludeId) continue;
      const state = connection.state as ConnectionState | undefined;
      if (!state?.feedPaid) continue;
      this.sendJson(connection, message);
    }
  }

  async onConnect(conn: Connection<ConnectionState>, ctx: ConnectionContext) {
    const latitude = ctx.request.cf?.latitude as string | undefined;
    const longitude = ctx.request.cf?.longitude as string | undefined;
    const lat = parseBoundedCoordinate(latitude, -90, 90);
    const lng = parseBoundedCoordinate(longitude, -180, 180);
    if (lat === null || lng === null) {
      console.warn(`Missing position information for connection ${conn.id}`);
      this.closeConnection(conn, CLOSE_POLICY_VIOLATION, "invalid location");
      return;
    }

    // Full IP only for server rate limits — never on the wire
    const ip = getClientIp(ctx.request);
    const clientKey = ip ?? "unknown";
    const rateLimitReason = this.getConnectionLimitReason(clientKey);

    if (rateLimitReason) {
      this.closeConnection(conn, CLOSE_TRY_AGAIN_LATER, rateLimitReason);
      return;
    }

    const connections = Array.from(this.getConnections<ConnectionState>());

    if (connections.length > MAX_ACTIVE_CONNECTIONS) {
      this.closeConnection(conn, CLOSE_TRY_AGAIN_LATER, "server at capacity");
      return;
    }

    const matchingIpConnections = connections.filter((connection) => {
      const state = connection.state as ConnectionState | undefined;
      return state?.clientKey === clientKey && clientKey !== "unknown";
    });

    if (ip && matchingIpConnections.length >= MAX_CONNECTIONS_PER_IP) {
      this.closeConnection(conn, CLOSE_TRY_AGAIN_LATER, "too many connections");
      return;
    }

    const country = limitText(ctx.request.cf?.country as string | undefined, 4);
    const city = limitText(ctx.request.cf?.city as string | undefined, 80);
    const org = limitText(ctx.request.cf?.org as string | undefined, 120);

    // Public marker: lat/lng/id + coarse country only
    const position: Position = publicMarker({
      lat,
      lng,
      id: conn.id,
      country,
    });

    // Paid feed meta — never includes full IP
    const feedMeta: FeedVisitorMeta = {
      id: conn.id,
      city,
      country,
      org,
      ipMasked: maskIpForFeed(ip),
    };

    // Cookie session on same-origin WS determines paid feed access
    let feedPaid = false;
    try {
      const session = await getSessionUser(
        ctx.request,
        this.env as AuthEnv,
      );
      feedPaid = Boolean(session?.user.transitPaid);
    } catch {
      feedPaid = false;
    }

    const joinedAt = Date.now();
    conn.setState({
      position,
      clientKey,
      feedMeta,
      joinedAt,
      feedPaid,
    });

    // Tell this client whether it will receive feed events
    this.sendJson(conn, { type: "feed-access", paid: feedPaid });

    // Replay public markers (+ paid feed meta if entitled)
    let replayedMarkers = 0;
    for (const connection of connections) {
      try {
        const state = connection.state as ConnectionState | undefined;
        if (!state?.position) continue;
        if (replayedMarkers >= MAX_REPLAY_MARKERS) break;

        this.sendJson(conn, {
          type: "add-marker",
          position: publicMarker(state.position),
        });
        if (feedPaid && state.feedMeta) {
          this.sendJson(conn, { type: "feed-join", meta: state.feedMeta });
        }
        replayedMarkers += 1;

        // Notify other clients of the newcomer
        if (connection.id !== conn.id) {
          this.sendJson(connection, {
            type: "add-marker",
            position,
          });
          const peer = connection.state as ConnectionState | undefined;
          if (peer?.feedPaid) {
            this.sendJson(connection, { type: "feed-join", meta: feedMeta });
          }
        }
      } catch {
        this.onCloseOrError(connection);
      }
    }
  }

  onCloseOrError(connection: Connection) {
    const state = connection.state as ConnectionState | undefined;

    if (!state?.position) {
      return;
    }

    const sessionMs = Math.max(0, Date.now() - (state.joinedAt || Date.now()));

    this.broadcast(
      JSON.stringify({
        type: "remove-marker",
        id: connection.id,
      } satisfies OutgoingMessage),
      [connection.id],
    );

    // Paid feed leave (no full IP)
    this.broadcastFeed(
      {
        type: "feed-leave",
        id: connection.id,
        sessionMs,
        meta: state.feedMeta,
      },
      connection.id,
    );
  }

  onClose(connection: Connection): void | Promise<void> {
    this.onCloseOrError(connection);
  }

  onError(connection: Connection): void | Promise<void> {
    this.onCloseOrError(connection);
  }
}

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    const url = new URL(request.url);

    // Path A: Comtrade + Trade Pulse stay free/public (not Stripe-gated).
    // Monetization is Transit / Live Feed only. Do not expose or resell UN API keys.
    // Edge Cache API first — rate-limit + hydrate only on miss (major lag fix).
    if (url.pathname === "/api/comtrade-preview") {
      if (!isReadApiMethod(request)) {
        return methodNotAllowedResponse();
      }
      return withoutResponseBodyForHead(
        request,
        await withPublicEdgeCache(request, ctx, async () => {
          const limited = await rateLimitDurable(
            env,
            `preview:comtrade:${clientIpFromRequest(request)}`,
            40,
            60_000,
            applySecurityHeaders,
          );
          if (limited) return limited;
          return await getComtradePreview(env);
        }),
      );
    }

    if (url.pathname === "/api/comtrade-pulse-preview") {
      if (!isReadApiMethod(request)) {
        return methodNotAllowedResponse();
      }
      return withoutResponseBodyForHead(
        request,
        await withPublicEdgeCache(request, ctx, async () => {
          const limited = await rateLimitDurable(
            env,
            `preview:pulse:${clientIpFromRequest(request)}`,
            40,
            60_000,
            applySecurityHeaders,
          );
          if (limited) return limited;
          const pulsePeriod = parseTradePulsePeriod(
            url.searchParams.get("period"),
          );
          return await getTradePulsePreview(env, pulsePeriod, ctx);
        }),
      );
    }

    if (url.pathname === "/api/un-global-preview") {
      if (!isReadApiMethod(request)) {
        return methodNotAllowedResponse();
      }
      return withoutResponseBodyForHead(
        request,
        await withPublicEdgeCache(request, ctx, async () => {
          const limited = rateLimitOrNull(
            `preview:un:${clientIpFromRequest(request)}`,
            30,
            60_000,
            applySecurityHeaders,
          );
          if (limited) return limited;
          return await getUnGlobalPreview();
        }),
      );
    }

    if (url.pathname === "/api/unodc-hotspots-preview") {
      if (!isReadApiMethod(request)) {
        return methodNotAllowedResponse();
      }
      // Edge cache HIT → no DO rate limit, no OWID hydrate.
      return withoutResponseBodyForHead(
        request,
        await withPublicEdgeCache(
          request,
          ctx,
          async () => {
            const limited = await rateLimitDurable(
              env,
              `preview:unodc:${clientIpFromRequest(request)}`,
              30,
              60_000,
              applySecurityHeaders,
            );
            if (limited) return limited;
            return withSecurityHeaders(
              await getUnodcHotspotsPreview(env),
              request,
            );
          },
          { cacheVersion: UNODC_EDGE_CACHE_VERSION },
        ),
      );
    }

    if (url.pathname === "/api/nearby-paths") {
      if (!isReadApiMethod(request)) {
        return methodNotAllowedResponse();
      }

      return withoutResponseBodyForHead(
        request,
        await getNearbyPathsPreview(request, url, env),
      );
    }

    if (url.pathname === "/api/transit-nearby") {
      if (!isReadApiMethod(request)) {
        return methodNotAllowedResponse();
      }

      return withoutResponseBodyForHead(
        request,
        await getTransitNearbyPreview(request, url, env),
      );
    }

    // --- Auth (OpenPGP challenge–response + HttpOnly session cookie) ---
    if (url.pathname === "/api/auth/register") {
      if (request.method !== "POST") {
        return methodNotAllowedResponse();
      }
      return registerUser(request, env, applySecurityHeaders);
    }

    if (url.pathname === "/api/auth/challenge") {
      if (request.method !== "POST") {
        return methodNotAllowedResponse();
      }
      return createAuthChallenge(request, env, applySecurityHeaders);
    }

    if (url.pathname === "/api/auth/login") {
      if (request.method !== "POST") {
        return methodNotAllowedResponse();
      }
      return loginUser(request, env, applySecurityHeaders);
    }

    if (url.pathname === "/api/auth/adopt-token") {
      if (request.method !== "POST") {
        return methodNotAllowedResponse();
      }
      return adoptSessionToken(request, env, applySecurityHeaders);
    }

    if (url.pathname === "/api/auth/logout") {
      if (request.method !== "POST") {
        return methodNotAllowedResponse();
      }
      return logoutUser(request, env, applySecurityHeaders);
    }

    if (url.pathname === "/api/auth/me") {
      if (!isReadApiMethod(request)) {
        return methodNotAllowedResponse();
      }
      return withoutResponseBodyForHead(
        request,
        await getMe(request, env, applySecurityHeaders),
      );
    }

    // --- Admin portal (allowlist + secret + PGP elevation for mutations) ---
    if (url.pathname === "/api/admin/status") {
      if (!isReadApiMethod(request)) {
        return methodNotAllowedResponse();
      }
      return withoutResponseBodyForHead(
        request,
        await adminStatus(request, env, applySecurityHeaders),
      );
    }
    if (url.pathname === "/api/admin/elevate-challenge") {
      if (request.method !== "POST") {
        return methodNotAllowedResponse();
      }
      return adminElevateChallenge(request, env, applySecurityHeaders);
    }
    if (url.pathname === "/api/admin/elevate") {
      if (request.method !== "POST") {
        return methodNotAllowedResponse();
      }
      return adminElevate(request, env, applySecurityHeaders);
    }
    if (url.pathname === "/api/admin/lookup") {
      if (!isReadApiMethod(request)) {
        return methodNotAllowedResponse();
      }
      return withoutResponseBodyForHead(
        request,
        await adminLookupUser(request, env, applySecurityHeaders),
      );
    }
    if (url.pathname === "/api/admin/grant-transit") {
      if (request.method !== "POST") {
        return methodNotAllowedResponse();
      }
      return adminGrantTransit(request, env, applySecurityHeaders);
    }
    if (url.pathname === "/api/admin/revoke-transit") {
      if (request.method !== "POST") {
        return methodNotAllowedResponse();
      }
      return adminRevokeTransit(request, env, applySecurityHeaders);
    }
    if (url.pathname === "/api/admin/claim-session") {
      if (request.method !== "POST") {
        return methodNotAllowedResponse();
      }
      return adminClaimSession(request, env, applySecurityHeaders);
    }
    if (url.pathname === "/api/admin/audit") {
      if (!isReadApiMethod(request)) {
        return methodNotAllowedResponse();
      }
      return withoutResponseBodyForHead(
        request,
        await adminListAudit(request, env, applySecurityHeaders),
      );
    }
    if (url.pathname === "/api/admin/users") {
      // GET for simple clients; POST preferred (elevated list with headers/body)
      if (request.method === "POST") {
        return adminListUsers(request, env, applySecurityHeaders);
      }
      if (!isReadApiMethod(request)) {
        return methodNotAllowedResponse();
      }
      return withoutResponseBodyForHead(
        request,
        await adminListUsers(request, env, applySecurityHeaders),
      );
    }
    if (url.pathname === "/api/admin/delete-user") {
      if (request.method !== "POST") {
        return methodNotAllowedResponse();
      }
      return adminDeleteUser(request, env, applySecurityHeaders);
    }

    // --- Stripe Payment Link + webhook entitlement ---
    if (url.pathname === "/api/billing/ensure-catalog") {
      if (request.method !== "POST" && request.method !== "GET") {
        return methodNotAllowedResponse();
      }
      return ensureBillingCatalog(request, env, applySecurityHeaders);
    }

    if (url.pathname === "/api/billing/payment-link") {
      if (!isReadApiMethod(request)) {
        return methodNotAllowedResponse();
      }
      return withoutResponseBodyForHead(
        request,
        await getPaymentLink(request, env, applySecurityHeaders),
      );
    }

    if (url.pathname === "/api/billing/access") {
      if (!isReadApiMethod(request)) {
        return methodNotAllowedResponse();
      }
      return withoutResponseBodyForHead(
        request,
        await getAccessStatus(request, env, applySecurityHeaders),
      );
    }

    if (url.pathname === "/api/billing/claim-session") {
      if (request.method !== "POST") {
        return methodNotAllowedResponse();
      }
      return claimCheckoutSession(request, env, applySecurityHeaders);
    }

    if (url.pathname === "/api/billing/webhook") {
      if (request.method !== "POST") {
        return methodNotAllowedResponse();
      }
      return handleStripeWebhook(request, env, applySecurityHeaders);
    }

    if (url.pathname === "/api/billing/payment-status") {
      if (!isReadApiMethod(request)) {
        return methodNotAllowedResponse();
      }
      return withoutResponseBodyForHead(
        request,
        await getPaymentStatus(request, env, applySecurityHeaders),
      );
    }

    const response =
      (await routePartykitRequest(request, { ...env })) ||
      new Response("Not Found", {
        status: 404,
        headers: {
          "content-type": "text/plain; charset=utf-8",
        },
      });

    return isWebSocketRequest(request)
      ? response
      : withSecurityHeaders(response, request);
  },
} satisfies ExportedHandler<Env>;
