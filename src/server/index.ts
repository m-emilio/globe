import { routePartykitRequest, Server } from "partyserver";
import {
  createCheckoutSession,
  ensureBillingProduct,
  getPaymentStatus,
  handleStripeWebhook,
} from "./billing";

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
const COMTRADE_EXPORT_URL =
  `${COMTRADE_API_BASE}/public/v1/preview/C/A/HS?reporterCode=${COMTRADE_REPORTER_CODE}` +
  `&period=${COMTRADE_PERIOD}&cmdCode=TOTAL&flowCode=X&partnerCode=0` +
  "&maxRecords=10&format=JSON&includeDesc=true";
const COMTRADE_IMPORT_URL =
  `${COMTRADE_API_BASE}/public/v1/preview/C/A/HS?reporterCode=${COMTRADE_REPORTER_CODE}` +
  `&period=${COMTRADE_PERIOD}&cmdCode=TOTAL&flowCode=M&partnerCode=0` +
  "&maxRecords=10&format=JSON&includeDesc=true";
const COMTRADE_AVAILABILITY_URL =
  `${COMTRADE_API_BASE}/public/v1/getDa/C/A/HS?reporterCode=${COMTRADE_REPORTER_CODE}` +
  `&period=${COMTRADE_PERIOD}`;
const COMTRADE_REFERENCES_URL =
  `${COMTRADE_API_BASE}/files/v1/app/reference/ListofReferences.json`;
const COMTRADE_REPORTERS_URL =
  `${COMTRADE_API_BASE}/files/v1/app/reference/Reporters.json`;
const COMTRADE_RETRY_DELAY_MS = 1_250;
const COMTRADE_PREVIEW_LIMIT = 5;
const TRADE_PULSE_SOURCE = "UN Comtrade Plus derived preview";
const TRADE_PULSE_API_URL = `${COMTRADE_API_BASE}/public/v1/preview/C/A/HS`;
const TRADE_PULSE_QUERY =
  "Derived global dependency radar using Comtrade reporter, partner, flow, value, CIF/FOB, mode of transport, second partner, and customs procedure fields";
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
] as const;
const OSM_MAP_ATTEMPT_MS = 9_000;
const OVERPASS_ATTEMPT_MS = 4_000;
const NEARBY_DEFAULT_RADIUS_M = 500;
const NEARBY_MIN_RADIUS_M = 250;
const NEARBY_MAX_RADIUS_M = 1000;
const NEARBY_MAX_WAYS = 90;
const NEARBY_MAX_POINTS_PER_WAY = 28;
const OSM_FETCH_RADIUS_CAP_M = 400;
const NEARBY_CACHE_SECONDS = 15 * 60;
const NEARBY_COORD_DECIMALS = 5;
const HIGHWAY_ALLOW =
  /^(motorway|trunk|primary|secondary|tertiary|unclassified|residential|living_street|service|track|footway|path|cycleway|pedestrian|steps|bridleway)$/;
const NEARBY_CACHE = new Map<
  string,
  { expiresAt: number; payload: NearbyPathsPreview }
>();
const UN_MEMBER_STATES_TOTAL = 193;
const UN_GEO_AREAS_FALLBACK_TOTAL = 460;
const UN_GLOBAL_PREVIEW_LIMIT = 100;
const SECURITY_HEADERS = {
  "content-security-policy":
    "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; " +
    "frame-src 'none'; worker-src 'none'; manifest-src 'self'; script-src 'self'; " +
    "style-src 'self' 'unsafe-inline'; img-src 'self' data: https://imagedelivery.net; " +
    "connect-src 'self' ws: wss: https://api.open-meteo.com; form-action 'self'",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "origin-agent-cluster": "?1",
  "referrer-policy": "strict-origin-when-cross-origin",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "permissions-policy": "camera=(), microphone=(), geolocation=(self)",
} satisfies Record<string, string>;

// This is the state that we'll store on each connection
type ConnectionState = {
  position: Position;
};

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
}: {
  tradeRecords: ComtradeTradeRecordPreview[];
  availability: ComtradeAvailabilityPreview[];
  references: ComtradeReferencePreview[];
  reporters: ComtradeReporterPreview[];
  referenceTablesTotal: number;
  reportersTotal: number;
  stale?: boolean;
}): ComtradePreview {
  const exportsUsd = getTradeValue(tradeRecords, "export");
  const importsUsd = getTradeValue(tradeRecords, "import");

  return {
    source: COMTRADE_SOURCE,
    sourceUrl: COMTRADE_SOURCE_URL,
    apiUrl: COMTRADE_EXPORT_URL,
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
    stale,
  };
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

function buildTradePulsePreview(): TradePulsePreview {
  return {
    source: TRADE_PULSE_SOURCE,
    sourceUrl: COMTRADE_SOURCE_URL,
    apiUrl: TRADE_PULSE_API_URL,
    updatedAt: new Date().toISOString(),
    queryLabel: TRADE_PULSE_QUERY,
    period: "2023",
    dataMode: "derived-preview",
    routes: TRADE_PULSE_ROUTES,
    metrics: buildTradePulseMetrics(TRADE_PULSE_ROUTES),
    notes: [
      "This preview is a derived scenario layer for UI testing, not literal vessel or shipment tracking.",
      "Single Supplier Dependency measures supplier concentration; Bilateral Asymmetry compares mirrored reporter and partner values.",
      "A live build would hydrate these records from Comtrade Plus fields including flow, partner, second partner, transport mode, customs procedure, CIF, FOB, quantity, and gross weight.",
    ],
  };
}

function getTradePulsePreview() {
  return jsonResponse(buildTradePulsePreview(), {
    headers: {
      "cache-control": "public, max-age=600, s-maxage=21600",
    },
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
  return "road";
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

  // ~3–4 m tolerance at mid-latitudes for thinner payloads
  let simplified = douglasPeucker(cleaned, 0.00003);
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
    roadCount: paths.filter((p) => p.kind === "road" || p.kind === "service").length,
    footCount: paths.filter((p) => p.kind === "path" || p.kind === "cycle").length,
    paths,
    ...(payload.stale ? { stale: true } : {}),
    ...(payload.note ? { note: payload.note.slice(0, 96) } : {}),
  };
}

function buildFallbackNearbyPaths(
  lat: number,
  lng: number,
  radiusM: number,
): NearbyPathsPreview {
  // Dense synthetic block grid + paths when live OSM is unavailable
  const metersPerDegLat = 111_320;
  const metersPerDegLng = 111_320 * Math.cos((lat * Math.PI) / 180) || 1;
  const toLat = (northM: number) => lat + northM / metersPerDegLat;
  const toLng = (eastM: number) => lng + eastM / metersPerDegLng;
  const arm = radiusM * 0.9;
  const block = Math.max(70, radiusM / 6);
  const paths: NearbyPathSegment[] = [];

  // North-south streets
  for (let i = -4; i <= 4; i++) {
    const x = i * block;
    if (Math.abs(x) > arm) continue;
    const major = i === 0 || i === 2 || i === -2;
    paths.push({
      id: `fb-ns-${i}`,
      name: major ? `Avenue ${Math.abs(i) + 1}` : `Street N${i}`,
      highway: major ? "secondary" : "residential",
      kind: major ? "road" : "service",
      points: [
        { lat: toLat(-arm), lng: toLng(x) },
        { lat: toLat(arm), lng: toLng(x) },
      ],
    });
  }

  // East-west streets
  for (let j = -4; j <= 4; j++) {
    const y = j * block;
    if (Math.abs(y) > arm) continue;
    const major = j === 0 || j === 3 || j === -3;
    paths.push({
      id: `fb-ew-${j}`,
      name: major ? `Boulevard ${Math.abs(j) + 1}` : `Lane E${j}`,
      highway: major ? "primary" : "residential",
      kind: "road",
      points: [
        { lat: toLat(y), lng: toLng(-arm) },
        { lat: toLat(y), lng: toLng(arm) },
      ],
    });
  }

  // Foot paths / alleys
  paths.push(
    {
      id: "fb-path-1",
      name: "Greenway",
      highway: "footway",
      kind: "path",
      points: [
        { lat: toLat(-arm * 0.55), lng: toLng(-arm * 0.35) },
        { lat: toLat(-arm * 0.1), lng: toLng(-arm * 0.05) },
        { lat: toLat(arm * 0.35), lng: toLng(arm * 0.25) },
        { lat: toLat(arm * 0.65), lng: toLng(arm * 0.55) },
      ],
    },
    {
      id: "fb-path-2",
      name: "Alley",
      highway: "footway",
      kind: "path",
      points: [
        { lat: toLat(arm * 0.2), lng: toLng(-arm * 0.7) },
        { lat: toLat(arm * 0.15), lng: toLng(-arm * 0.2) },
        { lat: toLat(-arm * 0.25), lng: toLng(arm * 0.15) },
        { lat: toLat(-arm * 0.45), lng: toLng(arm * 0.6) },
      ],
    },
    {
      id: "fb-cycle-1",
      name: "Cycle loop",
      highway: "cycleway",
      kind: "cycle",
      points: [
        { lat: toLat(arm * 0.55), lng: toLng(-arm * 0.55) },
        { lat: toLat(arm * 0.55), lng: toLng(arm * 0.55) },
        { lat: toLat(-arm * 0.55), lng: toLng(arm * 0.55) },
        { lat: toLat(-arm * 0.55), lng: toLng(-arm * 0.55) },
        { lat: toLat(arm * 0.55), lng: toLng(-arm * 0.55) },
      ],
    },
  );

  return {
    source: NEARBY_PATHS_SOURCE,
    sourceUrl: NEARBY_PATHS_SOURCE_URL,
    lat,
    lng,
    radiusM,
    updatedAt: new Date().toISOString(),
    pathCount: paths.length,
    roadCount: paths.filter((p) => p.kind === "road" || p.kind === "service").length,
    footCount: paths.filter((p) => p.kind === "path" || p.kind === "cycle").length,
    paths,
    stale: true,
    note: "Sketch mode — live OSM unavailable from this network",
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

function clipPathToRadius(
  points: Array<{ lat: number; lng: number }>,
  lat: number,
  lng: number,
  radiusM: number,
): Array<{ lat: number; lng: number }> {
  // Keep vertices inside radius; drop tiny stubs
  const kept = points.filter(
    (p) => haversineMeters(lat, lng, p.lat, p.lng) <= radiusM * 1.08,
  );
  return kept.length >= 2 ? kept : [];
}

function buildPreviewFromPaths(
  lat: number,
  lng: number,
  radiusM: number,
  paths: NearbyPathSegment[],
  note: string,
  stale = false,
): NearbyPathsPreview {
  return {
    source: NEARBY_PATHS_SOURCE,
    sourceUrl: NEARBY_PATHS_SOURCE_URL,
    lat,
    lng,
    radiusM,
    updatedAt: new Date().toISOString(),
    pathCount: paths.length,
    roadCount: paths.filter((p) => p.kind === "road" || p.kind === "service")
      .length,
    footCount: paths.filter((p) => p.kind === "path" || p.kind === "cycle")
      .length,
    paths,
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
  const nodeTagRe = /<node\b([^>]*?)\/>/g;
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
  const wayRe = /<way\b([^>]*)>([\s\S]*?)<\/way>/g;
  let wayMatch: RegExpExecArray | null;
  while ((wayMatch = wayRe.exec(xml)) !== null) {
    if (paths.length >= NEARBY_MAX_WAYS) break;

    const wayAttrs = parseXmlAttrs(wayMatch[1]);
    const body = wayMatch[2];
    const tags: Record<string, string> = {};
    const tagRe = /<tag\b([^>]*?)\/>/g;
    let tagMatch: RegExpExecArray | null;
    while ((tagMatch = tagRe.exec(body)) !== null) {
      const t = parseXmlAttrs(tagMatch[1]);
      if (t.k && t.v) tags[t.k] = t.v;
    }

    const highway = tags.highway;
    if (!highway || !HIGHWAY_ALLOW.test(highway)) continue;

    const pts: Array<{ lat: number; lng: number }> = [];
    const ndRe = /<nd\b([^>]*?)\/>/g;
    let ndMatch: RegExpExecArray | null;
    while ((ndMatch = ndRe.exec(body)) !== null) {
      const ref = parseXmlAttrs(ndMatch[1]).ref;
      if (!ref) continue;
      const node = nodes.get(ref);
      if (node) pts.push(node);
    }

    const clipped = clipPathToRadius(pts, lat, lng, radiusM);
    const simplified = simplifyGeometry(
      clipped.map((p) => ({ lat: p.lat, lon: p.lng })),
      NEARBY_MAX_POINTS_PER_WAY,
    );
    if (simplified.length < 2) continue;

    const name = (tags.name || tags.ref || highway).slice(0, 80);
    paths.push({
      id: `w${wayAttrs.id ?? paths.length}`,
      name,
      highway: highway.slice(0, 32),
      kind: classifyHighway(highway),
      points: simplified,
    });
  }

  // Prefer named / major roads first for clarity in dense areas
  const rank = (p: NearbyPathSegment) => {
    let score = 0;
    if (p.name && p.name !== p.highway) score += 3;
    if (p.kind === "road") score += 2;
    if (p.kind === "path" || p.kind === "cycle") score += 1;
    if (
      p.highway === "primary" ||
      p.highway === "secondary" ||
      p.highway === "tertiary"
    ) {
      score += 2;
    }
    return score;
  };
  paths.sort((a, b) => rank(b) - rank(a));
  return paths.slice(0, NEARBY_MAX_WAYS);
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
  for (const element of payload.elements ?? []) {
    if (element.type !== "way" || !element.geometry || !element.id) {
      continue;
    }
    const highway = element.tags?.highway ?? "";
    if (!HIGHWAY_ALLOW.test(highway)) continue;

    const raw = element.geometry
      .map((p) => ({ lat: Number(p.lat), lng: Number(p.lon) }))
      .filter((p) => Number.isFinite(p.lat) && Number.isFinite(p.lng));
    const clipped = clipPathToRadius(raw, lat, lng, radiusM);
    const points = simplifyGeometry(
      clipped.map((p) => ({ lat: p.lat, lon: p.lng })),
      NEARBY_MAX_POINTS_PER_WAY,
    );
    if (points.length < 2) continue;

    const name = (element.tags?.name || element.tags?.ref || highway).slice(0, 80);
    paths.push({
      id: `w${element.id}`,
      name,
      highway: highway.slice(0, 32),
      kind: classifyHighway(highway),
      points,
    });

    if (paths.length >= NEARBY_MAX_WAYS) break;
  }
  return paths;
}

async function fetchNearbyPathsFromOsmMapApi(
  lat: number,
  lng: number,
  radiusM: number,
): Promise<NearbyPathsPreview | null> {
  // Official OSM map API — real way geometries for a tight bbox
  const metersPerDegLat = 111_320;
  const metersPerDegLng = 111_320 * Math.cos((lat * Math.PI) / 180) || 1;
  // Tight bbox — dense cities otherwise return multi‑MB payloads
  const fetchRadius = Math.min(radiusM, OSM_FETCH_RADIUS_CAP_M);
  const dLat = fetchRadius / metersPerDegLat;
  const dLng = fetchRadius / metersPerDegLng;
  const left = lng - dLng;
  const right = lng + dLng;
  const bottom = lat - dLat;
  const top = lat + dLat;
  const bbox = `${left.toFixed(6)},${bottom.toFixed(6)},${right.toFixed(6)},${top.toFixed(6)}`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), OSM_MAP_ATTEMPT_MS);
  try {
    const response = await fetch(`${OSM_MAP_API}?bbox=${bbox}`, {
      headers: {
        accept: "application/xml, text/xml, */*",
        "user-agent":
          "Mozilla/5.0 (compatible; GlobeNearby/1.1; +https://github.com/m-emilio/globe)",
      },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!response.ok) return null;

    const xml = await response.text();
    if (!xml.includes("<osm") || xml.length < 200) return null;

    const paths = parseOsmMapXml(xml, lat, lng, radiusM);
    if (paths.length < 3) return null;

    return buildPreviewFromPaths(
      lat,
      lng,
      radiusM,
      paths,
      "Live OpenStreetMap streets & paths",
      false,
    );
  } catch {
    clearTimeout(timer);
    return null;
  }
}

async function fetchNearbyPathsFromOverpass(
  lat: number,
  lng: number,
  radiusM: number,
): Promise<NearbyPathsPreview | null> {
  const query = `
[out:json][timeout:15];
(
  way["highway"~"^(primary|secondary|tertiary|residential|unclassified|living_street|service|footway|path|cycleway|pedestrian)$"](around:${Math.min(radiusM, 700)},${lat},${lng});
);
out geom;
`.trim();

  const body = `data=${encodeURIComponent(query)}`;

  for (const endpoint of OVERPASS_ENDPOINTS) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), OVERPASS_ATTEMPT_MS);
      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded;charset=UTF-8",
          accept: "*/*",
          "user-agent":
            "Mozilla/5.0 (compatible; GlobeNearby/1.1; +https://github.com/m-emilio/globe)",
        },
        body,
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (!response.ok) continue;

      const payload = (await response.json()) as {
        elements?: Array<{
          type?: string;
          id?: number;
          tags?: Record<string, string>;
          geometry?: Array<{ lat?: number; lon?: number }>;
        }>;
      };

      const paths = parseOverpassElements(payload, lat, lng, radiusM);
      if (paths.length < 3) continue;

      return buildPreviewFromPaths(
        lat,
        lng,
        radiusM,
        paths,
        "Live Overpass streets & paths",
        false,
      );
    } catch {
      // try next mirror
    }
  }

  return null;
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

async function getTransitNearbyPreview(url: URL, env: Env) {
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
        message,
      },
      {
        status: 502,
        headers: { "cache-control": "no-store" },
      },
    );
  }
}

async function getNearbyPathsPreview(url: URL) {
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

  let payload: NearbyPathsPreview | null = null;

  // 1) Official OSM map API (most accurate when reachable)
  try {
    payload = await fetchNearbyPathsFromOsmMapApi(lat, lng, radiusM);
  } catch {
    payload = null;
  }

  // 2) Overpass mirrors (quick attempt)
  if (!payload) {
    try {
      payload = await Promise.race([
        fetchNearbyPathsFromOverpass(lat, lng, radiusM),
        new Promise<null>((resolve) => {
          setTimeout(() => resolve(null), OVERPASS_ATTEMPT_MS + 400);
        }),
      ]);
    } catch {
      payload = null;
    }
  }

  // 3) Local sketch only if live data unavailable
  if (!payload || payload.paths.length === 0) {
    payload = buildFallbackNearbyPaths(lat, lng, radiusM);
  }

  NEARBY_CACHE.set(cacheKey, {
    expiresAt: Date.now() + NEARBY_CACHE_SECONDS * 1000,
    payload,
  });

  if (NEARBY_CACHE.size > 64) {
    const first = NEARBY_CACHE.keys().next().value;
    if (first) NEARBY_CACHE.delete(first);
  }

  const compact = compactNearbyPayload(payload);

  return jsonResponse(compact, {
    headers: {
      "cache-control": compact.stale
        ? "public, max-age=60"
        : `public, max-age=${NEARBY_CACHE_SECONDS}`,
      // Encourage intermediate/browser reuse on limited Wi‑Fi
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

function applySecurityHeaders(headers: Headers) {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    if (!headers.has(name)) {
      headers.set(name, value);
    }
  }
}

function withSecurityHeaders(response: Response) {
  const headers = new Headers(response.headers);
  applySecurityHeaders(headers);

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

async function fetchComtradeJson(url: string) {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const response = await fetch(url, {
      headers: {
        accept: "application/json",
      },
      cf: {
        cacheEverything: true,
        cacheTtl: COMTRADE_CACHE_SECONDS,
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

async function fetchOptionalComtradeJson(label: string, url: string) {
  try {
    return await fetchComtradeJson(url);
  } catch (error) {
    console.warn(`Comtrade ${label} request failed`, error);
    return null;
  }
}

async function getComtradePreview() {
  const exportPayload = await fetchOptionalComtradeJson("exports", COMTRADE_EXPORT_URL);
  const importPayload = await fetchOptionalComtradeJson("imports", COMTRADE_IMPORT_URL);
  const availabilityPayload = await fetchOptionalComtradeJson(
    "availability",
    COMTRADE_AVAILABILITY_URL,
  );
  const referencesPayload = await fetchOptionalComtradeJson(
    "references",
    COMTRADE_REFERENCES_URL,
  );
  const reportersPayload = await fetchOptionalComtradeJson(
    "reporters",
    COMTRADE_REPORTERS_URL,
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

  return jsonResponse(
    buildComtradePreview({
      tradeRecords,
      availability,
      references,
      reporters,
      referenceTablesTotal,
      reportersTotal,
      stale,
    }),
    {
      headers: {
        "cache-control": stale
          ? "no-store"
          : "public, max-age=600, s-maxage=21600",
        ...(stale ? { "x-comtrade-preview": "partial-fallback" } : {}),
      },
    },
  );
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
    console.warn(`UN global ${label} request failed`, error);
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
    console.warn(`UN global ${label} request failed`, error);
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
          : "public, max-age=600, s-maxage=21600",
        ...(stale ? { "x-un-global-preview": "partial-fallback" } : {}),
      },
    },
  );
}

export class Globe extends Server {
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

  onConnect(conn: Connection<ConnectionState>, ctx: ConnectionContext) {
    // Whenever a fresh connection is made, we'll
    // send the entire state to the new connection

    // First, let's extract the position from the Cloudflare headers
    const latitude = ctx.request.cf?.latitude as string | undefined;
    const longitude = ctx.request.cf?.longitude as string | undefined;
    const lat = parseBoundedCoordinate(latitude, -90, 90);
    const lng = parseBoundedCoordinate(longitude, -180, 180);
    if (lat === null || lng === null) {
      console.warn(`Missing position information for connection ${conn.id}`);
      this.closeConnection(conn, CLOSE_POLICY_VIOLATION, "invalid location");
      return;
    }
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
      return state?.position.ip === ip;
    });

    if (ip && matchingIpConnections.length >= MAX_CONNECTIONS_PER_IP) {
      this.closeConnection(conn, CLOSE_TRY_AGAIN_LATER, "too many connections");
      return;
    }

    const country = limitText(ctx.request.cf?.country as string | undefined, 4);
    const city = limitText(ctx.request.cf?.city as string | undefined, 80);
    const org = limitText(ctx.request.cf?.org as string | undefined, 120);

    const position = {
      lat,
      lng,
      id: conn.id,
      ip,
      country,
      city,
      org,
    };
    // And save this on the connection's state
    conn.setState({
      position,
    });

    // Now, let's send the entire state to the new connection
    let replayedMarkers = 0;
    for (const connection of connections) {
      try {
        const state = connection.state as ConnectionState | undefined;

        if (!state?.position) {
          continue;
        }

        if (replayedMarkers >= MAX_REPLAY_MARKERS) {
          break;
        }

        conn.send(
          JSON.stringify({
              type: "add-marker",
              position: state.position,
        } satisfies OutgoingMessage),
      );
        replayedMarkers += 1;

        // And let's send the new connection's position to all other connections
        if (connection.id !== conn.id) {
          connection.send(
            JSON.stringify({
              type: "add-marker",
              position,
            } satisfies OutgoingMessage),
          );
        }
      } catch {
        this.onCloseOrError(connection);
      }
    }
  }

  // Whenever a connection closes (or errors), we'll broadcast a message to all
  // other connections to remove the marker.
  onCloseOrError(connection: Connection) {
    const state = connection.state as ConnectionState | undefined;

    if (!state?.position) {
      return;
    }

    this.broadcast(
      JSON.stringify({
        type: "remove-marker",
        id: connection.id,
      } satisfies OutgoingMessage),
      [connection.id],
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
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/api/comtrade-preview") {
      if (!isReadApiMethod(request)) {
        return methodNotAllowedResponse();
      }

      return withoutResponseBodyForHead(request, await getComtradePreview());
    }

    if (url.pathname === "/api/comtrade-pulse-preview") {
      if (!isReadApiMethod(request)) {
        return methodNotAllowedResponse();
      }

      return withoutResponseBodyForHead(request, getTradePulsePreview());
    }

    if (url.pathname === "/api/un-global-preview") {
      if (!isReadApiMethod(request)) {
        return methodNotAllowedResponse();
      }

      return withoutResponseBodyForHead(request, await getUnGlobalPreview());
    }

    if (url.pathname === "/api/nearby-paths") {
      if (!isReadApiMethod(request)) {
        return methodNotAllowedResponse();
      }

      return withoutResponseBodyForHead(request, await getNearbyPathsPreview(url));
    }

    if (url.pathname === "/api/transit-nearby") {
      if (!isReadApiMethod(request)) {
        return methodNotAllowedResponse();
      }

      return withoutResponseBodyForHead(
        request,
        await getTransitNearbyPreview(url, env),
      );
    }

    // --- Stripe one-time Checkout (product → session → webhook) ---
    if (url.pathname === "/api/billing/ensure-product") {
      if (request.method !== "POST" && request.method !== "GET") {
        return methodNotAllowedResponse();
      }
      return ensureBillingProduct(env, applySecurityHeaders);
    }

    if (url.pathname === "/api/billing/create-checkout-session") {
      if (request.method !== "POST") {
        return methodNotAllowedResponse();
      }
      return createCheckoutSession(request, env, applySecurityHeaders);
    }

    if (url.pathname === "/api/billing/webhook") {
      if (request.method !== "POST") {
        return methodNotAllowedResponse();
      }
      // Do not wrap with withSecurityHeaders body clone issues — handler returns JSON
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

    return isWebSocketRequest(request) ? response : withSecurityHeaders(response);
  },
} satisfies ExportedHandler<Env>;
