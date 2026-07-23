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
    };

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
