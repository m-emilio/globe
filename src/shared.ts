// Messages that we'll send to the client

// Representing a person's position
export type Position = {
  lat: number;
  lng: number;
  id: string;
  ip?: string;
  country?: string;
  city?: string;
  org?: string;
};

export type OutgoingMessage =
  | {
      type: "add-marker";
      position: Position;
    }
  | {
      type: "remove-marker";
      id: string;
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
  dataMode: "derived-preview";
  routes: TradePulseRoutePreview[];
  metrics: TradePulseMetricPreview[];
  notes: string[];
};

export type NearbyPathKind = "road" | "path" | "cycle" | "service";

export type NearbyPathPoint = {
  lat: number;
  lng: number;
};

export type NearbyPathSegment = {
  id: string;
  name: string;
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
