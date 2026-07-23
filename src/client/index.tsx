import "./styles.css";


import React, {
  Suspense,
  lazy,
  useState,
  useRef,
  useEffect,
  useCallback,
  useMemo,
} from "react";
import { createRoot } from "react-dom/client";
import {
  Cobe,
  type GlobeArc,
  type GlobeChoroplethRegion,
  type GlobeHeatZone,
} from "./CobeGlobe";
import { FloatingChrome } from "./FloatingChrome";
import {
  ActivityFeed,
  createActivityEvent,
  prependActivityEvent,
  type ActivityEvent,
  type ActivityFilter,
  type LiveFeedAccess,
} from "./ActivityFeed";
import usePartySocket from "partysocket/react";
import {
  clearPreviewCache,
  fetchPreviewJson,
  getPreviewCache,
  warmPreviewUrl,
} from "./previewCache";
import type {
  OutgoingMessage,
  ComtradePreview,
  NearbyPathsPreview,
  TradePulseLayer,
  TradePulsePreview,
  TradePulseRoutePreview,
  TransitNearbyPreview,
  UnGlobalPreview,
  UnodcHotspotsPreview,
  UnodcThemeId,
} from "../shared";
import {
  authFetch,
  clearLastFingerprint,
  clearSessionToken,
  containsPrivateKeyBlock,
  deleteDeviceKey,
  downloadPrivateKeyFile,
  ensureOpenPgp,
  exportPrivateKeyToArmoredFile,
  formatFingerprint,
  generateAndKeepOnDevice,
  requestPersistentDeviceStorage,
  getDeviceKey,
  getKeyGenProfile,
  getPreferredDeviceKey,
  keyGenProfilesBySafety,
  listDeviceKeys,
  preferredExportS2k,
  privateKeyIsEncrypted,
  readKeyFile,
  SAFETY_LEVEL_META,
  saveDeviceKey,
  setLastFingerprint,
  shortFingerprint,
  signChallenge,
  signInWithDeviceKey,
  S2K_PROTOCOLS,
  SYMMETRIC_CIPHERS,
  type AeadModeId,
  type DeviceKeyRecord,
  type KeyGenProfileId,
  type PrivateKeyExportEncryption,
  type PublicIdentity,
  type S2kProtocolId,
  type SymmetricCipherId,
} from "./pgpAuth";

/** Heavy panels — loaded only when opened (keeps initial shell small). */
const NearbyMap = lazy(() =>
  import("./NearbyMap").then((m) => ({ default: m.NearbyMap })),
);
const TransitPanelContent = lazy(() =>
  import("./TransitPanelContent").then((m) => ({
    default: m.TransitPanelContent,
  })),
);

/** ECDHE lab types/labels only — implementation loaded on demand via import("./ecdhe") */
type EcdheCurveId = "P-256" | "P-384" | "P-521" | "X25519";
type EcdheEphemeralPair = {
  curve: EcdheCurveId;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicKeyJwk: JsonWebKey;
  publicKeySpkiB64: string;
  createdAt: string;
};
const ECDHE_CURVE_META: Record<
  EcdheCurveId,
  { label: string; description: string; securityBits: number }
> = {
  "P-256": {
    label: "ECDHE P-256 (secp256r1)",
    description: "NIST P-256 ECDH — wide WebCrypto support.",
    securityBits: 128,
  },
  "P-384": {
    label: "ECDHE P-384",
    description: "NIST P-384 ECDH — CNSA classical key-agreement curve.",
    securityBits: 192,
  },
  "P-521": {
    label: "ECDHE P-521",
    description: "NIST P-521 ECDH — highest NIST prime curve here.",
    securityBits: 256,
  },
  X25519: {
    label: "X25519 (ECDH)",
    description:
      "Modern Montgomery ECDH. Requires a recent browser with WebCrypto X25519.",
    securityBits: 128,
  },
};
const ECDHE_CURVE_IDS = Object.keys(ECDHE_CURVE_META) as EcdheCurveId[];

async function loadEcdhe() {
  return import("./ecdhe");
}
type WeatherStatus = "idle" | "loading" | "ready" | "error";
type NearbyStatus = "idle" | "loading" | "ready" | "error";
type TransitStatus = "idle" | "loading" | "ready" | "error";

type ForecastView = "daily" | "hourly";
type ComtradeStatus = "idle" | "loading" | "ready" | "error";
type ComtradeSection = "records" | "availability" | "references" | "reporters";
type ComtradeValueMode = "compact" | "full";
type UnGlobalStatus = "idle" | "loading" | "ready" | "error";
type TradePulseStatus = "idle" | "loading" | "ready" | "error";
type UnGlobalSection =
  | "offices"
  | "activeMissions"
  | "pastMissions"
  | "memberStates"
  | "affiliates"
  | "embassies";

const DEFAULT_COMTRADE_SECTIONS: Record<ComtradeSection, boolean> = {
  records: true,
  availability: true,
  references: true,
  reporters: true,
};

const COMTRADE_SECTION_LABELS: Record<ComtradeSection, string> = {
  records: "Trade rows",
  availability: "Availability",
  references: "References",
  reporters: "Reporters",
};

const COMTRADE_SECTION_DESCRIPTIONS: Record<ComtradeSection, string> = {
  records: "sample export/import rows with partner, commodity, and value",
  availability: "dataset coverage, release windows, and total record counts",
  references: "API reference tables that explain Comtrade variables",
  reporters: "reporting economies available through Comtrade+ metadata",
};

const COMTRADE_SECTIONS: ComtradeSection[] = [
  "records",
  "availability",
  "references",
  "reporters",
];

const DEFAULT_UN_GLOBAL_SECTIONS: Record<UnGlobalSection, boolean> = {
  offices: true,
  activeMissions: true,
  pastMissions: true,
  memberStates: true,
  affiliates: true,
  embassies: true,
};

const UN_GLOBAL_SECTION_LABELS: Record<UnGlobalSection, string> = {
  offices: "HQ offices",
  activeMissions: "Active missions",
  pastMissions: "Past missions",
  memberStates: "Member states",
  affiliates: "Affiliates",
  embassies: "Embassies",
};

type UnodcStatus = "idle" | "loading" | "ready" | "error";

const UNODC_THEME_IDS /*sec-pass*/: UnodcThemeId[] = [
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
const DEFAULT_UNODC_THEMES: Record<UnodcThemeId, boolean> = {
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
const UNODC_FOCUS_THEMES: UnodcThemeId[] = [
  "homicide",
  "firearms",
  "trafficking-persons",
];

/** Versioned URL busts browser HTTP cache when server theme sources change. */
const UNODC_PREVIEW_URL = "/api/unodc-hotspots-preview?v=3";

function countLiveUnodcThemes(data: UnodcHotspotsPreview | null | undefined) {
  if (!data?.themes?.length) return 0;
  return data.themes.filter(
    (t) => t.dataMode === "live" && t.hotspotCount > 0,
  ).length;
}

/** Reject stale session/HTTP payloads that still only have the old 7 live themes. */
function isCompleteUnodcPreview(data: UnodcHotspotsPreview | null | undefined) {
  return Boolean(
    data &&
      Array.isArray(data.themes) &&
      data.themes.length >= UNODC_THEME_IDS.length &&
      countLiveUnodcThemes(data) >= UNODC_THEME_IDS.length,
  );
}

/** Vivid theme fills for choropleth (no heat glow; opacity scaled by intensity). */
const UNODC_THEME_CSS: Record<UnodcThemeId, string> = {
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
function haversineKm(
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

type UnodcHotspotLike = {
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
function clusterUnodcHotspots(
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

function buildUnodcThemeHeatZones(
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

const TRADE_PULSE_LAYERS: TradePulseLayer[] = [
  "dependency",
  "lifelines",
  "asymmetry",
  "intermediary",
  "transport",
  "friction",
  "hubs",
  "confidence",
];

const DEFAULT_TRADE_PULSE_LAYERS: Record<TradePulseLayer, boolean> = {
  dependency: true,
  lifelines: true,
  asymmetry: true,
  intermediary: true,
  transport: true,
  friction: true,
  hubs: true,
  confidence: true,
};

const TRADE_PULSE_LAYER_LABELS: Record<TradePulseLayer, string> = {
  dependency: "Single supplier dependency",
  lifelines: "Commodity lifelines",
  asymmetry: "Bilateral asymmetry alerts",
  intermediary: "Hidden intermediary signal",
  transport: "Transport mode skin",
  friction: "CIF/FOB friction",
  hubs: "Re-export hubs",
  confidence: "Data confidence",
};

const TRADE_PULSE_LAYER_SHORT_LABELS: Record<TradePulseLayer, string> = {
  dependency: "Dependency",
  lifelines: "Lifelines",
  asymmetry: "Asymmetry",
  intermediary: "Intermediary",
  transport: "Transport",
  friction: "Friction",
  hubs: "Hubs",
  confidence: "Confidence",
};

const TRADE_PULSE_LAYER_COLORS: Record<TradePulseLayer, string> = {
  dependency: "#ff3b3b",
  lifelines: "#ffd166",
  asymmetry: "#ff2fb3",
  intermediary: "#7c5cff",
  transport: "#00d9ff",
  friction: "#ff8a00",
  hubs: "#00ff88",
  confidence: "#8f99a2",
};

const TRADE_PULSE_TRANSPORT_DASHES: Record<
  TradePulseRoutePreview["transportMode"],
  string
> = {
  sea: "0",
  air: "4 7",
  rail: "10 5 2 5",
  road: "2 5",
  mixed: "12 5 4 5",
};

interface WeatherForecastDay {
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

interface WeatherForecastHour {
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

interface WeatherFeed {
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

type OpenMeteoForecastResponse = {
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

const DEFAULT_WEATHER_LOCATION = {
  latitude: 40.7128,
  longitude: -74.006,
  label: "New York, NY",
};

const WEATHER_CODE_LABELS: Record<number, string> = {
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

const LIGHTNING_WEATHER_CODES = new Set([95, 96, 99]);
const BUTTON_RATE_LIMIT_MS = 500;
const SOCKET_MESSAGE_MAX_CHARS = 4096;

function getBoundedNumber(value: unknown, min: number, max: number) {
  const number = Number(value);
  return Number.isFinite(number) && number >= min && number <= max ? number : null;
}

function getLimitedString(value: unknown, maxLength: number) {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : undefined;
}

function parseSocketMessage(data: unknown): OutgoingMessage | null {
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

function describeWeatherCode(code: number) {
  return WEATHER_CODE_LABELS[code] ?? `Weather code ${code}`;
}

function getBrowserPosition(timeoutMs = 5000) {
  return new Promise<GeolocationPosition>((resolve, reject) => {
    if (!navigator.geolocation) {
      reject(new Error("Geolocation unavailable"));
      return;
    }

    navigator.geolocation.getCurrentPosition(resolve, reject, {
      enableHighAccuracy: false,
      timeout: timeoutMs,
      maximumAge: 10 * 60 * 1000,
    });
  });
}

function buildWeatherUrl(latitude: number, longitude: number) {
  const params = new URLSearchParams({
    latitude: String(latitude),
    longitude: String(longitude),
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

function formatWeatherTime(time: string) {
  return time.replace("T", " ");
}

function getForecastNumber(values: number[] | undefined, index: number) {
  const value = Number(values?.[index]);
  return Number.isFinite(value) ? value : 0;
}

function formatForecastDay(date: string) {
  return new Intl.DateTimeFormat(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
  }).format(new Date(`${date}T12:00:00`));
}

function formatForecastHour(time: string) {
  return new Intl.DateTimeFormat(undefined, {
    weekday: "short",
    hour: "numeric",
  }).format(new Date(time));
}

function formatPreviewNumber(value: number, stale?: boolean) {
  if (stale && value === 0) {
    return "n/a";
  }

  return value.toLocaleString();
}

function formatUsd(
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

function formatSignedUsd(
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

function formatNullableUsd(
  value: number | null,
  stale?: boolean,
  valueMode: ComtradeValueMode = "compact",
) {
  return value === null ? "n/a" : formatUsd(value, stale, valueMode);
}

function formatPreviewDate(time: string) {
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

function formatPercent(value: number) {
  return `${Math.round(value)}%`;
}

function getIsTradePulsePreview() {
  const url = new URL(window.location.href);
  return (
    url.pathname === "/preview/trade-pulse" ||
    url.searchParams.get("preview") === "trade-pulse"
  );
}

function getRoutePulseLayer(
  route: TradePulseRoutePreview,
  layers: Record<TradePulseLayer, boolean>,
) {
  return route.layers.find((layer) => layers[layer]) ?? route.layers[0] ?? "dependency";
}

function getVisibleTradePulseRoutes(
  preview: TradePulsePreview | null,
  layers: Record<TradePulseLayer, boolean>,
) {
  if (!preview) {
    return [];
  }

  return preview.routes.filter((route) => route.layers.some((layer) => layers[layer]));
}

function buildTradePulsePoints(
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

function getTradePulseGlobeMarkers(
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

function buildDailyForecast(data: OpenMeteoForecastResponse): WeatherForecastDay[] {
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

function buildHourlyForecast(data: OpenMeteoForecastResponse): WeatherForecastHour[] {
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
function getWeatherGlow(weather: WeatherFeed | null): {
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

function App() {
  const isTradePulsePreview = getIsTradePulsePreview();
  const [showAbout, setShowAbout] = useState(false);
  const [showMenu, setShowMenu] = useState(false);
  const [showWeatherPanel, setShowWeatherPanel] = useState(false);
  const [weatherStatus, setWeatherStatus] = useState<WeatherStatus>("idle");
  const [weatherFeed, setWeatherFeed] = useState<WeatherFeed | null>(null);
  const [weatherError, setWeatherError] = useState("");
  const [showWeatherForecast, setShowWeatherForecast] = useState(false);
  const [forecastView, setForecastView] = useState<ForecastView>("daily");
  const [showComtradePanel, setShowComtradePanel] = useState(false);
  const [comtradeStatus, setComtradeStatus] = useState<ComtradeStatus>("idle");
  const [comtradePreview, setComtradePreview] = useState<ComtradePreview | null>(null);
  const [comtradeError, setComtradeError] = useState("");
  const [comtradeSections, setComtradeSections] = useState(DEFAULT_COMTRADE_SECTIONS);
  const [comtradeValueMode, setComtradeValueMode] =
    useState<ComtradeValueMode>("compact");
  const [showTradePulsePanel, setShowTradePulsePanel] = useState(isTradePulsePreview);
  /** Start minimized so the globe (and point + popups) stay primary */
  const [isTradePulsePanelMinimized, setIsTradePulsePanelMinimized] =
    useState(true);
  const [tradePulseStatus, setTradePulseStatus] = useState<TradePulseStatus>("idle");
  const [tradePulsePreview, setTradePulsePreview] = useState<TradePulsePreview | null>(
    null,
  );
  const [tradePulseError, setTradePulseError] = useState("");
  const [tradePulsePeriod, setTradePulsePeriod] = useState("2023");
  const [tradePulseLayers, setTradePulseLayers] = useState(DEFAULT_TRADE_PULSE_LAYERS);
  const [showUnGlobalPanel, setShowUnGlobalPanel] = useState(false);
  const [isUnGlobalPanelMinimized, setIsUnGlobalPanelMinimized] = useState(false);
  const [unGlobalStatus, setUnGlobalStatus] = useState<UnGlobalStatus>("idle");
  const [unGlobalPreview, setUnGlobalPreview] = useState<UnGlobalPreview | null>(null);
  const [unGlobalError, setUnGlobalError] = useState("");
  const [unGlobalSections, setUnGlobalSections] = useState(DEFAULT_UN_GLOBAL_SECTIONS);
  const [showUnodcPanel, setShowUnodcPanel] = useState(false);
  const [isUnodcPanelMinimized, setIsUnodcPanelMinimized] = useState(true);
  const [unodcStatus, setUnodcStatus] = useState<UnodcStatus>("idle");
  const [unodcPreview, setUnodcPreview] = useState<UnodcHotspotsPreview | null>(null);
  const [unodcError, setUnodcError] = useState("");
  const [unodcThemes, setUnodcThemes] = useState(DEFAULT_UNODC_THEMES);
  const [unodcCountryPolygons, setUnodcCountryPolygons] = useState<
    Map<string, { iso3: string; name: string; rings: [number, number][][] }> | null
  >(null);
  const [showActivityMenu, setShowActivityMenu] = useState(false);
  const [activityFilter, setActivityFilter] = useState<ActivityFilter>("all");
  const [isDisconnected, setIsDisconnected] = useState(false);
  const [isFeedPaused, setIsFeedPaused] = useState(false);
  const [isCompactFeed, setIsCompactFeed] = useState(false);
  const [isSocketConnected, setIsSocketConnected] = useState(false);
  const [counter, setCounter] = useState(0);
  const [activityFeed, setActivityFeed] = useState<ActivityEvent[]>([]);
  const [showNearbyPanel, setShowNearbyPanel] = useState(false);
  const [nearbyStatus, setNearbyStatus] = useState<NearbyStatus>("idle");
  const [nearbyPreview, setNearbyPreview] = useState<NearbyPathsPreview | null>(
    null,
  );
  const [nearbyError, setNearbyError] = useState("");
  const [nearbyRadiusM, setNearbyRadiusM] = useState(750);
  const [showTransitPanel, setShowTransitPanel] = useState(false);
  const [transitStatus, setTransitStatus] = useState<TransitStatus>("idle");
  const [transitPreview, setTransitPreview] = useState<TransitNearbyPreview | null>(
    null,
  );
  const [transitError, setTransitError] = useState("");
  const [transitDistanceM, setTransitDistanceM] = useState(800);
  const [authBusy, setAuthBusy] = useState(false);
  const [checkoutBusy, setCheckoutBusy] = useState(false);
  const [authMessage, setAuthMessage] = useState("");
  const [authError, setAuthError] = useState("");
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [showAuthPanel, setShowAuthPanel] = useState(false);
  // Prefetch OpenPGP (~380KB) only when Auth is open — not on first paint
  useEffect(() => {
    if (!showAuthPanel) return;
    void ensureOpenPgp().catch(() => {
      // Loaded on demand when user signs in / generates; ignore idle prefetch errors
    });
  }, [showAuthPanel]);
  const [authUser, setAuthUser] = useState<{
    id: string;
    fingerprint: string;
    primaryUserId: string | null;
    transitPaid: boolean;
  } | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const [adminAllowlistConfigured, setAdminAllowlistConfigured] =
    useState(false);
  const [adminSecretRequired, setAdminSecretRequired] = useState(true);
  const [adminSecretConfigured, setAdminSecretConfigured] = useState(false);
  const [showAdminPanel, setShowAdminPanel] = useState(false);
  const [adminQuery, setAdminQuery] = useState("");
  const [adminLookupUser, setAdminLookupUser] = useState<{
    id: string;
    fingerprint: string;
    primaryUserId: string | null;
    transitPaid: boolean;
    createdAt?: string;
  } | null>(null);
  const [adminSessionId, setAdminSessionId] = useState("");
  /** Memory-only — never persisted; required for grant/revoke/claim. */
  const [adminActionSecret, setAdminActionSecret] = useState("");
  /**
   * One-time reveal after Generate/Rotate. Memory only; cleared when panel closes.
   * Never written to localStorage / IndexedDB.
   */
  const [adminSecretRevealOnce, setAdminSecretRevealOnce] = useState<
    string | null
  >(null);
  /** Memory-only elevation after PGP step-up (10 min server TTL). */
  const [adminElevationToken, setAdminElevationToken] = useState<string | null>(
    null,
  );
  const [adminElevationExpiresAt, setAdminElevationExpiresAt] = useState<
    string | null
  >(null);
  const [adminNote, setAdminNote] = useState("");
  const [adminAudit, setAdminAudit] = useState<
    {
      at: string;
      action: string;
      targetUserId?: string | null;
      targetFingerprint?: string | null;
      detail?: string;
    }[]
  >([]);
  type AdminUserRow = {
    id: string;
    fingerprint: string;
    primaryUserId: string | null;
    transitPaid: boolean;
    createdAt?: string;
  };
  const [adminUsers, setAdminUsers] = useState<AdminUserRow[]>([]);
  const [adminUsersCursor, setAdminUsersCursor] = useState<string | null>(null);
  const [adminUsersComplete, setAdminUsersComplete] = useState(true);
  const [adminUsersFilter, setAdminUsersFilter] = useState<
    "all" | "paid" | "locked"
  >("all");
  const [adminBusy, setAdminBusy] = useState(false);
  const [adminMessage, setAdminMessage] = useState("");
  const [adminError, setAdminError] = useState("");
  // Register: public key in state; private key lives in device vault (IndexedDB), never uploaded
  const [regPublicKey, setRegPublicKey] = useState("");
  const [generatedPublic, setGeneratedPublic] = useState<PublicIdentity | null>(
    null,
  );
  const [keySavedAck, setKeySavedAck] = useState(false);
  const [keyGenProfile, setKeyGenProfile] =
    useState<KeyGenProfileId>("curve25519");
  const [deviceKeys, setDeviceKeys] = useState<DeviceKeyRecord[]>([]);
  const [selectedDeviceFp, setSelectedDeviceFp] = useState("");
  // Optional key passphrase — only when the *device key* is OpenPGP-encrypted
  const [keyPassphrase, setKeyPassphrase] = useState("");
  // Optional file export of the device private key (still never uploaded)
  const [exportPassphrase, setExportPassphrase] = useState("");
  const [exportPassphrase2, setExportPassphrase2] = useState("");
  const [exportCipher, setExportCipher] =
    useState<SymmetricCipherId>("aes256");
  const [exportS2k, setExportS2k] = useState<S2kProtocolId>(() =>
    preferredExportS2k(),
  );
  const [exportS2kIterByte, setExportS2kIterByte] = useState(224);
  const [exportArgonPasses, setExportArgonPasses] = useState(3);
  const [exportArgonParallel, setExportArgonParallel] = useState(4);
  const [exportArgonMemExp, setExportArgonMemExp] = useState(16);
  const [exportAead, setExportAead] = useState(false);
  const [exportAeadMode, setExportAeadMode] = useState<AeadModeId>("gcm");
  const [exportAllowUnencrypted, setExportAllowUnencrypted] = useState(false);
  const [showImportDevice, setShowImportDevice] = useState(false);
  const [importKeyText, setImportKeyText] = useState("");
  // Experimental ECDHE (ephemeral WebCrypto) — memory only, not for OpenPGP login
  const [showEcdheLab, setShowEcdheLab] = useState(false);
  const [ecdheCurve, setEcdheCurve] = useState<EcdheCurveId>("P-256");
  const [ecdheSupported, setEcdheSupported] = useState<EcdheCurveId[]>([]);
  const [ecdhePair, setEcdhePair] = useState<EcdheEphemeralPair | null>(null);
  const [ecdhePeerPub, setEcdhePeerPub] = useState("");
  const [ecdheSharedFp, setEcdheSharedFp] = useState("");
  const [ecdheBusy, setEcdheBusy] = useState(false);
  const [ecdheMessage, setEcdheMessage] = useState("");
  const [ecdheError, setEcdheError] = useState("");
  const navBarRef = useRef<HTMLElement | null>(null);

  type AuthUser = {
    id: string;
    fingerprint: string;
    primaryUserId: string | null;
    transitPaid: boolean;
  };

  const refreshAuth = async (): Promise<AuthUser | null> => {
    try {
      const response = await authFetch("/api/auth/me");
      const data = (await response.json()) as {
        authenticated?: boolean;
        user?: AuthUser | null;
        isAdmin?: boolean;
        adminActionSecretRequired?: boolean;
        adminAllowlistConfigured?: boolean;
      };
      if (data.authenticated && data.user?.fingerprint) {
        setAuthUser(data.user);
        setIsAdmin(Boolean(data.isAdmin));
        setAdminSecretRequired(Boolean(data.adminActionSecretRequired));
        setAdminAllowlistConfigured(Boolean(data.adminAllowlistConfigured));
        return data.user;
      }
      setAuthUser(null);
      setIsAdmin(false);
      setAdminSecretRequired(false);
      setAdminAllowlistConfigured(false);
      return null;
    } catch {
      setAuthUser(null);
      setIsAdmin(false);
      setAdminAllowlistConfigured(false);
      return null;
    }
  };

  const adminElevationValid = (): boolean => {
    if (!adminElevationToken || !adminElevationExpiresAt) return false;
    return new Date(adminElevationExpiresAt).getTime() > Date.now() + 5_000;
  };

  const adminHeaders = (): HeadersInit => {
    const h: Record<string, string> = {
      accept: "application/json",
      "content-type": "application/json",
    };
    if (adminActionSecret.trim()) {
      h["x-admin-action-secret"] = adminActionSecret.trim();
    }
    if (adminElevationToken) {
      h["x-admin-elevation"] = adminElevationToken;
    }
    return h;
  };

  const loadAdminAudit = async () => {
    try {
      const res = await authFetch("/api/admin/audit");
      const data = (await res.json()) as { entries?: typeof adminAudit };
      if (res.ok) setAdminAudit(data.entries || []);
    } catch {
      // ignore
    }
  };

  /**
   * Elevated directory: requires unlock + action secret (same gate as mutations).
   * Returns public fields only (no keys). Uses POST so admin headers are reliable.
   */
  const loadAdminUsers = async (opts?: {
    append?: boolean;
    cursor?: string | null;
  }) => {
    setAdminBusy(true);
    setAdminError("");
    try {
      if (!adminElevationValid()) {
        throw new Error("Unlock privileges first (PGP step-up).");
      }
      if (!adminActionSecret.trim()) {
        throw new Error("Enter ADMIN_ACTION_SECRET to list all users.");
      }
      const res = await authFetch("/api/admin/users", {
        method: "POST",
        headers: adminHeaders(),
        body: JSON.stringify({
          limit: 100,
          cursor: opts?.cursor ?? null,
          paid: adminUsersFilter === "paid",
          locked: adminUsersFilter === "locked",
        }),
      });
      const data = (await res.json()) as {
        users?: AdminUserRow[];
        cursor?: string | null;
        complete?: boolean;
        count?: number;
        message?: string;
        error?: string;
      };
      if (!res.ok) {
        const code = data.error || "";
        if (code === "rate_limited") {
          throw new Error(
            "Too many admin list requests. Wait about a minute, then Load users again.",
          );
        }
        if (code === "elevation_expired" || code === "elevation_required") {
          throw new Error(
            "Admin elevation expired. Unlock privileges (PGP step-up) again, then Load users.",
          );
        }
        if (code === "admin_secret_required") {
          throw new Error(
            "Action secret rejected. Paste the current ADMIN_ACTION_SECRET Worker secret, then retry.",
          );
        }
        throw new Error(data.message || data.error || "Could not list users");
      }
      const next = data.users || [];
      setAdminUsers((prev) => {
        const merged = opts?.append ? [...prev, ...next] : next;
        // Dedupe by id (pagination / filter rescans can overlap)
        const seen = new Set<string>();
        const deduped = merged.filter((u) => {
          if (!u?.id || seen.has(u.id)) return false;
          seen.add(u.id);
          return true;
        });
        setAdminMessage(
          `Loaded ${deduped.length} user(s)${
            data.complete === false ? " (more available)" : ""
          }.`,
        );
        return deduped;
      });
      setAdminUsersCursor(data.cursor ?? null);
      setAdminUsersComplete(Boolean(data.complete ?? true));
      try {
        await loadAdminAudit();
      } catch {
        // list still succeeds if audit refresh fails
      }
    } catch (error) {
      setAdminError(
        error instanceof Error ? error.message : "List users failed",
      );
    } finally {
      setAdminBusy(false);
    }
  };

  /** Permanently remove a user (elevated). Confirms in the browser first. */
  const adminDeleteUser = async (target?: AdminUserRow | null) => {
    const user = target || adminLookupUser;
    if (!user) {
      setAdminError("Select or lookup a user before removing.");
      return;
    }
    const short = user.id.slice(0, 12);
    const ok = window.confirm(
      `Permanently DELETE user ${short}…?\n\nFingerprint: ${user.fingerprint}\nThis revokes sessions and removes the account from the app. Cannot be undone.`,
    );
    if (!ok) return;

    setAdminBusy(true);
    setAdminError("");
    setAdminMessage("");
    try {
      if (!adminElevationValid()) {
        throw new Error("Unlock privileges first (PGP step-up).");
      }
      if (!adminActionSecret.trim()) {
        throw new Error("Enter ADMIN_ACTION_SECRET before deleting users.");
      }
      const res = await authFetch("/api/admin/delete-user", {
        method: "POST",
        headers: adminHeaders(),
        body: JSON.stringify({
          userId: user.id,
          fingerprint: user.fingerprint,
          confirm: "DELETE",
        }),
      });
      const data = (await res.json()) as {
        ok?: boolean;
        message?: string;
        error?: string;
      };
      if (!res.ok) {
        throw new Error(data.message || data.error || "Delete failed");
      }
      setAdminLookupUser(null);
      setAdminUsers((prev) => prev.filter((u) => u.id !== user.id));
      setAdminMessage(data.message || "User deleted.");
      await loadAdminAudit();
    } catch (error) {
      setAdminError(
        error instanceof Error ? error.message : "Delete user failed",
      );
    } finally {
      setAdminBusy(false);
    }
  };

  const clearAdminElevation = () => {
    setAdminElevationToken(null);
    setAdminElevationExpiresAt(null);
    setAdminUsers([]);
    setAdminUsersCursor(null);
    setAdminUsersComplete(true);
  };

  /**
   * PGP step-up: sign a server challenge with the device private key.
   * Does NOT need the action secret — that is only checked on grant/revoke/claim
   * and on rotate when a secret already exists. Private key never leaves the browser.
   */
  const unlockAdminPrivileges = async () => {
    setAdminBusy(true);
    setAdminError("");
    setAdminMessage("");
    try {
      if (!authUser) throw new Error("Sign in first.");

      const chalRes = await authFetch("/api/admin/elevate-challenge", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      const chal = (await chalRes.json()) as {
        challengeId?: string;
        message?: string;
        error?: string;
      };
      if (!chalRes.ok || !chal.challengeId || !chal.message) {
        throw new Error(
          chal.message ||
            chal.error ||
            "Could not start admin elevation. Sign in with an allowlisted admin key.",
        );
      }

      const dk =
        (await getDeviceKey(authUser.fingerprint)) ||
        (await getPreferredDeviceKey());
      if (!dk) {
        throw new Error(
          "No device private key on this browser for your admin fingerprint. Import the key onto this device first.",
        );
      }
      if (
        dk.fingerprint.replace(/[\s:]/g, "").toLowerCase() !==
        authUser.fingerprint.replace(/[\s:]/g, "").toLowerCase()
      ) {
        throw new Error(
          "Device key fingerprint does not match the signed-in admin account.",
        );
      }

      const signatureArmored = await signChallenge(
        chal.message,
        dk.privateKeyArmored,
        dk.encrypted ? keyPassphrase || undefined : undefined,
      );

      const elevRes = await authFetch("/api/admin/elevate", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          challengeId: chal.challengeId,
          signatureArmored,
        }),
      });
      const elev = (await elevRes.json()) as {
        elevationToken?: string;
        expiresAt?: string;
        message?: string;
        error?: string;
      };
      if (!elevRes.ok || !elev.elevationToken) {
        throw new Error(
          elev.message || elev.error || "Elevation signature rejected",
        );
      }

      setAdminElevationToken(elev.elevationToken);
      setAdminElevationExpiresAt(elev.expiresAt || null);
      setAdminMessage(
        elev.message ||
          "Privileged window unlocked (~10 min). Grant / revoke / claim now available.",
      );
      await loadAdminAudit();
    } catch (error) {
      clearAdminElevation();
      setAdminError(
        error instanceof Error ? error.message : "Could not unlock privileges",
      );
    } finally {
      setAdminBusy(false);
    }
  };

  /**
   * Generate a strong action-secret candidate in the browser only.
   * Never sent to the server for storage. Operator must set it as a Cloudflare
   * Worker secret (wrangler secret put ADMIN_ACTION_SECRET) for the server to accept it.
   * Memory-only reveal for this panel — no localStorage / IndexedDB.
   */
  const generateAdminActionSecret = () => {
    setAdminError("");
    setAdminSecretRevealOnce(null);
    try {
      if (!isAdmin) {
        throw new Error("Admin only.");
      }
      const bytes = new Uint8Array(32);
      crypto.getRandomValues(bytes);
      const secret = [...bytes]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      // Memory only — never persisted client-side or uploaded for storage.
      setAdminActionSecret(secret);
      setAdminSecretRevealOnce(secret);
      setAdminMessage(
        "Generated in this browser only. Copy it, then set as a Worker secret: npx wrangler secret put ADMIN_ACTION_SECRET --name globe  (and the same for local .dev.vars). Server never stores this from the UI.",
      );
    } catch (error) {
      setAdminError(
        error instanceof Error ? error.message : "Generate secret failed",
      );
    }
  };

  const openAdminPanel = async () => {
    setShowMenu(false);
    setAdminError("");
    setAdminMessage("");
    setAdminSecretRevealOnce(null);
    clearAdminElevation();
    const user = await refreshAuth();
    if (!user) {
      setShowAuthPanel(true);
      setAuthMode("login");
      setAuthMessage("Sign in with your admin key to open Admin.");
      return;
    }
    try {
      const res = await authFetch("/api/auth/me");
      const data = (await res.json()) as {
        isAdmin?: boolean;
        adminAllowlistConfigured?: boolean;
        adminActionSecretRequired?: boolean;
      };
      setIsAdmin(Boolean(data.isAdmin));
      setAdminAllowlistConfigured(Boolean(data.adminAllowlistConfigured));
      setAdminSecretRequired(Boolean(data.adminActionSecretRequired));
      if (!data.isAdmin) {
        const fp = formatFingerprint(user.fingerprint);
        const hex = user.fingerprint.replace(/[\s:]/g, "").toLowerCase();
        setAdminError(
          !data.adminAllowlistConfigured
            ? `No admin allowlist on the server. Set Cloudflare secret ADMIN_FINGERPRINTS to your fingerprint (no spaces):\n${hex}`
            : `This signed-in key is not on ADMIN_FINGERPRINTS.\n\nYour full fingerprint (copy into Cloudflare Worker secret ADMIN_FINGERPRINTS):\n${hex}\n\nFormatted:\n${fp}`,
        );
        // Still open panel so the message + fingerprint are visible
        setShowAdminPanel(true);
        return;
      }
    } catch {
      setAdminError("Could not verify admin status. Try signing out and back in.");
      setShowAdminPanel(true);
      return;
    }
    try {
      const st = await authFetch("/api/admin/status");
      const stData = (await st.json()) as {
        actionSecretConfigured?: boolean;
        actionSecretRequired?: boolean;
        error?: string;
        message?: string;
      };
      if (st.ok) {
        setAdminSecretConfigured(Boolean(stData.actionSecretConfigured));
        setAdminSecretRequired(Boolean(stData.actionSecretRequired ?? true));
      } else {
        setAdminError(
          stData.message ||
            stData.error ||
            "Admin status denied by server (allowlist or session).",
        );
      }
    } catch {
      // ignore
    }
    setShowAdminPanel(true);
    if (isAdmin || true) {
      // load audit only when server allows (fails closed otherwise)
      try {
        await loadAdminAudit();
      } catch {
        // ignore
      }
    }
  };

  const adminLookup = async () => {
    setAdminBusy(true);
    setAdminError("");
    setAdminMessage("");
    try {
      const res = await authFetch(
        `/api/admin/lookup?q=${encodeURIComponent(adminQuery.trim())}`,
      );
      const data = (await res.json()) as {
        found?: boolean;
        user?: typeof adminLookupUser;
        message?: string;
        error?: string;
      };
      if (!res.ok) {
        throw new Error(data.message || data.error || "Lookup failed");
      }
      setAdminLookupUser(data.found ? data.user || null : null);
      setAdminMessage(data.found ? "User found." : "No user matched that query.");
    } catch (error) {
      setAdminError(error instanceof Error ? error.message : "Lookup failed");
    } finally {
      setAdminBusy(false);
    }
  };

  const adminGrant = async (grant: boolean) => {
    setAdminBusy(true);
    setAdminError("");
    setAdminMessage("");
    try {
      const target = adminLookupUser;
      if (!target) throw new Error("Lookup a user first.");
      if (!adminElevationValid()) {
        throw new Error(
          "Unlock privileges first (PGP step-up). Grant/revoke need a fresh elevation.",
        );
      }
      if (!adminActionSecret.trim()) {
        throw new Error("Enter ADMIN_ACTION_SECRET before mutating.");
      }
      const res = await authFetch(
        grant ? "/api/admin/grant-transit" : "/api/admin/revoke-transit",
        {
          method: "POST",
          headers: adminHeaders(),
          body: JSON.stringify({
            userId: target.id,
            fingerprint: target.fingerprint,
            note: adminNote.trim() || undefined,
          }),
        },
      );
      const data = (await res.json()) as {
        user?: typeof adminLookupUser;
        message?: string;
        error?: string;
      };
      if (!res.ok) {
        throw new Error(data.message || data.error || "Action failed");
      }
      if (data.user) setAdminLookupUser(data.user);
      setAdminMessage(data.message || (grant ? "Granted." : "Revoked."));
      await loadAdminAudit();
      if (authUser && data.user && data.user.id === authUser.id) {
        await refreshAuth();
      }
    } catch (error) {
      setAdminError(error instanceof Error ? error.message : "Action failed");
    } finally {
      setAdminBusy(false);
    }
  };

  const adminClaim = async () => {
    setAdminBusy(true);
    setAdminError("");
    setAdminMessage("");
    try {
      if (!adminElevationValid()) {
        throw new Error(
          "Unlock privileges first (PGP step-up). Claim needs a fresh elevation.",
        );
      }
      if (!adminActionSecret.trim()) {
        throw new Error("Enter ADMIN_ACTION_SECRET before claiming.");
      }
      const res = await authFetch("/api/admin/claim-session", {
        method: "POST",
        headers: adminHeaders(),
        body: JSON.stringify({
          session_id: adminSessionId.trim(),
          userId: adminLookupUser?.id,
          fingerprint: adminLookupUser?.fingerprint,
        }),
      });
      const data = (await res.json()) as {
        user?: typeof adminLookupUser;
        message?: string;
        error?: string;
        paymentStatus?: string;
      };
      if (!res.ok) {
        throw new Error(data.message || data.error || "Claim failed");
      }
      if (data.user) setAdminLookupUser(data.user);
      setAdminMessage(
        `Claimed session (${data.paymentStatus || "paid"}). Transit granted.`,
      );
      await loadAdminAudit();
      if (authUser && data.user && data.user.id === authUser.id) {
        await refreshAuth();
      }
    } catch (error) {
      setAdminError(error instanceof Error ? error.message : "Claim failed");
    } finally {
      setAdminBusy(false);
    }
  };

  const refreshDeviceKeys = async () => {
    try {
      const keys = await listDeviceKeys();
      setDeviceKeys(keys);
      if (!selectedDeviceFp && keys[0]) {
        setSelectedDeviceFp(keys[0].fingerprint);
      }
    } catch {
      setDeviceKeys([]);
    }
  };

  const selectedDeviceKey =
    deviceKeys.find((k) => k.fingerprint === selectedDeviceFp) || null;

  const clearSensitiveAuthState = () => {
    setKeyPassphrase("");
    setExportPassphrase("");
    setExportPassphrase2("");
    setImportKeyText("");
    setGeneratedPublic(null);
    setKeySavedAck(false);
  };

  const buildExportEncryption = (): PrivateKeyExportEncryption | null => {
    if (exportAllowUnencrypted && !exportPassphrase) {
      return null;
    }
    if (!exportPassphrase) {
      throw new Error(
        "Set an export passphrase (or allow unencrypted export).",
      );
    }
    if (exportPassphrase !== exportPassphrase2) {
      throw new Error("Export passphrases do not match.");
    }
    return {
      passphrase: exportPassphrase,
      cipher: exportCipher,
      s2k: exportS2k,
      s2kIterationCountByte: exportS2kIterByte,
      argon2: {
        passes: exportArgonPasses,
        parallelism: exportArgonParallel,
        memoryExponent: exportArgonMemExp,
      },
      aeadProtect: exportAead,
      aeadMode: exportAeadMode,
    };
  };

  /**
   * Create identity on this device:
   * - private key stays in IndexedDB (never uploaded)
   * - OpenPGP layer unencrypted by default → login needs no password
   * - At rest: AES-GCM wrapped with non-extractable device-bound WebCrypto key
   */
  const refreshEcdheSupport = async () => {
    try {
      const { listSupportedEcdheCurves } = await loadEcdhe();
      const list = await listSupportedEcdheCurves();
      const ids = list.map((c) => c.id);
      setEcdheSupported(ids);
      if (ids.length && !ids.includes(ecdheCurve)) {
        setEcdheCurve(ids[0]!);
      }
    } catch {
      setEcdheSupported([]);
    }
  };

  const handleEcdheGenerate = async () => {
    setEcdheBusy(true);
    setEcdheError("");
    setEcdheMessage("");
    setEcdheSharedFp("");
    try {
      const { generateEcdheKeyPair } = await loadEcdhe();
      const pair = await generateEcdheKeyPair(ecdheCurve);
      setEcdhePair(pair);
      setEcdheMessage(
        `Ephemeral ${ECDHE_CURVE_META[ecdheCurve].label} key pair ready. Private key is non-extractable in memory only (not for OpenPGP login). Share the public SPKI/JWK with a peer, then derive.`,
      );
    } catch (error) {
      setEcdhePair(null);
      setEcdheError(
        error instanceof Error ? error.message : "ECDHE generate failed",
      );
    } finally {
      setEcdheBusy(false);
    }
  };

  const handleEcdheDerive = async () => {
    setEcdheBusy(true);
    setEcdheError("");
    setEcdheMessage("");
    try {
      if (!ecdhePair) {
        throw new Error("Generate a local ephemeral key pair first.");
      }
      const { importEcdhePeerPublicKey, deriveEcdheSession } = await loadEcdhe();
      const peer = await importEcdhePeerPublicKey(
        ecdhePair.curve,
        ecdhePeerPub,
      );
      const derived = await deriveEcdheSession(
        ecdhePair.privateKey,
        peer,
        ecdhePair.curve,
      );
      setEcdheSharedFp(derived.sharedSecretSha256Hex);
      setEcdheMessage(
        `ECDHE shared secret agreed (${derived.sharedBitsLength}-bit field). Showing SHA-256 fingerprint only; AES-GCM session key is non-extractable in memory.`,
      );
    } catch (error) {
      setEcdheSharedFp("");
      setEcdheError(
        error instanceof Error ? error.message : "ECDHE derive failed",
      );
    } finally {
      setEcdheBusy(false);
    }
  };

  const handleEcdheSelfTest = async () => {
    setEcdheBusy(true);
    setEcdheError("");
    setEcdheMessage("");
    try {
      const { ecdheSelfTest } = await loadEcdhe();
      const result = await ecdheSelfTest(ecdheCurve);
      setEcdheSharedFp(result.sharedSecretSha256Hex);
      setEcdheMessage(
        `Self-test passed for ${result.curve}: both parties derived the same shared fingerprint.`,
      );
    } catch (error) {
      setEcdheSharedFp("");
      setEcdheError(
        error instanceof Error ? error.message : "ECDHE self-test failed",
      );
    } finally {
      setEcdheBusy(false);
    }
  };

  const handleGenerateKeypair = async () => {
    setAuthBusy(true);
    setAuthError("");
    try {
      await requestPersistentDeviceStorage();
      const result = await generateAndKeepOnDevice({
        profile: keyGenProfile,
      });
      setGeneratedPublic(result.public);
      setRegPublicKey(result.public.publicKeyArmored);
      setSelectedDeviceFp(result.deviceKey.fingerprint);
      setKeySavedAck(true); // device already holds the key
      await refreshDeviceKeys();
      // Confirm vault can list the key (mobile storage races)
      const listed = await listDeviceKeys();
      const found = listed.some(
        (k) =>
          k.fingerprint.replace(/[\s:]/g, "").toLowerCase() ===
          result.deviceKey.fingerprint.replace(/[\s:]/g, "").toLowerCase(),
      );
      if (!found) {
        throw new Error(
          "Key was generated but is not visible in this browser’s vault yet. Leave private mode, allow site data, and tap Generate again — or download a backup .asc.",
        );
      }
      setAuthMessage(
        `Created ${result.profileLabel} on this device. Private key never leaves the browser; stored device-bound (AES-wrapped). Next: tap Register & stay signed in (public key only) — required before Sign in works.`,
      );
    } catch (error) {
      setAuthError(
        error instanceof Error ? error.message : "Key generation failed",
      );
    } finally {
      setAuthBusy(false);
    }
  };

  /** Optional: export device private key to a file (still never uploaded). */
  const handleExportPrivateKey = async () => {
    setAuthBusy(true);
    setAuthError("");
    try {
      const dk =
        selectedDeviceKey ||
        (generatedPublic
          ? await getDeviceKey(generatedPublic.fingerprint)
          : null);
      if (!dk) {
        throw new Error("No device key to export. Generate one first.");
      }
      const encryption = buildExportEncryption();
      const result = await exportPrivateKeyToArmoredFile({
        privateKeyArmored: dk.privateKeyArmored,
        sourcePassphrase: dk.encrypted
          ? keyPassphrase || undefined
          : undefined,
        encryption,
      });
      downloadPrivateKeyFile(result.armored, result.filename);
      // Device vault stays device-bound (AES wrap). Backup file may add OpenPGP passphrase.
      setAuthMessage(
        `Backup saved as ${result.filename} (${result.encrypted ? "passphrase-encrypted" : "UNENCRYPTED"}).${result.notice ? ` ${result.notice}` : ""} Device vault key unchanged for sign-in.`,
      );
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Export failed");
    } finally {
      setAuthBusy(false);
    }
  };

  const registerWithPublicKey = async () => {
    setAuthBusy(true);
    setAuthError("");
    setAuthMessage("");
    try {
      const publicKeyArmored = regPublicKey.trim();
      if (!publicKeyArmored) {
        throw new Error("Generate a device key first (or paste a public key).");
      }
      if (containsPrivateKeyBlock(publicKeyArmored)) {
        throw new Error("Never paste a private key into registration.");
      }

      const response = await authFetch("/api/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ publicKeyArmored }),
      });
      const data = (await response.json()) as {
        user?: AuthUser;
        sessionToken?: string;
        isAdmin?: boolean;
        adminActionSecretRequired?: boolean;
        message?: string;
        error?: string;
      };
      if (!response.ok || !data.user) {
        throw new Error(data.message || data.error || "Registration failed");
      }
      // Session is HttpOnly cookie from Set-Cookie — never store sessionToken in JS.
      clearSessionToken();
      setLastFingerprint(data.user.fingerprint);
      setSelectedDeviceFp(data.user.fingerprint);
      setGeneratedPublic(null);
      setRegPublicKey("");
      // Re-fetch /me so cookie + admin/transit flags settle (mobile ITP / WebViews).
      const me = await refreshAuth();
      if (!me) {
        setAuthUser(null);
        setIsAdmin(false);
        setAuthMessage(
          "Public key registered, but this browser blocked the session cookie. Allow cookies for this site (not private mode / not an in-app browser), then use Sign in → Continue with device key.",
        );
        setAuthMode("login");
        await refreshDeviceKeys();
        return;
      }
      setAuthUser(me);
      setIsAdmin(Boolean(data.isAdmin));
      setAdminSecretRequired(Boolean(data.adminActionSecretRequired));
      setShowAuthPanel(false);
      setAuthMessage(
        "Registered. You are signed in. Next visits: open Sign in → Continue with device key (no private key upload).",
      );
    } catch (error) {
      setAuthError(
        error instanceof Error ? error.message : "Registration failed",
      );
    } finally {
      setAuthBusy(false);
    }
  };

  /** Sign in with key already on this device — never uploads the private key. */
  const handleDeviceSignIn = async () => {
    setAuthBusy(true);
    setAuthError("");
    setAuthMessage("");
    try {
      const dk =
        selectedDeviceKey ||
        (await getPreferredDeviceKey()) ||
        null;
      if (!dk) {
        throw new Error(
          "No device key on this browser. Create one under Create identity, or import a backup onto this device once.",
        );
      }
      const result = await signInWithDeviceKey({
        deviceKey: dk,
        passphrase: dk.encrypted ? keyPassphrase || undefined : undefined,
      });
      setAuthUser(result.user);
      setIsAdmin(result.isAdmin);
      setAdminSecretRequired(result.adminActionSecretRequired);
      setSelectedDeviceFp(result.user.fingerprint);
      setKeyPassphrase("");
      setShowAuthPanel(false);
      // Confirm admin allowlist + transit flags from server after cookie/token settle.
      await refreshAuth();
      setAuthMessage(
        dk.encrypted
          ? "Signed in with passphrase-protected device key (cookie session; key stays on device)."
          : dk.deviceBound
            ? "Signed in with device-bound key (AES-wrapped at rest; HttpOnly cookie session)."
            : "Signed in with device key — no password, no private key upload.",
      );
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Sign-in failed");
    } finally {
      setAuthBusy(false);
    }
  };

  /** Import a private key onto this device once (for a new browser). Never uploaded. */
  const handleImportDeviceKey = async (file?: File | null) => {
    setAuthBusy(true);
    setAuthError("");
    try {
      await requestPersistentDeviceStorage();
      let text = importKeyText.trim();
      if (file) {
        text = await readKeyFile(file);
      }
      if (!containsPrivateKeyBlock(text)) {
        throw new Error("That is not an OpenPGP private key.");
      }
      const encrypted = await privateKeyIsEncrypted(text);
      const openpgpMod = await import("openpgp");
      const priv = await openpgpMod.readPrivateKey({ armoredKey: text });
      const fingerprint = priv
        .getFingerprint()
        .toLowerCase()
        .replace(/[\s:]/g, "");
      const publicKeyArmored = priv.toPublic().armor();
      await saveDeviceKey({
        fingerprint,
        publicKeyArmored,
        privateKeyArmored: text,
        encrypted,
        profileLabel: "Imported",
      });
      setImportKeyText("");
      setShowImportDevice(false);
      setSelectedDeviceFp(fingerprint);
      await refreshDeviceKeys();
      setAuthMessage(
        encrypted
          ? "Imported encrypted key onto this device. Sign-in asks for the key passphrase only. If the key is new to this site, Register the public key once first."
          : "Imported key onto this device. Sign-in needs no password. If the key is new to this site, Register the public key once first.",
      );
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Import failed");
    } finally {
      setAuthBusy(false);
    }
  };

  const handleRemoveDeviceKey = async (fp: string) => {
    await deleteDeviceKey(fp);
    await refreshDeviceKeys();
    setAuthMessage("Removed key from this device only (server account unchanged).");
  };

  const logout = async (allSessions = false) => {
    setAuthBusy(true);
    setAuthError("");
    try {
      await authFetch("/api/auth/logout", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ all: allSessions }),
      });
      setAuthUser(null);
      setIsAdmin(false);
      setShowAdminPanel(false);
      clearAdminElevation();
      setAdminActionSecret("");
      setAdminSecretRevealOnce(null);
      clearSessionToken();
      clearLastFingerprint(); // localStorage remember — not browser “cache”
      clearSensitiveAuthState();
      setActivityFeed([]);
      activeVisitors.current.clear();
      setAuthMessage(
        allSessions
          ? "Logged out of all sessions. Device key still on this browser for next sign-in."
          : "Logged out. Session cleared. Device key still on this browser for next sign-in (clear site data to remove keys).",
      );
      setTransitPreview(null);
      setTransitStatus("idle");
      setNearbyPreview(null);
      setNearbyStatus("idle");
    } catch {
      setAuthError("Logout failed");
    } finally {
      setAuthBusy(false);
    }
  };

  /**
   * Stripe Payment Link checkout for paid API access (Transit + Live Feed).
   * Requires an active session so the server can bind client_reference_id.
   * Guests never receive a payment URL — only a sign-in prompt.
   */
  const startTransitCheckout = async () => {
    setAuthError("");
    setAuthMessage("");

    if (!authUser) {
      setShowMenu(false);
      setShowAuthPanel(true);
      setAuthMode("login");
      setAuthMessage("Sign in first, then buy Stripe access ($20).");
      return;
    }
    if (authUser.transitPaid) {
      setAuthMessage(
        "Stripe access already unlocked (Transit + Live Feed).",
      );
      return;
    }

    setCheckoutBusy(true);
    setShowMenu(false);
    try {
      await authFetch("/api/billing/ensure-catalog", { method: "POST" });
      const response = await authFetch("/api/billing/payment-link");
      const data = (await response.json()) as {
        url?: string | null;
        amountLabel?: string;
        message?: string;
        error?: string;
      };
      if (!response.ok || !data.url) {
        throw new Error(
          data.message || data.error || "Payment link unavailable",
        );
      }
      // Only allow same-origin-configured Stripe Payment Link hosts.
      let checkoutUrl: URL;
      try {
        checkoutUrl = new URL(data.url);
      } catch {
        throw new Error("Invalid payment link from server");
      }
      if (
        checkoutUrl.protocol !== "https:" ||
        !(
          checkoutUrl.hostname === "buy.stripe.com" ||
          checkoutUrl.hostname === "checkout.stripe.com"
        )
      ) {
        throw new Error("Unexpected payment link host");
      }
      setAuthMessage("Redirecting to Stripe Checkout…");
      window.location.href = checkoutUrl.toString();
    } catch (error) {
      setAuthError(
        error instanceof Error ? error.message : "Could not start checkout",
      );
      setCheckoutBusy(false);
    }
  };

  useEffect(() => {
    void refreshDeviceKeys();
  }, []);

  const positions = useRef<
    Map<
      string,
      {
        location: [number, number];
        size: number;
      }
    >
  >(new Map());
  const activeVisitors = useRef<Map<string, ActivityEvent>>(new Map());
  const isFeedPausedRef = useRef(false);
  /** Server only sends feed-* when paid; this gates client-side record as well */
  const liveFeedUnlockedRef = useRef(false);
  const lastButtonClickAt = useRef(0);
  const lastButtonClicks = useRef<Map<string, number>>(new Map());

  // UI lock + client-side record gate. Server also withholds feed-* unless transitPaid.
  const liveFeedAccess: LiveFeedAccess = !authUser
    ? "login_required"
    : authUser.transitPaid
      ? "ok"
      : "payment_required";

  useEffect(() => {
    isFeedPausedRef.current = isFeedPaused;
  }, [isFeedPaused]);

  useEffect(() => {
    liveFeedUnlockedRef.current = liveFeedAccess === "ok";
    if (liveFeedAccess !== "ok") {
      setActivityFeed([]);
      activeVisitors.current.clear();
    }
  }, [liveFeedAccess]);

  // Session restore, URL auth_token handoff, optional Stripe return
  useEffect(() => {
    void (async () => {
      const params = new URLSearchParams(window.location.search);
      // One-shot URL handoff → adopt into HttpOnly cookie, never keep token in JS storage.
      const urlToken = params.get("auth_token") || params.get("session_token");
      if (urlToken && /^[a-f0-9]{32,128}$/i.test(urlToken)) {
        clearSessionToken();
        try {
          await authFetch("/api/auth/adopt-token", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ sessionToken: urlToken }),
          });
        } catch {
          // cookie may still work on /me
        }
        params.delete("auth_token");
        params.delete("session_token");
        const next = `${window.location.pathname}${params.toString() ? `?${params}` : ""}${window.location.hash}`;
        window.history.replaceState({}, "", next);
        setAuthMessage(
          "Session adopted into HttpOnly cookie (not stored in the page).",
        );
      }
      clearSessionToken();
      await refreshAuth();
    })();

    const params = new URLSearchParams(window.location.search);
    const billing = params.get("billing");
    // Stripe Payment Link can return session_id even without billing=success if only {CHECKOUT_SESSION_ID} is used
    const sessionId = params.get("session_id");

    if (billing === "cancel") {
      setAuthMessage("Checkout canceled — no charge was made.");
      setAuthError("");
    }

    // Unlock without Stripe CLI: claim paid Checkout Session after redirect
    if (sessionId && /^cs_[a-zA-Z0-9_]+$/.test(sessionId)) {
      setAuthMessage("Payment submitted. Confirming access…");
      setAuthError("");
      void (async () => {
        try {
          const claimRes = await authFetch("/api/billing/claim-session", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ session_id: sessionId }),
          });
          const claimData = (await claimRes.json()) as {
            message?: string;
            error?: string;
          };
          const user = await refreshAuth();
          if (user?.transitPaid) {
            setAuthMessage(
              "Payment confirmed — Transit, Nearby maps, and Live Feed unlocked. Refreshing…",
            );
            // Reconnect WebSocket so server re-evaluates feedPaid from session cookie
            window.setTimeout(() => {
              window.location.reload();
            }, 600);
          } else if (!claimRes.ok) {
            setAuthError(
              claimData.message ||
                claimData.error ||
                "Could not claim payment. Stay signed in with the same account you used at checkout.",
            );
            setAuthMessage("");
          } else {
            setAuthMessage(
              "Payment return received. If still locked, wait a moment and hard-refresh.",
            );
          }
        } catch {
          setAuthError(
            "Payment return handling failed. Try Buy access again if still locked.",
          );
        }
      })();
    }

    params.delete("billing");
    params.delete("session_id");
    const next = `${window.location.pathname}${params.toString() ? `?${params}` : ""}${window.location.hash}`;
    window.history.replaceState({}, "", next);
  }, []);

  // Keep menu/panel offsets in sync with the real nav height (prevents overlap/clipping on mobile)
  useEffect(() => {
    const nav = navBarRef.current;
    if (!nav || typeof ResizeObserver === "undefined") {
      return;
    }

    const publishNavHeight = () => {
      const height = Math.ceil(nav.getBoundingClientRect().height);
      if (height > 0) {
        document.documentElement.style.setProperty(
          "--mobile-nav-height",
          `${height}px`,
        );
        document.documentElement.style.setProperty("--nav-offset", `${height}px`);
      }
    };

    publishNavHeight();
    const observer = new ResizeObserver(publishNavHeight);
    observer.observe(nav);
    window.addEventListener("resize", publishNavHeight);
    window.addEventListener("orientationchange", publishNavHeight);

    return () => {
      observer.disconnect();
      window.removeEventListener("resize", publishNavHeight);
      window.removeEventListener("orientationchange", publishNavHeight);
    };
  }, []);

  const addActivityEvent = useCallback(
    (event: ActivityEvent, options?: { force?: boolean }) => {
      // Pause hides new joins from the feed, but leaves always log (ops visibility)
      if (
        isFeedPausedRef.current &&
        !options?.force &&
        event.type !== "disconnect"
      ) {
        return;
      }
      setActivityFeed((prev) => prependActivityEvent(prev, event));
    },
    [],
  );

  const runRateLimitedButtonAction = (actionKey: string, action: () => void) => {
    const now = Date.now();
    const lastClickAt = lastButtonClicks.current.get(actionKey) ?? 0;

    if (
      now - lastButtonClickAt.current < BUTTON_RATE_LIMIT_MS ||
      now - lastClickAt < BUTTON_RATE_LIMIT_MS
    ) {
      return;
    }

    lastButtonClickAt.current = now;
    lastButtonClicks.current.set(actionKey, now);
    action();
  };

  const clearActivityFeed = useCallback(() => {
    // Keep currently online visitors as connect events; drop history noise
    const activeEvents = Array.from(activeVisitors.current.values()).sort(
      (a, b) => b.timestamp - a.timestamp,
    );
    setActivityFilter("all");
    setActivityFeed(activeEvents);
  }, []);

  const handleActivityFilterChange = useCallback((filter: ActivityFilter) => {
    setActivityFilter(filter);
  }, []);

  const resolveUserCoordinates = async (timeoutMs = 5000) => {
    try {
      const position = await getBrowserPosition(timeoutMs);
      return {
        latitude: position.coords.latitude,
        longitude: position.coords.longitude,
        label: "Your location",
      };
    } catch {
      return {
        latitude: DEFAULT_WEATHER_LOCATION.latitude,
        longitude: DEFAULT_WEATHER_LOCATION.longitude,
        label: DEFAULT_WEATHER_LOCATION.label,
      };
    }
  };

  const nearbySessionKey = (latitude: number, longitude: number, radiusM: number) =>
    `globe-nearby-v8:${latitude.toFixed(4)}:${longitude.toFixed(4)}:${radiusM}`;

  const readNearbySessionCache = (
    latitude: number,
    longitude: number,
    radiusM: number,
  ): NearbyPathsPreview | null => {
    try {
      const raw = sessionStorage.getItem(
        nearbySessionKey(latitude, longitude, radiusM),
      );
      if (!raw) return null;
      const data = JSON.parse(raw) as NearbyPathsPreview;
      // Never restore empty/stale frames from session cache
      if (!data?.paths?.length || data.stale) return null;
      return data;
    } catch {
      return null;
    }
  };

  const writeNearbySessionCache = (
    latitude: number,
    longitude: number,
    radiusM: number,
    data: NearbyPathsPreview,
  ) => {
    if (!data.paths?.length || data.stale) return;
    try {
      sessionStorage.setItem(
        nearbySessionKey(latitude, longitude, radiusM),
        JSON.stringify(data),
      );
    } catch {
      // quota / private mode — ignore
    }
  };

  const fetchNearbyPathsAt = async (
    latitude: number,
    longitude: number,
    radiusM: number,
    options?: { allowCache?: boolean },
  ) => {
    if (options?.allowCache !== false) {
      const cached = readNearbySessionCache(latitude, longitude, radiusM);
      if (cached) {
        return cached;
      }
    }

    const params = new URLSearchParams({
      lat: String(latitude),
      lng: String(longitude),
      radius: String(radiusM),
      // Bust intermediaries on forced refresh
      _t: String(Date.now()),
    });
    // Credentials include session cookie (required — nearby is auth-gated)
    const response = await authFetch(
      `/api/nearby-paths?${params.toString()}`,
      {
        headers: { accept: "application/json" },
        cache: "no-store",
      },
    );

    if (!response.ok) {
      let detail = `Nearby paths request failed (${response.status})`;
      try {
        const err = (await response.json()) as {
          message?: string;
          code?: string;
          error?: string;
        };
        if (err.message) detail = err.message;
        else if (err.error) detail = err.error;
      } catch {
        // ignore
      }
      throw new Error(detail);
    }

    const data = (await response.json()) as NearbyPathsPreview;
    if (!data || !Array.isArray(data.paths) || !Number.isFinite(data.lat)) {
      throw new Error("Nearby paths response incomplete");
    }
    if (data.paths.length > 0 && !data.stale) {
      writeNearbySessionCache(latitude, longitude, radiusM, data);
    }
    return data;
  };

  const loadNearbyPaths = async (
    closeMenu = true,
    radiusM = nearbyRadiusM,
    forceRefresh = false,
  ) => {
    // Open immediately — do not depend on the global button rate limiter succeeding twice
    setShowNearbyPanel(true);
    if (closeMenu) {
      setShowMenu(false);
    }
    setNearbyStatus("loading");
    setNearbyError("");

    const clampedRadius = Math.min(1500, Math.max(250, Math.round(radiusM)));
    setNearbyRadiusM(clampedRadius);

    try {
      // Wait for real GPS — do NOT race a short default (wrong city → empty map)
      let location: {
        latitude: number;
        longitude: number;
        label: string;
      };
      try {
        // 4s geo budget — maps should not wait 8s on GPS alone
        location = await resolveUserCoordinates(4000);
      } catch {
        location = {
          latitude: DEFAULT_WEATHER_LOCATION.latitude,
          longitude: DEFAULT_WEATHER_LOCATION.longitude,
          label: DEFAULT_WEATHER_LOCATION.label,
        };
      }

      // Request the full selected radius (server tiles OSM to fill the ring)
      const data = await fetchNearbyPathsAt(
        location.latitude,
        location.longitude,
        clampedRadius,
        { allowCache: !forceRefresh },
      );
      setNearbyPreview(data);
      setNearbyStatus("ready");

      // Optional refinement if GPS improves (non-blocking)
      void resolveUserCoordinates(5000).then(async (precise) => {
        const dLat = Math.abs(precise.latitude - location.latitude);
        const dLng = Math.abs(precise.longitude - location.longitude);
        if (dLat < 0.0015 && dLng < 0.0015) {
          return;
        }
        try {
          const upgraded = await fetchNearbyPathsAt(
            precise.latitude,
            precise.longitude,
            clampedRadius,
            { allowCache: true },
          );
          setNearbyPreview(upgraded);
        } catch {
          // keep first successful result
        }
      });
    } catch (error) {
      setNearbyError(
        error instanceof Error
          ? error.message
          : "Nearby street traces unavailable",
      );
      setNearbyStatus("error");
    }
  };

  const loadLocalTransit = async (
    closeMenu = true,
    maxDistanceM = transitDistanceM,
  ) => {
    setShowTransitPanel(true);
    if (closeMenu) {
      setShowMenu(false);
    }
    setTransitStatus("loading");
    setTransitError("");

    const clamped = Math.min(1500, Math.max(150, Math.round(maxDistanceM)));
    setTransitDistanceM(clamped);

    try {
      const location = await resolveUserCoordinates(3000);
      const params = new URLSearchParams({
        lat: String(location.latitude),
        lon: String(location.longitude),
        max_distance: String(clamped),
      });
      const response = await authFetch(
        `/api/transit-nearby?${params.toString()}`,
      );

      const payload = (await response.json()) as
        | TransitNearbyPreview
        | {
            error?: string;
            message?: string;
            code?: string;
          };

      if (
        response.status === 401 ||
        response.status === 402 ||
        response.status === 503
      ) {
        const errPayload = payload as {
          message?: string;
          error?: string;
          code?: string;
        };
        setShowTransitPanel(true);
        setTransitStatus("error");
        if (response.status === 401) {
          setShowAuthPanel(true);
          setAuthMode("login");
        }
        setTransitError(
          errPayload.message ||
            (response.status === 401
              ? "Sign in with your device key to use Local Transit."
              : response.status === 402
                ? "Local Transit requires a paid unlock on this deployment."
                : errPayload.error || "Transit is not fully configured yet."),
        );
        return;
      }

      if (!response.ok) {
        const errPayload = payload as { message?: string; error?: string };
        const message =
          errPayload.message || errPayload.error || "Local transit unavailable";
        throw new Error(message);
      }

      if (
        !("routes" in payload) ||
        !Array.isArray(payload.routes) ||
        !Array.isArray(payload.stops)
      ) {
        throw new Error("Transit response incomplete");
      }

      setTransitPreview(payload);
      setTransitStatus("ready");
    } catch (error) {
      setTransitError(
        error instanceof Error ? error.message : "Local transit unavailable",
      );
      setTransitStatus("error");
    }
  };

  /** Shared street engine with Nearby traces (session cache first). */
  const fetchNearbyMapForTransit = useCallback(
    (lat: number, lng: number, radiusM: number) =>
      fetchNearbyPathsAt(lat, lng, radiusM, { allowCache: true }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );

  const loadWeatherFeed = async () => {
    setShowWeatherPanel(true);
    setShowMenu(false);
    setWeatherStatus("loading");
    setWeatherError("");

    let latitude = DEFAULT_WEATHER_LOCATION.latitude;
    let longitude = DEFAULT_WEATHER_LOCATION.longitude;
    let locationLabel = DEFAULT_WEATHER_LOCATION.label;

    try {
      const location = await resolveUserCoordinates();
      latitude = location.latitude;
      longitude = location.longitude;
      locationLabel = location.label;
    } catch {
      locationLabel = DEFAULT_WEATHER_LOCATION.label;
    }

    try {
      const response = await fetch(buildWeatherUrl(latitude, longitude));

      if (!response.ok) {
        throw new Error("Weather request failed");
      }

      const data = (await response.json()) as OpenMeteoForecastResponse;
      const current = data.current;
      const tempF = Number(current?.temperature_2m);
      const humidityPct = Number(current?.relative_humidity_2m);
      const windMph = Number(current?.wind_speed_10m);
      const weatherCode = Number(current?.weather_code);

      if (
        !Number.isFinite(tempF) ||
        !Number.isFinite(humidityPct) ||
        !Number.isFinite(windMph) ||
        !Number.isFinite(weatherCode) ||
        !current?.time
      ) {
        throw new Error("Weather response incomplete");
      }

      setWeatherFeed({
        tempF: Math.round(tempF),
        humidityPct: Math.round(humidityPct),
        windMph: Math.round(windMph),
        weatherCode,
        condition: describeWeatherCode(weatherCode),
        hasLightning: LIGHTNING_WEATHER_CODES.has(weatherCode),
        locationLabel,
        updatedAt: formatWeatherTime(current.time),
        dailyForecast: buildDailyForecast(data),
        hourlyForecast: buildHourlyForecast(data),
      });
      setWeatherStatus("ready");
    } catch {
      setWeatherError("Weather feed unavailable");
      setWeatherStatus("error");
    }
  };

  const toggleComtradeSection = (section: ComtradeSection) => {
    setComtradeSections((current) => ({
      ...current,
      [section]: !current[section],
    }));
  };

  const toggleComtradePanelFromMenu = () => {
    if (showComtradePanel) {
      setShowComtradePanel(false);
      return;
    }

    void loadComtradePreview(false);
  };

  const loadComtradePreview = async (closeMenu = true) => {
    // Keep other popups open so multiple panels can be used side by side
    setShowComtradePanel(true);
    if (closeMenu) {
      setShowMenu(false);
    }
    setComtradeError("");

    const url = "/api/comtrade-preview";
    const cached = getPreviewCache<ComtradePreview>(url);
    if (cached?.data && Array.isArray(cached.data.tradeRecords)) {
      setComtradePreview(cached.data);
      setComtradeStatus("ready");
      if (cached.fresh) return;
    } else {
      setComtradeStatus("loading");
    }

    try {
      const data = await fetchPreviewJson<ComtradePreview>(url, {
        validate: (v): v is ComtradePreview =>
          Boolean(
            v &&
              typeof v === "object" &&
              Array.isArray((v as ComtradePreview).tradeRecords),
          ),
        forceNetwork: Boolean(cached?.stale),
      });
      setComtradePreview(data);
      setComtradeStatus("ready");
    } catch {
      if (!cached) {
        setComtradeError("UN COMTRADE preview unavailable");
        setComtradeStatus("error");
      }
    }
  };

  const toggleTradePulseLayer = (layer: TradePulseLayer) => {
    setTradePulseLayers((current) => ({
      ...current,
      [layer]: !current[layer],
    }));
  };

  const toggleAllTradePulseLayers = () => {
    setTradePulseLayers((current) => {
      const shouldEnableAll = Object.values(current).some((enabled) => !enabled);

      return {
        dependency: shouldEnableAll,
        lifelines: shouldEnableAll,
        asymmetry: shouldEnableAll,
        intermediary: shouldEnableAll,
        transport: shouldEnableAll,
        friction: shouldEnableAll,
        hubs: shouldEnableAll,
        confidence: shouldEnableAll,
      };
    });
  };

  const loadTradePulsePreview = async (
    closeMenu = true,
    periodOverride?: string,
    options?: { keepExpanded?: boolean },
  ) => {
    // Keep other popups open so multiple panels can be used side by side
    setShowTradePulsePanel(true);
    if (!options?.keepExpanded) {
      // Always open the Trade Pulse menu minimized (expand with header control)
      setIsTradePulsePanelMinimized(true);
    }
    if (closeMenu) {
      setShowMenu(false);
    }
    const period = periodOverride || tradePulsePeriod || "2023";
    if (periodOverride) {
      setTradePulsePeriod(periodOverride);
    }
    setTradePulseError("");

    const url = `/api/comtrade-pulse-preview?period=${encodeURIComponent(period)}`;
    const cached = getPreviewCache<TradePulsePreview>(url);
    if (cached?.data && Array.isArray(cached.data.routes)) {
      setTradePulsePreview(cached.data);
      if (cached.data.period) setTradePulsePeriod(cached.data.period);
      setTradePulseStatus("ready");
      if (cached.fresh) return;
    } else {
      setTradePulseStatus("loading");
    }

    try {
      const data = await fetchPreviewJson<TradePulsePreview>(url, {
        validate: (v): v is TradePulsePreview =>
          Boolean(
            v &&
              typeof v === "object" &&
              Array.isArray((v as TradePulsePreview).routes),
          ),
        forceNetwork: Boolean(cached?.stale),
      });
      setTradePulsePreview(data);
      if (data.period) {
        setTradePulsePeriod(data.period);
      }
      setTradePulseStatus("ready");
      // Do not prefetch all years here — parallel heavy responses stall the main thread
      // and compete with the globe. Server waitUntil still warms KV/edge in the background.
    } catch {
      if (!cached) {
        setTradePulseError("Trade Pulse unavailable");
        setTradePulseStatus("error");
      }
    }
  };

  const tradePulseYearOptions =
    tradePulsePreview?.availablePeriods?.length
      ? tradePulsePreview.availablePeriods
      : ["2022", "2023", "2024", "2025"];

  const selectTradePulsePeriod = (period: string) => {
    if (period === tradePulsePeriod && tradePulseStatus === "ready") {
      return;
    }
    void loadTradePulsePreview(false, period, { keepExpanded: true });
  };

  useEffect(() => {
    if (isTradePulsePreview) {
      void loadTradePulsePreview(false);
    }
  }, []);

  const toggleUnGlobalSection = (section: UnGlobalSection) => {
    setUnGlobalSections((current) => ({
      ...current,
      [section]: !current[section],
    }));
  };

  const toggleAllUnGlobalSections = () => {
    setUnGlobalSections((current) => {
      const shouldEnableAll = Object.values(current).some((enabled) => !enabled);

      return {
        offices: shouldEnableAll,
        activeMissions: shouldEnableAll,
        pastMissions: shouldEnableAll,
        memberStates: shouldEnableAll,
        affiliates: shouldEnableAll,
        embassies: shouldEnableAll,
      };
    });
  };

  const toggleUnGlobalPanelFromMenu = () => {
    if (showUnGlobalPanel) {
      setIsUnGlobalPanelMinimized((minimized) => !minimized);
      return;
    }

    void loadUnGlobalPreview(false);
  };

  const toggleUnodcTheme = (themeId: UnodcThemeId) => {
    setUnodcThemes((current) => ({
      ...current,
      [themeId]: !current[themeId],
    }));
  };

  const applyUnodcPreview = (
    data: UnodcHotspotsPreview,
    options?: { keepThemeSelection?: boolean },
  ) => {
    setUnodcPreview(data);
    if (!options?.keepThemeSelection) {
      // Focus mode: only a few high-signal themes on by default (less clutter).
      // All 12 remain toggleable via cards / "All live".
      const nextThemes = { ...DEFAULT_UNODC_THEMES };
      for (const id of UNODC_THEME_IDS) {
        const theme = data.themes.find((t) => t.id === id);
        const hasLive = Boolean(
          theme && theme.dataMode === "live" && theme.hotspotCount > 0,
        );
        nextThemes[id] = hasLive && UNODC_FOCUS_THEMES.includes(id);
      }
      setUnodcThemes(nextThemes);
    }
    setUnodcStatus("ready");

    // Load country polygons after panel is usable — heavy parse must not block first paint.
    const loadGeo = () => {
      void import("./worldCountries")
        .then((m) => m.loadCountryPolygons())
        .then((polygons) => {
          if (polygons) setUnodcCountryPolygons(polygons);
        })
        .catch(() => {});
    };
    if (typeof requestIdleCallback === "function") {
      requestIdleCallback(() => loadGeo(), { timeout: 2000 });
    } else {
      window.setTimeout(loadGeo, 0);
    }
  };

  const loadUnodcHotspots = async (
    closeMenu = true,
    options?: { forceRefresh?: boolean },
  ) => {
    setShowUnodcPanel(true);
    setIsUnodcPanelMinimized(true);
    if (closeMenu) {
      setShowMenu(false);
    }
    setUnodcError("");

    const url = UNODC_PREVIEW_URL;
    // Capture before async setState so refresh keeps the user's theme toggles.
    const keepSelection =
      unodcStatus === "ready" && isCompleteUnodcPreview(unodcPreview);

    if (options?.forceRefresh) {
      clearPreviewCache(url);
    }

    const cached = options?.forceRefresh
      ? null
      : getPreviewCache<UnodcHotspotsPreview>(url);
    const cachedComplete = isCompleteUnodcPreview(cached?.data);
    // Never trust a “fresh” cache that still only has 7 live themes.
    if (cached?.data && Array.isArray(cached.data.themes) && cachedComplete) {
      applyUnodcPreview(cached.data, { keepThemeSelection: keepSelection });
      if (cached.fresh) return;
    } else if (cached?.data && !cachedComplete) {
      clearPreviewCache(url);
      setUnodcStatus("loading");
    } else if (!cached) {
      setUnodcStatus("loading");
    }

    try {
      const data = await fetchPreviewJson<UnodcHotspotsPreview>(url, {
        validate: (v): v is UnodcHotspotsPreview =>
          Boolean(
            v &&
              typeof v === "object" &&
              Array.isArray((v as UnodcHotspotsPreview).themes),
          ),
        // Bust HTTP cache when incomplete or user hit Refresh.
        forceNetwork:
          Boolean(options?.forceRefresh) ||
          !cachedComplete ||
          Boolean(cached?.stale),
      });
      applyUnodcPreview(data, {
        keepThemeSelection: keepSelection && isCompleteUnodcPreview(data),
      });
    } catch {
      if (!cachedComplete) {
        setUnodcError("UNODC hotspots unavailable");
        setUnodcStatus("error");
      }
    }
  };

  const setUnodcFocusMode = (mode: "focus" | "all-live" | "none") => {
    if (!unodcPreview) return;
    const next = { ...DEFAULT_UNODC_THEMES };
    for (const theme of unodcPreview.themes) {
      const hasLive = theme.dataMode === "live" && theme.hotspotCount > 0;
      if (mode === "none") {
        next[theme.id] = false;
      } else if (mode === "all-live") {
        next[theme.id] = hasLive;
      } else {
        next[theme.id] = hasLive && UNODC_FOCUS_THEMES.includes(theme.id);
      }
    }
    setUnodcThemes(next);
  };

  const loadUnGlobalPreview = async (closeMenu = true) => {
    // Keep other popups open so multiple panels can be used side by side
    setShowUnGlobalPanel(true);
    setIsUnGlobalPanelMinimized(false);
    if (closeMenu) {
      setShowMenu(false);
    }
    setUnGlobalError("");

    const url = "/api/un-global-preview";
    const cached = getPreviewCache<UnGlobalPreview>(url);
    if (cached?.data && Array.isArray(cached.data.missionLocations)) {
      setUnGlobalPreview(cached.data);
      setUnGlobalStatus("ready");
      if (cached.fresh) return;
    } else {
      setUnGlobalStatus("loading");
    }

    try {
      const data = await fetchPreviewJson<UnGlobalPreview>(url, {
        validate: (v): v is UnGlobalPreview =>
          Boolean(
            v &&
              typeof v === "object" &&
              Array.isArray((v as UnGlobalPreview).missionLocations),
          ),
        forceNetwork: Boolean(cached?.stale),
      });
      setUnGlobalPreview(data);
      setUnGlobalStatus("ready");
    } catch {
      if (!cached) {
        setUnGlobalError("UN global preview unavailable");
        setUnGlobalStatus("error");
      }
    }
  };

  // After globe first paint: warm edge/browser caches so panel opens are free.
  // Staggered so we never compete with WebGL init.
  useEffect(() => {
    const warm = () => {
      warmPreviewUrl(UNODC_PREVIEW_URL);
      warmPreviewUrl("/api/comtrade-pulse-preview?period=2023");
      // Geo atlas for choropleth — force-cache immutable asset
      void import("./worldCountries")
        .then((m) => m.loadCountryPolygons())
        .catch(() => {});
    };
    let idleId = 0;
    let timeoutId = 0;
    if (typeof requestIdleCallback === "function") {
      idleId = requestIdleCallback(warm, { timeout: 8000 });
    } else {
      timeoutId = window.setTimeout(warm, 4000);
    }
    return () => {
      if (idleId && typeof cancelIdleCallback === "function") {
        cancelIdleCallback(idleId);
      }
      if (timeoutId) window.clearTimeout(timeoutId);
    };
  }, []);

  const disableUnGlobalLayer = () => {
    setShowUnGlobalPanel(false);
    setIsUnGlobalPanelMinimized(false);
  };

  const socket = usePartySocket({
    room: "default",
    party: "globe",
    onOpen() {
      setIsSocketConnected(true);
      setIsDisconnected(false);
    },
    onClose() {
      setIsSocketConnected(false);
      setIsDisconnected(true);
    },
    onError() {
      setIsSocketConnected(false);
    },
    onMessage(evt) {
      const message = parseSocketMessage(evt.data);

      if (!message) {
        return;
      }

      // Public globe markers only — no activity feed from this path
      if (message.type === "add-marker") {
        const visitorId = message.position.id;
        positions.current.set(visitorId, {
          location: [message.position.lat, message.position.lng],
          size: visitorId === socket.id ? 0.1 : 0.05,
        });

        if (visitorId === socket.id) {
          setIsDisconnected(false);
          setIsSocketConnected(true);
        }

        setCounter(positions.current.size);
        return;
      }

      if (message.type === "remove-marker") {
        const removedId = message.id;
        const wasSelf = removedId === socket.id;
        positions.current.delete(removedId);
        setCounter(positions.current.size);
        if (wasSelf) {
          setIsDisconnected(true);
        }
        // Leaves for the paid feed arrive as feed-leave (not here)
        return;
      }

      // Paid Live Feed channel (server only sends if transitPaid)
      if (message.type === "feed-access") {
        // Access is still driven by authUser.transitPaid for UI lock;
        // server already gated feed-join/leave delivery.
        return;
      }

      if (message.type === "feed-join") {
        if (!liveFeedUnlockedRef.current) return;
        const meta = message.meta;
        const isYou = meta.id === socket.id;
        const activityEvent = createActivityEvent({
          id: meta.id,
          type: "connect",
          timestamp: Date.now(),
          userName: isYou ? "You" : `User ${meta.id.slice(0, 8)}`,
          ip: meta.ipMasked,
          country: meta.country,
          city: meta.city,
          org: meta.org,
          isSelf: isYou,
        });
        activeVisitors.current.set(meta.id, activityEvent);
        addActivityEvent(activityEvent);
        return;
      }

      if (message.type === "feed-leave") {
        if (!liveFeedUnlockedRef.current) return;
        const removedId = message.id;
        const wasSelf = removedId === socket.id;
        const prior = activeVisitors.current.get(removedId);
        const meta = message.meta;
        activeVisitors.current.delete(removedId);
        addActivityEvent(
          createActivityEvent({
            id: removedId,
            type: "disconnect",
            timestamp: Date.now(),
            userName:
              prior?.userName ??
              (wasSelf ? "You" : `User ${removedId.slice(0, 8)}`),
            city: meta?.city ?? prior?.city,
            country: meta?.country ?? prior?.country,
            org: meta?.org ?? prior?.org,
            ip: meta?.ipMasked ?? prior?.ip,
            isSelf: wasSelf,
            sessionMs: message.sessionMs,
          }),
          { force: true },
        );
      }
    },
  });
  const weatherGlow = getWeatherGlow(weatherFeed);
  const enabledComtradeSectionCount =
    Object.values(comtradeSections).filter(Boolean).length;
  const isFullUsdMode = comtradeValueMode === "full";
  const comtradeMenuStatus =
    comtradeStatus === "ready" && comtradePreview
      ? "Ready"
      : comtradeStatus === "loading"
        ? "Loading"
        : comtradeStatus === "error"
          ? "Offline"
          : "Not loaded";
  const comtradeMenuSource =
    comtradeStatus === "ready" && comtradePreview
      ? comtradePreview.stale
        ? "Fallback"
        : comtradePreview.dataMode === "free-subscription" ||
            comtradePreview.subscriptionBacked
          ? "Live"
          : "Preview"
      : comtradeStatus === "error"
        ? "Unavailable"
        : "Not loaded";
  const comtradeMenuQuery =
    comtradeStatus === "ready" && comtradePreview
      ? `${comtradePreview.reporter} · ${comtradePreview.period}`
      : comtradeStatus === "loading"
        ? "Loading…"
        : "USA annual totals";
  const comtradeMenuUpdated =
    comtradeStatus === "ready" && comtradePreview
      ? formatPreviewDate(comtradePreview.updatedAt)
      : "Awaiting preview";
  const getComtradeSectionDetail = (section: ComtradeSection) => {
    if (comtradeStatus === "loading") {
      return "Loading Comtrade+ preview data";
    }

    if (comtradeStatus === "error") {
      return comtradeError || "Comtrade+ preview unavailable";
    }

    if (!comtradePreview) {
      return COMTRADE_SECTION_DESCRIPTIONS[section];
    }

    if (section === "records") {
      return `${comtradePreview.tradeRecords.length} rows; ${comtradePreview.reporter} ${comtradePreview.period}`;
    }

    if (section === "availability") {
      return `${comtradePreview.availability.length} datasets; ${formatPreviewNumber(
        comtradePreview.availabilityTotalRecords,
        comtradePreview.stale,
      )} records indexed`;
    }

    if (section === "references") {
      return `${comtradePreview.references.length} shown; ${formatPreviewNumber(
        comtradePreview.referenceTablesTotal,
        comtradePreview.stale,
      )} reference tables`;
    }

    return `${comtradePreview.reporters.length} sampled; ${formatPreviewNumber(
      comtradePreview.reportersTotal,
      comtradePreview.stale,
    )} reporters total`;
  };
  const enabledUnGlobalSectionCount =
    Object.values(unGlobalSections).filter(Boolean).length;
  const allUnGlobalSectionsEnabled =
    enabledUnGlobalSectionCount === Object.keys(DEFAULT_UN_GLOBAL_SECTIONS).length;
  const visibleUnMissionLocations =
    unGlobalPreview?.missionLocations.filter((mission) =>
      mission.active ? unGlobalSections.activeMissions : unGlobalSections.pastMissions,
    ) ?? [];
  const unGlobalOverlayMarkers =
    showUnGlobalPanel && unGlobalStatus === "ready" && unGlobalPreview
      ? [
          ...(unGlobalSections.offices
            ? unGlobalPreview.offices.map((office) => ({
                location: [office.lat, office.lng] as [number, number],
                size: office.category === "headquarters" ? 0.09 : 0.07,
              }))
            : []),
          ...visibleUnMissionLocations.map((mission) => ({
            location: [mission.lat, mission.lng] as [number, number],
            size: mission.active ? 0.08 : 0.045,
          })),
          ...(unGlobalSections.memberStates
            ? unGlobalPreview.memberStates.map((state) => ({
                location: [state.lat, state.lng] as [number, number],
                size: 0.045,
              }))
            : []),
          ...(unGlobalSections.affiliates
            ? unGlobalPreview.affiliates.map((affiliate) => ({
                location: [affiliate.lat, affiliate.lng] as [number, number],
                size: affiliate.category === "observer" ? 0.065 : 0.055,
              }))
            : []),
          ...(unGlobalSections.embassies
            ? unGlobalPreview.embassies.map((embassy) => ({
                location: [embassy.lat, embassy.lng] as [number, number],
                size: 0.035,
              }))
            : []),
        ]
      : [];
  /**
   * Multi-theme choropleth: one fill per (theme, country) so several themes
   * stack with semi-transparent colors instead of a single winner-takes-all.
   */
  const unodcChoroplethRegions: GlobeChoroplethRegion[] = useMemo(() => {
    if (
      !showUnodcPanel ||
      unodcStatus !== "ready" ||
      !unodcPreview ||
      !unodcCountryPolygons
    ) {
      return [];
    }
    type Entry = {
      id: string;
      iso3: string;
      intensity: number;
      color: string;
      themeId: UnodcThemeId;
      label: string;
      rings: [number, number][][];
    };
    const entries: Entry[] = [];
    // Per-theme cap keeps “All live” usable; total cap protects frame budget.
    const PER_THEME = 40;
    const MAX_TOTAL = 140;

    for (const theme of unodcPreview.themes) {
      if (!unodcThemes[theme.id] || theme.hotspots.length === 0) continue;
      const color = UNODC_THEME_CSS[theme.id];
      const ranked = [...theme.hotspots]
        .sort((a, b) => b.intensity - a.intensity)
        .slice(0, PER_THEME);
      for (const spot of ranked) {
        const poly = unodcCountryPolygons.get(spot.iso3);
        if (!poly) continue;
        entries.push({
          id: `${theme.id}-${spot.iso3}`,
          iso3: spot.iso3,
          intensity: spot.intensity,
          color,
          themeId: theme.id,
          rings: poly.rings,
          label: `${theme.label}: ${spot.name} · ${spot.value} (${spot.year})`,
        });
      }
    }

    entries.sort((a, b) => b.intensity - a.intensity);
    return entries.slice(0, MAX_TOTAL).map((b) => ({
      id: b.id,
      iso3: b.iso3,
      rings: b.rings,
      color: b.color,
      intensity: b.intensity,
      themeId: b.themeId,
      label: b.label,
    }));
  }, [
    showUnodcPanel,
    unodcStatus,
    unodcPreview,
    unodcCountryPolygons,
    unodcThemes,
  ]);

  /**
   * Heat blobs only when country polygons failed to load.
   * Choropleth alone is calmer and more accurate.
   */
  const unodcHeatZones: GlobeHeatZone[] = useMemo(() => {
    if (
      !showUnodcPanel ||
      unodcStatus !== "ready" ||
      !unodcPreview ||
      unodcCountryPolygons
    ) {
      return [];
    }
    return unodcPreview.themes.flatMap((theme) => {
      if (!unodcThemes[theme.id] || theme.hotspots.length === 0) {
        return [];
      }
      return buildUnodcThemeHeatZones(theme, UNODC_THEME_CSS[theme.id]).map(
        (z) => ({
          ...z,
          intensity: z.intensity * 0.65,
        }),
      );
    });
  }, [
    showUnodcPanel,
    unodcStatus,
    unodcPreview,
    unodcCountryPolygons,
    unodcThemes,
  ]);
  const unGlobalMarkerColor =
    unGlobalOverlayMarkers.length > 0
      ? ([0, 0.65, 1] as [number, number, number])
      : ([0.8, 0.1, 0.1] as [number, number, number]);
  const enabledTradePulseLayerCount =
    Object.values(tradePulseLayers).filter(Boolean).length;
  const allTradePulseLayersEnabled =
    enabledTradePulseLayerCount === TRADE_PULSE_LAYERS.length;
  const visibleTradePulseRoutes =
    showTradePulsePanel && tradePulseStatus === "ready"
      ? getVisibleTradePulseRoutes(tradePulsePreview, tradePulseLayers)
      : [];
  const tradePulseGlobeMarkers =
    showTradePulsePanel && tradePulseStatus === "ready"
      ? getTradePulseGlobeMarkers(tradePulsePreview, tradePulseLayers)
      : [];
  const tradePulseGlobeArcs: GlobeArc[] =
    showTradePulsePanel && tradePulseStatus === "ready"
      ? visibleTradePulseRoutes.map((route) => {
          const layer = getRoutePulseLayer(route, tradePulseLayers);

          return {
            id: route.id,
            from: [route.origin.lat, route.origin.lng] as [number, number],
            to: [route.destination.lat, route.destination.lng] as [number, number],
            via: route.intermediary
              ? ([route.intermediary.lat, route.intermediary.lng] as [number, number])
              : null,
            fromLabel: `${route.origin.name} origin`,
            toLabel: `${route.destination.name} destination`,
            viaLabel: route.intermediary
              ? `${route.intermediary.name} relay`
              : undefined,
            color: TRADE_PULSE_LAYER_COLORS[layer],
            width:
              route.severity === "critical" ? 3.2 : route.severity === "high" ? 2.6 : 2,
            dash: TRADE_PULSE_TRANSPORT_DASHES[route.transportMode],
            severity: route.severity,
            comtrade: {
              routeId: route.id,
              commodity: route.commodity,
              commodityCode: route.commodityCode,
              period: route.period,
              originName: route.origin.name,
              originIso3: route.origin.iso3,
              destName: route.destination.name,
              destIso3: route.destination.iso3,
              hubName: route.intermediary?.name ?? null,
              hubIso3: route.intermediary?.iso3 ?? null,
              transportMode: route.transportMode,
              customsProcedure: route.customsProcedure,
              valueUsd: route.valueUsd,
              quantity: route.quantity,
              supplierSharePct: route.supplierSharePct,
              exportValueUsd: route.exportValueUsd,
              importValueUsd: route.importValueUsd,
              asymmetryPct: route.asymmetryPct,
              fobValueUsd: route.fobValueUsd,
              cifValueUsd: route.cifValueUsd,
              frictionPct: route.frictionPct,
              reExportSharePct: route.reExportSharePct,
              confidencePct: route.confidencePct,
              severity: route.severity,
              layers: route.layers.map(
                (l) => TRADE_PULSE_LAYER_SHORT_LABELS[l] || l,
              ),
              insight: route.insight,
              dataMode: tradePulsePreview?.dataMode,
            },
          };
        })
      : [];
  const globeOverlayMarkers = [
    ...unGlobalOverlayMarkers,
    ...tradePulseGlobeMarkers,
  ];
  const globeMarkerColor =
    tradePulseGlobeMarkers.length > 0
      ? ([1, 0.24, 0.18] as [number, number, number])
      : unGlobalMarkerColor;

  return (
    <div className="App">
      {(authMessage || authError) && (
        <div
          className={`billing-banner ${authError ? "billing-banner-error" : "billing-banner-ok"}`}
          role="status"
        >
          <span>{authError || authMessage}</span>
          <button
            type="button"
            onClick={() => {
              setAuthMessage("");
              setAuthError("");
            }}
          >
            Dismiss
          </button>
        </div>
      )}

      {showAuthPanel && (
        <div
          className="auth-modal-backdrop"
          role="presentation"
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              clearSensitiveAuthState();
              setShowAuthPanel(false);
            }
          }}
        >
          <div
            className="auth-modal auth-modal-wide"
            role="dialog"
            aria-label={
              authMode === "register" ? "Create device identity" : "Device sign-in"
            }
          >
            <div className="auth-modal-header">
              <strong>
                {authMode === "register"
                  ? "Create identity · this device"
                  : "Sign in · this device"}
              </strong>
              <button
                type="button"
                className="nearby-close"
                onClick={() => {
                  clearSensitiveAuthState();
                  setShowAuthPanel(false);
                }}
                aria-label="Close"
              >
                ×
              </button>
            </div>
            <p className="auth-modal-copy">
              You do <strong>not</strong> upload a private key to log in. The
              browser keeps the private key on this device; the server only gets
              your public key + a one-time signature. No account password —
              passphrase only if <em>you</em> encrypted the device key.
            </p>
            <p className="auth-field-hint auth-mobile-hint">
              <strong>Mobile:</strong> use Safari or Chrome in a normal tab (not
              private, not Instagram/Facebook/TikTok in-app browsers). New keys
              must be <strong>Registered</strong> once before Sign in works.
              Allow cookies + site data for this domain.
            </p>

            {authMode === "register" ? (
              <>
                <label className="auth-field">
                  <span>Key algorithm / size / protocol</span>
                  <select
                    value={keyGenProfile}
                    onChange={(e) =>
                      setKeyGenProfile(e.target.value as KeyGenProfileId)
                    }
                    disabled={authBusy}
                  >
                    {keyGenProfilesBySafety().map((group) => (
                      <optgroup
                        key={group.safety}
                        label={`${group.label} — ${
                          group.safety === "recommended"
                            ? "best default"
                            : group.safety === "insecure"
                              ? "do not use for real accounts"
                              : group.safety
                        }`}
                      >
                        {group.profiles.map((p) => (
                          <option key={p.id} value={p.id}>
                            [{SAFETY_LEVEL_META[p.safety].short}] {p.label}
                            {!p.canRegister ? " · export-only" : ""}
                          </option>
                        ))}
                      </optgroup>
                    ))}
                  </select>
                </label>
                {(() => {
                  const selected = getKeyGenProfile(keyGenProfile);
                  const meta = SAFETY_LEVEL_META[selected.safety];
                  return (
                    <div
                      className={`auth-safety-card auth-safety-${selected.safety}`}
                    >
                      <div className="auth-safety-header">
                        <span
                          className="auth-safety-badge"
                          style={{
                            borderColor: meta.color,
                            color: meta.color,
                          }}
                        >
                          {meta.short}
                        </span>
                        <strong>{selected.safetyLabel}</strong>
                      </div>
                      <p className="auth-safety-desc">{selected.description}</p>
                      <div className="auth-safety-meta">
                        ~{selected.securityBits}-bit classical · {selected.family}
                        {selected.canRegister
                          ? " · can register on this app"
                          : " · cannot register (export/lab only)"}
                      </div>
                      <ul className="auth-compliance-list">
                        <li>
                          <span>NIST</span> {selected.compliance.nist}
                        </li>
                        <li>
                          <span>BSI</span> {selected.compliance.bsi}
                        </li>
                        <li>
                          <span>ENISA</span> {selected.compliance.enisa}
                        </li>
                        <li>
                          <span>ANSSI</span> {selected.compliance.anssi}
                        </li>
                        <li>
                          <span>CNSA</span> {selected.compliance.cnsa}
                        </li>
                      </ul>
                      {selected.registerNote && (
                        <p className="auth-safety-warn">{selected.registerNote}</p>
                      )}
                      <p className="auth-field-hint">
                        Guidance summarized from NIST SP 800-57, BSI TR-02102,
                        ENISA, ANSSI, and NSA CNSA documents — not legal advice.
                        Quantum threats are out of scope for these classical
                        ratings.
                      </p>
                    </div>
                  );
                })()}
                <div className="auth-modal-actions auth-row">
                  <button
                    type="button"
                    disabled={authBusy}
                    onClick={() => void handleGenerateKeypair()}
                  >
                    {authBusy
                      ? "Working…"
                      : "Generate key on this device"}
                  </button>
                </div>

                {generatedPublic && (
                  <div className="auth-export-panel">
                    <div className="auth-fp-block">
                      <div>
                        Fingerprint:{" "}
                        <code>
                          {formatFingerprint(generatedPublic.fingerprint)}
                        </code>
                      </div>
                      {(() => {
                        const selected = getKeyGenProfile(keyGenProfile);
                        const meta = SAFETY_LEVEL_META[selected.safety];
                        return (
                          <div className="auth-safety-inline">
                            <span
                              className="auth-safety-badge"
                              style={{
                                borderColor: meta.color,
                                color: meta.color,
                              }}
                            >
                              {meta.short}
                            </span>
                            <span>
                              {selected.label} · ~{selected.securityBits}-bit ·{" "}
                              {selected.safetyLabel}
                            </span>
                          </div>
                        );
                      })()}
                      <div>
                        Private key is stored on this device only (IndexedDB).
                        It is never uploaded. Register publishes the public key.
                      </div>
                      {!getKeyGenProfile(keyGenProfile).canRegister && (
                        <p className="auth-safety-warn">
                          This size/protocol is below app registration policy
                          (export-only).
                        </p>
                      )}
                    </div>

                    <div className="auth-section-title">
                      Optional backup file (local only)
                    </div>
                    <label className="auth-field">
                      <span>Symmetric cipher</span>
                      <select
                        value={exportCipher}
                        onChange={(e) =>
                          setExportCipher(e.target.value as SymmetricCipherId)
                        }
                        disabled={authBusy}
                      >
                        {SYMMETRIC_CIPHERS.map((c) => (
                          <option key={c.id} value={c.id}>
                            {c.label}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="auth-field">
                      <span>Passphrase KDF (S2K protocol)</span>
                      <select
                        value={exportS2k}
                        onChange={(e) =>
                          setExportS2k(e.target.value as S2kProtocolId)
                        }
                        disabled={authBusy}
                      >
                        {S2K_PROTOCOLS.map((s) => (
                          <option key={s.id} value={s.id}>
                            {s.label}
                          </option>
                        ))}
                      </select>
                      <span className="auth-field-hint">
                        {
                          S2K_PROTOCOLS.find((s) => s.id === exportS2k)
                            ?.description
                        }
                      </span>
                    </label>
                    {exportS2k === "iterated" && (
                      <label className="auth-field">
                        <span>
                          S2K iteration count byte (0–255, higher = slower)
                        </span>
                        <input
                          type="number"
                          min={0}
                          max={255}
                          value={exportS2kIterByte}
                          onChange={(e) =>
                            setExportS2kIterByte(Number(e.target.value) || 0)
                          }
                          disabled={authBusy}
                        />
                      </label>
                    )}
                    {exportS2k === "argon2" && (
                      <div className="auth-export-grid">
                        <label className="auth-field">
                          <span>Argon2 passes</span>
                          <input
                            type="number"
                            min={1}
                            max={10}
                            value={exportArgonPasses}
                            onChange={(e) =>
                              setExportArgonPasses(
                                Number(e.target.value) || 1,
                              )
                            }
                            disabled={authBusy}
                          />
                        </label>
                        <label className="auth-field">
                          <span>Parallelism</span>
                          <input
                            type="number"
                            min={1}
                            max={16}
                            value={exportArgonParallel}
                            onChange={(e) =>
                              setExportArgonParallel(
                                Number(e.target.value) || 1,
                              )
                            }
                            disabled={authBusy}
                          />
                        </label>
                        <label className="auth-field">
                          <span>Memory exp (2^n KiB)</span>
                          <input
                            type="number"
                            min={16}
                            max={21}
                            value={exportArgonMemExp}
                            onChange={(e) =>
                              setExportArgonMemExp(
                                Number(e.target.value) || 16,
                              )
                            }
                            disabled={authBusy}
                          />
                        </label>
                      </div>
                    )}
                    <label className="auth-check">
                      <input
                        type="checkbox"
                        checked={exportAead}
                        onChange={(e) => setExportAead(e.target.checked)}
                        disabled={authBusy}
                      />
                      AEAD-protect secret key packets
                    </label>
                    {exportAead && (
                      <label className="auth-field">
                        <span>AEAD mode</span>
                        <select
                          value={exportAeadMode}
                          onChange={(e) =>
                            setExportAeadMode(e.target.value as AeadModeId)
                          }
                          disabled={authBusy}
                        >
                          <option value="gcm">GCM</option>
                          <option value="eax">EAX</option>
                          <option value="ocb">OCB</option>
                        </select>
                      </label>
                    )}
                    <label className="auth-field">
                      <span>Export passphrase</span>
                      <input
                        type="password"
                        autoComplete="new-password"
                        value={exportPassphrase}
                        onChange={(e) => setExportPassphrase(e.target.value)}
                        disabled={authBusy}
                        placeholder="Min 8 characters"
                      />
                    </label>
                    <label className="auth-field">
                      <span>Confirm passphrase</span>
                      <input
                        type="password"
                        autoComplete="new-password"
                        value={exportPassphrase2}
                        onChange={(e) => setExportPassphrase2(e.target.value)}
                        disabled={authBusy}
                      />
                    </label>
                    <label className="auth-check">
                      <input
                        type="checkbox"
                        checked={exportAllowUnencrypted}
                        onChange={(e) =>
                          setExportAllowUnencrypted(e.target.checked)
                        }
                        disabled={authBusy}
                      />
                      Allow unencrypted export (not recommended)
                    </label>
                    <div className="auth-modal-actions auth-row">
                      <button
                        type="button"
                        disabled={authBusy || !generatedPublic}
                        onClick={() => void handleExportPrivateKey()}
                      >
                        {authBusy
                          ? "Exporting…"
                          : "Download backup .asc (optional)"}
                      </button>
                    </div>
                  </div>
                )}

                <label className="auth-field">
                  <span>Public key (only thing sent to server)</span>
                  <textarea
                    value={regPublicKey}
                    onChange={(e) => setRegPublicKey(e.target.value)}
                    disabled={authBusy}
                    rows={4}
                    spellCheck={false}
                    placeholder="Generated automatically — public key only"
                  />
                </label>
                {authError && (
                  <div className="auth-inline-error">{authError}</div>
                )}
                <div className="auth-modal-actions">
                  <button
                    type="button"
                    disabled={
                      authBusy ||
                      !regPublicKey.trim() ||
                      (Boolean(generatedPublic) &&
                        !getKeyGenProfile(keyGenProfile).canRegister)
                    }
                    onClick={() => void registerWithPublicKey()}
                  >
                    {authBusy
                      ? "Registering…"
                      : generatedPublic &&
                          !getKeyGenProfile(keyGenProfile).canRegister
                        ? "Cannot register (safety floor)"
                        : "Register & stay signed in"}
                  </button>
                  <button
                    type="button"
                    className="auth-switch"
                    disabled={authBusy}
                    onClick={() => {
                      setAuthError("");
                      void refreshDeviceKeys();
                      setAuthMode("login");
                    }}
                  >
                    Already have a device key? Sign in
                  </button>
                </div>

                <div className="auth-section-title auth-ecdhe-title">
                  Experimental · ECDHE key agreement
                </div>
                <p className="auth-field-hint">
                  Ephemeral elliptic-curve Diffie–Hellman (WebCrypto). Not an
                  OpenPGP login key — private material stays non-extractable in
                  memory and is never uploaded. Use for lab / peer key agreement
                  only.
                </p>
                <div className="auth-modal-actions auth-row">
                  <button
                    type="button"
                    className="auth-switch"
                    disabled={authBusy || ecdheBusy}
                    onClick={() => {
                      const next = !showEcdheLab;
                      setShowEcdheLab(next);
                      if (next) void refreshEcdheSupport();
                    }}
                  >
                    {showEcdheLab ? "Hide ECDHE lab" : "Open ECDHE lab"}
                  </button>
                </div>
                {showEcdheLab && (
                  <div className="auth-ecdhe-lab">
                    <label className="auth-field">
                      <span>Curve</span>
                      <select
                        value={ecdheCurve}
                        onChange={(e) => {
                          setEcdheCurve(e.target.value as EcdheCurveId);
                          setEcdhePair(null);
                          setEcdheSharedFp("");
                          setEcdheError("");
                          setEcdheMessage("");
                        }}
                        disabled={ecdheBusy}
                      >
                        {ECDHE_CURVE_IDS.map((id) => (
                          <option
                            key={id}
                            value={id}
                            disabled={
                              ecdheSupported.length > 0 &&
                              !ecdheSupported.includes(id)
                            }
                          >
                            {ECDHE_CURVE_META[id].label}
                            {ecdheSupported.length > 0 &&
                            !ecdheSupported.includes(id)
                              ? " · unsupported here"
                              : " · experimental"}
                          </option>
                        ))}
                      </select>
                      <span className="auth-field-hint">
                        {ECDHE_CURVE_META[ecdheCurve].description} ~
                        {ECDHE_CURVE_META[ecdheCurve].securityBits}-bit
                        classical.
                      </span>
                    </label>
                    <div className="auth-modal-actions auth-row">
                      <button
                        type="button"
                        disabled={ecdheBusy}
                        onClick={() => void handleEcdheGenerate()}
                      >
                        {ecdheBusy ? "Working…" : "Generate ephemeral pair"}
                      </button>
                      <button
                        type="button"
                        className="auth-switch"
                        disabled={ecdheBusy}
                        onClick={() => void handleEcdheSelfTest()}
                      >
                        Self-test (A↔B)
                      </button>
                    </div>
                    {ecdhePair && (
                      <>
                        <label className="auth-field">
                          <span>Your public key (SPKI base64) — share this</span>
                          <textarea
                            readOnly
                            rows={3}
                            spellCheck={false}
                            value={ecdhePair.publicKeySpkiB64}
                            onFocus={(e) => e.currentTarget.select()}
                          />
                        </label>
                        <label className="auth-field">
                          <span>Your public key (JWK JSON)</span>
                          <textarea
                            readOnly
                            rows={4}
                            spellCheck={false}
                            value={JSON.stringify(ecdhePair.publicKeyJwk)}
                            onFocus={(e) => e.currentTarget.select()}
                          />
                        </label>
                        <label className="auth-field">
                          <span>Peer public key (JWK or SPKI base64)</span>
                          <textarea
                            rows={3}
                            spellCheck={false}
                            value={ecdhePeerPub}
                            onChange={(e) => setEcdhePeerPub(e.target.value)}
                            disabled={ecdheBusy}
                            placeholder="Paste peer SPKI base64 or JWK JSON"
                          />
                        </label>
                        <div className="auth-modal-actions auth-row">
                          <button
                            type="button"
                            disabled={ecdheBusy || !ecdhePeerPub.trim()}
                            onClick={() => void handleEcdheDerive()}
                          >
                            {ecdheBusy
                              ? "Deriving…"
                              : "Derive shared secret (HKDF)"}
                          </button>
                          <button
                            type="button"
                            className="auth-switch"
                            disabled={ecdheBusy}
                            onClick={() => {
                              setEcdhePair(null);
                              setEcdhePeerPub("");
                              setEcdheSharedFp("");
                              setEcdheMessage("Cleared ephemeral material.");
                              setEcdheError("");
                            }}
                          >
                            Clear ephemeral keys
                          </button>
                        </div>
                      </>
                    )}
                    {ecdheSharedFp && (
                      <div className="auth-fp-block">
                        <div>
                          <strong>Shared secret fingerprint (SHA-256)</strong>
                        </div>
                        <code className="admin-fp-hex" style={{ userSelect: "all" }}>
                          {ecdheSharedFp}
                        </code>
                        <p className="auth-field-hint">
                          Raw shared bits are not shown. Matching fingerprints on
                          both peers means ECDHE agreed. Session AES key stays
                          non-extractable in memory.
                        </p>
                      </div>
                    )}
                    {ecdheError && (
                      <div className="auth-inline-error">{ecdheError}</div>
                    )}
                    {ecdheMessage && !ecdheError && (
                      <div className="auth-inline-ok">{ecdheMessage}</div>
                    )}
                  </div>
                )}
              </>
            ) : (
              <>
                {deviceKeys.length > 0 ? (
                  <>
                    <label className="auth-field">
                      <span>Device key on this browser</span>
                      <select
                        value={selectedDeviceFp}
                        onChange={(e) => setSelectedDeviceFp(e.target.value)}
                        disabled={authBusy}
                      >
                        {deviceKeys.map((k) => (
                          <option key={k.fingerprint} value={k.fingerprint}>
                            {shortFingerprint(k.fingerprint)}
                            {k.encrypted ? " · encrypted" : " · no passphrase"}
                            {k.profileLabel ? ` · ${k.profileLabel}` : ""}
                          </option>
                        ))}
                      </select>
                    </label>
                    {selectedDeviceKey?.encrypted && (
                      <label className="auth-field">
                        <span>Key passphrase (only because this key is encrypted)</span>
                        <input
                          type="password"
                          value={keyPassphrase}
                          onChange={(e) => setKeyPassphrase(e.target.value)}
                          disabled={authBusy}
                          autoComplete="off"
                          placeholder="OpenPGP key passphrase"
                        />
                      </label>
                    )}
                    {selectedDeviceKey && !selectedDeviceKey.encrypted && (
                      <p className="auth-field-hint">
                        Sign-in needs no password
                        {selectedDeviceKey.deviceBound
                          ? " (private key is AES-wrapped on this device at rest)."
                          : "."}{" "}
                        Session uses an HttpOnly cookie only.
                      </p>
                    )}
                    <div className="auth-modal-actions">
                      <button
                        type="button"
                        disabled={authBusy || !selectedDeviceKey}
                        onClick={() => void handleDeviceSignIn()}
                      >
                        {authBusy
                          ? "Signing in…"
                          : "Continue with device key"}
                      </button>
                      <button
                        type="button"
                        className="auth-switch"
                        disabled={authBusy || !selectedDeviceKey}
                        onClick={() => {
                          if (selectedDeviceKey) {
                            void handleRemoveDeviceKey(
                              selectedDeviceKey.fingerprint,
                            );
                          }
                        }}
                      >
                        Remove key from this device
                      </button>
                    </div>
                  </>
                ) : (
                  <div className="auth-fp-block">
                    No device key on this browser yet. Create one under{" "}
                    <strong>Create identity</strong>, or import a backup once
                    (still never uploaded to the server).
                  </div>
                )}

                <button
                  type="button"
                  className="auth-switch"
                  disabled={authBusy}
                  onClick={() => setShowImportDevice((v) => !v)}
                >
                  {showImportDevice
                    ? "Hide import"
                    : "Import backup onto this device…"}
                </button>
                {showImportDevice && (
                  <div className="auth-export-panel">
                    <p className="auth-field-hint">
                      Only for a new browser/computer. The private key stays
                      here and is never sent to the server.
                    </p>
                    <label className="auth-field">
                      <span>Private key file</span>
                      <input
                        type="file"
                        accept=".asc,.pgp,.gpg,.txt,text/plain"
                        disabled={authBusy}
                        onChange={(e) => {
                          const file = e.target.files?.[0] || null;
                          void handleImportDeviceKey(file);
                          e.target.value = "";
                        }}
                      />
                    </label>
                  </div>
                )}

                {authError && (
                  <div className="auth-inline-error">{authError}</div>
                )}
                <div className="auth-modal-actions">
                  <button
                    type="button"
                    className="auth-switch"
                    disabled={authBusy}
                    onClick={() => {
                      setAuthError("");
                      clearSensitiveAuthState();
                      setAuthMode("register");
                    }}
                  >
                    New here? Create device identity
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {showAdminPanel && (
        <div
          className="auth-modal-backdrop"
          role="presentation"
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              setShowAdminPanel(false);
              clearAdminElevation();
              setAdminActionSecret("");
              setAdminSecretRevealOnce(null);
              setAdminUsers([]);
            }
          }}
        >
          <div
            className="auth-modal auth-modal-wide admin-modal"
            role="dialog"
            aria-label="Admin portal"
          >
            <div className="auth-modal-header">
              <strong>Admin · Transit support</strong>
              <button
                type="button"
                className="nearby-close"
                onClick={() => {
                  setShowAdminPanel(false);
                  clearAdminElevation();
                  setAdminActionSecret("");
                  setAdminSecretRevealOnce(null);
                  setAdminUsers([]);
                }}
                aria-label="Close"
              >
                ×
              </button>
            </div>
            <p className="auth-modal-copy">
              Privileged ops are server-enforced: allowlisted fingerprint +
              action secret + fresh PGP step-up (not the client{" "}
              <code>isAdmin</code> flag). Lookups need session only; grant /
              revoke / claim need full elevation. Audited.
            </p>

            {authUser && (
              <div className="admin-identity-box">
                <span>Signed-in fingerprint (must match ADMIN_FINGERPRINTS)</span>
                <code className="auth-user-fingerprint">
                  {formatFingerprint(authUser.fingerprint)}
                </code>
                <code className="admin-fp-hex">
                  {authUser.fingerprint.replace(/[\s:]/g, "").toLowerCase()}
                </code>
                <span className="admin-identity-status">
                  {isAdmin
                    ? "Allowlist: matched — admin access granted"
                    : adminAllowlistConfigured
                      ? "Allowlist: configured, but this fingerprint is not on it"
                      : "Allowlist: empty / not configured on this Worker"}
                </span>
              </div>
            )}

            {adminError && (
              <div className="auth-error" style={{ whiteSpace: "pre-wrap" }}>
                {adminError}
              </div>
            )}

            {!isAdmin && (
              <p className="auth-modal-copy">
                To fix: Cloudflare Dashboard → Workers → <strong>globe</strong>{" "}
                → Settings → Variables and Secrets → set{" "}
                <code>ADMIN_FINGERPRINTS</code> to the hex fingerprint above
                (no spaces), then sign out and sign in again. Or run:{" "}
                <code>
                  npx wrangler secret put ADMIN_FINGERPRINTS --name globe
                </code>
              </p>
            )}

            {isAdmin && (
              <>
                <div className="auth-section-title">
                  1 · Action secret (generate here)
                </div>
                {!adminSecretConfigured && (
                  <div className="auth-inline-error">
                    Server has no strong{" "}
                    <code>ADMIN_ACTION_SECRET</code> Worker secret yet.
                    Generate below (browser only), then run{" "}
                    <code>
                      npx wrangler secret put ADMIN_ACTION_SECRET --name globe
                    </code>
                    . Never KV or git.
                  </div>
                )}
                <p className="auth-modal-copy">
                  Creates a random value <strong>in this browser only</strong> —
                  not saved on the server. You must set it as a Cloudflare Worker
                  secret, then paste it here for grant/revoke/claim.
                </p>
                <div className="auth-modal-actions auth-row">
                  <button
                    type="button"
                    className="admin-generate-secret-btn"
                    disabled={adminBusy}
                    title="Create a random secret in browser memory (not stored on server)"
                    onClick={() => generateAdminActionSecret()}
                  >
                    Generate action secret
                  </button>
                </div>
                {adminSecretRevealOnce && (
                  <div className="auth-fp-block admin-secret-reveal">
                    <strong>Copy now — browser memory only</strong>
                    <p className="auth-modal-copy">
                      Not stored on the server. Set it as a Worker secret, then
                      use it in the field below.
                    </p>
                    <code className="admin-fp-hex" style={{ userSelect: "all" }}>
                      {adminSecretRevealOnce}
                    </code>
                    <div className="auth-modal-actions auth-row">
                      <button
                        type="button"
                        onClick={() => {
                          void navigator.clipboard
                            ?.writeText(adminSecretRevealOnce)
                            .then(() =>
                              setAdminMessage(
                                "Copied. Next: wrangler secret put ADMIN_ACTION_SECRET --name globe — not git or chat.",
                              ),
                            )
                            .catch(() =>
                              setAdminError(
                                "Clipboard blocked — select the secret above and copy manually.",
                              ),
                            );
                        }}
                      >
                        Copy secret
                      </button>
                      <button
                        type="button"
                        className="auth-switch"
                        onClick={() => setAdminSecretRevealOnce(null)}
                      >
                        Hide from screen
                      </button>
                    </div>
                  </div>
                )}
                <label className="auth-field">
                  <span>Action secret (memory only)</span>
                  <input
                    type="password"
                    value={adminActionSecret}
                    onChange={(e) => setAdminActionSecret(e.target.value)}
                    autoComplete="off"
                    spellCheck={false}
                    placeholder="paste Worker secret (needed only for mutations)"
                  />
                </label>

                <div className="auth-section-title">2 · Unlock with your key</div>
                <p className="auth-modal-copy">
                  Signs a one-time server challenge with your{" "}
                  <strong>device private key</strong>. Elevation lasts ~10
                  minutes. Requires{" "}
                  <code>ADMIN_ACTION_SECRET</code> set on the Worker first.
                </p>
                <div className="auth-modal-actions auth-row">
                  <button
                    type="button"
                    disabled={adminBusy || !adminSecretConfigured}
                    onClick={() => void unlockAdminPrivileges()}
                  >
                    {adminBusy
                      ? "Working…"
                      : adminElevationValid()
                        ? "Re-unlock privileges"
                        : "Unlock privileges (sign challenge)"}
                  </button>
                  {adminElevationValid() && (
                    <button
                      type="button"
                      className="auth-switch"
                      disabled={adminBusy}
                      onClick={() => {
                        clearAdminElevation();
                        setAdminMessage("Elevation cleared.");
                      }}
                    >
                      Lock again
                    </button>
                  )}
                </div>
                {adminElevationValid() && adminElevationExpiresAt && (
                  <div className="auth-inline-ok">
                    Elevated until{" "}
                    {new Date(adminElevationExpiresAt).toLocaleTimeString()}
                  </div>
                )}

                <div className="auth-section-title">All users</div>
                <p className="auth-modal-copy">
                  Directory for elevated admins only (action secret + unlock).
                  Public fields only — no private or public keys.
                </p>
                <div className="auth-modal-actions auth-row admin-users-filters">
                  <button
                    type="button"
                    className={
                      adminUsersFilter === "all" ? "" : "auth-switch"
                    }
                    disabled={adminBusy}
                    onClick={() => setAdminUsersFilter("all")}
                  >
                    All
                  </button>
                  <button
                    type="button"
                    className={
                      adminUsersFilter === "paid" ? "" : "auth-switch"
                    }
                    disabled={adminBusy}
                    onClick={() => setAdminUsersFilter("paid")}
                  >
                    Paid
                  </button>
                  <button
                    type="button"
                    className={
                      adminUsersFilter === "locked" ? "" : "auth-switch"
                    }
                    disabled={adminBusy}
                    onClick={() => setAdminUsersFilter("locked")}
                  >
                    Locked
                  </button>
                  <button
                    type="button"
                    disabled={
                      adminBusy ||
                      !adminElevationValid() ||
                      !adminActionSecret.trim()
                    }
                    title={
                      !adminElevationValid()
                        ? "Unlock privileges first"
                        : !adminActionSecret.trim()
                          ? "Enter action secret first"
                          : "Load user directory"
                    }
                    onClick={() => void loadAdminUsers()}
                  >
                    {adminBusy ? "Loading…" : "Load users"}
                  </button>
                  {!adminUsersComplete && adminUsersCursor && (
                    <button
                      type="button"
                      className="auth-switch"
                      disabled={
                        adminBusy ||
                        !adminElevationValid() ||
                        !adminActionSecret.trim()
                      }
                      onClick={() =>
                        void loadAdminUsers({
                          append: true,
                          cursor: adminUsersCursor,
                        })
                      }
                    >
                      Load more
                    </button>
                  )}
                </div>
                {adminUsers.length > 0 && (
                  <div className="admin-users-list">
                    <div className="admin-users-meta">
                      {adminUsers.length} shown
                      {!adminUsersComplete ? " · more available" : ""}
                    </div>
                    {adminUsers.map((u) => (
                      <div key={u.id} className="admin-user-row-wrap">
                        <button
                          type="button"
                          className="admin-user-row"
                          onClick={() => {
                            setAdminLookupUser(u);
                            setAdminQuery(u.id);
                            setAdminMessage(
                              `Selected user ${u.id.slice(0, 12)}… for grant/revoke/remove.`,
                            );
                          }}
                          title="Select for grant / revoke / remove"
                        >
                          <span
                            className={
                              u.transitPaid
                                ? "admin-user-badge paid"
                                : "admin-user-badge locked"
                            }
                          >
                            {u.transitPaid ? "PAID" : "LOCKED"}
                          </span>
                          <code className="admin-user-id">{u.id}</code>
                          <code className="admin-user-fp">
                            {formatFingerprint(u.fingerprint)}
                          </code>
                          {u.primaryUserId && (
                            <span className="admin-user-uid">
                              {u.primaryUserId}
                            </span>
                          )}
                          {u.createdAt && (
                            <span className="admin-user-created">
                              {new Date(u.createdAt).toLocaleString()}
                            </span>
                          )}
                        </button>
                        <button
                          type="button"
                          className="admin-user-remove"
                          disabled={
                            adminBusy ||
                            !adminElevationValid() ||
                            !adminActionSecret.trim()
                          }
                          title="Permanently delete this user"
                          onClick={(e) => {
                            e.stopPropagation();
                            void adminDeleteUser(u);
                          }}
                        >
                          Remove
                        </button>
                      </div>
                    ))}
                  </div>
                )}

                <div className="auth-section-title">Lookup customer</div>
                <label className="auth-field">
                  <span>User id or fingerprint</span>
                  <input
                    type="text"
                    value={adminQuery}
                    onChange={(e) => setAdminQuery(e.target.value)}
                    placeholder="paste user id or fingerprint"
                    spellCheck={false}
                  />
                </label>
                <div className="auth-modal-actions auth-row">
                  <button
                    type="button"
                    disabled={adminBusy || adminQuery.trim().length < 6}
                    onClick={() => void adminLookup()}
                  >
                    {adminBusy ? "Working…" : "Lookup"}
                  </button>
                </div>

                {adminLookupUser && (
                  <div className="auth-fp-block">
                    <div>
                      <strong>User</strong> <code>{adminLookupUser.id}</code>
                    </div>
                    <div>
                      Fingerprint{" "}
                      <code>
                        {formatFingerprint(adminLookupUser.fingerprint)}
                      </code>
                    </div>
                    {adminLookupUser.primaryUserId && (
                      <div>UID: {adminLookupUser.primaryUserId}</div>
                    )}
                    <div>
                      Transit:{" "}
                      <strong>
                        {adminLookupUser.transitPaid
                          ? "PAID / unlocked"
                          : "LOCKED"}
                      </strong>
                    </div>
                    <label className="auth-field" style={{ marginTop: 10 }}>
                      <span>Note (audit log)</span>
                      <input
                        type="text"
                        value={adminNote}
                        onChange={(e) => setAdminNote(e.target.value)}
                        placeholder="e.g. paid but webhook missed"
                      />
                    </label>
                    <div className="auth-modal-actions auth-row">
                      <button
                        type="button"
                        disabled={
                          adminBusy ||
                          !adminElevationValid() ||
                          !adminActionSecret.trim()
                        }
                        title={
                          adminElevationValid()
                            ? "Grant Transit (elevated)"
                            : "Unlock privileges first"
                        }
                        onClick={() => void adminGrant(true)}
                      >
                        Grant Transit
                      </button>
                      <button
                        type="button"
                        className="auth-switch"
                        disabled={
                          adminBusy ||
                          !adminElevationValid() ||
                          !adminActionSecret.trim()
                        }
                        onClick={() => void adminGrant(false)}
                      >
                        Revoke Transit
                      </button>
                      <button
                        type="button"
                        className="admin-user-remove"
                        disabled={
                          adminBusy ||
                          !adminElevationValid() ||
                          !adminActionSecret.trim()
                        }
                        title="Permanently delete this user account"
                        onClick={() => void adminDeleteUser(adminLookupUser)}
                      >
                        Remove user
                      </button>
                    </div>
                  </div>
                )}

                <div className="auth-section-title">Recover Stripe session</div>
                <label className="auth-field">
                  <span>Checkout session id (cs_…)</span>
                  <input
                    type="text"
                    value={adminSessionId}
                    onChange={(e) => setAdminSessionId(e.target.value)}
                    placeholder="cs_live_… or cs_test_…"
                    spellCheck={false}
                  />
                </label>
                <div className="auth-modal-actions auth-row">
                  <button
                    type="button"
                    disabled={
                      adminBusy ||
                      !adminSessionId.trim() ||
                      !adminElevationValid() ||
                      !adminActionSecret.trim()
                    }
                    title={
                      adminElevationValid()
                        ? "Claim paid Stripe session"
                        : "Unlock privileges first"
                    }
                    onClick={() => void adminClaim()}
                  >
                    Claim session → unlock user
                  </button>
                </div>

                {adminMessage && (
                  <div className="auth-fp-block">{adminMessage}</div>
                )}

                <div className="auth-section-title">Recent audit</div>
                <div className="admin-audit-list">
                  {adminAudit.length === 0 ? (
                    <div className="auth-field-hint">No audit entries yet.</div>
                  ) : (
                    adminAudit.slice(0, 12).map((e, i) => (
                      <div key={`${e.at}-${i}`} className="admin-audit-row">
                        <span>{new Date(e.at).toLocaleString()}</span>
                        <strong>{e.action}</strong>
                        <code>
                          {(
                            e.targetFingerprint ||
                            e.targetUserId ||
                            ""
                          ).slice(0, 16)}
                        </code>
                        {e.detail && <em>{e.detail}</em>}
                      </div>
                    ))
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      )}

      <nav className="nav-bar" ref={navBarRef}>
        <div className="nav-left">
          <h1 className="nav-title">FEDERALKEY</h1>
        </div>

        <div className="nav-center">
          {/* ABOUT button commented out / sent to background
          <button
            className="nav-btn"
            onClick={() =>
              runRateLimitedButtonAction("about-open", () => setShowAbout(true))
            }
          >
            ABOUT
          </button>
          */}
          <button
            className="nav-btn"
            onClick={() =>
              runRateLimitedButtonAction("cve-feed", () => {
                window.location.href = "https://cvefeed.io/dashboard/";
              })
            }
          >
            CVE FEED
          </button>
          <button
            className="nav-btn trade-pulse-nav-btn"
            onClick={() =>
              runRateLimitedButtonAction("trade-pulse-load", () => {
                void loadTradePulsePreview();
              })
            }
          >
            TRADE PULSE
          </button>
          <button
            className="nav-btn"
            onClick={() =>
              runRateLimitedButtonAction("unodc-load", () => {
                void loadUnodcHotspots();
              })
            }
          >
            UNODC
          </button>
          <button
            className="nav-btn"
            onClick={() =>
              runRateLimitedButtonAction("un-global-load", () => {
                void loadUnGlobalPreview();
              })
            }
          >
            UN LAYER
          </button>
        </div>

        <div className="nav-right">
          <button
            type="button"
            className={`weather-icon-btn transit-icon-btn ${
              transitStatus === "loading" ? "weather-icon-loading" : ""
            } ${showTransitPanel ? "transit-icon-btn-open" : ""}`}
            onClick={() => {
              void loadLocalTransit();
            }}
            aria-label="Local transit options"
            title="Local transit"
            aria-pressed={showTransitPanel}
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <rect x="5" y="3.5" width="14" height="14" rx="2.5" />
              <path d="M5 10.5h14" />
              <path d="M9 17.5v2.5" />
              <path d="M15 17.5v2.5" />
              <path d="M8 20h8" />
              <circle cx="9" cy="13.5" r="1" />
              <circle cx="15" cy="13.5" r="1" />
            </svg>
          </button>
          <button
            type="button"
            className={`weather-icon-btn nearby-icon-btn ${
              nearbyStatus === "loading" ? "weather-icon-loading" : ""
            } ${showNearbyPanel ? "nearby-icon-btn-open" : ""}`}
            onClick={() => {
              void loadNearbyPaths();
            }}
            aria-label="Nearby street traces"
            title="Nearby streets & paths"
            aria-pressed={showNearbyPanel}
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path d="M4 18V6" />
              <path d="M10 18V9" />
              <path d="M16 18V4" />
              <path d="M20 14H4" />
              <path d="M20 10H10" />
              <circle cx="4" cy="14" r="1.2" />
              <circle cx="10" cy="10" r="1.2" />
              <circle cx="16" cy="14" r="1.2" />
            </svg>
          </button>
          <button
            type="button"
            className={`weather-icon-btn ${weatherStatus === "loading" ? "weather-icon-loading" : ""}`}
            onClick={() =>
              runRateLimitedButtonAction("weather-load", () => {
                void loadWeatherFeed();
              })
            }
            aria-label="Load current weather"
            title="Current weather"
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path d="M7.5 17.5H17a4 4 0 0 0 .6-7.95 6 6 0 0 0-11.15 1.9A3.2 3.2 0 0 0 7.5 17.5Z" />
              <path d="m13 11-3 5h3l-2 5 5-7h-3l2-3Z" />
            </svg>
          </button>
          <button
            className="nav-menu-btn"
            onClick={() =>
              runRateLimitedButtonAction("menu-toggle", () =>
                setShowMenu((open) => !open),
              )
            }
          >
            <span>MENU</span>
            <span className="menu-icon">v</span>
          </button>
        </div>
      </nav>

      {showTransitPanel && (
        <FloatingChrome
          className="transit-panel"
          role="dialog"
          aria-label="Local transit options"
        >
          <div className="transit-panel-header nearby-panel-header">
            <div>
              <h3>LOCAL TRANSIT</h3>
              <span>
                {transitPreview
                  ? `${transitPreview.lat.toFixed(4)}, ${transitPreview.lng.toFixed(4)} · ${transitPreview.maxDistanceM}m`
                  : "Routes & stops near you"}
              </span>
            </div>
            <button
              type="button"
              className="nearby-close"
              onClick={() =>
                runRateLimitedButtonAction("transit-close", () =>
                  setShowTransitPanel(false),
                )
              }
              aria-label="Close local transit"
            >
              x
            </button>
          </div>

          {transitStatus === "loading" && (
            <div className="nearby-loading">Loading local transit...</div>
          )}

          {transitStatus === "error" && (
            <div className="nearby-error">
              <span>{transitError}</span>
              <div className="nearby-footer-actions" style={{ marginTop: 10 }}>
                {!authUser && (
                  <button
                    type="button"
                    onClick={() => {
                      setShowAuthPanel(true);
                      setAuthMode("login");
                    }}
                    disabled={authBusy}
                  >
                    Sign in
                  </button>
                )}
                {authUser && !authUser.transitPaid && (
                  <button
                    type="button"
                    className="billing-buy-btn"
                    onClick={() => {
                      void startTransitCheckout();
                    }}
                    disabled={checkoutBusy}
                  >
                    {checkoutBusy ? "Opening Stripe…" : "Buy Transit ($20)"}
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => {
                    void loadLocalTransit(false);
                  }}
                >
                  Retry
                </button>
              </div>
            </div>
          )}

          {transitStatus === "ready" && transitPreview && (
            <Suspense
              fallback={
                <div className="auth-field-hint" style={{ padding: 12 }}>
                  Loading transit map…
                </div>
              }
            >
              <TransitPanelContent
                preview={transitPreview}
                distanceM={transitDistanceM}
                onRadius={(m) => {
                  void loadLocalTransit(false, m);
                }}
                onRefresh={() => {
                  void loadLocalTransit(false, transitDistanceM);
                }}
                fetchNearbyMap={fetchNearbyMapForTransit}
              />
            </Suspense>
          )}
        </FloatingChrome>
      )}

      {showNearbyPanel && (
        <FloatingChrome
          className="nearby-panel"
          role="dialog"
          aria-label="Nearby street and path traces"
        >
          <div className="nearby-panel-header">
            <div>
              <h3>NEARBY MAP</h3>
              <span>
                {nearbyPreview
                  ? `${nearbyPreview.lat.toFixed(4)}, ${nearbyPreview.lng.toFixed(4)} · ${nearbyPreview.radiusM}m · drag header to move`
                  : "Local streets & paths"}
              </span>
            </div>
            <button
              type="button"
              className="nearby-close"
              onClick={() =>
                runRateLimitedButtonAction("nearby-close", () =>
                  setShowNearbyPanel(false),
                )
              }
              aria-label="Close nearby map"
            >
              x
            </button>
          </div>

          {nearbyStatus === "loading" && (
            <div className="nearby-loading">Tracing nearby streets...</div>
          )}

          {nearbyStatus === "error" && (
            <div className="nearby-error">
              <span>{nearbyError}</span>
              <button
                type="button"
                onClick={() => {
                  void loadNearbyPaths(false, nearbyRadiusM, true);
                }}
              >
                Retry
              </button>
            </div>
          )}

          {nearbyStatus === "ready" && nearbyPreview && (
            <>
              <div className="nearby-metrics">
                <div className="nearby-metric">
                  <span>Segments</span>
                  <strong>{nearbyPreview.paths?.length ?? nearbyPreview.pathCount}</strong>
                </div>
                <div className="nearby-metric">
                  <span>Roads</span>
                  <strong>{nearbyPreview.roadCount}</strong>
                </div>
                <div className="nearby-metric">
                  <span>Paths</span>
                  <strong>{nearbyPreview.footCount}</strong>
                </div>
                <div className="nearby-metric">
                  <span>Parks</span>
                  <strong>{nearbyPreview.parkCount ?? 0}</strong>
                </div>
                <div className="nearby-metric">
                  <span>Radius</span>
                  <strong>{nearbyPreview.radiusM}m</strong>
                </div>
              </div>
              {nearbyPreview.stale || !nearbyPreview.paths?.length ? (
                <div className="nearby-map-status-banner">
                  {nearbyPreview.note ||
                    "No live streets for this location. Allow GPS and retry."}
                  <button
                    type="button"
                    onClick={() => {
                      void loadNearbyPaths(false, nearbyRadiusM, true);
                    }}
                  >
                    Force refresh
                  </button>
                </div>
              ) : null}

              {/*
                Map keeps full square size; this region scrolls if the panel
                is shorter than header+metrics+map+actions. Radius/footer stay
                pinned below so they are never clipped off-screen.
              */}
              <div className="nearby-panel-body">
                <Suspense
                  fallback={
                    <div className="auth-field-hint" style={{ padding: 12 }}>
                      Loading map…
                    </div>
                  }
                >
                  <NearbyMap data={nearbyPreview} />
                </Suspense>
              </div>

              <div className="nearby-panel-actions">
                <div
                  className="nearby-radius-controls"
                  role="group"
                  aria-label="Trace radius"
                >
                  {[250, 500, 750, 1000, 1500].map((radius) => (
                    <button
                      key={radius}
                      type="button"
                      className={nearbyRadiusM === radius ? "active" : ""}
                      onClick={() => {
                        void loadNearbyPaths(false, radius);
                      }}
                    >
                      {radius}m
                    </button>
                  ))}
                </div>

                <div className="nearby-footer">
                  <span>
                    {nearbyPreview.stale
                      ? nearbyPreview.note ?? "Fallback sketch"
                      : nearbyPreview.note ?? "OSM centerlines"}
                  </span>
                  <div className="nearby-footer-actions">
                    <a
                      href={nearbyPreview.sourceUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      Source
                    </a>
                    <button
                      type="button"
                      onClick={() => {
                        void loadNearbyPaths(false, nearbyRadiusM, true);
                      }}
                    >
                      Refresh
                    </button>
                  </div>
                </div>
              </div>
            </>
          )}
        </FloatingChrome>
      )}

      {showWeatherPanel && (
        <FloatingChrome
          className={`weather-panel ${showWeatherForecast ? "weather-panel-expanded" : ""}`}
          role="dialog"
          aria-label="Weather forecast"
        >
          <div className="weather-panel-header">
            <div>
              <h3>WEATHER</h3>
              <span>{weatherFeed?.locationLabel ?? DEFAULT_WEATHER_LOCATION.label}</span>
            </div>
            <button
              type="button"
              className="weather-close"
              onClick={() =>
                runRateLimitedButtonAction("weather-close", () =>
                  setShowWeatherPanel(false),
                )
              }
              aria-label="Close weather"
            >
              x
            </button>
          </div>

          <div className="weather-panel-body">
            {weatherStatus === "loading" && (
              <div className="weather-loading">Loading weather...</div>
            )}

            {weatherStatus === "error" && (
              <div className="weather-error">
                <span>{weatherError}</span>
                <button
                  type="button"
                  onClick={() =>
                    runRateLimitedButtonAction("weather-retry", () => {
                      void loadWeatherFeed();
                    })
                  }
                >
                  Retry
                </button>
              </div>
            )}

            {weatherStatus === "ready" && weatherFeed && (
              <>
                <div className="weather-grid">
                  <div className="weather-metric">
                    <span>Temp</span>
                    <strong>{weatherFeed.tempF} F</strong>
                  </div>
                  <div className="weather-metric">
                    <span>Humidity</span>
                    <strong>{weatherFeed.humidityPct}%</strong>
                  </div>
                  <div className="weather-metric">
                    <span>Wind</span>
                    <strong>{weatherFeed.windMph} mph</strong>
                  </div>
                  <div
                    className={`weather-metric weather-condition ${
                      weatherFeed.hasLightning ? "weather-condition-alert" : ""
                    }`}
                    style={
                      {
                        ["--weather-condition-color"]: weatherGlow.text,
                        ["--weather-condition-glow"]: weatherGlow.css,
                      } as React.CSSProperties
                    }
                  >
                    <span>Condition</span>
                    <strong
                      className="weather-condition-value"
                      style={{
                        color: weatherGlow.text,
                        textShadow: `0 0 14px ${weatherGlow.css}`,
                      }}
                    >
                      {weatherFeed.condition}
                    </strong>
                  </div>
                </div>
                <div className="weather-footer">
                  <span>Updated {weatherFeed.updatedAt}</span>
                  <div className="weather-footer-actions">
                    <button
                      type="button"
                      className={`weather-forecast-toggle ${
                        showWeatherForecast ? "active" : ""
                      }`}
                      onClick={() =>
                        runRateLimitedButtonAction(
                          "weather-forecast-toggle",
                          () => setShowWeatherForecast((open) => !open),
                        )
                      }
                      aria-expanded={showWeatherForecast}
                      aria-controls="weather-forecast"
                    >
                      {showWeatherForecast ? "Hide forecast" : "Forecast"}
                    </button>
                    <button
                      type="button"
                      onClick={() =>
                        runRateLimitedButtonAction("weather-refresh", () => {
                          void loadWeatherFeed();
                        })
                      }
                    >
                      Refresh
                    </button>
                  </div>
                </div>
                {showWeatherForecast && (
                  <section
                    id="weather-forecast"
                    className="weather-forecast"
                    aria-label="Detailed weather forecast"
                  >
                    <div className="weather-forecast-header">
                      <span>Detailed outlook</span>
                      <span>7 days / next 7 hours</span>
                    </div>
                    <div
                      className="weather-forecast-tabs"
                      role="tablist"
                      aria-label="Forecast range"
                    >
                      <button
                        type="button"
                        role="tab"
                        aria-selected={forecastView === "daily"}
                        className={forecastView === "daily" ? "active" : ""}
                        onClick={() =>
                          runRateLimitedButtonAction("weather-daily-tab", () =>
                            setForecastView("daily"),
                          )
                        }
                      >
                        7 days
                      </button>
                      <button
                        type="button"
                        role="tab"
                        aria-selected={forecastView === "hourly"}
                        className={forecastView === "hourly" ? "active" : ""}
                        onClick={() =>
                          runRateLimitedButtonAction("weather-hourly-tab", () =>
                            setForecastView("hourly"),
                          )
                        }
                      >
                        7 hours
                      </button>
                    </div>
                    <div className="weather-forecast-list">
                      {forecastView === "daily"
                        ? weatherFeed.dailyForecast.map((day) => (
                            <article
                              className="weather-forecast-row"
                              key={day.date}
                            >
                              <div className="weather-forecast-time">
                                <strong>{formatForecastDay(day.date)}</strong>
                                <span>{day.condition}</span>
                              </div>
                              <div className="weather-forecast-temp">
                                <strong>{day.highF}°</strong>
                                <span>{day.lowF}° low</span>
                              </div>
                              <div className="weather-forecast-details">
                                <span>
                                  Rain {day.precipitationChancePct}% ·{" "}
                                  {day.precipitationIn.toFixed(2)} in
                                </span>
                                <span>
                                  Wind {day.windMph} mph · Gusts {day.gustMph} ·
                                  UV {day.uvIndex}
                                </span>
                              </div>
                            </article>
                          ))
                        : weatherFeed.hourlyForecast.map((hour) => (
                            <article
                              className="weather-forecast-row"
                              key={hour.time}
                            >
                              <div className="weather-forecast-time">
                                <strong>{formatForecastHour(hour.time)}</strong>
                                <span>{hour.condition}</span>
                              </div>
                              <div className="weather-forecast-temp">
                                <strong>{hour.tempF}°</strong>
                                <span>Feels {hour.feelsLikeF}°</span>
                              </div>
                              <div className="weather-forecast-details">
                                <span>
                                  Hum {hour.humidityPct}% · Rain{" "}
                                  {hour.precipitationChancePct}% ·{" "}
                                  {hour.precipitationIn.toFixed(2)} in
                                </span>
                                <span>
                                  Wind {hour.windMph} mph · Gusts {hour.gustMph}{" "}
                                  · Cloud {hour.cloudCoverPct}%
                                </span>
                              </div>
                            </article>
                          ))}
                    </div>
                  </section>
                )}
              </>
            )}
          </div>
        </FloatingChrome>
      )}

      {showComtradePanel && (
        <FloatingChrome className="un-panel" role="dialog" aria-label="UN Comtrade">
          <div className="un-panel-header">
            <div>
              <h3>Comtrade</h3>
              <span>
                {comtradeStatus === "ready" && comtradePreview
                  ? `${comtradePreview.period} · ${
                      comtradePreview.dataMode === "free-subscription" ||
                      comtradePreview.subscriptionBacked
                        ? "Live"
                        : "Preview"
                    }`
                  : "Annual trade sample"}
              </span>
            </div>
            <button
              type="button"
              className="un-close"
              onClick={() =>
                runRateLimitedButtonAction("comtrade-close", () => {
                  setShowComtradePanel(false);
                  setShowMenu(false);
                })
              }
              aria-label="Close UN Comtrade preview"
            >
              x
            </button>
          </div>

          {comtradeStatus === "loading" && (
            <div className="un-loading">Loading UN Comtrade public sample...</div>
          )}

          {comtradeStatus === "error" && (
            <div className="un-error">
              <span>{comtradeError}</span>
              <button
                type="button"
                onClick={() =>
                  runRateLimitedButtonAction("comtrade-retry", () => {
                    void loadComtradePreview();
                  })
                }
              >
                Retry
              </button>
            </div>
          )}

          {comtradeStatus === "ready" && comtradePreview && (
            <>
              <div className="un-status-row">
                <span>{comtradePreview.source}</span>
                <strong>
                  {comtradePreview.stale
                    ? "Fallback"
                    : comtradePreview.dataMode === "free-subscription" ||
                        comtradePreview.subscriptionBacked
                      ? "Live"
                      : "Preview"}
                </strong>
              </div>
              <div className="un-summary-grid">
                <div className="un-metric">
                  <span>Exports</span>
                  <strong>
                    {formatUsd(
                      comtradePreview.exportsUsd,
                      comtradePreview.stale,
                      comtradeValueMode,
                    )}
                  </strong>
                </div>
                <div className="un-metric">
                  <span>Imports</span>
                  <strong>
                    {formatUsd(
                      comtradePreview.importsUsd,
                      comtradePreview.stale,
                      comtradeValueMode,
                    )}
                  </strong>
                </div>
                <div className="un-metric">
                  <span>Balance</span>
                  <strong>
                    {formatSignedUsd(
                      comtradePreview.tradeBalanceUsd,
                      comtradePreview.stale,
                      comtradeValueMode,
                    )}
                  </strong>
                </div>
                <div className="un-metric">
                  <span>Records</span>
                  <strong>
                    {formatPreviewNumber(
                      comtradePreview.availabilityTotalRecords,
                      comtradePreview.stale,
                    )}
                  </strong>
                </div>
                <div className="un-metric">
                  <span>Refs</span>
                  <strong>
                    {formatPreviewNumber(
                      comtradePreview.referenceTablesTotal,
                      comtradePreview.stale,
                    )}
                  </strong>
                </div>
              </div>

              <div className="un-update-row">
                <span>{comtradePreview.queryLabel}</span>
                <strong>
                  Latest{" "}
                  {comtradePreview.latestRelease
                    ? formatPreviewDate(comtradePreview.latestRelease)
                    : "n/a"}
                </strong>
              </div>

              <div className="un-goal-list" aria-label="UN COMTRADE data preview">
                {enabledComtradeSectionCount === 0 && (
                  <div className="un-empty-state">
                    Enable a Comtrade section from the menu.
                  </div>
                )}

                {comtradeSections.records && (
                  <section className="un-data-section">
                    <div className="un-section-heading">
                      <span>Trade records</span>
                      <strong>{comtradePreview.tradeRecords.length} shown</strong>
                    </div>
                    {comtradePreview.tradeRecords.map((record) => (
                      <article className="un-goal-row" key={`${record.flow}-${record.period}`}>
                        <div className="un-goal-heading">
                          <span>{record.flow}</span>
                          <strong>
                            {formatUsd(
                              record.primaryValueUsd,
                              comtradePreview.stale,
                              comtradeValueMode,
                            )}
                          </strong>
                        </div>
                        <p>
                          {record.reporter} to {record.partner} · {record.commodity} (
                          {record.commodityCode})
                        </p>
                        <div className="un-goal-meta">
                          <span>Period {record.period}</span>
                          <span>
                            CIF{" "}
                            {formatNullableUsd(
                              record.cifValueUsd,
                              comtradePreview.stale,
                              comtradeValueMode,
                            )}
                          </span>
                          <span>
                            FOB{" "}
                            {formatNullableUsd(
                              record.fobValueUsd,
                              comtradePreview.stale,
                              comtradeValueMode,
                            )}
                          </span>
                        </div>
                      </article>
                    ))}
                  </section>
                )}

                {comtradeSections.availability && (
                  <section className="un-data-section">
                    <div className="un-section-heading">
                      <span>Data availability</span>
                      <strong>{comtradePreview.availability.length} shown</strong>
                    </div>
                    {comtradePreview.availability.map((dataset) => (
                      <article className="un-compact-row" key={dataset.datasetCode}>
                        <div className="un-compact-heading">
                          <span>{dataset.classification || "Dataset"}</span>
                          <strong>{formatPreviewNumber(dataset.totalRecords)} records</strong>
                        </div>
                        <p>
                          {dataset.reporter} · {dataset.period} · dataset {dataset.datasetCode}
                        </p>
                        <div className="un-goal-meta">
                          <span>
                            First{" "}
                            {dataset.firstReleased
                              ? formatPreviewDate(dataset.firstReleased)
                              : "n/a"}
                          </span>
                          <span>
                            Last{" "}
                            {dataset.lastReleased
                              ? formatPreviewDate(dataset.lastReleased)
                              : "n/a"}
                          </span>
                        </div>
                      </article>
                    ))}
                  </section>
                )}

                {comtradeSections.references && (
                  <section className="un-data-section">
                    <div className="un-section-heading">
                      <span>Reference tables</span>
                      <strong>{comtradePreview.references.length} shown</strong>
                    </div>
                    {comtradePreview.references.map((reference) => (
                      <article className="un-compact-row" key={reference.category}>
                        <div className="un-compact-heading">
                          <span>{reference.category}</span>
                          <strong>{reference.variable}</strong>
                        </div>
                        <p>{reference.description}</p>
                      </article>
                    ))}
                  </section>
                )}

                {comtradeSections.reporters && (
                  <section className="un-data-section">
                    <div className="un-section-heading">
                      <span>Reporters</span>
                      <strong>{formatPreviewNumber(comtradePreview.reportersTotal)} total</strong>
                    </div>
                    <div className="un-chip-list">
                      {comtradePreview.reporters.map((reporter) => (
                        <span className="un-chip" key={reporter.code}>
                          {reporter.name} <small>{reporter.iso3 || reporter.code}</small>
                        </span>
                      ))}
                    </div>
                  </section>
                )}
              </div>

              <div className="un-footer">
                <span>{formatPreviewDate(comtradePreview.updatedAt)}</span>
                <div className="un-footer-actions">
                  <a
                    href={comtradePreview.sourceUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Source
                  </a>
                  <button
                    type="button"
                    onClick={() =>
                      runRateLimitedButtonAction("comtrade-refresh", () => {
                        void loadComtradePreview();
                      })
                    }
                  >
                    Refresh
                  </button>
                </div>
              </div>
            </>
          )}
        </FloatingChrome>
      )}

      {showTradePulsePanel && (
        <FloatingChrome
          className={`un-panel trade-pulse-panel ${
            isTradePulsePanelMinimized ? "un-panel-minimized" : ""
          }`}
          role="dialog"
          aria-label="Trade Pulse"
        >
          <div className="un-panel-header">
            <div>
              <h3>Trade Pulse</h3>
              <span>
                {tradePulseStatus === "ready" && tradePulsePreview
                  ? `${tradePulsePreview.period} · ${
                      tradePulsePreview.dataMode === "free-subscription" ||
                      tradePulsePreview.subscriptionBacked
                        ? "Live"
                        : "Preview"
                    }`
                  : "Dependency radar"}
              </span>
            </div>
            <div className="un-panel-actions">
              <button
                type="button"
                className="un-minimize"
                onClick={() =>
                  runRateLimitedButtonAction("trade-pulse-minimize", () =>
                    setIsTradePulsePanelMinimized((minimized) => !minimized),
                  )
                }
                aria-label={
                  isTradePulsePanelMinimized
                    ? "Restore Trade Pulse preview"
                    : "Minimize Trade Pulse preview"
                }
              >
                {isTradePulsePanelMinimized ? "+" : "_"}
              </button>
              <button
                type="button"
                className="un-close"
                onClick={() =>
                  runRateLimitedButtonAction("trade-pulse-close", () =>
                    setShowTradePulsePanel(false),
                  )
                }
                aria-label="Close Trade Pulse preview"
              >
                x
              </button>
            </div>
          </div>

          {!isTradePulsePanelMinimized && (
            <div className="trade-pulse-panel-scroll">
              <div className="trade-pulse-panel-inner">
                <div
                  className="trade-pulse-year-row"
                  role="group"
                  aria-label="Trade year"
                >
                  <span className="trade-pulse-year-label">Year</span>
                  <div className="trade-pulse-year-buttons">
                    {tradePulseYearOptions.map((year) => (
                      <button
                        type="button"
                        key={year}
                        className={`trade-pulse-year-btn ${
                          tradePulsePeriod === year ? "active" : ""
                        }`}
                        aria-pressed={tradePulsePeriod === year}
                        disabled={tradePulseStatus === "loading"}
                        onClick={() =>
                          runRateLimitedButtonAction(`trade-pulse-year-${year}`, () => {
                            selectTradePulsePeriod(year);
                          })
                        }
                      >
                        {year}
                      </button>
                    ))}
                  </div>
                </div>

                {tradePulseStatus === "loading" && (
                  <div className="un-loading">Loading {tradePulsePeriod}…</div>
                )}

                {tradePulseStatus === "error" && (
                  <div className="un-error">
                    <span>{tradePulseError}</span>
                    <button
                      type="button"
                      onClick={() =>
                        runRateLimitedButtonAction("trade-pulse-retry", () => {
                          void loadTradePulsePreview(false, tradePulsePeriod, {
                            keepExpanded: true,
                          });
                        })
                      }
                    >
                      Retry
                    </button>
                  </div>
                )}

                {tradePulseStatus === "ready" && tradePulsePreview && (
                  <>
                    <div className="un-status-row trade-pulse-status-row">
                      <span>{tradePulsePreview.source}</span>
                      <strong>
                        {tradePulsePreview.dataMode === "free-subscription" ||
                        tradePulsePreview.subscriptionBacked
                          ? `Live · ${tradePulsePreview.liveRouteCount ?? tradePulsePreview.routes.length} routes`
                          : "Preview"}
                      </strong>
                    </div>

                    <div className="un-summary-grid trade-pulse-summary-grid">
                      {tradePulsePreview.metrics.slice(0, 8).map((metric) => (
                        <div className="un-metric" key={metric.label}>
                          <span>{metric.label}</span>
                          <strong>{metric.value}</strong>
                        </div>
                      ))}
                    </div>

                    <div className="un-update-row">
                      <span>HS annual · {tradePulsePreview.period}</span>
                      <strong>{visibleTradePulseRoutes.length} routes</strong>
                    </div>

                    <div
                      className="trade-pulse-layer-grid"
                      role="group"
                      aria-label="Trade Pulse layers"
                    >
                      {TRADE_PULSE_LAYERS.map((layer) => (
                        <button
                          type="button"
                          key={layer}
                          className={`trade-pulse-layer-toggle ${
                            tradePulseLayers[layer] ? "active" : ""
                          }`}
                          style={
                            {
                              "--layer-color": TRADE_PULSE_LAYER_COLORS[layer],
                            } as React.CSSProperties
                          }
                          aria-pressed={tradePulseLayers[layer]}
                          onClick={() =>
                            runRateLimitedButtonAction(`trade-pulse-layer-${layer}`, () =>
                              toggleTradePulseLayer(layer),
                            )
                          }
                        >
                          <span>{TRADE_PULSE_LAYER_LABELS[layer]}</span>
                          <strong>{tradePulseLayers[layer] ? "On" : "Off"}</strong>
                        </button>
                      ))}
                    </div>

                    <div
                      className="un-goal-list trade-pulse-route-list"
                      aria-label="Trade Pulse routes"
                    >
                      {enabledTradePulseLayerCount === 0 && (
                        <div className="un-empty-state">
                          Enable a Trade Pulse layer from the panel or menu.
                        </div>
                      )}

                      {visibleTradePulseRoutes.map((route) => {
                        const activeLayer = getRoutePulseLayer(route, tradePulseLayers);

                        return (
                          <article
                            className={`un-goal-row trade-pulse-route-card trade-pulse-card-${route.severity}`}
                            key={route.id}
                            style={
                              {
                                "--route-card-color": TRADE_PULSE_LAYER_COLORS[activeLayer],
                              } as React.CSSProperties
                            }
                          >
                            <div className="un-goal-heading trade-pulse-card-heading">
                              <span>
                                {route.origin.iso3} to {route.destination.iso3}
                              </span>
                              <strong>{route.commodity}</strong>
                            </div>
                            <p>
                              {route.origin.name} to {route.destination.name}
                              {route.intermediary
                                ? ` via ${route.intermediary.name}`
                                : ""}{" "}
                              · {route.transportMode} · {route.customsProcedure}
                            </p>
                            <div className="trade-pulse-badge-row">
                              {route.layers
                                .filter((layer) => tradePulseLayers[layer])
                                .map((layer) => (
                                  <span
                                    className="trade-pulse-layer-badge"
                                    key={layer}
                                    style={
                                      {
                                        "--layer-color": TRADE_PULSE_LAYER_COLORS[layer],
                                      } as React.CSSProperties
                                    }
                                  >
                                    {TRADE_PULSE_LAYER_SHORT_LABELS[layer]}
                                  </span>
                                ))}
                            </div>
                            <div className="un-goal-meta trade-pulse-metrics">
                              <span>
                                Value {formatUsd(route.valueUsd, false, comtradeValueMode)}
                              </span>
                              <span>Supplier {formatPercent(route.supplierSharePct)}</span>
                              <span>Mirror gap {formatPercent(route.asymmetryPct)}</span>
                              <span>CIF/FOB {formatPercent(route.frictionPct)}</span>
                              <span>Re-export {formatPercent(route.reExportSharePct)}</span>
                              <span>Confidence {formatPercent(route.confidencePct)}</span>
                            </div>
                            <p className="trade-pulse-insight">{route.insight}</p>
                          </article>
                        );
                      })}
                    </div>

                    <div className="un-footer">
                      <span>{formatPreviewDate(tradePulsePreview.updatedAt)}</span>
                      <div className="un-footer-actions">
                        <a
                          href={tradePulsePreview.sourceUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          Source
                        </a>
                        <button
                          type="button"
                          onClick={() =>
                            runRateLimitedButtonAction("trade-pulse-refresh", () => {
                              void loadTradePulsePreview(false, tradePulsePeriod, {
                                keepExpanded: true,
                              });
                            })
                          }
                        >
                          Refresh
                        </button>
                      </div>
                    </div>
                  </>
                )}
              </div>
            </div>
          )}
        </FloatingChrome>
      )}

      {showUnodcPanel && (
        <FloatingChrome
          className={`un-panel unodc-panel ${
            isUnodcPanelMinimized ? "un-panel-minimized" : ""
          }`}
          role="dialog"
          aria-label="UNODC theme hotspots"
        >
          <div className="un-panel-header">
            <div>
              <h3>UNODC Hotspots</h3>
              <span>
                {unodcStatus === "ready" && unodcPreview
                  ? unodcPreview.queryLabel
                  : "Data Portal themes"}
              </span>
            </div>
            <div className="un-panel-actions">
              <button
                type="button"
                className="un-minimize"
                onClick={() =>
                  runRateLimitedButtonAction("unodc-minimize", () =>
                    setIsUnodcPanelMinimized((m) => !m),
                  )
                }
                aria-label={
                  isUnodcPanelMinimized ? "Expand UNODC panel" : "Minimize UNODC panel"
                }
              >
                {isUnodcPanelMinimized ? "+" : "_"}
              </button>
              <button
                type="button"
                className="un-close"
                onClick={() =>
                  runRateLimitedButtonAction("unodc-close", () => {
                    setShowUnodcPanel(false);
                  })
                }
                aria-label="Close UNODC panel"
              >
                x
              </button>
            </div>
          </div>

          {!isUnodcPanelMinimized && (
            <div className="trade-pulse-panel-scroll">
              <div className="trade-pulse-panel-inner">
                {unodcStatus === "loading" && (
                  <div className="un-loading">Loading UNODC themes…</div>
                )}
                {unodcStatus === "error" && (
                  <div className="un-error">
                    <span>{unodcError}</span>
                    <button
                      type="button"
                      onClick={() =>
                        runRateLimitedButtonAction("unodc-retry", () => {
                          void loadUnodcHotspots(false);
                        })
                      }
                    >
                      Retry
                    </button>
                  </div>
                )}
                {unodcStatus === "ready" && unodcPreview && (
                  <>
                    <div className="un-status-row">
                      <span>{unodcPreview.source}</span>
                      <strong>
                        {Object.values(unodcThemes).filter(Boolean).length} on globe
                        · {unodcCountryPolygons ? "choropleth" : "heat"}
                      </strong>
                    </div>
                    <div className="unodc-mode-row" role="group" aria-label="Theme focus">
                      <button
                        type="button"
                        className="trade-pulse-year-btn active"
                        onClick={() =>
                          runRateLimitedButtonAction("unodc-mode-focus", () =>
                            setUnodcFocusMode("focus"),
                          )
                        }
                      >
                        Focus
                      </button>
                      <button
                        type="button"
                        className="trade-pulse-year-btn"
                        onClick={() =>
                          runRateLimitedButtonAction("unodc-mode-all", () =>
                            setUnodcFocusMode("all-live"),
                          )
                        }
                      >
                        All live
                      </button>
                      <button
                        type="button"
                        className="trade-pulse-year-btn"
                        onClick={() =>
                          runRateLimitedButtonAction("unodc-mode-none", () =>
                            setUnodcFocusMode("none"),
                          )
                        }
                      >
                        Clear
                      </button>
                    </div>
                    <div className="un-status-row unodc-live-count">
                      <span>
                        {countLiveUnodcThemes(unodcPreview)}/
                        {unodcPreview.themes.length} themes with country data
                      </span>
                      {countLiveUnodcThemes(unodcPreview) <
                        unodcPreview.themes.length && (
                        <button
                          type="button"
                          className="trade-pulse-year-btn"
                          onClick={() =>
                            runRateLimitedButtonAction("unodc-reload-all", () => {
                              void loadUnodcHotspots(false, {
                                forceRefresh: true,
                              });
                            })
                          }
                        >
                          Reload all themes
                        </button>
                      )}
                    </div>
                    <div className="unodc-legend" aria-label="Theme colors">
                      {unodcPreview.themes.map((theme) => {
                        const canToggle =
                          theme.dataMode === "live" && theme.hotspotCount > 0;
                        return (
                          <button
                            type="button"
                            key={`legend-${theme.id}`}
                            className={`unodc-legend-item ${
                              unodcThemes[theme.id] ? "active" : ""
                            } ${canToggle ? "" : "disabled"}`}
                            disabled={!canToggle}
                            title={
                              canToggle
                                ? theme.label
                                : `${theme.label} — no country series yet`
                            }
                            onClick={() =>
                              runRateLimitedButtonAction(
                                `unodc-legend-${theme.id}`,
                                () => toggleUnodcTheme(theme.id),
                              )
                            }
                          >
                            <i
                              className="unodc-legend-swatch"
                              style={{ background: UNODC_THEME_CSS[theme.id] }}
                            />
                            <span>{theme.label}</span>
                          </button>
                        );
                      })}
                    </div>
                    <div className="un-goal-list" aria-label="UNODC themes">
                      {unodcPreview.themes.map((theme) => {
                        const canToggle =
                          theme.dataMode === "live" && theme.hotspotCount > 0;
                        return (
                          <article
                            className={`un-goal-row unodc-theme-card ${
                              unodcThemes[theme.id] ? "active" : ""
                            } ${canToggle ? "" : "is-unavailable"}`}
                            key={theme.id}
                            style={
                              {
                                "--unodc-theme-color": UNODC_THEME_CSS[theme.id],
                              } as React.CSSProperties
                            }
                          >
                            <div className="un-goal-heading">
                              <span>
                                <i
                                  className="unodc-legend-swatch"
                                  style={{
                                    background: UNODC_THEME_CSS[theme.id],
                                  }}
                                />{" "}
                                {theme.label}
                              </span>
                              <strong>
                                {canToggle
                                  ? `${theme.hotspotCount} areas`
                                  : "No country data"}
                              </strong>
                            </div>
                            <p>
                              {theme.seriesLabel}
                              {theme.period ? ` · ${theme.period}` : ""}
                              {theme.unit ? ` · ${theme.unit}` : ""}
                            </p>
                            {theme.note && (
                              <p className="trade-pulse-insight">{theme.note}</p>
                            )}
                            <div className="un-goal-meta">
                              <button
                                type="button"
                                className={`trade-pulse-year-btn ${
                                  unodcThemes[theme.id] ? "active" : ""
                                }`}
                                aria-pressed={unodcThemes[theme.id]}
                                disabled={!canToggle}
                                title={
                                  canToggle
                                    ? undefined
                                    : "No open country hotspots for this theme yet"
                                }
                                onClick={() =>
                                  runRateLimitedButtonAction(
                                    `unodc-theme-${theme.id}`,
                                    () => toggleUnodcTheme(theme.id),
                                  )
                                }
                              >
                                {unodcThemes[theme.id] ? "On globe" : "Off"}
                              </button>
                              <a
                                href={theme.portalUrl}
                                target="_blank"
                                rel="noopener noreferrer"
                              >
                                Portal
                              </a>
                            </div>
                            {unodcThemes[theme.id] &&
                              theme.hotspots.length > 0 && (
                                <div className="unodc-hotspot-list">
                                  {theme.hotspots.slice(0, 8).map((spot) => (
                                    <span key={spot.id}>
                                      {spot.iso3} {spot.value}
                                      <small> ({spot.year})</small>
                                    </span>
                                  ))}
                                </div>
                              )}
                          </article>
                        );
                      })}
                    </div>
                    <div className="un-footer">
                      <span>{formatPreviewDate(unodcPreview.updatedAt)}</span>
                      <div className="un-footer-actions">
                        <a
                          href={unodcPreview.datasearchUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          Datasearch
                        </a>
                        <a
                          href={unodcPreview.sourceUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          Portal
                        </a>
                        <button
                          type="button"
                          onClick={() =>
                            runRateLimitedButtonAction("unodc-refresh", () => {
                              void loadUnodcHotspots(false, {
                                forceRefresh: true,
                              });
                            })
                          }
                        >
                          Refresh
                        </button>
                      </div>
                    </div>
                  </>
                )}
              </div>
            </div>
          )}
        </FloatingChrome>
      )}

      {showUnGlobalPanel && (
        <FloatingChrome
          className={`un-panel un-layer-panel ${
            isUnGlobalPanelMinimized ? "un-panel-minimized" : ""
          }`}
          role="dialog"
          aria-label="UN global location preview"
        >
          <div className="un-panel-header">
            <div>
              <h3>UN Global Layer</h3>
              <span>HQ, missions, states, affiliates</span>
            </div>
            <div className="un-panel-actions">
              <button
                type="button"
                className="un-minimize"
                onClick={() =>
                  runRateLimitedButtonAction("un-global-minimize", () =>
                    setIsUnGlobalPanelMinimized((minimized) => !minimized),
                  )
                }
                aria-label={
                  isUnGlobalPanelMinimized
                    ? "Restore UN global preview"
                    : "Minimize UN global preview"
                }
              >
                {isUnGlobalPanelMinimized ? "+" : "_"}
              </button>
              <button
                type="button"
                className="un-close"
                onClick={() =>
                  runRateLimitedButtonAction("un-global-close", disableUnGlobalLayer)
                }
                aria-label="Disable UN global layer"
              >
                x
              </button>
            </div>
          </div>

          {!isUnGlobalPanelMinimized && unGlobalStatus === "loading" && (
            <div className="un-loading">Loading UN global data...</div>
          )}

          {!isUnGlobalPanelMinimized && unGlobalStatus === "error" && (
            <div className="un-error">
              <span>{unGlobalError}</span>
              <button
                type="button"
                onClick={() =>
                  runRateLimitedButtonAction("un-global-retry", () => {
                    void loadUnGlobalPreview();
                  })
                }
              >
                Retry
              </button>
            </div>
          )}

          {!isUnGlobalPanelMinimized && unGlobalStatus === "ready" && unGlobalPreview && (
            <>
              <div className="un-status-row">
                <span>{unGlobalPreview.source}</span>
                {unGlobalPreview.stale && <strong>Fallback snapshot</strong>}
              </div>
              <div className="un-summary-grid">
                <div className="un-metric">
                  <span>HQ</span>
                  <strong>{formatPreviewNumber(unGlobalPreview.officesTotal)}</strong>
                </div>
                <div className="un-metric">
                  <span>Missions</span>
                  <strong>{formatPreviewNumber(unGlobalPreview.missionCoordinateTotal)}</strong>
                </div>
                <div className="un-metric">
                  <span>Members</span>
                  <strong>{formatPreviewNumber(unGlobalPreview.memberStatesTotal)}</strong>
                </div>
                <div className="un-metric">
                  <span>Affiliates</span>
                  <strong>{formatPreviewNumber(unGlobalPreview.affiliatesTotal)}</strong>
                </div>
                <div className="un-metric">
                  <span>Embassies</span>
                  <strong>{formatPreviewNumber(unGlobalPreview.embassiesTotal)}</strong>
                </div>
              </div>

              <div className="un-update-row">
                <span>{unGlobalPreview.queryLabel}</span>
                <strong>
                  Latest{" "}
                  {unGlobalPreview.latestMissionUpdate
                    ? formatPreviewDate(unGlobalPreview.latestMissionUpdate)
                    : "n/a"}
                </strong>
              </div>

              <div className="un-goal-list" aria-label="UN global location data preview">
                {enabledUnGlobalSectionCount === 0 && (
                  <div className="un-empty-state">
                    Enable a UN global layer section from the menu.
                  </div>
                )}

                {unGlobalSections.offices && (
                  <section className="un-data-section">
                    <div className="un-section-heading">
                      <span>UN HQ and main offices</span>
                      <strong>{unGlobalPreview.offices.length} markers</strong>
                    </div>
                    {unGlobalPreview.offices.map((office) => (
                      <article className="un-compact-row" key={office.id}>
                        <div className="un-compact-heading">
                          <span>{office.name}</span>
                          <strong>{office.category}</strong>
                        </div>
                        <p>
                          {office.city}, {office.country} · {office.lat.toFixed(2)},{" "}
                          {office.lng.toFixed(2)}
                        </p>
                      </article>
                    ))}
                  </section>
                )}

                {visibleUnMissionLocations.length > 0 && (
                  <section className="un-data-section">
                    <div className="un-section-heading">
                      <span>Mission HQ locations</span>
                      <strong>{visibleUnMissionLocations.length} shown</strong>
                    </div>
                    {visibleUnMissionLocations.map((mission) => (
                      <article className="un-goal-row" key={mission.id}>
                        <div className="un-goal-heading">
                          <span>{mission.acronym}</span>
                          <strong>{mission.active ? "Active" : "Historic"}</strong>
                        </div>
                        <p>
                          {mission.name} · {mission.location}
                        </p>
                        <div className="un-goal-meta">
                          <span>Lat {mission.lat.toFixed(2)}</span>
                          <span>Lng {mission.lng.toFixed(2)}</span>
                          <span>
                            Start{" "}
                            {mission.startDate
                              ? formatPreviewDate(mission.startDate)
                              : "n/a"}
                          </span>
                        </div>
                      </article>
                    ))}
                  </section>
                )}

                {unGlobalSections.memberStates && (
                  <section className="un-data-section">
                    <div className="un-section-heading">
                      <span>Member states</span>
                      <strong>{unGlobalPreview.memberStates.length} markers</strong>
                    </div>
                    <div className="un-chip-list">
                      {unGlobalPreview.memberStates.map((state) => (
                        <span className="un-chip" key={state.code}>
                          {state.name} <small>{state.code}</small>
                        </span>
                      ))}
                    </div>
                  </section>
                )}

                {unGlobalSections.affiliates && (
                  <section className="un-data-section">
                    <div className="un-section-heading">
                      <span>Non-member affiliates</span>
                      <strong>{unGlobalPreview.affiliates.length} markers</strong>
                    </div>
                    {unGlobalPreview.affiliates.map((affiliate) => (
                      <article className="un-compact-row" key={affiliate.code}>
                        <div className="un-compact-heading">
                          <span>{affiliate.name}</span>
                          <strong>{affiliate.category}</strong>
                        </div>
                        <p>
                          SDG/M49 area {affiliate.code} · {affiliate.lat.toFixed(2)},{" "}
                          {affiliate.lng.toFixed(2)}
                        </p>
                      </article>
                    ))}
                  </section>
                )}

                {unGlobalSections.embassies && (
                  <section className="un-data-section">
                    <div className="un-section-heading">
                      <span>Permanent missions / embassies</span>
                      <strong>{unGlobalPreview.embassies.length} markers</strong>
                    </div>
                    {unGlobalPreview.embassies.map((embassy) => (
                      <article className="un-compact-row" key={embassy.code}>
                        <div className="un-compact-heading">
                          <span>{embassy.name}</span>
                          <strong>Blue Book</strong>
                        </div>
                        <p>
                          UN diplomatic directory marker · {embassy.lat.toFixed(2)},{" "}
                          {embassy.lng.toFixed(2)}
                        </p>
                      </article>
                    ))}
                  </section>
                )}
              </div>

              <div className="un-footer">
                <span>Updated {formatPreviewDate(unGlobalPreview.updatedAt)}</span>
                <div className="un-footer-actions">
                  <a
                    href={unGlobalPreview.sourceUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Source
                  </a>
                  <a
                    href={unGlobalPreview.apiUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    API
                  </a>
                  <button
                    type="button"
                    onClick={() =>
                      runRateLimitedButtonAction("un-global-refresh", () => {
                        void loadUnGlobalPreview();
                      })
                    }
                  >
                    Refresh
                  </button>
                </div>
              </div>
            </>
          )}
        </FloatingChrome>
      )}

      <div className={`main-content ${showTradePulsePanel ? "trade-pulse-main" : ""}`}>
        <div className="globe-stage">
          <Cobe
            counter={counter}
            positions={positions.current}
            overlayMarkers={globeOverlayMarkers}
            overlayRoutes={tradePulseGlobeArcs}
            heatZones={unodcHeatZones}
            choroplethRegions={unodcChoroplethRegions}
            markerColor={globeMarkerColor}
            glowColor={weatherGlow.color}
            glowCssColor={weatherGlow.css}
          />
        </div>
      </div>

      <div className="bottom-dock">
        <div id="globe-controls-slot" className="globe-controls-slot" />
        <ActivityFeed
          open={showActivityMenu}
          onToggle={() =>
            runRateLimitedButtonAction("activity-toggle", () =>
              setShowActivityMenu((open) => !open),
            )
          }
          onClose={() =>
            runRateLimitedButtonAction("activity-close", () =>
              setShowActivityMenu(false),
            )
          }
          counter={counter}
          events={activityFeed}
          onClear={() =>
            runRateLimitedButtonAction("activity-clear", clearActivityFeed)
          }
          isPaused={isFeedPaused}
          onTogglePause={() =>
            runRateLimitedButtonAction("activity-pause", () =>
              setIsFeedPaused((paused) => !paused),
            )
          }
          isCompact={isCompactFeed}
          onToggleCompact={() =>
            runRateLimitedButtonAction("activity-compact", () =>
              setIsCompactFeed((compact) => !compact),
            )
          }
          filter={activityFilter}
          onFilterChange={handleActivityFilterChange}
          isSocketConnected={isSocketConnected && !isDisconnected}
          access={liveFeedAccess}
          checkoutBusy={checkoutBusy}
          onSignIn={() => {
            setShowActivityMenu(false);
            setShowAuthPanel(true);
            setAuthMode("login");
            setAuthMessage(
              "Sign in, then buy Stripe access to unlock Live Feed.",
            );
          }}
          onBuyAccess={() => {
            void startTransitCheckout();
          }}
        />
      </div>

      {showAbout && (
        <div className="modal-overlay" onClick={() => setShowAbout(false)}>
          <FloatingChrome
            className="modal-content"
            onClick={(e) => e.stopPropagation()}
            onPointerDown={(e) => e.stopPropagation()}
          >
            <button
              type="button"
              className="modal-close"
              onClick={() =>
                runRateLimitedButtonAction("about-close", () => setShowAbout(false))
              }
              aria-label="Close about dialog"
            >
              x
            </button>
            <h2>About & Credits</h2>
            <p>Interactive globe powered by:</p>
            <ul className="credits-list">
              <li>
                <a href="https://cobe.vercel.app/" target="_blank" rel="noopener noreferrer">
                  Cobe
                </a>
              </li>
              <li>
                <a
                  href="https://www.npmjs.com/package/phenomenon"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Phenomenon
                </a>
              </li>
              <li>
                <a href="https://npmjs.com/package/partyserver/" target="_blank" rel="noopener noreferrer">
                  PartyServer
                </a>
              </li>
              <li>
                <a href="https://federalkey.org" target="_blank" rel="noopener noreferrer">
                  FederalKey
                </a>
              </li>
            </ul>
          </FloatingChrome>
        </div>
      )}

      {showMenu && (
        <FloatingChrome className="menu-dropdown" aria-label="Global controls menu">
          <div className="menu-dropdown-scroll">
          <div className="menu-dropdown-inner">
          <div className="menu-section">
            <div className="menu-section-title">Comtrade</div>
            <div className="menu-comtrade-summary" aria-label="Comtrade snapshot summary">
              <div className="menu-comtrade-summary-head">
                <span>{comtradeMenuStatus}</span>
                <strong>{comtradeMenuSource}</strong>
              </div>
              <small>{comtradeMenuQuery}</small>
              <div className="menu-comtrade-metrics">
                <div>
                  <span>Exports</span>
                  <strong>
                    {comtradePreview
                      ? formatUsd(
                          comtradePreview.exportsUsd,
                          comtradePreview.stale,
                          comtradeValueMode,
                        )
                      : "n/a"}
                  </strong>
                </div>
                <div>
                  <span>Imports</span>
                  <strong>
                    {comtradePreview
                      ? formatUsd(
                          comtradePreview.importsUsd,
                          comtradePreview.stale,
                          comtradeValueMode,
                        )
                      : "n/a"}
                  </strong>
                </div>
                <div>
                  <span>Balance</span>
                  <strong>
                    {comtradePreview
                      ? formatSignedUsd(
                          comtradePreview.tradeBalanceUsd,
                          comtradePreview.stale,
                          comtradeValueMode,
                        )
                      : "n/a"}
                  </strong>
                </div>
                <div>
                  <span>Updated</span>
                  <strong>{comtradeMenuUpdated}</strong>
                </div>
              </div>
            </div>
            <button
              type="button"
              className={`menu-toggle-item ${showComtradePanel ? "active" : ""}`}
              aria-pressed={showComtradePanel}
              onClick={() =>
                runRateLimitedButtonAction(
                  "menu-comtrade-panel",
                  toggleComtradePanelFromMenu,
                )
              }
            >
              <div className="menu-toggle-copy">
                <span>Panel</span>
                <small>Trade totals and records</small>
              </div>
              <strong>{showComtradePanel ? "Open" : "Closed"}</strong>
            </button>
            {COMTRADE_SECTIONS.map((section) => (
                <button
                  type="button"
                  className={`menu-toggle-item ${
                    comtradeSections[section] ? "active" : ""
                  }`}
                  aria-pressed={comtradeSections[section]}
                  key={section}
                  onClick={() =>
                    runRateLimitedButtonAction(`menu-comtrade-${section}`, () =>
                      toggleComtradeSection(section),
                    )
                  }
                >
                  <div className="menu-toggle-copy">
                    <span>{COMTRADE_SECTION_LABELS[section]}</span>
                    <small>{getComtradeSectionDetail(section)}</small>
                  </div>
                  <strong>{comtradeSections[section] ? "On" : "Off"}</strong>
                </button>
              ))}
            <button
              type="button"
              className={`menu-toggle-item ${isFullUsdMode ? "active" : ""}`}
              aria-pressed={isFullUsdMode}
              onClick={() =>
                runRateLimitedButtonAction("menu-comtrade-usd-mode", () =>
                  setComtradeValueMode((mode) => (mode === "compact" ? "full" : "compact")),
                )
              }
            >
              <div className="menu-toggle-copy">
                <span>USD format</span>
                <small>{isFullUsdMode ? "Full figures" : "Compact"}</small>
              </div>
              <strong>{isFullUsdMode ? "Full" : "Compact"}</strong>
            </button>
            <div className="menu-section-meta">
              {enabledComtradeSectionCount}/4 sections
            </div>
          </div>
          <div className="menu-section menu-section-trade-pulse">
            <div className="menu-section-title">Trade Pulse</div>
            <button
              type="button"
              className={`menu-toggle-item ${showTradePulsePanel ? "active" : ""}`}
              aria-pressed={showTradePulsePanel}
              onClick={() =>
                runRateLimitedButtonAction("menu-trade-pulse-panel", () => {
                  if (showTradePulsePanel) {
                    setIsTradePulsePanelMinimized((minimized) => !minimized);
                  } else {
                    void loadTradePulsePreview(false);
                  }
                })
              }
            >
              <div className="menu-toggle-copy">
                <span>Panel</span>
                <small>Globe dependency radar</small>
              </div>
              <strong>
                {showTradePulsePanel
                  ? isTradePulsePanelMinimized
                    ? "Minimized"
                    : "Open"
                  : "Closed"}
              </strong>
            </button>
            <div className="menu-trade-pulse-years" role="group" aria-label="Trade year">
              {tradePulseYearOptions.map((year) => (
                <button
                  type="button"
                  key={year}
                  className={`menu-toggle-item menu-trade-pulse-year ${
                    tradePulsePeriod === year ? "active" : ""
                  }`}
                  aria-pressed={tradePulsePeriod === year}
                  onClick={() =>
                    runRateLimitedButtonAction(`menu-trade-pulse-year-${year}`, () => {
                      selectTradePulsePeriod(year);
                    })
                  }
                >
                  <div className="menu-toggle-copy">
                    <span>{year}</span>
                    <small>Annual period</small>
                  </div>
                  <strong>{tradePulsePeriod === year ? "On" : "Off"}</strong>
                </button>
              ))}
            </div>
            <button
              type="button"
              className={`menu-toggle-item ${allTradePulseLayersEnabled ? "active" : ""}`}
              aria-pressed={allTradePulseLayersEnabled}
              onClick={() =>
                runRateLimitedButtonAction(
                  "menu-trade-pulse-all",
                  toggleAllTradePulseLayers,
                )
              }
            >
              <div className="menu-toggle-copy">
                <span>All layers</span>
                <small>Show every radar layer</small>
              </div>
              <strong>{allTradePulseLayersEnabled ? "On" : "Mixed"}</strong>
            </button>
            <div className="menu-trade-pulse-layers" role="group" aria-label="Trade Pulse layers">
              {TRADE_PULSE_LAYERS.map((layer) => (
                <button
                  type="button"
                  className={`menu-toggle-item menu-trade-pulse-layer ${
                    tradePulseLayers[layer] ? "active" : ""
                  }`}
                  aria-pressed={tradePulseLayers[layer]}
                  key={layer}
                  onClick={() =>
                    runRateLimitedButtonAction(`menu-trade-pulse-${layer}`, () =>
                      toggleTradePulseLayer(layer),
                    )
                  }
                >
                  <div className="menu-toggle-copy">
                    <span>{TRADE_PULSE_LAYER_SHORT_LABELS[layer]}</span>
                    <small className="menu-trade-pulse-detail">
                      {TRADE_PULSE_LAYER_LABELS[layer]}
                    </small>
                  </div>
                  <strong>{tradePulseLayers[layer] ? "On" : "Off"}</strong>
                </button>
              ))}
            </div>
            <div className="menu-section-meta">
              {enabledTradePulseLayerCount}/8 pulse layers visible
            </div>
          </div>
          <div className="menu-section">
            <div className="menu-section-title">UNODC Hotspots</div>
            <button
              type="button"
              className={`menu-toggle-item ${showUnodcPanel ? "active" : ""}`}
              aria-pressed={showUnodcPanel}
              onClick={() =>
                runRateLimitedButtonAction("menu-unodc-panel", () => {
                  if (showUnodcPanel) {
                    setIsUnodcPanelMinimized((m) => !m);
                  } else {
                    void loadUnodcHotspots(false);
                  }
                })
              }
            >
              <div className="menu-toggle-copy">
                <span>Panel</span>
                <small>Theme hotspots on globe</small>
              </div>
              <strong>
                {showUnodcPanel
                  ? isUnodcPanelMinimized
                    ? "Minimized"
                    : "Open"
                  : "Closed"}
              </strong>
            </button>
            {UNODC_THEME_IDS.map((themeId) => {
              const theme = unodcPreview?.themes.find((t) => t.id === themeId);
              return (
                <button
                  type="button"
                  key={themeId}
                  className={`menu-toggle-item ${unodcThemes[themeId] ? "active" : ""}`}
                  aria-pressed={unodcThemes[themeId]}
                  onClick={() =>
                    runRateLimitedButtonAction(`menu-unodc-${themeId}`, () =>
                      toggleUnodcTheme(themeId),
                    )
                  }
                >
                  <div className="menu-toggle-copy">
                    <span>{theme?.label || themeId}</span>
                    <small>
                      {theme
                        ? theme.dataMode === "live"
                          ? `${theme.hotspotCount} hotspots`
                          : "Portal tables"
                        : "Load panel for data"}
                    </small>
                  </div>
                  <strong>{unodcThemes[themeId] ? "On" : "Off"}</strong>
                </button>
              );
            })}
          </div>
          <div className="menu-section">
            <div className="menu-section-title">UN Global Layer</div>
            <button
              type="button"
              className={`menu-toggle-item ${showUnGlobalPanel ? "active" : ""}`}
              aria-pressed={showUnGlobalPanel}
              onClick={() =>
                runRateLimitedButtonAction(
                  "menu-un-global-panel",
                  toggleUnGlobalPanelFromMenu,
                )
              }
            >
              <span>Panel view</span>
              <strong>
                {showUnGlobalPanel
                  ? isUnGlobalPanelMinimized
                    ? "Minimized"
                    : "Open"
                  : "Closed"}
              </strong>
            </button>
            <button
              type="button"
              className={`menu-toggle-item ${allUnGlobalSectionsEnabled ? "active" : ""}`}
              aria-pressed={allUnGlobalSectionsEnabled}
              onClick={() =>
                runRateLimitedButtonAction(
                  "menu-un-global-all",
                  toggleAllUnGlobalSections,
                )
              }
            >
              <span>All locations</span>
              <strong>{allUnGlobalSectionsEnabled ? "On" : "Mixed"}</strong>
            </button>
            {(
              [
                "offices",
                "activeMissions",
                "pastMissions",
                "memberStates",
                "affiliates",
                "embassies",
              ] as UnGlobalSection[]
            ).map((section) => (
              <button
                type="button"
                className={`menu-toggle-item ${unGlobalSections[section] ? "active" : ""}`}
                aria-pressed={unGlobalSections[section]}
                key={section}
                onClick={() =>
                  runRateLimitedButtonAction(`menu-un-global-${section}`, () =>
                    toggleUnGlobalSection(section),
                  )
                }
              >
                <span>{UN_GLOBAL_SECTION_LABELS[section]}</span>
                <strong>{unGlobalSections[section] ? "On" : "Off"}</strong>
              </button>
            ))}
            <div className="menu-section-meta">
              {enabledUnGlobalSectionCount}/6 global sections visible
            </div>
          </div>

          <div className="menu-section menu-section-links" aria-label="App links">
            <a
              href="https://federalkey.org"
              className="menu-item"
              target="_blank"
              rel="noopener noreferrer"
            >
              Federalkey
            </a>
            <button
              type="button"
              className={`menu-item menu-item-button ${showTransitPanel ? "active" : ""}`}
              onClick={() => {
                void loadLocalTransit(false);
              }}
            >
              Local transit
            </button>
            <button
              type="button"
              className={`menu-item menu-item-button ${showNearbyPanel ? "active" : ""}`}
              onClick={() => {
                void loadNearbyPaths(false);
              }}
            >
              Nearby traces
            </button>
            <button
              type="button"
              className="menu-item menu-item-button billing-menu-item"
              disabled={checkoutBusy || Boolean(authUser?.transitPaid)}
              onClick={() => {
                // Guests: open sign-in only — never hit Stripe APIs.
                if (!authUser) {
                  setShowMenu(false);
                  setShowAuthPanel(true);
                  setAuthMode("login");
                  setAuthMessage(
                    "Sign in first, then buy Stripe access ($20).",
                  );
                  return;
                }
                void startTransitCheckout();
              }}
            >
              {checkoutBusy
                ? "Opening Stripe…"
                : authUser?.transitPaid
                  ? "Stripe access unlocked ✓"
                  : authUser
                    ? "Buy Stripe access ($20)"
                    : "Sign in to buy access"}
            </button>
            {authUser ? (
              <>
                <div className="menu-section-meta auth-user-meta">
                  <div className="auth-user-meta-status">
                    Signed in
                    {authUser.transitPaid
                      ? " · Transit + Live Feed paid"
                      : ""}
                    {authUser.primaryUserId
                      ? ` · ${authUser.primaryUserId}`
                      : ""}
                  </div>
                  <div
                    className="auth-user-fingerprint"
                    title="Full OpenPGP fingerprint"
                  >
                    {formatFingerprint(authUser.fingerprint)}
                  </div>
                </div>
                <button
                  type="button"
                  className="menu-item menu-item-button"
                  disabled={authBusy}
                  onClick={() => {
                    void logout(false);
                    setShowMenu(false);
                  }}
                >
                  {authBusy ? "Working…" : "Log out"}
                </button>
                <button
                  type="button"
                  className="menu-item menu-item-button"
                  disabled={authBusy}
                  title="Revoke every session for this account (all devices)"
                  onClick={() => {
                    void logout(true);
                    setShowMenu(false);
                  }}
                >
                  Log out all devices
                </button>
              </>
            ) : (
              <button
                type="button"
                className="menu-item menu-item-button"
                disabled={authBusy}
                onClick={() => {
                  setShowMenu(false);
                  setShowAuthPanel(true);
                  setAuthMode("login");
                }}
              >
                Sign in
              </button>
            )}
            {authUser ? (
              <button
                type="button"
                className={`menu-item menu-item-button admin-menu-item ${
                  isAdmin ? "" : "admin-menu-item-locked"
                }`}
                onClick={() => {
                  void openAdminPanel();
                }}
                title={
                  isAdmin
                    ? "Open admin portal"
                    : "Open admin status (this key may not be allowlisted)"
                }
              >
                {isAdmin ? "Admin" : "Admin (locked)"}
              </button>
            ) : null}
            <a
              href="https://104041.webmail.dynadot.com/user/signin.html"
              className="menu-item"
              target="_blank"
              rel="noopener noreferrer"
            >
              Webmail
            </a>
            <a
              href="https://federalkeymarketplace.page.gd"
              className="menu-item"
              target="_blank"
              rel="noopener noreferrer"
            >
              Market
            </a>
          </div>
          </div>
          </div>
        </FloatingChrome>
      )}
    </div>
  );
}

// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
createRoot(document.getElementById("root")!).render(<App />);


