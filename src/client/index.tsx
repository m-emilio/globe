import "./styles.css";

import React, { useState, useRef, useEffect, useCallback } from "react";
import { createRoot } from "react-dom/client";
import { Cobe, type GlobeArc } from "./CobeGlobe";
import { FloatingChrome } from "./FloatingChrome";
import { NearbyMap } from "./NearbyMap";
import { TransitPanelContent } from "./TransitPanelContent";
import {
  ActivityFeed,
  createActivityEvent,
  prependActivityEvent,
  type ActivityEvent,
  type ActivityFilter,
  type LiveFeedAccess,
} from "./ActivityFeed";
import usePartySocket from "partysocket/react";
import type {
  OutgoingMessage,
  ComtradePreview,
  NearbyPathsPreview,
  TradePulseLayer,
  TradePulsePreview,
  TradePulseRoutePreview,
  TransitNearbyPreview,
  UnGlobalPreview,
} from "../shared";
import {
  authFetch,
  clearLastFingerprint,
  clearSessionToken,
  containsPrivateKeyBlock,
  deleteDeviceKey,
  downloadPrivateKeyFile,
  exportPrivateKeyToArmoredFile,
  formatFingerprint,
  generateAndKeepOnDevice,
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
  const [isTradePulsePanelMinimized, setIsTradePulsePanelMinimized] =
    useState(false);
  const [tradePulseStatus, setTradePulseStatus] = useState<TradePulseStatus>("idle");
  const [tradePulsePreview, setTradePulsePreview] = useState<TradePulsePreview | null>(
    null,
  );
  const [tradePulseError, setTradePulseError] = useState("");
  const [tradePulseLayers, setTradePulseLayers] = useState(DEFAULT_TRADE_PULSE_LAYERS);
  const [showUnGlobalPanel, setShowUnGlobalPanel] = useState(false);
  const [isUnGlobalPanelMinimized, setIsUnGlobalPanelMinimized] = useState(false);
  const [unGlobalStatus, setUnGlobalStatus] = useState<UnGlobalStatus>("idle");
  const [unGlobalPreview, setUnGlobalPreview] = useState<UnGlobalPreview | null>(null);
  const [unGlobalError, setUnGlobalError] = useState("");
  const [unGlobalSections, setUnGlobalSections] = useState(DEFAULT_UN_GLOBAL_SECTIONS);
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
  const [authUser, setAuthUser] = useState<{
    id: string;
    fingerprint: string;
    primaryUserId: string | null;
    transitPaid: boolean;
  } | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);
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
      };
      if (data.authenticated && data.user?.fingerprint) {
        setAuthUser(data.user);
        setIsAdmin(Boolean(data.isAdmin));
        setAdminSecretRequired(Boolean(data.adminActionSecretRequired));
        return data.user;
      }
      setAuthUser(null);
      setIsAdmin(false);
      setAdminSecretRequired(false);
      return null;
    } catch {
      setAuthUser(null);
      setIsAdmin(false);
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

  const clearAdminElevation = () => {
    setAdminElevationToken(null);
    setAdminElevationExpiresAt(null);
  };

  /**
   * PGP step-up: sign a server challenge with the device private key.
   * Does NOT need ADMIN_ACTION_SECRET in the form — that is only checked
   * on grant/revoke/claim. Private key never leaves the browser.
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
            "Could not start admin elevation (is ADMIN_ACTION_SECRET set in .dev.vars?)",
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

  const openAdminPanel = async () => {
    setShowMenu(false);
    setAdminError("");
    setAdminMessage("");
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
      const data = (await res.json()) as { isAdmin?: boolean };
      if (!data.isAdmin) {
        setAuthError(
          "This key is signed in but not on ADMIN_FINGERPRINTS. Add your full fingerprint to .dev.vars and restart.",
        );
        return;
      }
      setIsAdmin(true);
    } catch {
      // fall through
    }
    try {
      const st = await authFetch("/api/admin/status");
      const stData = (await st.json()) as {
        actionSecretConfigured?: boolean;
        actionSecretRequired?: boolean;
      };
      if (st.ok) {
        setAdminSecretConfigured(Boolean(stData.actionSecretConfigured));
        setAdminSecretRequired(Boolean(stData.actionSecretRequired ?? true));
      }
    } catch {
      // ignore
    }
    setShowAdminPanel(true);
    await loadAdminAudit();
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
  const handleGenerateKeypair = async () => {
    setAuthBusy(true);
    setAuthError("");
    try {
      const result = await generateAndKeepOnDevice({
        profile: keyGenProfile,
      });
      setGeneratedPublic(result.public);
      setRegPublicKey(result.public.publicKeyArmored);
      setSelectedDeviceFp(result.deviceKey.fingerprint);
      setKeySavedAck(true); // device already holds the key
      await refreshDeviceKeys();
      setAuthMessage(
        `Created ${result.profileLabel} on this device. Private key never leaves the browser; stored device-bound (AES-wrapped). Click Register to publish the public key only.`,
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
      setAuthUser(data.user);
      setIsAdmin(Boolean(data.isAdmin));
      setAdminSecretRequired(Boolean(data.adminActionSecretRequired));
      setLastFingerprint(data.user.fingerprint);
      setSelectedDeviceFp(data.user.fingerprint);
      setGeneratedPublic(null);
      setRegPublicKey("");
      setShowAuthPanel(false);
      // Re-fetch /me so admin/transit flags stay in sync with server allowlists.
      await refreshAuth();
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
          ? "Imported encrypted key onto this device. Sign-in asks for the key passphrase only."
          : "Imported key onto this device. Sign-in needs no password.",
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
    setComtradeStatus("loading");
    setComtradeError("");

    try {
      const response = await fetch("/api/comtrade-preview", {
        headers: {
          accept: "application/json",
        },
      });

      if (!response.ok) {
        throw new Error("UN COMTRADE preview request failed");
      }

      const data = (await response.json()) as ComtradePreview;

      if (!data || !Array.isArray(data.tradeRecords)) {
        throw new Error("UN COMTRADE preview response incomplete");
      }

      setComtradePreview(data);
      setComtradeStatus("ready");
    } catch {
      setComtradeError("UN COMTRADE preview unavailable");
      setComtradeStatus("error");
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

  const loadTradePulsePreview = async (closeMenu = true) => {
    // Keep other popups open so multiple panels can be used side by side
    setShowTradePulsePanel(true);
    if (closeMenu) {
      setShowMenu(false);
    }
    setTradePulseStatus("loading");
    setTradePulseError("");

    try {
      const response = await fetch("/api/comtrade-pulse-preview", {
        headers: {
          accept: "application/json",
        },
      });

      if (!response.ok) {
        throw new Error("Trade Pulse preview request failed");
      }

      const data = (await response.json()) as TradePulsePreview;

      if (!data || !Array.isArray(data.routes)) {
        throw new Error("Trade Pulse preview response incomplete");
      }

      setTradePulsePreview(data);
      setTradePulseStatus("ready");
    } catch {
      setTradePulseError("Trade Pulse preview unavailable");
      setTradePulseStatus("error");
    }
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

  const loadUnGlobalPreview = async (closeMenu = true) => {
    // Keep other popups open so multiple panels can be used side by side
    setShowUnGlobalPanel(true);
    setIsUnGlobalPanelMinimized(false);
    if (closeMenu) {
      setShowMenu(false);
    }
    setUnGlobalStatus("loading");
    setUnGlobalError("");

    try {
      const response = await fetch("/api/un-global-preview", {
        headers: {
          accept: "application/json",
        },
      });

      if (!response.ok) {
        throw new Error("UN global preview request failed");
      }

      const data = (await response.json()) as UnGlobalPreview;

      if (!data || !Array.isArray(data.missionLocations)) {
        throw new Error("UN global preview response incomplete");
      }

      setUnGlobalPreview(data);
      setUnGlobalStatus("ready");
    } catch {
      setUnGlobalError("UN global preview unavailable");
      setUnGlobalStatus("error");
    }
  };

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
        ? "Fallback snapshot"
        : "Comtrade+ API"
      : comtradeStatus === "error"
        ? "Preview unavailable"
        : "Open preview to fetch";
  const comtradeMenuQuery =
    comtradeStatus === "ready" && comtradePreview
      ? `${comtradePreview.queryLabel} / ${comtradePreview.period}`
      : comtradeStatus === "loading"
        ? "Fetching Comtrade+ preview data"
        : "Summary, records, coverage, references, and reporters";
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
          };
        })
      : [];
  const globeOverlayMarkers = [...unGlobalOverlayMarkers, ...tradePulseGlobeMarkers];
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
              passphrase only if <em>you</em> encrypted the device key. (The
              fingerprint in localStorage is public ID only — not browser
              “cache”.)
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

      {showAdminPanel && isAdmin && (
        <div
          className="auth-modal-backdrop"
          role="presentation"
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              setShowAdminPanel(false);
              clearAdminElevation();
              setAdminActionSecret("");
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

            {!adminSecretConfigured && (
              <div className="auth-inline-error">
                Server has no strong ADMIN_ACTION_SECRET. Set ≥16 random chars
                in <code>.dev.vars</code> and restart — mutations stay locked
                (fail closed).
              </div>
            )}

            <div className="auth-section-title">1 · Unlock with your key</div>
            <p className="auth-modal-copy">
              Signs a one-time server challenge with your <strong>device
              private key</strong> (already on this browser). Does not use the
              action secret. Elevation lasts ~10 minutes.
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

            <div className="auth-section-title">
              2 · Action secret (for grant / revoke / claim only)
            </div>
            <p className="auth-modal-copy">
              Paste the value of <code>ADMIN_ACTION_SECRET</code> from{" "}
              <code>.dev.vars</code> here when you grant/revoke/claim. The
              server already has it; this field is how you prove you know it.
              Memory only — not saved in the browser.
            </p>
            <label className="auth-field">
              <span>ADMIN_ACTION_SECRET</span>
              <input
                type="password"
                value={adminActionSecret}
                onChange={(e) => setAdminActionSecret(e.target.value)}
                autoComplete="off"
                spellCheck={false}
                placeholder="paste from .dev.vars (needed only for mutations)"
              />
            </label>

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
                  <strong>User</strong>{" "}
                  <code>{adminLookupUser.id}</code>
                </div>
                <div>
                  Fingerprint{" "}
                  <code>{formatFingerprint(adminLookupUser.fingerprint)}</code>
                </div>
                {adminLookupUser.primaryUserId && (
                  <div>UID: {adminLookupUser.primaryUserId}</div>
                )}
                <div>
                  Transit:{" "}
                  <strong>
                    {adminLookupUser.transitPaid ? "PAID / unlocked" : "LOCKED"}
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

            {adminError && (
              <div className="auth-inline-error">{adminError}</div>
            )}
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
                      {(e.targetFingerprint || e.targetUserId || "").slice(0, 16)}
                    </code>
                    {e.detail && <em>{e.detail}</em>}
                  </div>
                ))
              )}
            </div>
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
              runRateLimitedButtonAction("un-global-load", () => {
                void loadUnGlobalPreview();
              })
            }
          >
            UN LAYER
          </button>
          <button
            className={`nav-btn transit-nav-btn ${showTransitPanel ? "active" : ""}`}
            onClick={() => {
              void loadLocalTransit();
            }}
            aria-pressed={showTransitPanel}
            title="Local transit options"
          >
            TRANSIT
          </button>
        </div>

        <div className="nav-right">
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
                <NearbyMap data={nearbyPreview} />
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
        <FloatingChrome className="un-panel" role="dialog" aria-label="UN COMTRADE API preview">
          <div className="un-panel-header">
            <div>
              <h3>UN COMTRADE API</h3>
              <span>Official data preview</span>
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
              aria-label="Close UN COMTRADE preview"
            >
              x
            </button>
          </div>

          {comtradeStatus === "loading" && (
            <div className="un-loading">Loading UN data...</div>
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
                {comtradePreview.stale && <strong>Fallback snapshot</strong>}
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
                <span>Updated {formatPreviewDate(comtradePreview.updatedAt)}</span>
                <div className="un-footer-actions">
                  <a
                    href={comtradePreview.sourceUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Source
                  </a>
                  <a
                    href={comtradePreview.apiUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    API
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
          aria-label="Trade Pulse dependency radar preview"
        >
          <div className="un-panel-header">
            <div>
              <h3>Trade Pulse</h3>
              <span>Dependency radar preview</span>
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
                {tradePulseStatus === "loading" && (
                  <div className="un-loading">Loading Trade Pulse layers...</div>
                )}

                {tradePulseStatus === "error" && (
                  <div className="un-error">
                    <span>{tradePulseError}</span>
                    <button
                      type="button"
                      onClick={() =>
                        runRateLimitedButtonAction("trade-pulse-retry", () => {
                          void loadTradePulsePreview();
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
                      <strong>Derived preview</strong>
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
                      <span>{tradePulsePreview.period} Comtrade-shaped scenario</span>
                      <strong>{visibleTradePulseRoutes.length} active routes</strong>
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

                    <div className="trade-pulse-notes">
                      <strong>Preview notes</strong>
                      {tradePulsePreview.notes.map((note) => (
                        <span key={note}>{note}</span>
                      ))}
                    </div>

                    <div className="un-footer">
                      <span>Updated {formatPreviewDate(tradePulsePreview.updatedAt)}</span>
                      <div className="un-footer-actions">
                        <a
                          href={tradePulsePreview.sourceUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          Source
                        </a>
                        <a
                          href={tradePulsePreview.apiUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          API
                        </a>
                        <button
                          type="button"
                          onClick={() =>
                            runRateLimitedButtonAction("trade-pulse-refresh", () => {
                              void loadTradePulsePreview();
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
            <div className="menu-section-title">Comtrade Controls</div>
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
                <span>Preview panel</span>
                <small>open or close the detailed Comtrade+ drawer</small>
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
                <span>USD values</span>
                <small>
                  {isFullUsdMode
                    ? "full dollar figures for precise comparisons"
                    : "compact notation for faster scanning"}
                </small>
              </div>
              <strong>{isFullUsdMode ? "Full" : "Compact"}</strong>
            </button>
            <div className="menu-section-meta">
              {enabledComtradeSectionCount}/4 data sections visible
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
                <span>Panel view</span>
                <small>open, minimize, or close the dependency radar drawer</small>
              </div>
              <strong>
                {showTradePulsePanel
                  ? isTradePulsePanelMinimized
                    ? "Minimized"
                    : "Open"
                  : "Closed"}
              </strong>
            </button>
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
                <span>All pulse layers</span>
                <small>toggle every dependency radar layer at once</small>
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
                  Signed in · {shortFingerprint(authUser.fingerprint)}
                  {authUser.primaryUserId
                    ? ` · ${authUser.primaryUserId}`
                    : ""}
                  {authUser.transitPaid
                    ? " · Transit + Live Feed paid"
                    : ""}
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
            {authUser && isAdmin ? (
              <button
                type="button"
                className="menu-item menu-item-button admin-menu-item"
                onClick={() => {
                  void openAdminPanel();
                }}
              >
                Admin
              </button>
            ) : authUser ? (
              <button
                type="button"
                className="menu-item menu-item-button"
                disabled
                title="Settings is only available to allowlisted admin keys (ADMIN_FINGERPRINTS)"
              >
                Settings
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
