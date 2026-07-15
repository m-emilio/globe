import "./styles.css";

import React, { useState, useRef, useEffect, useCallback } from "react";
import { createRoot } from "react-dom/client";
import { Cobe, type GlobeArc } from "./CobeGlobe";
import { FloatingChrome } from "./FloatingChrome";
import { NearbyMap } from "./NearbyMap";
import {
  ActivityFeed,
  createActivityEvent,
  prependActivityEvent,
  type ActivityEvent,
  type ActivityFilter,
} from "./ActivityFeed";
import usePartySocket from "partysocket/react";
import type {
  OutgoingMessage,
  ComtradePreview,
  NearbyPathsPreview,
  TradePulseLayer,
  TradePulsePreview,
  TradePulseRoutePreview,
  UnGlobalPreview,
} from "../shared";
type WeatherStatus = "idle" | "loading" | "ready" | "error";
type NearbyStatus = "idle" | "loading" | "ready" | "error";
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

  return {
    type: "add-marker",
    position: {
      lat,
      lng,
      id,
      ip: getLimitedString(position.ip, 45),
      country: getLimitedString(position.country, 4),
      city: getLimitedString(position.city, 80),
      org: getLimitedString(position.org, 120),
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

function getWeatherGlow(weather: WeatherFeed | null) {
  if (!weather) {
    return {
      color: [0.18, 0.55, 0.8] as [number, number, number],
      css: "rgba(0, 217, 255, 0.35)",
    };
  }

  if (weather.hasLightning) {
    return {
      color: [0.78, 0.7, 1] as [number, number, number],
      css: "rgba(170, 145, 255, 0.55)",
    };
  }

  if (weather.weatherCode === 0 || weather.weatherCode === 1) {
    return {
      color: [1, 0.72, 0.18] as [number, number, number],
      css: "rgba(255, 184, 46, 0.46)",
    };
  }

  if ([2, 3, 45, 48].includes(weather.weatherCode)) {
    return {
      color: [0.52, 0.64, 0.76] as [number, number, number],
      css: "rgba(150, 178, 210, 0.38)",
    };
  }

  if (
    [
      51, 53, 55, 56, 57, 61, 63, 65, 66, 67, 80, 81, 82,
    ].includes(weather.weatherCode)
  ) {
    return {
      color: [0.1, 0.45, 0.95] as [number, number, number],
      css: "rgba(35, 126, 255, 0.48)",
    };
  }

  if ([71, 73, 75, 77, 85, 86].includes(weather.weatherCode)) {
    return {
      color: [0.72, 0.9, 1] as [number, number, number],
      css: "rgba(190, 232, 255, 0.5)",
    };
  }

  return {
    color: [0.18, 0.55, 0.8] as [number, number, number],
    css: "rgba(0, 217, 255, 0.35)",
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
  const navBarRef = useRef<HTMLElement | null>(null);

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
  const lastButtonClickAt = useRef(0);
  const lastButtonClicks = useRef<Map<string, number>>(new Map());

  useEffect(() => {
    isFeedPausedRef.current = isFeedPaused;
  }, [isFeedPaused]);

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
    `globe-nearby-v2:${latitude.toFixed(3)}:${longitude.toFixed(3)}:${radiusM}`;

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
      if (!data?.paths?.length) return null;
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
    });
    const response = await fetch(`/api/nearby-paths?${params.toString()}`, {
      headers: { accept: "application/json" },
      // Reuse browser HTTP cache for identical nearby queries
      cache: "default",
    });

    if (!response.ok) {
      throw new Error("Nearby paths request failed");
    }

    const data = (await response.json()) as NearbyPathsPreview;
    if (!data || !Array.isArray(data.paths) || data.paths.length === 0) {
      throw new Error("Nearby paths response incomplete");
    }
    writeNearbySessionCache(latitude, longitude, radiusM, data);
    return data;
  };

  const loadNearbyPaths = async (closeMenu = true, radiusM = nearbyRadiusM) => {
    // Open immediately — do not depend on the global button rate limiter succeeding twice
    setShowNearbyPanel(true);
    if (closeMenu) {
      setShowMenu(false);
    }
    setNearbyStatus("loading");
    setNearbyError("");

    const clampedRadius = Math.min(1000, Math.max(250, Math.round(radiusM)));
    setNearbyRadiusM(clampedRadius);

    try {
      // One geolocation wait (short) — avoid a second full download unless the user is far away
      const location = await Promise.race([
        resolveUserCoordinates(2800),
        new Promise<{
          latitude: number;
          longitude: number;
          label: string;
        }>((resolve) =>
          window.setTimeout(
            () =>
              resolve({
                latitude: DEFAULT_WEATHER_LOCATION.latitude,
                longitude: DEFAULT_WEATHER_LOCATION.longitude,
                label: DEFAULT_WEATHER_LOCATION.label,
              }),
            900,
          ),
        ),
      ]);

      const data = await fetchNearbyPathsAt(
        location.latitude,
        location.longitude,
        clampedRadius,
      );
      setNearbyPreview(data);
      setNearbyStatus("ready");

      // Optional refinement: only re-fetch if precise geo moves ~150m+
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
          );
          setNearbyPreview(upgraded);
        } catch {
          // keep first successful result
        }
      });
    } catch {
      setNearbyError("Nearby street traces unavailable");
      setNearbyStatus("error");
    }
  };

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

      if (message.type === "add-marker") {
        const visitorId = message.position.id;
        positions.current.set(visitorId, {
          location: [message.position.lat, message.position.lng],
          size: visitorId === socket.id ? 0.1 : 0.05,
        });

        const isYou = visitorId === socket.id;
        if (isYou) {
          setIsDisconnected(false);
          setIsSocketConnected(true);
        }

        const shortId = visitorId.slice(0, 8);
        const joinedAt = Date.now();
        const activityEvent = createActivityEvent({
          id: visitorId,
          type: "connect",
          timestamp: joinedAt,
          userName: isYou ? "You" : `User ${shortId}`,
          ip: message.position.ip,
          country: message.position.country,
          city: message.position.city,
          org: message.position.org,
          isSelf: isYou,
        });

        activeVisitors.current.set(visitorId, activityEvent);
        setCounter(positions.current.size);
        addActivityEvent(activityEvent);
        return;
      }

      if (message.type === "remove-marker") {
        const removedId = message.id;
        const wasSelf = removedId === socket.id;
        const prior = activeVisitors.current.get(removedId);
        const leftAt = Date.now();
        const sessionMs = prior
          ? Math.max(0, leftAt - prior.timestamp)
          : undefined;

        positions.current.delete(removedId);
        activeVisitors.current.delete(removedId);
        setCounter(positions.current.size);

        if (wasSelf) {
          setIsDisconnected(true);
        }

        // Always record leaves (even when feed is paused) with session + geo context
        addActivityEvent(
          createActivityEvent({
            id: removedId,
            type: "disconnect",
            timestamp: leftAt,
            userName:
              prior?.userName ??
              (wasSelf ? "You" : `User ${removedId.slice(0, 8)}`),
            city: prior?.city,
            country: prior?.country,
            org: prior?.org,
            ip: prior?.ip,
            isSelf: wasSelf,
            sessionMs,
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
      <nav className="nav-bar" ref={navBarRef}>
        <div className="nav-left">
          <h1 className="nav-title">
            GLOBE <span className="nav-subtitle">// OPS</span>
          </h1>
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
                  void loadNearbyPaths(false);
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
                  <strong>{nearbyPreview.pathCount}</strong>
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
                  <span>Radius</span>
                  <strong>{nearbyPreview.radiusM}m</strong>
                </div>
              </div>

              <NearbyMap data={nearbyPreview} />

              <div className="nearby-radius-controls" role="group" aria-label="Trace radius">
                {[350, 500, 750].map((radius) => (
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
                      void loadNearbyPaths(false, nearbyRadiusM);
                    }}
                  >
                    Refresh
                  </button>
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
                >
                  <span>Condition</span>
                  <strong>{weatherFeed.condition}</strong>
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
                      runRateLimitedButtonAction("weather-forecast-toggle", () =>
                        setShowWeatherForecast((open) => !open),
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
                  <div className="weather-forecast-tabs" role="tablist" aria-label="Forecast range">
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
                          <article className="weather-forecast-row" key={day.date}>
                            <div className="weather-forecast-time">
                              <strong>{formatForecastDay(day.date)}</strong>
                              <span>{day.condition}</span>
                            </div>
                            <div className="weather-forecast-temp">
                              <strong>{day.highF}°</strong>
                              <span>{day.lowF}° low</span>
                            </div>
                            <div className="weather-forecast-details">
                              <span>Rain {day.precipitationChancePct}% · {day.precipitationIn.toFixed(2)} in</span>
                              <span>Wind {day.windMph} mph · Gusts {day.gustMph} · UV {day.uvIndex}</span>
                            </div>
                          </article>
                        ))
                      : weatherFeed.hourlyForecast.map((hour) => (
                          <article className="weather-forecast-row" key={hour.time}>
                            <div className="weather-forecast-time">
                              <strong>{formatForecastHour(hour.time)}</strong>
                              <span>{hour.condition}</span>
                            </div>
                            <div className="weather-forecast-temp">
                              <strong>{hour.tempF}°</strong>
                              <span>Feels {hour.feelsLikeF}°</span>
                            </div>
                            <div className="weather-forecast-details">
                              <span>Hum {hour.humidityPct}% · Rain {hour.precipitationChancePct}% · {hour.precipitationIn.toFixed(2)} in</span>
                              <span>Wind {hour.windMph} mph · Gusts {hour.gustMph} · Cloud {hour.cloudCoverPct}%</span>
                            </div>
                          </article>
                        ))}
                  </div>
                </section>
              )}
            </>
          )}
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
            className={`menu-item menu-item-button ${showNearbyPanel ? "active" : ""}`}
            onClick={() => {
              void loadNearbyPaths(false);
            }}
          >
            Nearby traces
          </button>
          <button
            type="button"
            className="menu-item menu-item-button"
            onClick={() =>
              runRateLimitedButtonAction("settings-placeholder", () =>
                setShowMenu(false),
              )
            }
          >
            Settings
          </button>
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
        </FloatingChrome>
      )}
    </div>
  );
}

// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
createRoot(document.getElementById("root")!).render(<App />);
