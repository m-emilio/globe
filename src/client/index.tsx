import "./styles.css";

import React, { useState, useRef, useEffect } from "react";
import { createRoot } from "react-dom/client";
import { Cobe } from "./CobeGlobe";
import usePartySocket from "partysocket/react";
import type { OutgoingMessage } from "../shared";

interface ActivityEvent {
  id: string;
  type: "connect" | "disconnect";
  timestamp: number;
  userName: string;
  ip?: string;
  country?: string;
  city?: string;
  org?: string;
}

type ActivityFilter = "all" | "connect" | "disconnect";
type WeatherStatus = "idle" | "loading" | "ready" | "error";

interface WeatherFeed {
  tempF: number;
  humidityPct: number;
  windMph: number;
  weatherCode: number;
  condition: string;
  hasLightning: boolean;
  locationLabel: string;
  updatedAt: string;
}

type OpenMeteoCurrentResponse = {
  current?: {
    time?: string;
    temperature_2m?: number;
    relative_humidity_2m?: number;
    wind_speed_10m?: number;
    weather_code?: number;
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

function describeWeatherCode(code: number) {
  return WEATHER_CODE_LABELS[code] ?? `Weather code ${code}`;
}

function getBrowserPosition() {
  return new Promise<GeolocationPosition>((resolve, reject) => {
    if (!navigator.geolocation) {
      reject(new Error("Geolocation unavailable"));
      return;
    }

    navigator.geolocation.getCurrentPosition(resolve, reject, {
      enableHighAccuracy: false,
      timeout: 5000,
      maximumAge: 10 * 60 * 1000,
    });
  });
}

function buildWeatherUrl(latitude: number, longitude: number) {
  const params = new URLSearchParams({
    latitude: String(latitude),
    longitude: String(longitude),
    current: "temperature_2m,relative_humidity_2m,wind_speed_10m,weather_code",
    temperature_unit: "fahrenheit",
    wind_speed_unit: "mph",
    timezone: "auto",
  });

  return `https://api.open-meteo.com/v1/forecast?${params.toString()}`;
}

function formatWeatherTime(time: string) {
  return time.replace("T", " ");
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
  const [showAbout, setShowAbout] = useState(false);
  const [showMenu, setShowMenu] = useState(false);
  const [showWeatherPanel, setShowWeatherPanel] = useState(false);
  const [weatherStatus, setWeatherStatus] = useState<WeatherStatus>("idle");
  const [weatherFeed, setWeatherFeed] = useState<WeatherFeed | null>(null);
  const [weatherError, setWeatherError] = useState("");
  const [showActivityMenu, setShowActivityMenu] = useState(true);
  const [activityFilter, setActivityFilter] = useState<ActivityFilter>("all");
  const [isDisconnected, setIsDisconnected] = useState(false);
  const [isFeedPaused, setIsFeedPaused] = useState(false);
  const [isCompactFeed, setIsCompactFeed] = useState(false);
  const [counter, setCounter] = useState(0);
  const [activityFeed, setActivityFeed] = useState<ActivityEvent[]>([]);

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

  const addActivityEvent = (event: ActivityEvent) => {
    if (isFeedPausedRef.current) {
      return;
    }

    setActivityFeed((prev) => [event, ...prev.slice(0, 49)]);
  };

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

  const clearActivityFeed = () => {
    const activeEvents = Array.from(activeVisitors.current.values()).sort(
      (a, b) => b.timestamp - a.timestamp,
    );

    setActivityFilter("all");
    setIsDisconnected(false);
    setActivityFeed(activeEvents);
  };

  const handleActivityFilterChange = (filter: ActivityFilter) => {
    setActivityFilter(filter);

    if (filter !== "disconnect" || isDisconnected) {
      return;
    }

    const timestamp = Date.now();
    setIsDisconnected(true);
    setActivityFeed((prev) => [
      {
        id: `local-disconnect-${timestamp}`,
        type: "disconnect",
        timestamp,
        userName: "You",
      },
      ...prev.slice(0, 49),
    ]);
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
      const position = await getBrowserPosition();
      latitude = position.coords.latitude;
      longitude = position.coords.longitude;
      locationLabel = "Your location";
    } catch {
      locationLabel = DEFAULT_WEATHER_LOCATION.label;
    }

    try {
      const response = await fetch(buildWeatherUrl(latitude, longitude));

      if (!response.ok) {
        throw new Error("Weather request failed");
      }

      const data = (await response.json()) as OpenMeteoCurrentResponse;
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
      });
      setWeatherStatus("ready");
    } catch {
      setWeatherError("Weather feed unavailable");
      setWeatherStatus("error");
    }
  };

  const socket = usePartySocket({
    room: "default",
    party: "globe",
    onMessage(evt) {
      const message = JSON.parse(evt.data as string) as OutgoingMessage;

      if (message.type === "add-marker") {
        positions.current.set(message.position.id, {
          location: [message.position.lat, message.position.lng],
          size: message.position.id === socket.id ? 0.1 : 0.05,
        });

        const isYou = message.position.id === socket.id;
        if (isYou) {
          setIsDisconnected(false);
        }

        const activityEvent = {
          id: message.position.id,
          type: "connect",
          timestamp: Date.now(),
          userName: isYou ? "You" : `User ${message.position.id.slice(0, 8)}`,
          ip: message.position.ip,
          country: message.position.country,
          city: message.position.city,
          org: message.position.org,
        } satisfies ActivityEvent;

        activeVisitors.current.set(message.position.id, activityEvent);
        setCounter(positions.current.size);
        addActivityEvent(activityEvent);
      } else {
        const removedId = message.id;
        positions.current.delete(removedId);
        activeVisitors.current.delete(removedId);
        setCounter(positions.current.size);

        addActivityEvent({
          id: removedId,
          type: "disconnect",
          timestamp: Date.now(),
          userName: `User ${removedId.slice(0, 8)}`,
        });
      }
    },
  });

  const visibleActivityFeed = activityFeed.filter((event) =>
    activityFilter === "all" ? true : event.type === activityFilter,
  );
  const isLeaveQueueSelected = activityFilter === "disconnect";
  const disconnectedCount = activityFeed.reduce(
    (total, event) => total + (event.type === "disconnect" ? 1 : 0),
    0,
  );
  const latestEvent = activityFeed[0];
  const latestSignal =
    latestEvent?.city && latestEvent.country
      ? `${latestEvent.city}, ${latestEvent.country}`
      : latestEvent?.country || latestEvent?.ip || latestEvent?.org || "No signals";
  const filterLabels: Record<ActivityFilter, string> = {
    all: "All",
    connect: "Joins",
    disconnect: "Leaves",
  };
  const weatherGlow = getWeatherGlow(weatherFeed);

  return (
    <div className="App">
      <nav className="nav-bar">
        <div className="nav-left">
          <h1 className="nav-title">
            GLOBE <span className="nav-subtitle">// OPS</span>
          </h1>
        </div>

        <div className="nav-center">
          <button
            className="nav-btn"
            onClick={() =>
              runRateLimitedButtonAction("about-open", () => setShowAbout(true))
            }
          >
            ABOUT
          </button>
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
        </div>

        <div className="nav-right">
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

      {showWeatherPanel && (
        <div className="weather-panel" role="dialog" aria-label="Current weather">
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
            </>
          )}
        </div>
      )}

      <div className="main-content">
        <Cobe
          counter={counter}
          positions={positions.current}
          glowColor={weatherGlow.color}
          glowCssColor={weatherGlow.css}
        />
      </div>

      <div className="activity-floating">
        <button
          type="button"
          className="activity-launcher"
          onClick={() =>
            runRateLimitedButtonAction("activity-toggle", () =>
              setShowActivityMenu((open) => !open),
            )
          }
          aria-controls="live-feed-menu"
          aria-expanded={showActivityMenu}
        >
          <span className="pulse-dot"></span>
          <span className="launcher-copy">
            <span className="launcher-label">Live Feed</span>
            <span className="launcher-meta">{counter} online</span>
          </span>
          <span className="launcher-action">{showActivityMenu ? "Hide" : "Open"}</span>
        </button>

        {showActivityMenu && (
          <section
            id="live-feed-menu"
            className={`activity-menu ${isCompactFeed ? "activity-menu-compact" : ""}`}
            aria-label="Live activity feed"
          >
            <div className="activity-header">
              <div className="activity-title-group">
                <h3>LIVE FEED</h3>
                <p>{isFeedPaused ? "Capture paused" : "Capturing visitor signals"}</p>
              </div>
              <div className="activity-count">
                <span className="pulse-dot"></span>
                <span>{counter}</span>
              </div>
            </div>

            <div className="activity-summary">
              <div className="activity-stat">
                <span>Online</span>
                <strong>{counter}</strong>
              </div>
              <div className="activity-stat">
                <span>Events</span>
                <strong>{activityFeed.length}</strong>
              </div>
              <div
                className={`activity-stat activity-stat-disconnected ${
                  isDisconnected ? "activity-stat-active" : ""
                }`}
              >
                <span>Disconnected</span>
                <strong>{disconnectedCount}</strong>
              </div>
              <div className="activity-stat">
                <span>Latest</span>
                <strong title={latestSignal}>{latestSignal}</strong>
              </div>
            </div>

            <div className="activity-filter" role="group" aria-label="Filter activity feed">
              {(["all", "connect", "disconnect"] as ActivityFilter[]).map((filter) => (
                <button
                  key={filter}
                  type="button"
                  className={`activity-filter-btn activity-filter-${filter} ${
                    activityFilter === filter ? "active" : ""
                  }`}
                  onClick={() =>
                    runRateLimitedButtonAction(`activity-filter-${filter}`, () =>
                      handleActivityFilterChange(filter),
                    )
                  }
                  aria-pressed={activityFilter === filter}
                >
                  <span>{filterLabels[filter]}</span>
                  {filter === "disconnect" && (
                    <span className="activity-filter-count">{disconnectedCount}</span>
                  )}
                </button>
              ))}
            </div>

            <div className="activity-actions">
              <button
                type="button"
                onClick={() =>
                  runRateLimitedButtonAction("activity-pause", () =>
                    setIsFeedPaused((paused) => !paused),
                  )
                }
              >
                {isFeedPaused ? "Resume" : "Pause"}
              </button>
              <button
                type="button"
                onClick={() =>
                  runRateLimitedButtonAction("activity-compact", () =>
                    setIsCompactFeed((compact) => !compact),
                  )
                }
              >
                {isCompactFeed ? "Details" : "Compact"}
              </button>
              <button
                type="button"
                onClick={() =>
                  runRateLimitedButtonAction("activity-clear", clearActivityFeed)
                }
                disabled={activityFeed.length === 0 && activeVisitors.current.size === 0}
              >
                Clear
              </button>
            </div>

            <div className="activity-list">
              {isLeaveQueueSelected && (
                <div
                  className={`activity-disconnected-state ${
                    isDisconnected ? "activity-disconnected-state-active" : ""
                  }`}
                >
                  <span>{isDisconnected ? "Disconnected" : "Leave queue"}</span>
                  <strong>{disconnectedCount}</strong>
                </div>
              )}
              {visibleActivityFeed.length === 0 ? (
                isLeaveQueueSelected ? null : (
                  <div className="activity-empty">
                    {activityFeed.length === 0 ? "No activity yet" : "No matching events"}
                  </div>
                )
              ) : (
                visibleActivityFeed.map((event) => (
                  <div
                    key={`${event.id}-${event.timestamp}`}
                    className={`activity-item activity-${event.type}`}
                  >
                    <span className="activity-icon" aria-hidden="true">
                      {event.type === "connect" ? "+" : "-"}
                    </span>
                    <div className="activity-details">
                      <span className="activity-user">{event.userName}</span>
                      <span className="activity-action">
                        {event.type === "connect" ? "connected" : "disconnected"}
                      </span>
                      {!isCompactFeed &&
                        event.type === "connect" &&
                        (event.city || event.country || event.ip || event.org) && (
                          <div className="activity-location">
                            {event.city && event.country && (
                              <span className="location-text">
                                LOC {event.city}, {event.country}
                              </span>
                            )}
                            {event.ip && <span className="location-text">IP {event.ip}</span>}
                            {event.org && !event.ip && (
                              <span className="location-text">ORG {event.org}</span>
                            )}
                          </div>
                        )}
                      <span className="activity-time">
                        {Math.floor((Date.now() - event.timestamp) / 1000)}s ago
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </section>
        )}
      </div>

      {showAbout && (
        <div className="modal-overlay" onClick={() => setShowAbout(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <button
              className="modal-close"
              onClick={() =>
                runRateLimitedButtonAction("about-close", () => setShowAbout(false))
              }
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
          </div>
        </div>
      )}

      {showMenu && (
        <div className="menu-dropdown">
          <a href="#" className="menu-item">
            Dashboard
          </a>
          <a href="#" className="menu-item">
            Settings
          </a>
          <a href="#" className="menu-item">
            Help
          </a>
          <a href="#" className="menu-item">
            Support
          </a>
        </div>
      )}
    </div>
  );
}

// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
createRoot(document.getElementById("root")!).render(<App />);
