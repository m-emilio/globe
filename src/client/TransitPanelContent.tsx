import React, { useCallback, useEffect, useMemo, useState } from "react";
import type {
  NearbyPathsPreview,
  TransitNearbyPreview,
  TransitRoutePreview,
  TransitStopPreview,
} from "../shared";
import { NearbyMap } from "./NearbyMap";

export type TransitViewToggles = {
  showRoutes: boolean;
  showStops: boolean;
  showModeChips: boolean;
  showDepartures: boolean;
  alertsOnly: boolean;
  compactCards: boolean;
  showMap: boolean;
};

const DEFAULT_VIEW: TransitViewToggles = {
  showRoutes: true,
  showStops: true,
  showModeChips: true,
  showDepartures: true,
  alertsOnly: false,
  compactCards: true, // denser default = less DOM lag
  showMap: true,
};

const LIST_PAGE = 36;

type Props = {
  preview: TransitNearbyPreview;
  distanceM: number;
  onRadius: (m: number) => void;
  onRefresh: () => void;
  /** Same fetcher as Nearby traces (session cache friendly). */
  fetchNearbyMap: (
    lat: number,
    lng: number,
    radiusM: number,
  ) => Promise<NearbyPathsPreview>;
};

const TransitRouteCard = React.memo(function TransitRouteCard({
  route,
  compact,
  showDepartures,
}: {
  route: TransitRoutePreview;
  compact: boolean;
  showDepartures: boolean;
}) {
  return (
    <article
      className={`transit-route-card ${compact ? "compact" : ""}`}
      role="listitem"
      style={
        {
          "--route-color": `#${route.color}`,
          "--route-text": `#${route.textColor}`,
        } as React.CSSProperties
      }
    >
      <div className="transit-route-badge">{route.shortName}</div>
      <div className="transit-route-body">
        <strong>{route.longName || route.shortName}</strong>
        {!compact && (
          <>
            <span>
              {route.modeName}
              {route.networkName ? ` · ${route.networkName}` : ""}
            </span>
            {route.closestStopName && (
              <span className="transit-route-stop">
                Near {route.closestStopName}
                {route.closestStopDistanceM != null
                  ? ` · ${Math.round(route.closestStopDistanceM)}m`
                  : ""}
              </span>
            )}
            {showDepartures && route.nextDepartures.length > 0 && (
              <span className="transit-route-deps">
                Next: {route.nextDepartures.join(" · ")}
              </span>
            )}
            {route.alertCount > 0 && (
              <span className="transit-route-alert">
                {route.alertCount} alert
                {route.alertCount === 1 ? "" : "s"}
              </span>
            )}
          </>
        )}
        {compact && (
          <span>
            {route.modeName}
            {route.closestStopDistanceM != null
              ? ` · ${Math.round(route.closestStopDistanceM)}m`
              : ""}
            {route.alertCount > 0
              ? ` · ${route.alertCount} alert${route.alertCount === 1 ? "" : "s"}`
              : ""}
            {showDepartures && route.nextDepartures[0]
              ? ` · ${route.nextDepartures[0]}`
              : ""}
          </span>
        )}
      </div>
    </article>
  );
});

const TransitStopRow = React.memo(function TransitStopRow({
  stop,
}: {
  stop: TransitStopPreview;
}) {
  return (
    <div className="transit-stop-row" role="listitem">
      <strong>{stop.name}</strong>
      <span>
        {stop.code ? `#${stop.code}` : "Stop"}
        {stop.distanceM != null ? ` · ${Math.round(stop.distanceM)}m` : ""}
      </span>
    </div>
  );
});

/**
 * Isolated transit body — owns toggles/filters so globe App does not re-render
 * on every chip click (main lag source).
 */
export function TransitPanelContent({
  preview,
  distanceM,
  onRadius,
  onRefresh,
  fetchNearbyMap,
}: Props) {
  const [view, setView] = useState<TransitViewToggles>(DEFAULT_VIEW);
  const [modesEnabled, setModesEnabled] = useState<Record<string, boolean>>(
    () => {
      const init: Record<string, boolean> = {};
      for (const m of preview.modes) init[m.modeName] = true;
      return init;
    },
  );
  const [mapData, setMapData] = useState<NearbyPathsPreview | null>(null);
  const [mapStatus, setMapStatus] = useState<"idle" | "loading" | "ready" | "error">(
    "idle",
  );
  const [routesShown, setRoutesShown] = useState(LIST_PAGE);
  const [stopsShown, setStopsShown] = useState(LIST_PAGE);

  // Sync new modes when preview identity changes (new fetch)
  useEffect(() => {
    setModesEnabled((prev) => {
      const next = { ...prev };
      for (const m of preview.modes) {
        if (next[m.modeName] === undefined) next[m.modeName] = true;
      }
      return next;
    });
    setRoutesShown(LIST_PAGE);
    setStopsShown(LIST_PAGE);
  }, [preview.lat, preview.lng, preview.maxDistanceM, preview.updatedAt]);

  // Load street map for the full transit search radius (server tiles OSM)
  useEffect(() => {
    if (!view.showMap) return;
    let cancelled = false;
    setMapStatus("loading");
    void (async () => {
      const streetR = Math.min(1500, Math.max(250, preview.maxDistanceM));
      try {
        const data = await fetchNearbyMap(preview.lat, preview.lng, streetR);
        if (cancelled) return;
        // Prefer server radius; fall back to transit radius for the ring
        setMapData({
          ...data,
          radiusM: data.radiusM || preview.maxDistanceM,
        });
        setMapStatus("ready");
      } catch {
        if (!cancelled) {
          setMapData(null);
          setMapStatus("error");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [
    view.showMap,
    preview.lat,
    preview.lng,
    preview.maxDistanceM,
    fetchNearbyMap,
  ]);

  const toggleView = useCallback((key: keyof TransitViewToggles) => {
    setView((v) => ({ ...v, [key]: !v[key] }));
  }, []);

  const toggleMode = useCallback((modeName: string) => {
    setModesEnabled((prev) => ({
      ...prev,
      [modeName]: !(prev[modeName] !== false),
    }));
  }, []);

  const setAllModes = useCallback(
    (enabled: boolean) => {
      const next: Record<string, boolean> = {};
      for (const m of preview.modes) next[m.modeName] = enabled;
      setModesEnabled(next);
    },
    [preview.modes],
  );

  const filteredRoutes = useMemo(() => {
    return preview.routes.filter((route) => {
      if (view.alertsOnly && route.alertCount <= 0) return false;
      return modesEnabled[route.modeName] !== false;
    });
  }, [preview.routes, view.alertsOnly, modesEnabled]);

  const visibleRoutes = useMemo(
    () => filteredRoutes.slice(0, routesShown),
    [filteredRoutes, routesShown],
  );
  const visibleStops = useMemo(
    () => preview.stops.slice(0, stopsShown),
    [preview.stops, stopsShown],
  );

  return (
    <>
      <div className="nearby-metrics transit-metrics">
        <div className="nearby-metric">
          <span>Routes</span>
          <strong>
            {filteredRoutes.length}
            <span className="transit-metric-sub">/{preview.routeCount}</span>
          </strong>
        </div>
        <div className="nearby-metric">
          <span>Stops</span>
          <strong>{preview.stopCount}</strong>
        </div>
        <div className="nearby-metric">
          <span>Modes</span>
          <strong>{preview.modes.length}</strong>
        </div>
        <div className="nearby-metric">
          <span>Radius</span>
          <strong>{preview.maxDistanceM}m</strong>
        </div>
      </div>

      <div className="transit-panel-body">
        <div className="transit-section-title">View</div>
        <div className="transit-view-toggles" role="group" aria-label="Transit view">
          {(
            [
              ["showRoutes", "Routes list"],
              ["showStops", "Stops list"],
              ["showMap", "Street map"],
              ["showModeChips", "Mode filters"],
              ["showDepartures", "Next departures"],
              ["alertsOnly", "Alerts only"],
              ["compactCards", "Compact cards"],
            ] as const
          ).map(([key, label]) => (
            <button
              key={key}
              type="button"
              className={`transit-toggle-item ${view[key] ? "active" : ""}`}
              aria-pressed={view[key]}
              onClick={() => toggleView(key)}
            >
              <span>{label}</span>
              <strong>{view[key] ? "On" : "Off"}</strong>
            </button>
          ))}
        </div>

        {view.showModeChips && preview.modes.length > 0 && (
          <>
            <div className="transit-section-title">
              Modes
              <span className="transit-section-actions">
                <button
                  type="button"
                  className="transit-text-btn"
                  onClick={() => setAllModes(true)}
                >
                  All
                </button>
                <button
                  type="button"
                  className="transit-text-btn"
                  onClick={() => setAllModes(false)}
                >
                  None
                </button>
              </span>
            </div>
            <div
              className="transit-mode-chips"
              role="group"
              aria-label="Filter by transit mode"
            >
              {preview.modes.map((mode) => {
                const on = modesEnabled[mode.modeName] !== false;
                return (
                  <button
                    key={mode.modeName}
                    type="button"
                    className={`transit-mode-chip transit-mode-chip-btn ${on ? "active" : ""}`}
                    aria-pressed={on}
                    onClick={() => toggleMode(mode.modeName)}
                  >
                    {mode.modeName} · {mode.count}
                  </button>
                );
              })}
            </div>
          </>
        )}

        {view.showMap && (
          <>
            <div className="transit-section-title">Street map</div>
            {mapStatus === "loading" && (
              <div className="nearby-loading transit-map-status">
                Loading street traces…
              </div>
            )}
            {mapStatus === "error" && (
              <div className="nearby-error transit-map-status">
                Street map unavailable
              </div>
            )}
            {mapStatus === "ready" && mapData && (
              <div className="transit-nearby-map-wrap">
                <NearbyMap
                  data={mapData}
                  defaultShowOverlay={true}
                  title={`Transit streets · ${preview.maxDistanceM}m`}
                  stops={preview.stops}
                />
              </div>
            )}
          </>
        )}

        {view.showRoutes && (
          <>
            <div className="transit-section-title">
              Routes
              <span className="transit-section-count">
                {filteredRoutes.length}
              </span>
            </div>
            <div className="transit-list" role="list">
              {visibleRoutes.length === 0 ? (
                <div className="nearby-loading">No routes match filters</div>
              ) : (
                visibleRoutes.map((route) => (
                  <TransitRouteCard
                    key={route.id}
                    route={route}
                    compact={view.compactCards}
                    showDepartures={view.showDepartures}
                  />
                ))
              )}
              {filteredRoutes.length > routesShown && (
                <button
                  type="button"
                  className="transit-show-more"
                  onClick={() => setRoutesShown((n) => n + LIST_PAGE)}
                >
                  Show more routes ({filteredRoutes.length - routesShown} left)
                </button>
              )}
            </div>
          </>
        )}

        {view.showStops && (
          <>
            <div className="transit-section-title">
              Stops
              <span className="transit-section-count">{preview.stops.length}</span>
            </div>
            <div className="transit-stop-list" role="list">
              {visibleStops.length === 0 ? (
                <div className="nearby-loading">No stops nearby</div>
              ) : (
                visibleStops.map((stop) => (
                  <TransitStopRow key={stop.id} stop={stop} />
                ))
              )}
              {preview.stops.length > stopsShown && (
                <button
                  type="button"
                  className="transit-show-more"
                  onClick={() => setStopsShown((n) => n + LIST_PAGE)}
                >
                  Show more stops ({preview.stops.length - stopsShown} left)
                </button>
              )}
            </div>
          </>
        )}
      </div>

      <div className="transit-panel-actions">
        <div
          className="nearby-radius-controls transit-radius-controls"
          role="group"
          aria-label="Search radius"
        >
          {[400, 800, 1200, 1500].map((distance) => (
            <button
              key={distance}
              type="button"
              className={distanceM === distance ? "active" : ""}
              onClick={() => onRadius(distance)}
            >
              {distance}m
            </button>
          ))}
        </div>

        <div className="nearby-footer">
          <span>{preview.note ?? "Transit App"}</span>
          <div className="nearby-footer-actions">
            <a
              href={preview.sourceUrl}
              target="_blank"
              rel="noopener noreferrer"
            >
              API docs
            </a>
            <button type="button" onClick={onRefresh}>
              Refresh
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
