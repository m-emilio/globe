import React, { useId, useMemo, useState } from "react";
import type { NearbyPathSegment, NearbyPathsPreview } from "../shared";

/** Optional overlay markers (e.g. transit stops on street map). */
export type NearbyMapStop = {
  id: string;
  name: string;
  lat: number | null;
  lng: number | null;
  distanceM?: number | null;
};

type NearbyMapProps = {
  data: NearbyPathsPreview;
  className?: string;
  /** Initial visibility for legend strip (scale + radius always shown for accuracy). */
  defaultShowOverlay?: boolean;
  /** Drawn on top of street centerlines (same projection). Independent of panel. */
  stops?: NearbyMapStop[];
  /** Feature label for aria / empty state */
  title?: string;
};

type Projected = { x: number; y: number };

type ProjectedStop = Projected & {
  id: string;
  name: string;
  distanceM?: number | null;
};

type MapLine = {
  id: string;
  kind: string;
  highway: string;
  d: string;
  name: string;
  label?: Projected & { text: string; angle: number };
};

const VIEW = 440;
/** Padding around true radius so ring + scale fit without clipping */
const PAD = 28;

/**
 * Local ENU (east/north meters) from WGS84, fixed scale locked to radiusM.
 * 1 map unit of scale bar = true meters — ring radius matches radiusM.
 */
function projectPoints(
  paths: NearbyPathSegment[],
  centerLat: number,
  centerLng: number,
  radiusM: number,
  stops: NearbyMapStop[] = [],
): {
  lines: MapLine[];
  you: Projected;
  ring: string;
  scaleBar: { x: number; y: number; width: number; label: string };
  stopPoints: ProjectedStop[];
  pxPerMeter: number;
} {
  // WGS84 local meters (standard equirectangular local approximation)
  const latRad = (centerLat * Math.PI) / 180;
  const metersPerDegLat =
    111_132.92 - 559.82 * Math.cos(2 * latRad) + 1.175 * Math.cos(4 * latRad);
  const metersPerDegLng =
    111_412.84 * Math.cos(latRad) - 93.5 * Math.cos(3 * latRad);
  const mLat = metersPerDegLat || 111_320;
  const mLng = Math.abs(metersPerDegLng) || 1;

  // Drawable half-size in meters = exact search radius (no 1.05 fudge on ring)
  const halfM = Math.max(radiusM, 50);
  const usable = VIEW - PAD * 2;
  // px per meter: full diameter = 2 * halfM maps to usable pixels
  const pxPerMeter = usable / (2 * halfM);

  const toXY = (lat: number, lng: number): Projected => {
    const eastM = (lng - centerLng) * mLng;
    const northM = (lat - centerLat) * mLat;
    return {
      x: VIEW / 2 + eastM * pxPerMeter,
      y: VIEW / 2 - northM * pxPerMeter,
    };
  };

  const lines: MapLine[] = [];
  for (const path of paths) {
    const pts = path.points
      .filter((p) => Number.isFinite(p.lat) && Number.isFinite(p.lng))
      .map((p) => toXY(p.lat, p.lng));
    const isPark = path.kind === "park";
    if (isPark ? pts.length < 3 : pts.length < 2) continue;

    let d = pts
      .map(
        (p, i) =>
          `${i === 0 ? "M" : "L"}${p.x.toFixed(2)} ${p.y.toFixed(2)}`,
      )
      .join(" ");
    // Closed fill for park polygons
    if (isPark) d += " Z";

    let label: MapLine["label"];
    const named =
      path.name &&
      path.name !== path.highway &&
      path.kind === "road" &&
      pts.length >= 2;
    if (named) {
      const idx = Math.floor((pts.length - 1) * 0.4);
      const a = pts[idx];
      const b = pts[Math.min(pts.length - 1, idx + 1)];
      let angle = (Math.atan2(b.y - a.y, b.x - a.x) * 180) / Math.PI;
      if (angle > 90 || angle < -90) angle += 180;
      label = {
        x: (a.x + b.x) / 2,
        y: (a.y + b.y) / 2 - 1.5,
        text: path.name.slice(0, 20),
        angle,
      };
    }

    lines.push({
      id: path.id,
      kind: path.kind,
      highway: path.highway,
      d,
      name: path.name || path.highway,
      label,
    });
  }

  const you = toXY(centerLat, centerLng);
  // Exact radius in meters → SVG pixels
  const ringR = radiusM * pxPerMeter;
  const ring = `M ${you.x + ringR} ${you.y} a ${ringR} ${ringR} 0 1 0 ${-2 * ringR} 0 a ${ringR} ${ringR} 0 1 0 ${2 * ringR} 0`;

  const stopPoints: ProjectedStop[] = [];
  for (const stop of stops) {
    if (
      stop.lat == null ||
      stop.lng == null ||
      !Number.isFinite(stop.lat) ||
      !Number.isFinite(stop.lng)
    ) {
      continue;
    }
    const p = toXY(stop.lat, stop.lng);
    stopPoints.push({
      id: stop.id,
      name: stop.name,
      distanceM: stop.distanceM,
      x: p.x,
      y: p.y,
    });
  }

  // Nice round scale bars that fit
  const barMeters =
    radiusM >= 1200
      ? 300
      : radiusM >= 800
        ? 200
        : radiusM >= 500
          ? 100
          : radiusM >= 250
            ? 50
            : 25;
  const barWidth = barMeters * pxPerMeter;
  const scaleBar = {
    x: PAD + 4,
    y: VIEW - PAD + 4,
    width: Math.max(12, barWidth),
    label: `${barMeters} m`,
  };

  return { lines, you, ring, scaleBar, stopPoints, pxPerMeter };
}

function roadWeight(
  highway: string,
  kind: string,
): "major" | "minor" | "path" | "cycle" | "park" {
  if (kind === "park") return "park";
  if (kind === "path") return "path";
  if (kind === "cycle") return "cycle";
  if (
    highway === "motorway" ||
    highway === "trunk" ||
    highway === "primary" ||
    highway === "secondary" ||
    highway === "tertiary"
  ) {
    return "major";
  }
  return "minor";
}

export function NearbyMap({
  data,
  className = "",
  defaultShowOverlay = true,
  stops = [],
  title,
}: NearbyMapProps) {
  // Legend strip optional; radius ring + scale always on for accuracy.
  const [showLegend, setShowLegend] = useState(defaultShowOverlay);
  const uid = useId().replace(/:/g, "");

  const projected = useMemo(
    () =>
      projectPoints(
        data.paths,
        data.lat,
        data.lng,
        data.radiusM,
        stops,
      ),
    [data.paths, data.lat, data.lng, data.radiusM, stops],
  );

  const parks = useMemo(
    () => projected.lines.filter((l) => roadWeight(l.highway, l.kind) === "park"),
    [projected.lines],
  );
  const major = useMemo(
    () => projected.lines.filter((l) => roadWeight(l.highway, l.kind) === "major"),
    [projected.lines],
  );
  const minor = useMemo(
    () => projected.lines.filter((l) => roadWeight(l.highway, l.kind) === "minor"),
    [projected.lines],
  );
  const pathLines = useMemo(
    () => projected.lines.filter((l) => roadWeight(l.highway, l.kind) === "path"),
    [projected.lines],
  );
  const cycles = useMemo(
    () =>
      projected.lines.filter((l) => roadWeight(l.highway, l.kind) === "cycle"),
    [projected.lines],
  );

  const emptyLive = data.paths.length === 0;
  const landId = `nearby-land-${uid}`;
  const vignetteId = `nearby-vignette-${uid}`;
  const softId = `nearby-soft-${uid}`;
  const clipId = `nearby-clip-${uid}`;

  return (
    <div
      className={`nearby-map ${showLegend ? "nearby-map-overlay-on" : ""} ${className}`.trim()}
    >
      <div className="nearby-map-canvas">
        <button
          type="button"
          className={`nearby-map-overlay-toggle ${showLegend ? "active" : ""}`}
          aria-pressed={showLegend}
          aria-label={showLegend ? "Hide legend" : "Show legend"}
          title={showLegend ? "Hide legend" : "Show legend"}
          onClick={() => setShowLegend((v) => !v)}
        >
          {showLegend ? "Legend on" : "Legend"}
        </button>
        <svg
          className="nearby-map-svg"
          viewBox={`0 0 ${VIEW} ${VIEW}`}
          role="img"
          aria-label={
            title ||
            `Map within ${data.radiusM} meters of ${data.lat.toFixed(5)}, ${data.lng.toFixed(5)}`
          }
        >
          <defs>
            <linearGradient id={landId} x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stopColor="#1a2332" />
              <stop offset="45%" stopColor="#141c28" />
              <stop offset="100%" stopColor="#0d141e" />
            </linearGradient>
            <radialGradient id={vignetteId} cx="50%" cy="45%" r="65%">
              <stop offset="0%" stopColor="rgba(255,255,255,0.03)" />
              <stop offset="70%" stopColor="rgba(0,0,0,0)" />
              <stop offset="100%" stopColor="rgba(0,0,0,0.28)" />
            </radialGradient>
            <filter id={softId} x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="0.55" result="b" />
              <feMerge>
                <feMergeNode in="b" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <clipPath id={clipId}>
              <rect x={0} y={0} width={VIEW} height={VIEW} />
            </clipPath>
          </defs>

          <rect width={VIEW} height={VIEW} fill={`url(#${landId})`} />
          <rect width={VIEW} height={VIEW} fill={`url(#${vignetteId})`} />

          <g clipPath={`url(#${clipId})`}>
            {/* Always-true radius circle (meters) */}
            <path d={projected.ring} className="nearby-map-radius" />

            {/* Parks under roads so streets stay readable */}
            <g className="nearby-map-layer-parks">
              {parks.map((line) => (
                <path
                  key={line.id}
                  d={line.d}
                  className="nearby-map-park"
                >
                  <title>{line.name}</title>
                </path>
              ))}
            </g>

            <g className="nearby-map-layer-casing">
              {minor.map((line) => (
                <path
                  key={`c-${line.id}`}
                  d={line.d}
                  className="nearby-casing nearby-casing-minor"
                />
              ))}
              {major.map((line) => (
                <path
                  key={`c-${line.id}`}
                  d={line.d}
                  className="nearby-casing nearby-casing-major"
                />
              ))}
            </g>

            <g className="nearby-map-layer-fill">
              {minor.map((line) => (
                <path
                  key={line.id}
                  d={line.d}
                  className="nearby-fill nearby-fill-minor"
                >
                  <title>{line.name}</title>
                </path>
              ))}
              {major.map((line) => (
                <path
                  key={line.id}
                  d={line.d}
                  className="nearby-fill nearby-fill-major"
                >
                  <title>{line.name}</title>
                </path>
              ))}
              {pathLines.map((line) => (
                <path
                  key={line.id}
                  d={line.d}
                  className="nearby-fill nearby-fill-path"
                >
                  <title>{line.name}</title>
                </path>
              ))}
              {cycles.map((line) => (
                <path
                  key={line.id}
                  d={line.d}
                  className="nearby-fill nearby-fill-cycle"
                >
                  <title>{line.name}</title>
                </path>
              ))}
            </g>

            <g className="nearby-map-labels">
              {major
                .concat(minor)
                .filter((l) => l.label)
                .slice(0, 14)
                .map((line) =>
                  line.label ? (
                    <text
                      key={`lbl-${line.id}`}
                      x={line.label.x}
                      y={line.label.y}
                      transform={`rotate(${line.label.angle} ${line.label.x} ${line.label.y})`}
                      className="nearby-map-label"
                    >
                      {line.label.text}
                    </text>
                  ) : null,
                )}
            </g>

            {projected.stopPoints.length > 0 && (
              <g className="nearby-map-stops">
                {projected.stopPoints.map((stop) => (
                  <g
                    key={stop.id}
                    transform={`translate(${stop.x} ${stop.y})`}
                  >
                    <circle r="6.5" className="nearby-map-stop-halo" />
                    <circle r="4" className="nearby-map-stop-dot" />
                    <title>
                      {stop.name}
                      {stop.distanceM != null
                        ? ` · ${Math.round(stop.distanceM)}m`
                        : ""}
                    </title>
                  </g>
                ))}
              </g>
            )}

            <g
              className="nearby-map-you"
              transform={`translate(${projected.you.x} ${projected.you.y})`}
              filter={`url(#${softId})`}
            >
              <circle r="16" className="nearby-map-you-halo" />
              <circle r="7" className="nearby-map-you-ring" />
              <circle r="3" className="nearby-map-you-dot" />
            </g>
          </g>

          <g className="nearby-map-north" transform={`translate(${VIEW - 34} 34)`}>
            <circle r="14" className="nearby-map-north-disc" />
            <polygon
              points="0,-9 4,6 0,3 -4,6"
              className="nearby-map-north-arrow"
            />
            <text y="16" textAnchor="middle" className="nearby-map-north-text">
              N
            </text>
          </g>

          {/* Scale always visible — true meters */}
          <g
            className="nearby-map-scale"
            transform={`translate(${projected.scaleBar.x} ${projected.scaleBar.y})`}
          >
            <rect
              x={0}
              y={-6}
              width={projected.scaleBar.width}
              height={6}
              className="nearby-map-scale-bar"
            />
            <line x1={0} y1={-8} x2={0} y2={2} />
            <line
              x1={projected.scaleBar.width}
              y1={-8}
              x2={projected.scaleBar.width}
              y2={2}
            />
            <text x={projected.scaleBar.width / 2} y={12} textAnchor="middle">
              {projected.scaleBar.label}
            </text>
          </g>

          {emptyLive && (
            <text
              x={VIEW / 2}
              y={VIEW / 2}
              textAnchor="middle"
              className="nearby-map-empty-msg"
            >
              {data.stale
                ? "Live streets unavailable"
                : "No streets in this radius"}
            </text>
          )}
        </svg>
        {data.stale && (
          <div className="nearby-map-stale-badge">No live OSM data</div>
        )}
      </div>

      {showLegend && (
        <div className="nearby-map-legend" aria-hidden="true">
          <span className="nearby-leg nearby-leg-road">Roads</span>
          <span className="nearby-leg nearby-leg-path">Paths</span>
          <span className="nearby-leg nearby-leg-cycle">Cycle</span>
          <span className="nearby-leg nearby-leg-park">Parks</span>
          {projected.stopPoints.length > 0 && (
            <span className="nearby-leg nearby-leg-stop">Stops</span>
          )}
          <span className="nearby-leg nearby-leg-you">You</span>
          <span className="nearby-leg nearby-leg-radius">
            {data.radiusM}m ring
          </span>
        </div>
      )}
    </div>
  );
}
