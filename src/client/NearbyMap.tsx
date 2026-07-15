import React, { useMemo } from "react";
import type { NearbyPathSegment, NearbyPathsPreview } from "../shared";

type NearbyMapProps = {
  data: NearbyPathsPreview;
  className?: string;
};

type Projected = { x: number; y: number };

type MapLine = {
  id: string;
  kind: string;
  highway: string;
  d: string;
  name: string;
  label?: Projected & { text: string; angle: number };
};

const VIEW = 440;
const PAD = 22;

function projectPoints(
  paths: NearbyPathSegment[],
  centerLat: number,
  centerLng: number,
  radiusM: number,
): {
  lines: MapLine[];
  you: Projected;
  ring: string;
  parks: string[];
  water: string;
  scaleBar: { x: number; y: number; width: number; label: string };
} {
  const metersPerDegLat = 111_320;
  const metersPerDegLng =
    111_320 * Math.cos((centerLat * Math.PI) / 180) || 1;

  // Project to local meters first so scale fits actual geometry (more accurate framing)
  type LocalPt = { x: number; y: number; lat: number; lng: number };
  const toLocal = (lat: number, lng: number): LocalPt => ({
    x: (lng - centerLng) * metersPerDegLng,
    y: (lat - centerLat) * metersPerDegLat,
    lat,
    lng,
  });

  let minX = 0;
  let maxX = 0;
  let minY = 0;
  let maxY = 0;
  let hasPts = false;

  const localPaths = paths.map((path) => {
    const locals = path.points.map((p) => toLocal(p.lat, p.lng));
    for (const p of locals) {
      if (!hasPts) {
        minX = maxX = p.x;
        minY = maxY = p.y;
        hasPts = true;
      } else {
        minX = Math.min(minX, p.x);
        maxX = Math.max(maxX, p.x);
        minY = Math.min(minY, p.y);
        maxY = Math.max(maxY, p.y);
      }
    }
    return { path, locals };
  });

  // Fit extent around data + you, with radius as a floor so empty edges stay readable
  const dataHalf = Math.max(
    Math.abs(minX),
    Math.abs(maxX),
    Math.abs(minY),
    Math.abs(maxY),
    radiusM * 0.55,
    180,
  );
  const half = dataHalf * 1.08;
  const scale = (VIEW - PAD * 2) / (half * 2);

  const toXY = (localX: number, localY: number): Projected => ({
    x: VIEW / 2 + localX * scale,
    y: VIEW / 2 - localY * scale,
  });

  const lines: MapLine[] = localPaths.map(({ path, locals }) => {
    const pts = locals.map((p) => toXY(p.x, p.y));
    const d = pts
      .map((p, i) => `${i === 0 ? "M" : "L"}${p.x.toFixed(1)} ${p.y.toFixed(1)}`)
      .join(" ");

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

    return {
      id: path.id,
      kind: path.kind,
      highway: path.highway,
      d,
      name: path.name || path.highway,
      label,
    };
  });

  // Park blocks only as soft decoration away from dense roads (map-like blocks)
  const parks: string[] = [];
  if (paths.length < 40) {
    const block = half * 0.22 * scale;
    const offsets = [
      [-0.52, -0.42],
      [0.38, -0.48],
      [-0.48, 0.38],
      [0.42, 0.4],
    ];
    for (const [ox, oy] of offsets) {
      const cx = VIEW / 2 + ox * half * scale;
      const cy = VIEW / 2 + oy * half * scale;
      const w = block * (0.85 + Math.abs(ox) * 0.3);
      const h = block * (0.7 + Math.abs(oy) * 0.35);
      parks.push(
        `M${(cx - w / 2).toFixed(1)} ${(cy - h / 2).toFixed(1)} h${w.toFixed(1)} v${h.toFixed(1)} h${(-w).toFixed(1)} Z`,
      );
    }
  }

  const waterY = VIEW * 0.82;
  const water = `M ${PAD} ${waterY} Q ${VIEW / 2} ${waterY + 22} ${VIEW - PAD} ${waterY - 6} L ${VIEW - PAD} ${VIEW - PAD} L ${PAD} ${VIEW - PAD} Z`;

  const you = toXY(0, 0);
  const ringR = Math.min(radiusM, half * 0.95) * scale;
  const ring = `M ${you.x + ringR} ${you.y} a ${ringR} ${ringR} 0 1 0 ${-2 * ringR} 0 a ${ringR} ${ringR} 0 1 0 ${2 * ringR} 0`;

  const barMeters =
    radiusM >= 900 ? 300 : radiusM >= 600 ? 200 : 100;
  const barWidth = barMeters * scale;
  const scaleBar = {
    x: PAD + 6,
    y: VIEW - PAD - 12,
    width: Math.max(18, barWidth),
    label: `${barMeters} m`,
  };

  return { lines, you, ring, parks, water, scaleBar };
}

function roadWeight(
  highway: string,
  kind: string,
): "major" | "minor" | "path" | "cycle" {
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

export function NearbyMap({ data, className = "" }: NearbyMapProps) {
  const projected = useMemo(
    () => projectPoints(data.paths, data.lat, data.lng, data.radiusM),
    [data],
  );

  const major = projected.lines.filter(
    (l) => roadWeight(l.highway, l.kind) === "major",
  );
  const minor = projected.lines.filter(
    (l) => roadWeight(l.highway, l.kind) === "minor",
  );
  const paths = projected.lines.filter(
    (l) => roadWeight(l.highway, l.kind) === "path",
  );
  const cycles = projected.lines.filter(
    (l) => roadWeight(l.highway, l.kind) === "cycle",
  );

  return (
    <div className={`nearby-map ${className}`.trim()}>
      <svg
        className="nearby-map-svg"
        viewBox={`0 0 ${VIEW} ${VIEW}`}
        role="img"
        aria-label="Nearby street and path map"
      >
        <defs>
          <linearGradient id="nearby-land" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#1a2332" />
            <stop offset="45%" stopColor="#141c28" />
            <stop offset="100%" stopColor="#0d141e" />
          </linearGradient>
          <radialGradient id="nearby-vignette" cx="50%" cy="45%" r="65%">
            <stop offset="0%" stopColor="rgba(255,255,255,0.03)" />
            <stop offset="70%" stopColor="rgba(0,0,0,0)" />
            <stop offset="100%" stopColor="rgba(0,0,0,0.35)" />
          </radialGradient>
          <filter id="nearby-soft" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="0.55" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        <rect width={VIEW} height={VIEW} fill="url(#nearby-land)" />
        {/* Decorative water only when sketch/fallback-like density is low */}
        {data.paths.length < 35 && (
          <path d={projected.water} className="nearby-map-water" />
        )}
        {projected.parks.map((d, i) => (
          <path key={`park-${i}`} d={d} className="nearby-map-park" />
        ))}
        <rect width={VIEW} height={VIEW} fill="url(#nearby-vignette)" />

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
            <path key={line.id} d={line.d} className="nearby-fill nearby-fill-minor">
              <title>{line.name}</title>
            </path>
          ))}
          {major.map((line) => (
            <path key={line.id} d={line.d} className="nearby-fill nearby-fill-major">
              <title>{line.name}</title>
            </path>
          ))}
          {paths.map((line) => (
            <path key={line.id} d={line.d} className="nearby-fill nearby-fill-path">
              <title>{line.name}</title>
            </path>
          ))}
          {cycles.map((line) => (
            <path key={line.id} d={line.d} className="nearby-fill nearby-fill-cycle">
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

        <path d={projected.ring} className="nearby-map-radius" />

        <g
          className="nearby-map-you"
          transform={`translate(${projected.you.x} ${projected.you.y})`}
          filter="url(#nearby-soft)"
        >
          <circle r="16" className="nearby-map-you-halo" />
          <circle r="7" className="nearby-map-you-ring" />
          <circle r="3" className="nearby-map-you-dot" />
        </g>

        <g className="nearby-map-north" transform={`translate(${VIEW - 34} 34)`}>
          <circle r="14" className="nearby-map-north-disc" />
          <polygon points="0,-9 4,6 0,3 -4,6" className="nearby-map-north-arrow" />
          <text y="16" textAnchor="middle" className="nearby-map-north-text">
            N
          </text>
        </g>

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
      </svg>

      <div className="nearby-map-legend" aria-hidden="true">
        <span className="nearby-leg nearby-leg-road">Roads</span>
        <span className="nearby-leg nearby-leg-path">Paths</span>
        <span className="nearby-leg nearby-leg-cycle">Cycle</span>
        <span className="nearby-leg nearby-leg-you">You</span>
      </div>
      {data.stale && (
        <div className="nearby-map-stale-badge">Sketch mode</div>
      )}
    </div>
  );
}
