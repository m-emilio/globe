import React, { useEffect, useMemo, useRef, useState } from "react";
import createGlobe from "cobe";

type GlobeMarker = {
  location: [number, number];
  size: number;
};

export type GlobeArc = {
  id: string;
  from: [number, number];
  to: [number, number];
  via?: [number, number] | null;
  fromLabel?: string;
  toLabel?: string;
  viaLabel?: string;
  color: string;
  width: number;
  dash: string;
  severity: string;
};

interface CobeProps {
  counter: number;
  glowColor: [number, number, number];
  glowCssColor: string;
  markerColor?: [number, number, number];
  overlayMarkers?: GlobeMarker[];
  overlayRoutes?: GlobeArc[];
  positions: Map<
    string,
    GlobeMarker
  >;
}

type GlobeVector = {
  x: number;
  y: number;
  z: number;
};

type GlobeRotation = {
  phi: number;
  theta: number;
};

type PointerInteraction = {
  startX: number;
  startY: number;
  startPhi: number;
  startTheta: number;
};

const DEG_TO_RAD = Math.PI / 180;
const GLOBE_ROTATION_RADIANS_PER_MS = 0.0003;
const MAX_RENDER_DELTA_MS = 64;
const POINTER_DRAG_DIVISOR = 200;
const TOUCH_DRAG_DIVISOR = 100;
const GLOBE_SCREEN_RADIUS_RATIO = 0.4;
const DEFAULT_GLOBE_SCALE = 1;
const MIN_GLOBE_SCALE = 0.72;
const MAX_GLOBE_SCALE = 1.45;
const GLOBE_SCALE_STEP = 0.12;

type RoutePoint = {
  key: string;
  vector: GlobeVector;
  color: string;
  severity: string;
  label: string;
  role: string;
};

type PreparedRoute = {
  id: string;
  samples: GlobeVector[];
};

type RouteOverlayData = {
  key: string;
  routes: PreparedRoute[];
  points: RoutePoint[];
};

type RouteOverlayElementCache = {
  key: string;
  width: number;
  svg: SVGSVGElement | null;
  paths: SVGPathElement[];
  points: HTMLDivElement[];
};

function vectorFromLocation([lat, lng]: [number, number]): GlobeVector {
  const latRad = lat * DEG_TO_RAD;
  const lngRad = lng * DEG_TO_RAD;
  const cosLat = Math.cos(latRad);

  return {
    x: cosLat * Math.cos(lngRad),
    y: Math.sin(latRad),
    z: -cosLat * Math.sin(lngRad),
  };
}

function normalizeVector(vector: GlobeVector): GlobeVector {
  const length = Math.sqrt(vector.x * vector.x + vector.y * vector.y + vector.z * vector.z);

  if (length === 0) {
    return vector;
  }

  return {
    x: vector.x / length,
    y: vector.y / length,
    z: vector.z / length,
  };
}

function slerpVector(from: GlobeVector, to: GlobeVector, amount: number): GlobeVector {
  const dot = Math.max(
    -1,
    Math.min(1, from.x * to.x + from.y * to.y + from.z * to.z),
  );
  const omega = Math.acos(dot);
  const sinOmega = Math.sin(omega);

  if (sinOmega < 0.0001) {
    return normalizeVector({
      x: from.x + (to.x - from.x) * amount,
      y: from.y + (to.y - from.y) * amount,
      z: from.z + (to.z - from.z) * amount,
    });
  }

  const startScale = Math.sin((1 - amount) * omega) / sinOmega;
  const endScale = Math.sin(amount * omega) / sinOmega;

  return {
    x: from.x * startScale + to.x * endScale,
    y: from.y * startScale + to.y * endScale,
    z: from.z * startScale + to.z * endScale,
  };
}

function buildRouteVectors(from: [number, number], to: [number, number], steps: number) {
  const start = vectorFromLocation(from);
  const end = vectorFromLocation(to);

  return Array.from({ length: steps + 1 }, (_, index) =>
    slerpVector(start, end, index / steps),
  );
}

function buildRouteSamples(route: GlobeArc) {
  if (route.via) {
    return [
      ...buildRouteVectors(route.from, route.via, 16),
      ...buildRouteVectors(route.via, route.to, 16).slice(1),
    ];
  }

  return buildRouteVectors(route.from, route.to, 28);
}

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}

function projectVector(
  vector: GlobeVector,
  rotation: GlobeRotation,
  width: number,
  scale: number,
) {
  const cosPhi = Math.cos(rotation.phi);
  const sinPhi = Math.sin(rotation.phi);
  const cosTheta = Math.cos(rotation.theta);
  const sinTheta = Math.sin(rotation.theta);
  const x = vector.x * cosPhi + vector.z * sinPhi;
  const y =
    vector.x * sinPhi * sinTheta +
    vector.y * cosTheta -
    vector.z * cosPhi * sinTheta;
  const depth =
    -vector.x * sinPhi * cosTheta +
    vector.y * sinTheta +
    vector.z * cosPhi * cosTheta;
  const radius = width * GLOBE_SCREEN_RADIUS_RATIO * scale;

  return {
    x: width / 2 + x * radius,
    y: width / 2 - y * radius,
    visible: depth > -0.08,
    depth,
  };
}

function buildProjectedPath(
  samples: GlobeVector[],
  rotation: GlobeRotation,
  width: number,
  scale: number,
) {
  let path = "";
  let isDrawing = false;

  for (const sample of samples) {
    const point = projectVector(sample, rotation, width, scale);

    if (!point.visible) {
      isDrawing = false;
      continue;
    }

    path += `${isDrawing ? "L" : "M"} ${point.x.toFixed(1)} ${point.y.toFixed(1)} `;
    isDrawing = true;
  }

  return path.trim();
}

function getRoutePoints(routes: GlobeArc[]): RoutePoint[] {
  return routes.flatMap((route) => [
    {
      key: `${route.id}-from`,
      vector: vectorFromLocation(route.from),
      color: route.color,
      severity: route.severity,
      label: route.fromLabel ?? "Origin",
      role: "origin",
    },
    ...(route.via
      ? [
          {
            key: `${route.id}-via`,
            vector: vectorFromLocation(route.via),
            color: route.color,
            severity: route.severity,
            label: route.viaLabel ?? "Relay",
            role: "relay",
          },
        ]
      : []),
    {
      key: `${route.id}-to`,
      vector: vectorFromLocation(route.to),
      color: route.color,
      severity: route.severity,
      label: route.toLabel ?? "Destination",
      role: "destination",
    },
  ]);
}

function prepareRouteOverlay(routes: GlobeArc[]): RouteOverlayData {
  return {
    key: routes.map((route) => route.id).join("|"),
    routes: routes.map((route) => ({
      id: route.id,
      samples: buildRouteSamples(route),
    })),
    points: getRoutePoints(routes),
  };
}

function getRouteOverlayElements(
  container: HTMLDivElement,
  overlay: RouteOverlayData,
  width: number,
  cache: React.MutableRefObject<RouteOverlayElementCache | null>,
) {
  const cached = cache.current;

  if (cached && cached.key === overlay.key && cached.width === width) {
    return cached;
  }

  const elements = {
    key: overlay.key,
    width,
    svg: container.querySelector<SVGSVGElement>(".globe-arc-svg"),
    paths: Array.from(container.querySelectorAll<SVGPathElement>(".globe-arc-path")),
    points: Array.from(container.querySelectorAll<HTMLDivElement>(".globe-arc-point")),
  };

  elements.svg?.setAttribute("viewBox", `0 0 ${width} ${width}`);
  cache.current = elements;

  return elements;
}

function updateRouteOverlay(
  container: HTMLDivElement | null,
  overlay: RouteOverlayData,
  rotation: GlobeRotation,
  width: number,
  scale: number,
  cache: React.MutableRefObject<RouteOverlayElementCache | null>,
) {
  if (!container) {
    return;
  }

  const elements = getRouteOverlayElements(container, overlay, width, cache);

  overlay.routes.forEach((route, index) => {
    const path = elements.paths[index];

    if (!path) {
      return;
    }

    const projectedPath = buildProjectedPath(route.samples, rotation, width, scale);
    path.setAttribute("d", projectedPath);
    path.style.opacity = projectedPath ? "0.88" : "0";
  });

  overlay.points.forEach((point, index) => {
    const element = elements.points[index];

    if (!element) {
      return;
    }

    const projected = projectVector(point.vector, rotation, width, scale);
    element.style.left = `${projected.x}px`;
    element.style.top = `${projected.y}px`;
    element.style.opacity = projected.visible ? "1" : "0";
    element.style.transform = `translate(-50%, -50%) scale(${Math.max(
      0.7,
      0.85 + projected.depth * 0.18,
    ).toFixed(2)})`;
  });
}

export function Cobe({
  counter,
  positions,
  glowColor,
  glowCssColor,
  markerColor = [0.8, 0.1, 0.1],
  overlayMarkers = [],
  overlayRoutes = [],
}: CobeProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const routeOverlayRef = useRef<HTMLDivElement>(null);
  const routeOverlayCacheRef = useRef<RouteOverlayElementCache | null>(null);
  const glowColorRef = useRef(glowColor);
  const markerColorRef = useRef(markerColor);
  const overlayMarkersRef = useRef(overlayMarkers);
  const pointerInteracting = useRef<PointerInteraction | null>(null);
  const pointerRotationRef = useRef<GlobeRotation>({ phi: 0, theta: 0 });
  const autoRotationRef = useRef(0);
  const isAutoRotatePausedRef = useRef(false);
  const globeScaleRef = useRef(DEFAULT_GLOBE_SCALE);
  const [isAutoRotatePaused, setIsAutoRotatePaused] = useState(false);
  const [globeScale, setGlobeScale] = useState(DEFAULT_GLOBE_SCALE);
  const routeOverlayData = useMemo(
    () => prepareRouteOverlay(overlayRoutes),
    [overlayRoutes],
  );
  const overlayRoutesRef = useRef(routeOverlayData);

  useEffect(() => {
    glowColorRef.current = glowColor;
  }, [glowColor]);

  useEffect(() => {
    markerColorRef.current = markerColor;
  }, [markerColor]);

  useEffect(() => {
    overlayMarkersRef.current = overlayMarkers;
  }, [overlayMarkers]);

  useEffect(() => {
    overlayRoutesRef.current = routeOverlayData;
  }, [routeOverlayData]);

  const updatePointerRotation = (clientX: number, clientY: number, divisor: number) => {
    const interaction = pointerInteracting.current;

    if (interaction !== null) {
      pointerRotationRef.current = {
        phi: interaction.startPhi + (clientX - interaction.startX) / divisor,
        theta: interaction.startTheta + (clientY - interaction.startY) / divisor,
      };
    }
  };

  const setAutoRotatePausedValue = (paused: boolean) => {
    isAutoRotatePausedRef.current = paused;
    setIsAutoRotatePaused(paused);
  };

  const setGlobeScaleValue = (scale: number) => {
    const nextScale = clamp(scale, MIN_GLOBE_SCALE, MAX_GLOBE_SCALE);
    globeScaleRef.current = nextScale;
    setGlobeScale(nextScale);
  };

  const resetGlobeView = () => {
    autoRotationRef.current = 0;
    pointerRotationRef.current = { phi: 0, theta: 0 };
    setGlobeScaleValue(DEFAULT_GLOBE_SCALE);
  };

  useEffect(() => {
    let width = 0;
    let animationFrame = 0;
    let isDestroyed = false;
    let lastRenderAt = performance.now();
    const onResize = () => {
      if (canvasRef.current) {
        width = canvasRef.current.offsetWidth;
        if (!width || width === 0) {
          width = 400; // fallback default
        }
      }
    };
    window.addEventListener("resize", onResize);
    onResize();

    let globe: ReturnType<typeof createGlobe> | null = null;
    try {
      if (!canvasRef.current) {
        return;
      }
      globe = createGlobe(canvasRef.current, {
        devicePixelRatio: 2,
        width: width || 400,
        height: width || 400,
        phi: 0,
        theta: 0,
        dark: 1,
        diffuse: 0.8,
        mapSamples: 16000,
        mapBrightness: 6,
        baseColor: [212 / 255, 175 / 255, 55 / 255], // #d4af37 gold
        markerColor: markerColorRef.current,
        glowColor: glowColorRef.current,
        markers: [],
        opacity: 0.7,
        scale: DEFAULT_GLOBE_SCALE,
      });
    } catch (err) {
      // silent
    }

    const renderFrame = () => {
      if (!globe || isDestroyed) {
        return;
      }

      const now = performance.now();
      const elapsedMs = Math.min(
        MAX_RENDER_DELTA_MS,
        Math.max(0, now - lastRenderAt),
      );
      lastRenderAt = now;

      if (!isAutoRotatePausedRef.current && pointerInteracting.current === null) {
        autoRotationRef.current += elapsedMs * GLOBE_ROTATION_RADIANS_PER_MS;
      }

      const currentRotation = {
        phi: autoRotationRef.current + pointerRotationRef.current.phi,
        theta: pointerRotationRef.current.theta,
      };
      const currentWidth = width || 400;
      const currentScale = globeScaleRef.current;

      globe.update({
        markers: [...positions.values(), ...overlayMarkersRef.current],
        glowColor: glowColorRef.current,
        markerColor: markerColorRef.current,
        phi: currentRotation.phi,
        theta: currentRotation.theta,
        width: currentWidth,
        height: currentWidth,
        scale: currentScale,
      });

      updateRouteOverlay(
        routeOverlayRef.current,
        overlayRoutesRef.current,
        currentRotation,
        currentWidth,
        currentScale,
        routeOverlayCacheRef,
      );

      animationFrame = requestAnimationFrame(renderFrame);
    };

    animationFrame = requestAnimationFrame(renderFrame);

    setTimeout(() => {
      if (canvasRef.current) canvasRef.current.style.opacity = "1";
    });

    return () => {
      isDestroyed = true;
      cancelAnimationFrame(animationFrame);
      if (globe) globe.destroy();
      window.removeEventListener("resize", onResize);
    };
  }, []);

  const routePoints = routeOverlayData.points;

  return (
    <div
      style={{
        width: "min(400px, calc(100vw - 24px))",
        aspectRatio: "1 / 1",
        margin: "40px auto",
        position: "relative",
        background: "transparent",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        borderRadius: "50%",
        isolation: "isolate",
        touchAction: "none",
        overscrollBehavior: "contain",
        userSelect: "none",
      }}
    >
      <div
        aria-hidden="true"
        style={{
          position: "absolute",
          inset: -24,
          borderRadius: "50%",
          background: `radial-gradient(circle, ${glowCssColor} 0%, rgba(0, 0, 0, 0) 68%)`,
          filter: "blur(26px)",
          opacity: 0.78,
          transform: "translateZ(0)",
          transition: "background 450ms ease, opacity 450ms ease",
          zIndex: 0,
        }}
      />
      <div ref={routeOverlayRef} className="globe-arc-overlay" aria-hidden="true">
        <svg className="globe-arc-svg" viewBox="0 0 400 400">
          <defs>
            <filter id="globe-arc-glow" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="2.2" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          {overlayRoutes.map((route) => (
            <path
              className={`globe-arc-path globe-arc-${route.severity}`}
              key={route.id}
              style={
                {
                  "--arc-color": route.color,
                  "--arc-width": route.width,
                  "--arc-dash": route.dash,
                } as React.CSSProperties
              }
            />
          ))}
        </svg>
        {routePoints.map((point) => (
          <div
            className={`globe-arc-point globe-arc-point-${point.severity} globe-arc-point-${point.role}`}
            key={point.key}
            style={
              {
                "--arc-color": point.color,
              } as React.CSSProperties
            }
          >
            <span className="globe-arc-label">{point.label}</span>
          </div>
        ))}
      </div>
      <canvas
        ref={canvasRef}
        width={400}
        height={400}
        onPointerDown={(e) => {
          e.preventDefault();
          pointerInteracting.current = {
            startX: e.clientX,
            startY: e.clientY,
            startPhi: pointerRotationRef.current.phi,
            startTheta: pointerRotationRef.current.theta,
          };
          e.currentTarget.setPointerCapture?.(e.pointerId);
          if (canvasRef.current) canvasRef.current.style.cursor = "grabbing";
        }}
        onPointerMove={(e) => {
          e.preventDefault();
          updatePointerRotation(e.clientX, e.clientY, POINTER_DRAG_DIVISOR);
        }}
        onPointerUp={(e) => {
          pointerInteracting.current = null;
          e.currentTarget.releasePointerCapture?.(e.pointerId);
          if (canvasRef.current) canvasRef.current.style.cursor = "grab";
        }}
        onPointerOut={() => {
          pointerInteracting.current = null;
          if (canvasRef.current) canvasRef.current.style.cursor = "grab";
        }}
        onTouchMove={(e) => {
          e.preventDefault();
          if (pointerInteracting.current !== null && e.touches[0]) {
            updatePointerRotation(
              e.touches[0].clientX,
              e.touches[0].clientY,
              TOUCH_DRAG_DIVISOR,
            );
          }
        }}
        style={{
          width: "100%",
          height: "100%",
          cursor: "grab",
          background: "transparent",
          borderRadius: "50%",
          opacity: 1,
          transition: "opacity 1s ease",
          display: "block",
          position: "relative",
          zIndex: 1,
          touchAction: "none",
          userSelect: "none",
        }}
      />
      <div className="globe-controls" role="group" aria-label="Globe controls">
        <span className="globe-controls-label">GLOBE CTRL</span>
        <button
          type="button"
          className={`globe-control-btn ${isAutoRotatePaused ? "active" : ""}`}
          onClick={() => setAutoRotatePausedValue(!isAutoRotatePausedRef.current)}
          aria-pressed={isAutoRotatePaused}
          aria-label={isAutoRotatePaused ? "Start globe rotation" : "Stop globe rotation"}
        >
          {isAutoRotatePaused ? "START" : "STOP"}
        </button>
        <button
          type="button"
          className="globe-control-btn"
          onClick={() => setGlobeScaleValue(globeScaleRef.current + GLOBE_SCALE_STEP)}
          aria-label="Zoom globe in"
        >
          ZOOM
        </button>
        <button
          type="button"
          className="globe-control-btn"
          onClick={() => setGlobeScaleValue(globeScaleRef.current - GLOBE_SCALE_STEP)}
          aria-label="Zoom globe out"
        >
          UNZOOM
        </button>
        <button
          type="button"
          className="globe-control-btn"
          onClick={resetGlobeView}
          aria-label="Reset globe view"
        >
          RESET
        </button>
        <span className="globe-zoom-readout">{Math.round(globeScale * 100)}%</span>
      </div>
      {/* Multiplayer counter display */}
      <div style={{
        position: "absolute",
        top: 10,
        left: 0,
        width: "100%",
        zIndex: 2,
        textAlign: "center",
        color: "#fff",
        fontWeight: 600,
        textShadow: "0 1px 4px #000"
      }}>
        {counter !== 0 ? (
          <span><b>{counter}</b> {counter === 1 ? "person" : "people"} connected.</span>
        ) : (
          <span>&nbsp;</span>
        )}
      </div>
    </div>
  );
}
