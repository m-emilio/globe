import React, { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import createGlobe from "cobe";

type GlobeMarker = {
  location: [number, number];
  size: number;
};

/** Comtrade / Trade Pulse payload attached to globe route endpoints for + popups */
export type GlobeArcComtradeDetail = {
  routeId: string;
  commodity: string;
  commodityCode: string;
  period: string;
  originName: string;
  originIso3: string;
  destName: string;
  destIso3: string;
  hubName?: string | null;
  hubIso3?: string | null;
  transportMode: string;
  customsProcedure: string;
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
  severity: string;
  layers: string[];
  insight: string;
  /** free-subscription when Worker hydrated from Free API */
  dataMode?: "derived-preview" | "free-subscription";
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
  /** Optional Comtrade-shaped metrics for point + popups */
  comtrade?: GlobeArcComtradeDetail;
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
/**
 * Cobe draws the sphere inside a fixed canvas. Raising cobe `scale` above ~1
 * makes the sphere larger than the canvas/circle clip → edges get cut off.
 * We keep render scale fixed and zoom with CSS transform on the whole sphere
 * so the full disc scales together without clipping.
 */
const GLOBE_SCREEN_RADIUS_RATIO = 0.4;
const COBE_RENDER_SCALE = 1;
/** Visual zoom (CSS) — full globe stays intact at every level */
const DEFAULT_VIEW_ZOOM = 1;
const MIN_VIEW_ZOOM = 0.65;
const MAX_VIEW_ZOOM = 1.75;
const VIEW_ZOOM_STEP = 0.1;
const MAX_TILT = 1.15;

type RoutePoint = {
  key: string;
  vector: GlobeVector;
  color: string;
  severity: string;
  label: string;
  role: string;
  countryName: string;
  comtrade?: GlobeArcComtradeDetail;
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
      countryName: route.comtrade?.originName ?? route.fromLabel ?? "Origin",
      comtrade: route.comtrade,
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
            countryName:
              route.comtrade?.hubName ?? route.viaLabel ?? "Relay",
            comtrade: route.comtrade,
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
      countryName: route.comtrade?.destName ?? route.toLabel ?? "Destination",
      comtrade: route.comtrade,
    },
  ]);
}

function formatPopupUsd(value: number): string {
  if (!Number.isFinite(value)) return "n/a";
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    notation: Math.abs(value) >= 1_000_000 ? "compact" : "standard",
    maximumFractionDigits: Math.abs(value) >= 1_000_000 ? 1 : 0,
  }).format(value);
}

function formatPopupPct(value: number): string {
  if (!Number.isFinite(value)) return "n/a";
  return `${value.toFixed(1)}%`;
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
  const globeScaleRef = useRef(DEFAULT_VIEW_ZOOM);
  const [isAutoRotatePaused, setIsAutoRotatePaused] = useState(false);
  const [globeScale, setGlobeScale] = useState(DEFAULT_VIEW_ZOOM);
  const [isGlobeControlsOpen, setIsGlobeControlsOpen] = useState(false);
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
    // Hold globe still while a route-point Comtrade popup is open
    if (isPopupHoldingGlobeRef.current) {
      return;
    }

    const interaction = pointerInteracting.current;

    if (interaction !== null) {
      pointerRotationRef.current = {
        phi: interaction.startPhi + (clientX - interaction.startX) / divisor,
        theta: clamp(
          interaction.startTheta + (clientY - interaction.startY) / divisor,
          -MAX_TILT,
          MAX_TILT,
        ),
      };
    }
  };

  const setAutoRotatePausedValue = (paused: boolean) => {
    isAutoRotatePausedRef.current = paused;
    setIsAutoRotatePaused(paused);
  };

  const setViewZoomValue = (zoom: number) => {
    const next = clamp(
      Math.round(zoom * 100) / 100,
      MIN_VIEW_ZOOM,
      MAX_VIEW_ZOOM,
    );
    globeScaleRef.current = next;
    setGlobeScale(next);
  };

  const nudgeViewZoom = (delta: number) => {
    setViewZoomValue(globeScaleRef.current + delta);
  };

  const resetGlobeView = () => {
    autoRotationRef.current = 0;
    pointerRotationRef.current = { phi: 0, theta: 0 };
    setViewZoomValue(DEFAULT_VIEW_ZOOM);
    setAutoRotatePausedValue(false);
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
    // Never early-return after adding the resize listener — that would leak it.
    if (canvasRef.current) {
      try {
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
          // Fixed fit — visual zoom is CSS on the sphere wrapper (no edge cut-off)
          scale: COBE_RENDER_SCALE,
        });
      } catch {
        // WebGL/init failure — keep UI shell; render loop no-ops without globe
        globe = null;
      }
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

      globe.update({
        markers: [...positions.values(), ...overlayMarkersRef.current],
        glowColor: glowColorRef.current,
        markerColor: markerColorRef.current,
        phi: currentRotation.phi,
        theta: currentRotation.theta,
        width: currentWidth,
        height: currentWidth,
        scale: COBE_RENDER_SCALE,
      });

      // Overlay uses cobe render scale (not CSS zoom); CSS scales the parent as a unit.
      updateRouteOverlay(
        routeOverlayRef.current,
        overlayRoutesRef.current,
        currentRotation,
        currentWidth,
        COBE_RENDER_SCALE,
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
  const [selectedPointKey, setSelectedPointKey] = useState<string | null>(null);
  /** True when we paused auto-rotate only for a point popup (restore on close) */
  const popupPausedRotateRef = useRef(false);
  /** True while popup is open — freezes auto-rotate + drag so the view sticks */
  const isPopupHoldingGlobeRef = useRef(false);
  const popupRef = useRef<HTMLDivElement | null>(null);
  const popupDragRef = useRef<{
    mode: "move" | "resize";
    startX: number;
    startY: number;
    originLeft: number;
    originTop: number;
    originW: number;
    originH: number;
  } | null>(null);
  const [popupLayout, setPopupLayout] = useState({
    left: 24,
    top: 24,
    width: 340,
    height: 360,
    /** User dragged the popup — stop auto re-snapping */
    userMoved: false,
    /** User resized — keep their size on next open */
    userResized: false,
  });
  const selectedPoint =
    routePoints.find((p) => p.key === selectedPointKey) ?? null;

  const clampPopupLayout = (
    left: number,
    top: number,
    width: number,
    height: number,
  ) => {
    const minW = 260;
    const minH = 200;
    const maxW = Math.min(520, window.innerWidth - 16);
    const maxH = Math.min(560, window.innerHeight - 16);
    const w = Math.max(minW, Math.min(width, maxW));
    const h = Math.max(minH, Math.min(height, maxH));
    const l = Math.max(8, Math.min(left, window.innerWidth - w - 8));
    const t = Math.max(8, Math.min(top, window.innerHeight - h - 8));
    return { left: l, top: t, width: w, height: h };
  };

  /** Snap popup next to the selected globe point (viewport / fixed coordinates). */
  const snapPopupToPoint = (pointKey: string) => {
    const safe =
      typeof CSS !== "undefined" && typeof CSS.escape === "function"
        ? CSS.escape(pointKey)
        : pointKey.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
    const pointEl = document.querySelector(
      `[data-arc-point="${safe}"]`,
    ) as HTMLElement | null;
    if (!pointEl) return;

    const pr = pointEl.getBoundingClientRect();
    setPopupLayout((prev) => {
      const width = prev.userResized ? prev.width : 340;
      const height = prev.userResized ? prev.height : 360;
      // Prefer right of point; flip left if it would overflow
      let left = pr.right + 14;
      let top = pr.top - 12;
      if (left + width > window.innerWidth - 8) {
        left = pr.left - width - 14;
      }
      if (top + height > window.innerHeight - 8) {
        top = window.innerHeight - height - 8;
      }
      if (top < 8) top = 8;
      if (left < 8) left = 8;
      const clamped = clampPopupLayout(left, top, width, height);
      return {
        ...clamped,
        userMoved: false,
        userResized: prev.userResized,
      };
    });
  };

  const openRoutePointPopup = (key: string) => {
    setSelectedPointKey(key);
    isPopupHoldingGlobeRef.current = true;
    // Pause spinning only if it was already moving (don't clobber user Off)
    if (!isAutoRotatePausedRef.current) {
      popupPausedRotateRef.current = true;
      setAutoRotatePausedValue(true);
    }
    // Drop any active drag so the globe doesn't keep moving under the popup
    pointerInteracting.current = null;
    if (canvasRef.current) canvasRef.current.style.cursor = "grab";
    // Snap after the point is painted in its frozen position
    window.requestAnimationFrame(() => {
      window.requestAnimationFrame(() => snapPopupToPoint(key));
    });
  };

  const closeRoutePointPopup = () => {
    setSelectedPointKey(null);
    isPopupHoldingGlobeRef.current = false;
    popupDragRef.current = null;
    if (popupPausedRotateRef.current) {
      popupPausedRotateRef.current = false;
      setAutoRotatePausedValue(false);
    }
  };

  // Clear popup when routes change / Trade Pulse closes; restore spin if we paused it
  useEffect(() => {
    if (
      selectedPointKey &&
      !routePoints.some((p) => p.key === selectedPointKey)
    ) {
      closeRoutePointPopup();
    }
  }, [routePoints, selectedPointKey]);

  useEffect(() => {
    const onPointerMove = (e: PointerEvent) => {
      const drag = popupDragRef.current;
      if (!drag) return;
      e.preventDefault();
      if (drag.mode === "move") {
        const next = clampPopupLayout(
          drag.originLeft + (e.clientX - drag.startX),
          drag.originTop + (e.clientY - drag.startY),
          drag.originW,
          drag.originH,
        );
        setPopupLayout((prev) => ({
          ...prev,
          left: next.left,
          top: next.top,
          width: drag.originW,
          height: drag.originH,
          userMoved: true,
        }));
      } else {
        const next = clampPopupLayout(
          drag.originLeft,
          drag.originTop,
          drag.originW + (e.clientX - drag.startX),
          drag.originH + (e.clientY - drag.startY),
        );
        setPopupLayout((prev) => ({
          ...prev,
          left: drag.originLeft,
          top: drag.originTop,
          width: next.width,
          height: next.height,
          userResized: true,
        }));
      }
    };
    const onPointerUp = () => {
      popupDragRef.current = null;
    };
    window.addEventListener("pointermove", onPointerMove);
    window.addEventListener("pointerup", onPointerUp);
    window.addEventListener("pointercancel", onPointerUp);
    return () => {
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerup", onPointerUp);
      window.removeEventListener("pointercancel", onPointerUp);
    };
  }, []);

  const [controlsSlot, setControlsSlot] = useState<HTMLElement | null>(null);

  useEffect(() => {
    const bindSlot = () => {
      setControlsSlot(document.getElementById("globe-controls-slot"));
    };
    bindSlot();
    // Slot is rendered as a sibling later in the tree; re-check next frame if needed
    const frame = window.requestAnimationFrame(bindSlot);
    return () => window.cancelAnimationFrame(frame);
  }, []);

  const zoomPercent = Math.round(globeScale * 100);
  const atMinZoom = globeScale <= MIN_VIEW_ZOOM + 0.001;
  const atMaxZoom = globeScale >= MAX_VIEW_ZOOM - 0.001;

  const globeControls = (
    <div
      className={`globe-controls ${isGlobeControlsOpen ? "globe-controls-open" : "globe-controls-compact"}`}
      role="group"
      aria-label="Globe controls"
    >
      <button
        type="button"
        className={`globe-control-btn globe-controls-toggle ${isGlobeControlsOpen ? "active" : ""}`}
        onClick={() => setIsGlobeControlsOpen((open) => !open)}
        aria-expanded={isGlobeControlsOpen}
        aria-controls="globe-controls-panel"
        aria-label={
          isGlobeControlsOpen ? "Hide globe controls" : "Show globe controls"
        }
        title="Globe view controls"
      >
        {isGlobeControlsOpen ? "Globe ▾" : "Globe ▴"}
      </button>
      {isGlobeControlsOpen && (
        <div id="globe-controls-panel" className="globe-controls-panel">
          <div className="globe-controls-section-label">Zoom</div>
          <div className="globe-zoom-row" role="group" aria-label="Zoom">
            <button
              type="button"
              className="globe-control-btn globe-zoom-btn"
              onClick={() => nudgeViewZoom(-VIEW_ZOOM_STEP)}
              disabled={atMinZoom}
              aria-label="Zoom out"
              title="Zoom out"
            >
              −
            </button>
            <span className="globe-zoom-readout" aria-live="polite">
              {zoomPercent}%
            </span>
            <button
              type="button"
              className="globe-control-btn globe-zoom-btn"
              onClick={() => nudgeViewZoom(VIEW_ZOOM_STEP)}
              disabled={atMaxZoom}
              aria-label="Zoom in"
              title="Zoom in"
            >
              +
            </button>
          </div>
          <label className="globe-zoom-slider-label">
            <span className="visually-hidden">Zoom level</span>
            <input
              type="range"
              className="globe-zoom-slider"
              min={MIN_VIEW_ZOOM}
              max={MAX_VIEW_ZOOM}
              step={0.01}
              value={globeScale}
              onChange={(e) => setViewZoomValue(Number(e.target.value))}
              aria-valuemin={Math.round(MIN_VIEW_ZOOM * 100)}
              aria-valuemax={Math.round(MAX_VIEW_ZOOM * 100)}
              aria-valuenow={zoomPercent}
              aria-label="Zoom level"
            />
          </label>

          <div className="globe-controls-section-label">Motion</div>
          <button
            type="button"
            className={`globe-control-btn ${!isAutoRotatePaused ? "active" : ""}`}
            onClick={() =>
              setAutoRotatePausedValue(!isAutoRotatePausedRef.current)
            }
            aria-pressed={!isAutoRotatePaused}
            aria-label={
              isAutoRotatePaused ? "Resume auto-rotate" : "Pause auto-rotate"
            }
            title="Spin the globe slowly"
          >
            {isAutoRotatePaused ? "Auto-rotate: Off" : "Auto-rotate: On"}
          </button>

          <button
            type="button"
            className="globe-control-btn globe-control-btn-reset"
            onClick={resetGlobeView}
            aria-label="Reset view to default zoom and rotation"
            title="Reset zoom, tilt, and spin"
          >
            Reset view
          </button>
          <p className="globe-controls-hint">Drag globe to look around · scroll to zoom</p>
        </div>
      )}
    </div>
  );

  return (
    <div className="globe-cobe-root">
      <div
        className="globe-cobe-sphere"
        style={{
          background: "transparent",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          isolation: "isolate",
          touchAction: "none",
          overscrollBehavior: "contain",
          userSelect: "none",
          // CSS zoom keeps the full sphere disc intact (no canvas edge cut-off)
          transform: `scale(${globeScale})`,
          transformOrigin: "center center",
        }}
        onWheel={(e) => {
          // Pinch/trackpad/mouse wheel zoom without cutting the globe
          e.preventDefault();
          const delta = e.deltaY > 0 ? -VIEW_ZOOM_STEP : VIEW_ZOOM_STEP;
          nudgeViewZoom(delta * (e.ctrlKey ? 1.5 : 1));
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
      <div
        ref={routeOverlayRef}
        className="globe-arc-overlay"
        aria-hidden={routePoints.length === 0}
      >
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
            className={`globe-arc-point globe-arc-point-${point.severity} globe-arc-point-${point.role}${
              selectedPointKey === point.key ? " globe-arc-point-open" : ""
            }`}
            key={point.key}
            data-arc-point={point.key}
            style={
              {
                "--arc-color": point.color,
              } as React.CSSProperties
            }
          >
            <button
              type="button"
              className="globe-arc-plus"
              aria-label={
                selectedPointKey === point.key
                  ? `Close Comtrade data for ${point.countryName}`
                  : `Show Comtrade data for ${point.countryName}`
              }
              title={
                selectedPointKey === point.key
                  ? "Close (resume globe)"
                  : `${point.countryName} · Comtrade details (pauses globe)`
              }
              onPointerDown={(e) => {
                e.stopPropagation();
                e.preventDefault();
              }}
              onClick={(e) => {
                e.stopPropagation();
                e.preventDefault();
                if (selectedPointKey === point.key) {
                  closeRoutePointPopup();
                } else {
                  openRoutePointPopup(point.key);
                }
              }}
            >
              {selectedPointKey === point.key ? "×" : "+"}
            </button>
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
          // Don't start a drag while a point popup is holding the globe still
          if (isPopupHoldingGlobeRef.current) {
            return;
          }
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
          // No circular clip on the canvas — clipping was cutting zoomed edges
          borderRadius: 0,
          opacity: 1,
          transition: "opacity 1s ease",
          display: "block",
          position: "relative",
          zIndex: 1,
          touchAction: "none",
          userSelect: "none",
        }}
      />
      {/* Multiplayer counter display */}
      <div
        className="globe-counter"
        style={{
          position: "absolute",
          top: 10,
          left: 0,
          width: "100%",
          zIndex: 2,
          textAlign: "center",
          color: "#fff",
          fontWeight: 600,
          textShadow: "0 1px 4px #000",
          pointerEvents: "none",
        }}
      >
        {counter !== 0 ? (
          <span>
            <b>{counter}</b> {counter === 1 ? "person" : "people"} connected.
          </span>
        ) : (
          <span>&nbsp;</span>
        )}
      </div>
      </div>

      {selectedPoint?.comtrade &&
        createPortal(
          <div
            ref={popupRef}
            className="globe-arc-comtrade-popup"
            role="dialog"
            aria-label={`Comtrade data for ${selectedPoint.countryName}`}
            style={
              {
                "--arc-color": selectedPoint.color,
                left: popupLayout.left,
                top: popupLayout.top,
                width: popupLayout.width,
                height: popupLayout.height,
              } as React.CSSProperties
            }
            onPointerDown={(e) => e.stopPropagation()}
          >
            <div
              className="globe-arc-comtrade-popup-header"
              title="Drag to move"
              onPointerDown={(e) => {
                if ((e.target as HTMLElement).closest("button")) return;
                e.preventDefault();
                e.stopPropagation();
                popupDragRef.current = {
                  mode: "move",
                  startX: e.clientX,
                  startY: e.clientY,
                  originLeft: popupLayout.left,
                  originTop: popupLayout.top,
                  originW: popupLayout.width,
                  originH: popupLayout.height,
                };
                (e.currentTarget as HTMLElement).setPointerCapture?.(e.pointerId);
              }}
            >
              <div>
                <strong>{selectedPoint.countryName}</strong>
                <span>
                  {selectedPoint.role === "origin"
                    ? "Origin"
                    : selectedPoint.role === "relay"
                      ? "Intermediary hub"
                      : "Destination"}{" "}
                  · {selectedPoint.comtrade.severity}
                  <em className="globe-arc-comtrade-drag-hint"> · drag header to move</em>
                </span>
              </div>
              <div className="globe-arc-comtrade-header-actions">
                <button
                  type="button"
                  className="globe-arc-comtrade-snap"
                  aria-label="Snap popup next to point"
                  title="Snap next to point"
                  onClick={() => {
                    if (selectedPointKey) snapPopupToPoint(selectedPointKey);
                  }}
                >
                  ⊡
                </button>
                <button
                  type="button"
                  className="globe-arc-comtrade-close"
                  aria-label="Close Comtrade popup and resume globe"
                  onClick={() => closeRoutePointPopup()}
                >
                  ×
                </button>
              </div>
            </div>
            <div className="globe-arc-comtrade-popup-body">
              <p className="globe-arc-comtrade-route">
                {selectedPoint.comtrade.originIso3} →{" "}
                {selectedPoint.comtrade.destIso3}
                {selectedPoint.comtrade.hubIso3
                  ? ` via ${selectedPoint.comtrade.hubIso3}`
                  : ""}
              </p>
              <p className="globe-arc-comtrade-commodity">
                <strong>{selectedPoint.comtrade.commodity}</strong>
                <span>HS {selectedPoint.comtrade.commodityCode}</span>
              </p>
              <div className="globe-arc-comtrade-grid">
                <div>
                  <span>Period</span>
                  <strong>{selectedPoint.comtrade.period}</strong>
                </div>
                <div>
                  <span>Value</span>
                  <strong>
                    {formatPopupUsd(selectedPoint.comtrade.valueUsd)}
                  </strong>
                </div>
                <div>
                  <span>Quantity</span>
                  <strong>{selectedPoint.comtrade.quantity || "n/a"}</strong>
                </div>
                <div>
                  <span>Transport</span>
                  <strong>{selectedPoint.comtrade.transportMode}</strong>
                </div>
                <div>
                  <span>Supplier share</span>
                  <strong>
                    {formatPopupPct(selectedPoint.comtrade.supplierSharePct)}
                  </strong>
                </div>
                <div>
                  <span>Mirror gap</span>
                  <strong>
                    {formatPopupPct(selectedPoint.comtrade.asymmetryPct)}
                  </strong>
                </div>
                <div>
                  <span>Export</span>
                  <strong>
                    {formatPopupUsd(selectedPoint.comtrade.exportValueUsd)}
                  </strong>
                </div>
                <div>
                  <span>Import</span>
                  <strong>
                    {formatPopupUsd(selectedPoint.comtrade.importValueUsd)}
                  </strong>
                </div>
                <div>
                  <span>FOB</span>
                  <strong>
                    {formatPopupUsd(selectedPoint.comtrade.fobValueUsd)}
                  </strong>
                </div>
                <div>
                  <span>CIF</span>
                  <strong>
                    {formatPopupUsd(selectedPoint.comtrade.cifValueUsd)}
                  </strong>
                </div>
                <div>
                  <span>CIF/FOB friction</span>
                  <strong>
                    {formatPopupPct(selectedPoint.comtrade.frictionPct)}
                  </strong>
                </div>
                <div>
                  <span>Re-export</span>
                  <strong>
                    {formatPopupPct(selectedPoint.comtrade.reExportSharePct)}
                  </strong>
                </div>
                <div>
                  <span>Confidence</span>
                  <strong>
                    {formatPopupPct(selectedPoint.comtrade.confidencePct)}
                  </strong>
                </div>
                <div>
                  <span>Procedure</span>
                  <strong>{selectedPoint.comtrade.customsProcedure}</strong>
                </div>
              </div>
              {selectedPoint.comtrade.layers.length > 0 && (
                <div className="globe-arc-comtrade-layers">
                  {selectedPoint.comtrade.layers.map((layer) => (
                    <span key={layer}>{layer}</span>
                  ))}
                </div>
              )}
              <p className="globe-arc-comtrade-insight">
                {selectedPoint.comtrade.insight}
              </p>
              <p className="globe-arc-comtrade-disclaimer">
                {selectedPoint.comtrade.period}
                {selectedPoint.comtrade.dataMode === "free-subscription"
                  ? " · UN Comtrade"
                  : " · Preview"}
              </p>
            </div>
            <button
              type="button"
              className="globe-arc-comtrade-resize"
              aria-label="Resize popup"
              title="Drag to resize"
              onPointerDown={(e) => {
                e.preventDefault();
                e.stopPropagation();
                popupDragRef.current = {
                  mode: "resize",
                  startX: e.clientX,
                  startY: e.clientY,
                  originLeft: popupLayout.left,
                  originTop: popupLayout.top,
                  originW: popupLayout.width,
                  originH: popupLayout.height,
                };
                (e.currentTarget as HTMLElement).setPointerCapture?.(e.pointerId);
              }}
            />
          </div>,
          document.body,
        )}

      {controlsSlot ? createPortal(globeControls, controlsSlot) : null}
    </div>
  );
}
