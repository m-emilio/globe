import React, { useEffect, useRef } from "react";
import createGlobe from "cobe";
import { useSpring } from "react-spring";

interface CobeProps {
  counter: number;
  glowColor: [number, number, number];
  glowCssColor: string;
  positions: Map<
    string,
    {
      location: [number, number];
      size: number;
    }
  >;
}

export function Cobe({ counter, positions, glowColor, glowCssColor }: CobeProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const glowColorRef = useRef(glowColor);
  const pointerInteracting = useRef<number | null>(null);
  const pointerInteractionMovement = useRef(0);
  const [{ r }, api] = useSpring(() => ({
    r: 0,
    config: {
      mass: 1,
      tension: 280,
      friction: 40,
      precision: 0.001,
    },
  }));

  useEffect(() => {
    glowColorRef.current = glowColor;
  }, [glowColor]);

  useEffect(() => {
    let phi = 0;
    let width = 0;
    const onResize = () => {
      if (canvasRef.current) {
        width = canvasRef.current.offsetWidth;
        if (!width || width === 0) {
          width = 400; // fallback default
        }
        // Set canvas width/height attributes directly for pixel ratio
        canvasRef.current.width = width * 2;
        canvasRef.current.height = width * 2;
      }
    };
    window.addEventListener("resize", onResize);
    onResize();

    let globe: any = null;
    try {
      if (!canvasRef.current) {
        return;
      }
      globe = createGlobe(canvasRef.current, {
        devicePixelRatio: 2,
        width: (width || 400) * 2,
        height: (width || 400) * 2,
        phi: 0,
        theta: 0,
        dark: 1,
        diffuse: 0.8,
        mapSamples: 16000,
        mapBrightness: 6,
        baseColor: [212 / 255, 175 / 255, 55 / 255], // #d4af37 gold
        markerColor: [0.8, 0.1, 0.1],
        glowColor: glowColorRef.current,
        markers: [],
        opacity: 0.7,
        onRender: (state) => {
          // Multiplayer markers
          state.markers = [...positions.values()];
          state.glowColor = glowColorRef.current;
          if (!pointerInteracting.current) {
            phi += 0.005;
          }
          state.phi = phi + r.get();
          state.width = width * 2;
          state.height = width * 2;
        },
      });
    } catch (err) {
      // silent
    }

    setTimeout(() => {
      if (canvasRef.current) canvasRef.current.style.opacity = "1";
    });

    return () => {
      if (globe) globe.destroy();
      window.removeEventListener("resize", onResize);
    };
  }, [r]);

  return (
    <div
      style={{
        width: 400,
        height: 400,
        margin: "40px auto",
        position: "relative",
        background: "transparent",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        borderRadius: "50%",
        isolation: "isolate",
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
      <canvas
        ref={canvasRef}
        width={400}
        height={400}
        onPointerDown={(e) => {
          pointerInteracting.current = e.clientX - pointerInteractionMovement.current;
          if (canvasRef.current) canvasRef.current.style.cursor = "grabbing";
        }}
        onPointerUp={() => {
          pointerInteracting.current = null;
          if (canvasRef.current) canvasRef.current.style.cursor = "grab";
        }}
        onPointerOut={() => {
          pointerInteracting.current = null;
          if (canvasRef.current) canvasRef.current.style.cursor = "grab";
        }}
        onMouseMove={(e) => {
          if (pointerInteracting.current !== null) {
            const delta = e.clientX - pointerInteracting.current;
            pointerInteractionMovement.current = delta;
            api.start({ r: delta / 200 });
          }
        }}
        onTouchMove={(e) => {
          if (pointerInteracting.current !== null && e.touches[0]) {
            const delta = e.touches[0].clientX - pointerInteracting.current;
            pointerInteractionMovement.current = delta;
            api.start({ r: delta / 100 });
          }
        }}
        style={{
          width: 400,
          height: 400,
          cursor: "grab",
          background: "transparent",
          borderRadius: "50%",
          opacity: 1,
          transition: "opacity 1s ease",
          display: "block",
          position: "relative",
          zIndex: 1,
        }}
      />
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
