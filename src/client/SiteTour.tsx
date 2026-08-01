import React, { useCallback, useEffect, useRef, useState } from "react";

const TOUR_MS = 60_000;
const TOUR_STORAGE_KEY = "globe:site-tour:v1";

export type SiteTourStep = {
  title: string;
  body: string;
  hint?: string;
};

const TOUR_STEPS: SiteTourStep[] = [
  {
    title: "Welcome to FederalKey Globe",
    body: "A live multiplayer globe of visitors, security data layers, and local tools — running on Cloudflare at the edge.",
    hint: "This tour runs for about one minute, or browse with the arrows.",
  },
  {
    title: "The live globe",
    body: "Dots mark people connected right now. Your location is approximate (from the network edge). Rotate and zoom to explore the planet.",
    hint: "Markers are public presence only — no full IP on the wire.",
  },
  {
    title: "FEDERALKEY",
    body: "The gold badge opens federalkey.org — smartcards, identity, and the wider FederalKey project.",
    hint: "Top-left of the nav bar.",
  },
  {
    title: "Menu",
    body: "MENU opens location settings, billing, auth, admin, and app links. Buy Stripe access here after you sign in with a PGP key.",
    hint: "Top-right · MENU in the nav.",
  },
  {
    title: "Location",
    body: "Choose browser GPS, enter latitude/longitude, or look up a city/address. Transit, Nearby, and Weather use this preference.",
    hint: "MENU → Location.",
  },
  {
    title: "Globe controls",
    body: "The Globe button next to MENU zooms, toggles auto-rotate, and resets the view.",
    hint: "Top-right nav · next to MENU.",
  },
  {
    title: "App dock",
    body: "Live Feed, PKI, UN hub, Transit, Nearby, and Weather live in the macOS-style dock at the bottom of the screen.",
    hint: "Bottom center · hover to magnify.",
  },
  {
    title: "Live Feed app",
    body: "Open Feed from the dock for paid join/leave detail and web support chat after Stripe unlock. Globe markers stay free.",
    hint: "Bottom dock · Feed.",
  },
  {
    title: "PKI / CVE hub",
    body: "The lock icon opens Certificate & PKI exposure: CISA KEV and NVD vulns as severity-colored arcs. Filter, page, and focus a CVE on the map.",
    hint: "Bottom dock · padlock.",
  },
  {
    title: "UN Data Hub",
    body: "The 🇺🇳 icon opens Trade Pulse, UNODC crime/drugs themes, and UN Global locations (HQ, missions, members). Toggle layers for the globe.",
    hint: "Bottom dock · UN flag.",
  },
  {
    title: "Local transit & nearby",
    body: "Transit loads routes and stops near you; Nearby traces streets and paths. Both need sign-in and Stripe ($20) — same unlock as Live Feed.",
    hint: "Bottom dock · bus and path icons.",
  },
  {
    title: "Weather",
    body: "Pulls current conditions (and forecast) and can tint the globe glow to match the sky.",
    hint: "Bottom dock · weather icon.",
  },
  {
    title: "Web support chat",
    body: "Paid Live Feed includes an ephemeral web support channel for help while you browse. Relay only — not stored on the server.",
    hint: "Dock · Feed → Web support (Stripe).",
  },
  {
    title: "PGP sign-in",
    body: "Accounts use OpenPGP challenge–response — no account password. Your private key stays on your device; the session is an HttpOnly cookie.",
    hint: "Open MENU → sign in / register.",
  },
  {
    title: "You’re set",
    body: "Explore apps from the dock, use Globe next to MENU for view controls, and open Feed for presence or paid support chat.",
    hint: "Use ← → or the dots to revisit any step.",
  },
];

export function shouldShowSiteTour(): boolean {
  try {
    return localStorage.getItem(TOUR_STORAGE_KEY) !== "1";
  } catch {
    return true;
  }
}

export function markSiteTourSeen(): void {
  try {
    localStorage.setItem(TOUR_STORAGE_KEY, "1");
  } catch {
    // private mode / blocked storage
  }
}

type SiteTourProps = {
  onDone: () => void;
};

/**
 * Intro tour: auto-advances for ~60s, or pause and browse with arrows / dots.
 * Click the timer to pause/resume. Manual navigation also pauses auto-play.
 */
export function SiteTour({ onDone }: SiteTourProps) {
  const stepCount = TOUR_STEPS.length;
  const stepMs = TOUR_MS / stepCount;

  const [stepIndex, setStepIndex] = useState(0);
  const [elapsedMs, setElapsedMs] = useState(0);
  const [paused, setPaused] = useState(false);

  const pausedRef = useRef(false);
  const elapsedRef = useRef(0);
  const anchorRef = useRef(Date.now());

  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  useEffect(() => {
    const id = window.setInterval(() => {
      if (pausedRef.current) {
        // Keep wall-clock aligned so resume continues from remaining time
        anchorRef.current = Date.now() - elapsedRef.current;
        return;
      }
      const elapsed = Date.now() - anchorRef.current;
      if (elapsed >= TOUR_MS) {
        window.clearInterval(id);
        elapsedRef.current = TOUR_MS;
        setElapsedMs(TOUR_MS);
        setStepIndex(stepCount - 1);
        onDone();
        return;
      }
      elapsedRef.current = elapsed;
      setElapsedMs(elapsed);
      setStepIndex(Math.min(stepCount - 1, Math.floor(elapsed / stepMs)));
    }, 150);
    return () => window.clearInterval(id);
  }, [onDone, stepCount, stepMs]);

  const pauseAuto = useCallback(() => {
    setPaused(true);
  }, []);

  const togglePause = useCallback(() => {
    setPaused((p) => {
      if (p) {
        // Resume: re-anchor so remaining countdown is preserved
        anchorRef.current = Date.now() - elapsedRef.current;
      }
      return !p;
    });
  }, []);

  const goToStep = useCallback(
    (index: number) => {
      const next = Math.max(0, Math.min(stepCount - 1, index));
      setPaused(true);
      setStepIndex(next);
      // Keep progress bar / timer in sync with manual page (pause freezes remaining)
      const synced = Math.min(TOUR_MS - 1, next * stepMs);
      elapsedRef.current = synced;
      setElapsedMs(synced);
      anchorRef.current = Date.now() - synced;
    },
    [stepCount, stepMs],
  );

  const goPrev = useCallback(() => {
    goToStep(stepIndex - 1);
  }, [goToStep, stepIndex]);

  const goNext = useCallback(() => {
    if (stepIndex >= stepCount - 1) {
      pauseAuto();
      onDone();
      return;
    }
    goToStep(stepIndex + 1);
  }, [goToStep, stepIndex, stepCount, pauseAuto, onDone]);

  // Keyboard ← → when tour is open
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "ArrowLeft") {
        e.preventDefault();
        goPrev();
      } else if (e.key === "ArrowRight") {
        e.preventDefault();
        goNext();
      } else if (e.key === "Escape") {
        e.preventDefault();
        onDone();
      } else if (e.key === " " || e.key === "Spacebar") {
        // Space toggles pause when focus is not in an input
        const tag = (e.target as HTMLElement)?.tagName;
        if (tag === "INPUT" || tag === "TEXTAREA" || tag === "BUTTON") return;
        e.preventDefault();
        togglePause();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [goPrev, goNext, onDone, togglePause]);

  const step = TOUR_STEPS[stepIndex] ?? TOUR_STEPS[0];
  const remainingSec = Math.max(0, Math.ceil((TOUR_MS - elapsedMs) / 1000));
  const progressPct = Math.min(100, (elapsedMs / TOUR_MS) * 100);
  const atStart = stepIndex <= 0;
  const atEnd = stepIndex >= stepCount - 1;

  return (
    <div
      className="site-tour"
      role="dialog"
      aria-modal="false"
      aria-label="Site tour"
      aria-live="polite"
    >
      <div className="site-tour-card">
        <div className="site-tour-progress" aria-hidden="true">
          <span style={{ width: `${progressPct}%` }} />
        </div>
        <header className="site-tour-header">
          <div>
            <span className="site-tour-kicker">
              Quick tour · {stepIndex + 1}/{stepCount}
              {paused ? " · paused" : ""}
            </span>
            <h2>{step.title}</h2>
          </div>
          <button
            type="button"
            className={`site-tour-timer ${paused ? "site-tour-timer-paused" : ""}`}
            onClick={togglePause}
            title={
              paused
                ? "Resume auto-advance"
                : "Pause auto-advance (click timer)"
            }
            aria-pressed={paused}
            aria-label={
              paused
                ? `Tour paused, ${remainingSec} seconds left. Click to resume.`
                : `${remainingSec} seconds left. Click to pause auto-advance.`
            }
          >
            {paused ? "❚❚" : ""}
            {remainingSec}s
          </button>
        </header>
        <p className="site-tour-body">{step.body}</p>
        {step.hint ? <p className="site-tour-hint">{step.hint}</p> : null}

        <div
          className="site-tour-dots"
          role="tablist"
          aria-label="Tour steps"
        >
          {TOUR_STEPS.map((s, i) => (
            <button
              key={s.title}
              type="button"
              role="tab"
              aria-selected={i === stepIndex}
              aria-label={`Step ${i + 1}: ${s.title}`}
              className={`site-tour-dot-btn ${
                i === stepIndex ? "active" : i < stepIndex ? "done" : ""
              }`}
              onClick={() => goToStep(i)}
            />
          ))}
        </div>

        <div className="site-tour-nav" role="group" aria-label="Tour navigation">
          <button
            type="button"
            className="site-tour-arrow"
            onClick={goPrev}
            disabled={atStart}
            aria-label="Previous step"
            title="Previous (←)"
          >
            ←
          </button>
          <span className="site-tour-nav-label">
            {stepIndex + 1} / {stepCount}
          </span>
          <button
            type="button"
            className="site-tour-arrow"
            onClick={goNext}
            aria-label={atEnd ? "Finish tour" : "Next step"}
            title={atEnd ? "Finish" : "Next (→)"}
          >
            {atEnd ? "✓" : "→"}
          </button>
        </div>

        <footer className="site-tour-footer">
          <button type="button" className="site-tour-skip" onClick={onDone}>
            Skip tour
          </button>
          <span className="site-tour-auto">
            {paused
              ? "Paused · click timer to resume"
              : "Auto-plays · arrows or dots pause"}
          </span>
        </footer>
      </div>
    </div>
  );
}
