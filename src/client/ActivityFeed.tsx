import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

export type ActivityEventType = "connect" | "disconnect";

export interface ActivityEvent {
  /** Stable unique key for React lists */
  key: string;
  id: string;
  type: ActivityEventType;
  timestamp: number;
  userName: string;
  ip?: string;
  country?: string;
  city?: string;
  org?: string;
  isSelf?: boolean;
  /** How long the visitor was online before leaving (disconnect only) */
  sessionMs?: number;
}

export type ActivityFilter = "all" | "connect" | "disconnect";

const FEED_MAX_EVENTS = 100;
const TEXT_MAX_LEN = 96;

/** Strip control chars and cap length — React still escapes JSX text. */
export function sanitizeDisplayText(
  value: unknown,
  maxLength = TEXT_MAX_LEN,
): string {
  if (typeof value !== "string") return "";
  return value
    .replace(/[\u0000-\u001F\u007F\u202A-\u202E\u2066-\u2069]/g, "")
    .trim()
    .slice(0, maxLength);
}

/** Privacy: never show full client IP in the UI. */
export function maskIp(ip: unknown): string | undefined {
  if (typeof ip !== "string" || !ip.trim()) return undefined;
  const value = ip.trim().slice(0, 64);

  // Already masked / redacted — leave as-is
  if (
    value === "hidden" ||
    value.includes("x.x") ||
    value.includes("…") ||
    value.includes("...")
  ) {
    return value.slice(0, 64);
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
    const [a, b] = value.split(".");
    return `${a}.${b}.x.x`;
  }

  if (value.includes(":")) {
    const groups = value.split(":").filter(Boolean).slice(0, 2);
    return groups.length ? `${groups.join(":")}:…` : "ipv6:…";
  }

  return "hidden";
}

export function formatRelativeTime(timestamp: number, now: number): string {
  const deltaMs = Math.max(0, now - timestamp);
  const sec = Math.floor(deltaMs / 1000);
  if (sec < 5) return "just now";
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 48) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  return `${day}d ago`;
}

export function formatSessionDuration(sessionMs: number | undefined): string | undefined {
  if (typeof sessionMs !== "number" || !Number.isFinite(sessionMs) || sessionMs < 0) {
    return undefined;
  }
  const sec = Math.floor(sessionMs / 1000);
  if (sec < 60) return `${Math.max(1, sec)}s online`;
  const min = Math.floor(sec / 60);
  if (min < 60) {
    const rem = sec % 60;
    return rem > 0 ? `${min}m ${rem}s online` : `${min}m online`;
  }
  const hr = Math.floor(min / 60);
  const remMin = min % 60;
  return remMin > 0 ? `${hr}h ${remMin}m online` : `${hr}h online`;
}

export function createActivityEvent(
  partial: Omit<ActivityEvent, "key"> & { key?: string },
): ActivityEvent {
  const key =
    partial.key ??
    `${partial.id}:${partial.type}:${partial.timestamp}:${Math.random()
      .toString(36)
      .slice(2, 8)}`;

  const sessionMs =
    typeof partial.sessionMs === "number" &&
    Number.isFinite(partial.sessionMs) &&
    partial.sessionMs >= 0
      ? Math.min(partial.sessionMs, 7 * 24 * 60 * 60 * 1000)
      : undefined;

  return {
    key,
    id: sanitizeDisplayText(partial.id, 64),
    type: partial.type === "disconnect" ? "disconnect" : "connect",
    timestamp:
      typeof partial.timestamp === "number" && Number.isFinite(partial.timestamp)
        ? partial.timestamp
        : Date.now(),
    userName: sanitizeDisplayText(partial.userName, 48) || "Visitor",
    ip: maskIp(partial.ip),
    country: sanitizeDisplayText(partial.country, 48) || undefined,
    city: sanitizeDisplayText(partial.city, 48) || undefined,
    org: sanitizeDisplayText(partial.org, 64) || undefined,
    isSelf: Boolean(partial.isSelf),
    sessionMs,
  };
}

export function prependActivityEvent(
  prev: ActivityEvent[],
  event: ActivityEvent,
  max = FEED_MAX_EVENTS,
): ActivityEvent[] {
  // Drop an older duplicate leave for the same visitor within a short window
  if (event.type === "disconnect") {
    const next = prev.filter(
      (e) =>
        !(
          e.type === "disconnect" &&
          e.id === event.id &&
          Math.abs(e.timestamp - event.timestamp) < 2000
        ),
    );
    return [event, ...next].slice(0, max);
  }
  return [event, ...prev].slice(0, max);
}

/** Live feed is a Stripe-paid feature (same entitlement as Transit). */
export type LiveFeedAccess = "ok" | "login_required" | "payment_required";

type ActivityFeedProps = {
  open: boolean;
  onToggle: () => void;
  onClose: () => void;
  counter: number;
  events: ActivityEvent[];
  onClear: () => void;
  isPaused: boolean;
  onTogglePause: () => void;
  isCompact: boolean;
  onToggleCompact: () => void;
  filter: ActivityFilter;
  onFilterChange: (filter: ActivityFilter) => void;
  isSocketConnected: boolean;
  /** Stripe-paid unlock — feed content is hidden until ok */
  access: LiveFeedAccess;
  checkoutBusy?: boolean;
  onSignIn?: () => void;
  onBuyAccess?: () => void;
};

export function ActivityFeed({
  open,
  onToggle,
  onClose,
  counter,
  events,
  onClear,
  isPaused,
  onTogglePause,
  isCompact,
  onToggleCompact,
  filter,
  onFilterChange,
  isSocketConnected,
  access,
  checkoutBusy = false,
  onSignIn,
  onBuyAccess,
}: ActivityFeedProps) {
  const isLocked = access !== "ok";
  const [now, setNow] = useState(() => Date.now());
  const [copyState, setCopyState] = useState<"idle" | "ok" | "err">("idle");
  const listRef = useRef<HTMLDivElement>(null);
  const stickToTopRef = useRef(true);

  useEffect(() => {
    if (!open) return;
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  useEffect(() => {
    if (!open) setCopyState("idle");
  }, [open]);

  const joinCount = useMemo(
    () => events.reduce((n, e) => n + (e.type === "connect" ? 1 : 0), 0),
    [events],
  );
  const leaveCount = useMemo(
    () => events.reduce((n, e) => n + (e.type === "disconnect" ? 1 : 0), 0),
    [events],
  );

  const visibleEvents = useMemo(() => {
    if (filter === "all") return events;
    return events.filter((event) => event.type === filter);
  }, [events, filter]);

  const latestLeave = useMemo(
    () => events.find((e) => e.type === "disconnect") ?? null,
    [events],
  );

  const latestLabel = useMemo(() => {
    const pool =
      filter === "disconnect"
        ? events.filter((e) => e.type === "disconnect")
        : filter === "connect"
          ? events.filter((e) => e.type === "connect")
          : events;
    const latest = pool[0];
    if (!latest) return "—";
    if (latest.city && latest.country) return `${latest.city}, ${latest.country}`;
    if (latest.country) return latest.country;
    if (latest.org) return latest.org;
    if (latest.ip) return latest.ip;
    return latest.userName;
  }, [events, filter]);

  const onListScroll = useCallback(() => {
    const el = listRef.current;
    if (!el) return;
    stickToTopRef.current = el.scrollTop < 24;
  }, []);

  useEffect(() => {
    if (!open || !stickToTopRef.current) return;
    const el = listRef.current;
    if (el) el.scrollTop = 0;
  }, [open, visibleEvents.length, events[0]?.key]);

  const handleCopy = useCallback(async () => {
    const lines = visibleEvents.map((e) => {
      const when = new Date(e.timestamp).toISOString();
      const loc = [e.city, e.country].filter(Boolean).join(", ");
      const session = formatSessionDuration(e.sessionMs);
      const bits = [
        when,
        e.type.toUpperCase(),
        e.userName,
        loc || undefined,
        e.ip ? `ip=${e.ip}` : undefined,
        e.org ? `org=${e.org}` : undefined,
        session,
      ].filter(Boolean);
      return bits.join(" | ");
    });

    const payload = [
      `Live Feed export (${new Date().toISOString()})`,
      `online=${counter} joins=${joinCount} leaves=${leaveCount} shown=${visibleEvents.length}`,
      "",
      ...lines,
    ].join("\n");

    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error("clipboard unavailable");
      }
      await navigator.clipboard.writeText(payload);
      setCopyState("ok");
    } catch {
      setCopyState("err");
    }
    window.setTimeout(() => setCopyState("idle"), 1600);
  }, [visibleEvents, counter, joinCount, leaveCount]);

  const filterLabels: Record<ActivityFilter, string> = {
    all: "All",
    connect: "Joins",
    disconnect: "Leaves",
  };

  const filterCounts: Record<ActivityFilter, number> = {
    all: events.length,
    connect: joinCount,
    disconnect: leaveCount,
  };

  const selectFilter = (next: ActivityFilter) => {
    // Toggle off: clicking active Leaves/Joins returns to All
    if (next !== "all" && filter === next) {
      onFilterChange("all");
      return;
    }
    onFilterChange(next);
  };

  const launcherMeta = isLocked
    ? access === "login_required"
      ? "sign in required"
      : "Stripe access required"
    : isSocketConnected
      ? `${counter} online`
      : "reconnecting";

  return (
    <div className="activity-floating">
      <button
        type="button"
        className={`activity-launcher ${open ? "activity-launcher-open" : ""} ${
          !isSocketConnected && !isLocked ? "activity-launcher-offline" : ""
        } ${isLocked ? "activity-launcher-locked" : ""}`}
        onClick={onToggle}
        aria-controls="live-feed-menu"
        aria-expanded={open}
        title={
          isLocked
            ? "Live feed requires Stripe-paid access"
            : isSocketConnected
              ? "Live visitor feed"
              : "Feed reconnecting…"
        }
      >
        <span
          className={`pulse-dot ${
            isLocked
              ? "pulse-dot-locked"
              : !isSocketConnected
                ? "pulse-dot-offline"
                : ""
          } ${isPaused && !isLocked ? "pulse-dot-paused" : ""}`}
        />
        <span className="launcher-copy">
          <span className="launcher-label">Live Feed</span>
          <span className="launcher-meta">
            {launcherMeta}
            {!isLocked && isPaused ? " · paused" : ""}
            {!isLocked && leaveCount > 0 ? ` · ${leaveCount} left` : ""}
            {isLocked ? " · locked" : ""}
          </span>
        </span>
        <span className="launcher-action">{open ? "Hide" : "Open"}</span>
      </button>

      {open && (
        <section
          id="live-feed-menu"
          className={`activity-menu ${isCompact ? "activity-menu-compact" : ""} ${
            isLocked ? "activity-menu-locked" : ""
          }`}
          role="dialog"
          aria-label="Live activity feed"
          aria-modal="false"
        >
          <header className="activity-header">
            <div className="activity-title-group">
              <h3>LIVE FEED</h3>
              <p>
                {isLocked
                  ? access === "login_required"
                    ? "Sign in, then unlock with Stripe ($20)"
                    : "Stripe checkout required — same access as Transit"
                  : !isSocketConnected
                    ? "Connection interrupted"
                    : isPaused
                      ? "Joins paused — leaves still recorded"
                      : "Live visitor signals"}
              </p>
            </div>
            <div className="activity-header-actions">
              {!isLocked && (
                <div className="activity-count" title="Visitors currently online">
                  <span
                    className={`pulse-dot ${
                      !isSocketConnected ? "pulse-dot-offline" : ""
                    }`}
                  />
                  <span>{counter}</span>
                </div>
              )}
              <button
                type="button"
                className="activity-close-btn"
                onClick={onClose}
                aria-label="Close live feed"
              >
                ×
              </button>
            </div>
          </header>

          {isLocked ? (
            <div className="activity-lock-panel" role="status">
              <div className="activity-lock-badge">Stripe required</div>
              <p className="activity-lock-copy">
                The live visitor feed is a paid feature. Complete Stripe checkout
                ($20) to unlock Live Feed and Local Transit on this account.
              </p>
              <div className="activity-lock-actions">
                {access === "login_required" ? (
                  <button type="button" onClick={onSignIn}>
                    Sign in
                  </button>
                ) : (
                  <button
                    type="button"
                    className="billing-buy-btn"
                    onClick={onBuyAccess}
                    disabled={checkoutBusy}
                  >
                    {checkoutBusy
                      ? "Opening Stripe…"
                      : "Buy access ($20)"}
                  </button>
                )}
              </div>
              <p className="activity-lock-note">
                Globe markers stay free. Feed geo details are only sent after
                payment (server-gated).
              </p>
            </div>
          ) : (
            <>
              <div className="activity-summary" aria-label="Feed summary">
                <div className="activity-stat">
                  <span>Online</span>
                  <strong>{counter}</strong>
                </div>
                <div className="activity-stat">
                  <span>Joins</span>
                  <strong>{joinCount}</strong>
                </div>
                <div className="activity-stat">
                  <span>Leaves</span>
                  <strong>{leaveCount}</strong>
                </div>
                <div className="activity-stat activity-stat-latest">
                  <span>
                    {filter === "disconnect" ? "Last leave" : "Latest"}
                  </span>
                  <strong title={latestLabel}>{latestLabel}</strong>
                </div>
              </div>

              <div
                className="activity-filter"
                role="group"
                aria-label="Filter activity"
              >
                {(["all", "connect", "disconnect"] as ActivityFilter[]).map(
                  (f) => (
                    <button
                      key={f}
                      type="button"
                      className={`activity-filter-btn activity-filter-${f} ${
                        filter === f ? "active" : ""
                      }`}
                      onClick={() => selectFilter(f)}
                      aria-pressed={filter === f}
                    >
                      <span>{filterLabels[f]}</span>
                      <span className="activity-filter-count">
                        {filterCounts[f]}
                      </span>
                    </button>
                  ),
                )}
              </div>

              <div className="activity-actions">
                <button type="button" onClick={onTogglePause}>
                  {isPaused ? "Resume" : "Pause"}
                </button>
                <button type="button" onClick={onToggleCompact}>
                  {isCompact ? "Details" : "Compact"}
                </button>
                <button
                  type="button"
                  onClick={() => void handleCopy()}
                  disabled={visibleEvents.length === 0}
                  title="Copy visible events (IPs masked)"
                >
                  {copyState === "ok"
                    ? "Copied"
                    : copyState === "err"
                      ? "Failed"
                      : "Copy"}
                </button>
                <button
                  type="button"
                  onClick={onClear}
                  disabled={events.length === 0}
                  title="Clear history (keeps people still online)"
                >
                  Clear
                </button>
              </div>

              <div
                className="activity-list"
                ref={listRef}
                onScroll={onListScroll}
                role="log"
                aria-live={isPaused ? "off" : "polite"}
                aria-relevant="additions"
              >
                {!isSocketConnected && (
                  <div className="activity-banner activity-banner-warn">
                    Socket offline — feed will resume on reconnect.
                  </div>
                )}
                {isPaused && (
                  <div className="activity-banner activity-banner-info">
                    Paused — new joins are hidden; leaves are still logged.
                  </div>
                )}
                {filter === "disconnect" && leaveCount > 0 && latestLeave && (
                  <div className="activity-banner activity-banner-leave">
                    Showing {leaveCount} leave
                    {leaveCount === 1 ? "" : "s"} · last{" "}
                    {formatRelativeTime(latestLeave.timestamp, now)}
                  </div>
                )}

                {visibleEvents.length === 0 ? (
                  <div className="activity-empty">
                    {events.length === 0
                      ? "No activity yet — waiting for visitors."
                      : filter === "disconnect"
                        ? "No leaves yet. When a visitor closes the page, they appear here."
                        : filter === "connect"
                          ? "No joins recorded yet."
                          : "No events for this filter."}
                  </div>
                ) : (
                  visibleEvents.map((event) => {
                    const sessionLabel = formatSessionDuration(event.sessionMs);
                    const showMeta =
                      !isCompact &&
                      (event.city ||
                        event.country ||
                        event.ip ||
                        event.org ||
                        sessionLabel);

                    return (
                      <article
                        key={event.key}
                        className={`activity-item activity-${event.type} ${
                          event.isSelf ? "activity-item-self" : ""
                        }`}
                      >
                        <span className="activity-icon" aria-hidden="true">
                          {event.type === "connect" ? "↑" : "↓"}
                        </span>
                        <div className="activity-details">
                          <div className="activity-row-main">
                            <span className="activity-user">
                              {event.userName}
                              {event.isSelf ? (
                                <span className="activity-you-badge">you</span>
                              ) : null}
                            </span>
                            <time
                              className="activity-time"
                              dateTime={new Date(event.timestamp).toISOString()}
                              title={new Date(event.timestamp).toLocaleString()}
                            >
                              {formatRelativeTime(event.timestamp, now)}
                            </time>
                          </div>
                          <span
                            className={`activity-action activity-action-${event.type}`}
                          >
                            {event.type === "connect" ? "joined" : "left"}
                            {sessionLabel ? (
                              <span className="activity-session">
                                {" "}
                                · {sessionLabel}
                              </span>
                            ) : null}
                          </span>
                          {showMeta && (
                            <div className="activity-location">
                              {(event.city || event.country) && (
                                <span className="location-text">
                                  📍{" "}
                                  {[event.city, event.country]
                                    .filter(Boolean)
                                    .join(", ")}
                                </span>
                              )}
                              {event.ip && (
                                <span
                                  className="location-text"
                                  title="IP masked for privacy"
                                >
                                  🌐 {event.ip}
                                </span>
                              )}
                              {event.org && (
                                <span className="location-text">
                                  🏢 {event.org}
                                </span>
                              )}
                            </div>
                          )}
                        </div>
                      </article>
                    );
                  })
                )}
              </div>

              <footer className="activity-footer">
                <span>
                  Showing {visibleEvents.length}/{events.length}
                  {filter === "disconnect" ? " leaves" : ""}
                </span>
                <span className="activity-privacy-note">IPs masked</span>
              </footer>
            </>
          )}
        </section>
      )}
    </div>
  );
}
