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

/** Public globe WebSocket link — separate from paid Live Feed access. */
export type GlobeSocketStatus = "connecting" | "connected" | "disconnected";

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

/**
 * Free UN Web TV / UNTV channel catalog (static allow-list only).
 * Embeds must match CSP frame-src hosts. Never build iframe URLs from user input.
 */
type UnTvChannel =
  | {
      id: string;
      label: string;
      blurb: string;
      kind: "youtube";
      videoId: string;
      pageUrl: string;
    }
  | {
      id: string;
      label: string;
      blurb: string;
      kind: "kaltura";
      entryId: string;
      partnerId: string;
      uiconfId: string;
      pageUrl: string;
    }
  | {
      id: string;
      label: string;
      blurb: string;
      kind: "link";
      pageUrl: string;
    };

/** Official public streams — stable IDs from UN / UNTV. */
const UN_TV_CHANNELS: readonly UnTvChannel[] = [
  {
    id: "untv-yt",
    label: "UNTV 24/7",
    blurb: "United Nations YouTube live channel",
    kind: "youtube",
    // Official UNTV 24/7 live stream (youtube.com/unitednations/live)
    videoId: "vYRfQo6JMxc",
    pageUrl: "https://www.youtube.com/unitednations/live",
  },
  {
    id: "webtv-24h",
    label: "UN Web TV 24h",
    blurb: "24-hour live & pre-recorded programming",
    kind: "kaltura",
    // webtv.un.org continuous channel (Kaltura partner 2503451)
    partnerId: "2503451",
    uiconfId: "49754663",
    entryId: "1_gb6tjmle",
    pageUrl: "https://webtv.un.org/en/asset/k1g/k1gb6tjmle",
  },
  {
    id: "webtv-home",
    label: "Web TV site",
    blurb: "Browse live meetings on webtv.un.org",
    kind: "link",
    pageUrl: "https://webtv.un.org/en",
  },
  {
    id: "webtv-schedule",
    label: "Schedule",
    blurb: "Live schedule of UN meetings",
    kind: "link",
    pageUrl: "https://webtv.un.org/en/schedule",
  },
];

function unTvEmbedSrc(channel: UnTvChannel): string | null {
  if (channel.kind === "youtube") {
    // Allow-list video id shape
    if (!/^[A-Za-z0-9_-]{6,20}$/.test(channel.videoId)) return null;
    return (
      `https://www.youtube-nocookie.com/embed/${channel.videoId}` +
      "?autoplay=0&rel=0&modestbranding=1&playsinline=1"
    );
  }
  if (channel.kind === "kaltura") {
    if (
      !/^\d{4,10}$/.test(channel.partnerId) ||
      !/^\d{6,12}$/.test(channel.uiconfId) ||
      !/^[0-9a-z_]{6,24}$/i.test(channel.entryId)
    ) {
      return null;
    }
    const params = new URLSearchParams({
      iframeembed: "true",
      playerId: "kaltura_player",
      entry_id: channel.entryId,
    });
    return (
      `https://cdnapisec.kaltura.com/p/${channel.partnerId}` +
      `/sp/${channel.partnerId}00/embedIframeJs/uiconf_id/${channel.uiconfId}` +
      `/partner_id/${channel.partnerId}?${params.toString()}`
    );
  }
  return null;
}

export type LiveChatMessage = {
  id: string;
  fromId: string;
  text: string;
  displayName: string;
  ts: number;
  isSelf?: boolean;
};

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
  /** @deprecated prefer socketStatus — kept for compatibility */
  isSocketConnected?: boolean;
  /** Public WS link status (markers). Not the same as feed unlock. */
  socketStatus?: GlobeSocketStatus;
  /** Stripe-paid unlock — feed content is hidden until ok */
  access: LiveFeedAccess;
  checkoutBusy?: boolean;
  onSignIn?: () => void;
  onBuyAccess?: () => void;
  /** Manual PartySocket reconnect when link drops */
  onReconnectSocket?: () => void;
  /** Paid web-support chat in Live Feed (client memory only; server-gated) */
  chatMessages?: LiveChatMessage[];
  onSendChat?: (text: string) => boolean;
  /**
   * When false, the built-in launcher is hidden (e.g. opened from the dock app).
   * Panel still renders when `open` is true.
   */
  showLauncher?: boolean;
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
  socketStatus: socketStatusProp,
  access,
  checkoutBusy = false,
  onSignIn,
  onBuyAccess,
  onReconnectSocket,
  chatMessages = [],
  onSendChat,
  showLauncher = true,
}: ActivityFeedProps) {
  const isLocked = access !== "ok";
  const socketStatus: GlobeSocketStatus =
    socketStatusProp ??
    (isSocketConnected ? "connected" : "disconnected");
  const isLinkUp = socketStatus === "connected";
  const isLinkConnecting = socketStatus === "connecting";
  const [now, setNow] = useState(() => Date.now());
  const [copyState, setCopyState] = useState<"idle" | "ok" | "err">("idle");
  const [chatDraft, setChatDraft] = useState("");
  const [chatSendHint, setChatSendHint] = useState("");
  /** Free UN Web TV / UNTV selection — never gated by Stripe */
  const [unTvChannelId, setUnTvChannelId] = useState<string | null>(null);
  const [unTvPlaying, setUnTvPlaying] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);
  const chatListRef = useRef<HTMLDivElement>(null);
  const stickToTopRef = useRef(true);

  const activeUnTv = useMemo(
    () => UN_TV_CHANNELS.find((c) => c.id === unTvChannelId) ?? null,
    [unTvChannelId],
  );
  const unTvEmbed = useMemo(
    () => (activeUnTv && unTvPlaying ? unTvEmbedSrc(activeUnTv) : null),
    [activeUnTv, unTvPlaying],
  );

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

  useEffect(() => {
    // Keep newest chat visible (list is newest-first)
    const el = chatListRef.current;
    if (el) el.scrollTop = 0;
  }, [chatMessages[0]?.id, open]);

  const submitChat = useCallback(() => {
    if (!onSendChat || isLocked) return;
    const ok = onSendChat(chatDraft);
    if (ok) {
      setChatDraft("");
      setChatSendHint("");
    } else {
      setChatSendHint(
        !isLinkUp
          ? "Connect to send support chat"
          : isLocked
            ? "Unlock Live Feed for web support chat"
            : "Could not send — try again",
      );
      window.setTimeout(() => setChatSendHint(""), 2000);
    }
  }, [onSendChat, chatDraft, isLinkUp, isLocked]);

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

  // Locked = billing gate. Offline = public WS link. Never conflate them.
  const launcherMeta = isLocked
    ? access === "login_required"
      ? "locked · sign in"
      : "locked · Stripe $20"
    : isLinkUp
      ? `${counter} online`
      : isLinkConnecting
        ? "connecting…"
        : "link down · reconnect";

  const launcherTitle = isLocked
    ? access === "login_required"
      ? "Live Feed is locked — sign in, then buy Stripe access. Globe socket is separate."
      : "Live Feed is locked until Stripe ($20). Globe markers still work over the free socket."
    : isLinkUp
      ? "Live visitor feed (unlocked)"
      : isLinkConnecting
        ? "Connecting public globe socket…"
        : "Globe socket disconnected — reconnect to resume feed events";

  return (
    <div
      className={`activity-floating ${showLauncher ? "" : "activity-floating-app"} ${
        open ? "activity-floating-open" : ""
      }`}
    >
      {showLauncher ? (
        <button
          type="button"
          className={`activity-launcher ${open ? "activity-launcher-open" : ""} ${
            isLocked
              ? "activity-launcher-locked"
              : !isLinkUp
                ? "activity-launcher-offline"
                : ""
          }`}
          onClick={onToggle}
          aria-controls="live-feed-menu"
          aria-expanded={open}
          title={launcherTitle}
        >
          <span
            className={`pulse-dot ${
              isLocked
                ? "pulse-dot-locked"
                : !isLinkUp
                  ? isLinkConnecting
                    ? "pulse-dot-connecting"
                    : "pulse-dot-offline"
                  : ""
            } ${isPaused && !isLocked && isLinkUp ? "pulse-dot-paused" : ""}`}
          />
          <span className="launcher-copy">
            <span className="launcher-label">Live Feed</span>
            <span className="launcher-meta">
              {launcherMeta}
              {!isLocked && isPaused && isLinkUp ? " · paused" : ""}
              {!isLocked && isLinkUp && leaveCount > 0
                ? ` · ${leaveCount} left`
                : ""}
            </span>
          </span>
          <span className="launcher-action">{open ? "Hide" : "Open"}</span>
        </button>
      ) : null}

      {open && (
        <section
          id="live-feed-menu"
          className={`activity-menu ${isCompact ? "activity-menu-compact" : ""} ${
            isLocked ? "activity-menu-locked" : ""
          } ${showLauncher ? "" : "activity-menu-app"}`}
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
                    ? "Feed content locked — sign in, then Stripe ($20)"
                    : "Feed content locked — Stripe checkout required"
                  : !isLinkUp
                    ? isLinkConnecting
                      ? "Globe link connecting… feed events wait for socket"
                      : "Globe link down — reconnect to receive feed events"
                    : isPaused
                      ? "Joins paused — leaves still recorded"
                      : "Live visitor signals (unlocked)"}
              </p>
            </div>
            <div className="activity-header-actions">
              {!isLocked && isLinkUp && (
                <div className="activity-count" title="Visitors currently online">
                  <span className="pulse-dot" />
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

          <div
            className="activity-status-row"
            role="status"
            aria-label="Connection and access status"
          >
            <span
              className={`activity-status-chip ${
                isLinkUp
                  ? "chip-ok"
                  : isLinkConnecting
                    ? "chip-warn"
                    : "chip-bad"
              }`}
            >
              Link:{" "}
              {isLinkUp
                ? "connected"
                : isLinkConnecting
                  ? "connecting"
                  : "offline"}
            </span>
            <span
              className={`activity-status-chip ${
                isLocked ? "chip-locked" : "chip-ok"
              }`}
            >
              Feed:{" "}
              {isLocked
                ? access === "login_required"
                  ? "locked (sign in)"
                  : "locked (Stripe)"
                : "unlocked"}
            </span>
            {!isLinkUp && onReconnectSocket && (
              <button
                type="button"
                className="activity-reconnect-btn"
                onClick={onReconnectSocket}
              >
                Reconnect
              </button>
            )}
          </div>

          {/* Free UN Web TV / UNTV — always available, not behind Stripe */}
          <div className="un-tv-panel" aria-label="UN Web TV and UNTV">
            <div className="un-tv-head">
              <strong>UN Web TV · UNTV</strong>
              <span className="un-tv-free-badge">Free</span>
            </div>
            <p className="un-tv-blurb">
              Official United Nations webcasts from{" "}
              <a
                href="https://webtv.un.org/en"
                target="_blank"
                rel="noopener noreferrer"
              >
                webtv.un.org
              </a>{" "}
              and UNTV. Select a channel to embed — free for everyone.
            </p>
            <div
              className="un-tv-channels"
              role="tablist"
              aria-label="UN TV channels"
            >
              {UN_TV_CHANNELS.map((ch) => {
                const selected = unTvChannelId === ch.id;
                return (
                  <button
                    key={ch.id}
                    type="button"
                    role="tab"
                    aria-selected={selected}
                    className={`un-tv-chip ${selected ? "active" : ""}`}
                    title={ch.blurb}
                    onClick={() => {
                      if (ch.kind === "link") {
                        // External browse only — no iframe
                        setUnTvChannelId(ch.id);
                        setUnTvPlaying(false);
                        window.open(
                          ch.pageUrl,
                          "_blank",
                          "noopener,noreferrer",
                        );
                        return;
                      }
                      if (selected && unTvPlaying) {
                        setUnTvPlaying(false);
                        return;
                      }
                      setUnTvChannelId(ch.id);
                      setUnTvPlaying(true);
                    }}
                  >
                    {ch.label}
                  </button>
                );
              })}
            </div>
            {activeUnTv && unTvPlaying && unTvEmbed ? (
              <div className="un-tv-player-wrap">
                <iframe
                  key={activeUnTv.id}
                  className="un-tv-player"
                  title={`${activeUnTv.label} player`}
                  src={unTvEmbed}
                  allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; fullscreen"
                  allowFullScreen
                  loading="lazy"
                  referrerPolicy="strict-origin-when-cross-origin"
                />
                <div className="un-tv-player-actions">
                  <button
                    type="button"
                    className="un-tv-stop"
                    onClick={() => setUnTvPlaying(false)}
                  >
                    Stop embed
                  </button>
                  <a
                    href={activeUnTv.pageUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="un-tv-open-link"
                  >
                    Open on UN site
                  </a>
                </div>
              </div>
            ) : activeUnTv && activeUnTv.kind === "link" ? (
              <p className="un-tv-hint">
                Opened {activeUnTv.label} in a new tab.
              </p>
            ) : (
              <p className="un-tv-hint">
                Tap <strong>UNTV 24/7</strong> or <strong>UN Web TV 24h</strong>{" "}
                to watch here. Schedule opens webtv.un.org.
              </p>
            )}
          </div>

          {isLocked ? (
            <div className="activity-lock-panel" role="status">
              <div className="activity-lock-badge">
                {access === "login_required" ? "Sign in required" : "Stripe required"}
              </div>
              <p className="activity-lock-copy">
                Live Feed (joins/leaves with city/org) and web support chat need
                Stripe access ($20) — same unlock as Transit
                {isLinkUp
                  ? " (globe link connected)."
                  : isLinkConnecting
                    ? " (globe link still connecting)."
                    : " (globe link offline — use Reconnect)."}
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
                Globe markers stay free. Paid feed and support chat are
                server-gated after payment.
              </p>
            </div>
          ) : (
            <>
              {/* Paid web-support chat — only unlocked Live Feed sessions */}
              <div className="live-chat" aria-label="Web support chat">
                <div className="live-chat-head">
                  <strong>Web support</strong>
                  <span>Paid · ephemeral · not stored</span>
                </div>
                <div
                  className="live-chat-list"
                  ref={chatListRef}
                  role="log"
                  aria-live="polite"
                >
                  {chatMessages.length === 0 ? (
                    <div className="live-chat-empty">
                      {isLinkUp
                        ? "No support messages yet. Ask for help — messages vanish on refresh."
                        : "Connect the globe link to use support chat."}
                    </div>
                  ) : (
                    chatMessages.map((m) => (
                      <div
                        key={m.id}
                        className={`live-chat-row ${m.isSelf ? "live-chat-self" : ""}`}
                      >
                        {/* Text only — never dangerouslySetInnerHTML */}
                        <span className="live-chat-name">
                          {sanitizeDisplayText(m.displayName, 32)}
                          {m.isSelf ? " (you)" : ""}
                        </span>
                        <span className="live-chat-text">
                          {sanitizeDisplayText(m.text, 200)}
                        </span>
                        <time
                          className="live-chat-time"
                          dateTime={new Date(m.ts).toISOString()}
                          title={new Date(m.ts).toLocaleString()}
                        >
                          {formatRelativeTime(m.ts, now)}
                        </time>
                      </div>
                    ))
                  )}
                </div>
                <form
                  className="live-chat-compose"
                  onSubmit={(e) => {
                    e.preventDefault();
                    submitChat();
                  }}
                >
                  <input
                    type="text"
                    value={chatDraft}
                    maxLength={200}
                    placeholder={
                      isLinkUp
                        ? "Message web support…"
                        : "Waiting for link…"
                    }
                    disabled={!isLinkUp || !onSendChat}
                    onChange={(e) => {
                      // Cap draft early; full sanitize runs on send + server
                      setChatDraft(e.target.value.slice(0, 200));
                    }}
                    aria-label="Web support chat message"
                    autoComplete="off"
                    autoCorrect="off"
                    autoCapitalize="off"
                    spellCheck={false}
                    inputMode="text"
                  />
                  <button
                    type="submit"
                    disabled={!isLinkUp || !chatDraft.trim()}
                  >
                    Send
                  </button>
                </form>
                {chatSendHint ? (
                  <p className="live-chat-hint">{chatSendHint}</p>
                ) : (
                  <p className="live-chat-hint">
                    Support channel for paid Live Feed — relay only, not saved.
                  </p>
                )}
              </div>

              <div className="activity-summary" aria-label="Feed summary">
                <div className="activity-stat">
                  <span>Online</span>
                  <strong>{isLinkUp ? counter : "—"}</strong>
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
                {!isLinkUp && (
                  <div className="activity-banner activity-banner-warn">
                    {isLinkConnecting
                      ? "Globe link connecting… feed events pause until open."
                      : "Globe link offline — feed events pause until reconnect."}
                    {onReconnectSocket && !isLinkConnecting && (
                      <>
                        {" "}
                        <button
                          type="button"
                          className="activity-banner-action"
                          onClick={onReconnectSocket}
                        >
                          Reconnect now
                        </button>
                      </>
                    )}
                  </div>
                )}
                {isPaused && isLinkUp && (
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
