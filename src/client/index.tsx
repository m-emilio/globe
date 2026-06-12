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

function App() {
  const [showAbout, setShowAbout] = useState(false);
  const [showMenu, setShowMenu] = useState(false);
  const [showActivityMenu, setShowActivityMenu] = useState(true);
  const [activityFilter, setActivityFilter] = useState<ActivityFilter>("all");
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

  useEffect(() => {
    isFeedPausedRef.current = isFeedPaused;
  }, [isFeedPaused]);

  const addActivityEvent = (event: ActivityEvent) => {
    if (isFeedPausedRef.current) {
      return;
    }

    setActivityFeed((prev) => [event, ...prev.slice(0, 49)]);
  };

  const clearActivityFeed = () => {
    const activeEvents = Array.from(activeVisitors.current.values()).sort(
      (a, b) => b.timestamp - a.timestamp,
    );

    setActivityFilter("all");
    setActivityFeed(activeEvents);
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

  return (
    <div className="App">
      <nav className="nav-bar">
        <div className="nav-left">
          <h1 className="nav-title">
            GLOBE <span className="nav-subtitle">// OPS</span>
          </h1>
        </div>

        <div className="nav-center">
          <button className="nav-btn" onClick={() => setShowAbout(true)}>
            ABOUT
          </button>
          <button
            className="nav-btn"
            onClick={() => {
              window.location.href = "https://cvefeed.io/dashboard/";
            }}
          >
            CVE FEED
          </button>
        </div>

        <div className="nav-right">
          <button className="nav-menu-btn" onClick={() => setShowMenu(!showMenu)}>
            <span>MENU</span>
            <span className="menu-icon">v</span>
          </button>
        </div>
      </nav>

      <div className="main-content">
        <Cobe counter={counter} positions={positions.current} />
      </div>

      <div className="activity-floating">
        <button
          type="button"
          className="activity-launcher"
          onClick={() => setShowActivityMenu((open) => !open)}
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
                  className={activityFilter === filter ? "active" : ""}
                  onClick={() => setActivityFilter(filter)}
                  aria-pressed={activityFilter === filter}
                >
                  {filterLabels[filter]}
                </button>
              ))}
            </div>

            <div className="activity-actions">
              <button type="button" onClick={() => setIsFeedPaused((paused) => !paused)}>
                {isFeedPaused ? "Resume" : "Pause"}
              </button>
              <button type="button" onClick={() => setIsCompactFeed((compact) => !compact)}>
                {isCompactFeed ? "Details" : "Compact"}
              </button>
              <button
                type="button"
                onClick={clearActivityFeed}
                disabled={activityFeed.length === 0 && activeVisitors.current.size === 0}
              >
                Clear
              </button>
            </div>

            <div className="activity-list">
              {visibleActivityFeed.length === 0 ? (
                <div className="activity-empty">
                  {activityFeed.length === 0 ? "No activity yet" : "No matching events"}
                </div>
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
            <button className="modal-close" onClick={() => setShowAbout(false)}>
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
