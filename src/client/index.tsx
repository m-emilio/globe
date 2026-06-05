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

function App() {
  const [showAbout, setShowAbout] = useState(false);
  const [showMenu, setShowMenu] = useState(false);
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
        setCounter((c) => c + 1);
        
        // Add to activity feed
        const isYou = message.position.id === socket.id;
        setActivityFeed((prev) => [
          {
            id: message.position.id,
            type: "connect",
            timestamp: Date.now(),
            userName: isYou ? "You" : `User ${message.position.id.slice(0, 8)}`,
            ip: message.position.ip,
            country: message.position.country,
            city: message.position.city,
            org: message.position.org,
          },
          ...prev.slice(0, 49), // Keep last 50 events
        ]);
      } else {
        const removedId = message.id;
        positions.current.delete(removedId);
        setCounter((c) => c - 1);
        
        // Add to activity feed
        setActivityFeed((prev) => [
          {
            id: removedId,
            type: "disconnect",
            timestamp: Date.now(),
            userName: `User ${removedId.slice(0, 8)}`,
          },
          ...prev.slice(0, 49),
        ]);
      }
    },
  });

  return (
    <div className="App">
      {/* Top Navigation Bar */}
      <nav className="nav-bar">
        <div className="nav-left">
          <h1 className="nav-title">GLOBE <span className="nav-subtitle">// OPS</span></h1>
        </div>
        
        <div className="nav-center">
          <button className="nav-btn" onClick={() => setShowAbout(true)}>
            ABOUT
          </button>
          <button className="nav-btn" onClick={() => window.location.href = "https://cvefeed.io/dashboard/"}>
            CVE FEED
          </button>
        </div>
        
        <div className="nav-right">
          <button className="nav-menu-btn" onClick={() => setShowMenu(!showMenu)}>
            <span>MENU</span>
            <span className="menu-icon">▼</span>
          </button>
        </div>
      </nav>

      {/* Main Content */}
      <div className="main-content">
        <Cobe counter={counter} positions={positions.current} />
      </div>

      {/* Activity Feed Panel */}
      <div className="activity-feed">
        <div className="activity-header">
          <h3>LIVE FEED</h3>
          <div className="activity-count">
            <span className="pulse-dot"></span>
            <span>{counter}</span>
          </div>
        </div>
        <div className="activity-list">
          {activityFeed.length === 0 ? (
            <div className="activity-empty">No activity</div>
          ) : (
            activityFeed.map((event) => (
              <div key={`${event.id}-${event.timestamp}`} className={`activity-item activity-${event.type}`}>
                <span className="activity-icon">
                  {event.type === "connect" ? "⬆" : "⬇"}
                </span>
                <div className="activity-details">
                  <span className="activity-user">{event.userName}</span>
                  <span className="activity-action">
                    {event.type === "connect" ? "connected" : "disconnected"}
                  </span>
                  {event.type === "connect" && (event.city || event.country || event.ip || event.org) && (
                    <div className="activity-location">
                      {event.city && event.country && (
                        <span className="location-text">📍 {event.city}, {event.country}</span>
                      )}
                      {event.ip && (
                        <span className="location-text">🌐 {event.ip}</span>
                      )}
                      {event.org && !event.ip && (
                        <span className="location-text">🏢 {event.org}</span>
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
      </div>
      
      {/* About Modal */}
      {showAbout && (
        <div className="modal-overlay" onClick={() => setShowAbout(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <button className="modal-close" onClick={() => setShowAbout(false)}>✕</button>
            <h2>About & Credits</h2>
            <p>Interactive globe powered by:</p>
            <ul className="credits-list">
              <li><a href="https://cobe.vercel.app/" target="_blank" rel="noopener noreferrer">Cobe</a></li>
              <li><a href="https://www.npmjs.com/package/phenomenon" target="_blank" rel="noopener noreferrer">Phenomenon</a></li>
              <li><a href="https://npmjs.com/package/partyserver/" target="_blank" rel="noopener noreferrer">PartyServer</a></li>
              <li><a href="https://federalkey.org" target="_blank" rel="noopener noreferrer">FederalKey</a></li>
            </ul>
          </div>
        </div>
      )}
      
      {/* Menu Dropdown */}
      {showMenu && (
        <div className="menu-dropdown">
          <a href="#" className="menu-item">Dashboard</a>
          <a href="#" className="menu-item">Settings</a>
          <a href="#" className="menu-item">Help</a>
          <a href="#" className="menu-item">Support</a>
        </div>
      )}
    </div>
  );
}

// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
createRoot(document.getElementById("root")!).render(<App />);
