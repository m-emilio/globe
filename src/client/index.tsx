import "./styles.css";

import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import { Cobe } from "./CobeGlobe";

// The type of messages we'll be receiving from the server
import type { OutgoingMessage } from "../shared";

function App() {
  const [showAbout, setShowAbout] = useState(false);
  const [showMenu, setShowMenu] = useState(false);

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
        <Cobe />
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
