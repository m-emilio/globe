import "./styles.css";

import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import { Cobe } from "./CobeGlobe";

// The type of messages we'll be receiving from the server
import type { OutgoingMessage } from "../shared";

function App() {
  const [showAbout, setShowAbout] = useState(false);

  return (
    <div className="App">
      <Cobe />
      
      {/* Menu Buttons */}
      <div className="menu-buttons">
        <button 
          className="menu-btn" 
          onClick={() => setShowAbout(true)}
          title="About & Credits"
        >
          ℹ️
        </button>
        <button 
          className="menu-btn" 
          onClick={() => window.location.href = "https://cvefeed.io/dashboard/"}
          title="CVE Feed Dashboard"
        >
          📊
        </button>
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
    </div>
  );
}

// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
createRoot(document.getElementById("root")!).render(<App />);
