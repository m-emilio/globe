import "./styles.css";

import React from "react";
import { createRoot } from "react-dom/client";
import { Cobe } from "./CobeGlobe";

// The type of messages we'll be receiving from the server
import type { OutgoingMessage } from "../shared";
import type { LegacyRef } from "react";

function App() {
  return (
    <div className="App">
      <h1><a href="https://104041.webmail.dynadot.com/user/signin.html">WEBMAIL</a></h1>
      <Cobe />
      <p>
        Powered by <a href="https://cobe.vercel.app/">Cobe</a>,{" "}
        <a href="https://www.npmjs.com/package/phenomenon">Phenomenon</a>,{" "}
        <a href="https://npmjs.com/package/partyserver/">PartyServer</a> and{" "}
        <a href="https://federalkey.org">FederalKey</a>
      </p>
    </div>
  );
}

// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
createRoot(document.getElementById("root")!).render(<App />);
