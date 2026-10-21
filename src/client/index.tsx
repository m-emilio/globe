import "./styles.css";
import React from "react";
import { createRoot } from "react-dom/client";
import { AppView } from "./AppView";
import { useGlobeApp } from "./useGlobeApp";

function App() {
  const b = useGlobeApp();
  return <AppView b={b} />;
}

createRoot(document.getElementById("root")!).render(<App />);
