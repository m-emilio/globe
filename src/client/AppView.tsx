import React from "react";
import type { GlobeApi } from "./useGlobeApp";
import { AppChunk0 } from "./AppChunk0";
import { AppChunk1 } from "./AppChunk1";
import { AppChunk2 } from "./AppChunk2";
export function AppView({ b }: { b: GlobeApi }) {
  return (
    <div className="App">
      <AppChunk0 b={b} />
      <AppChunk1 b={b} />
      <AppChunk2 b={b} />
    </div>
  );
}
