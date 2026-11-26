import React, { useEffect } from "react";
import { LIVE_FEED_PATH } from "./ActivityFeed";
import type { GlobeApi } from "./useGlobeApp";
import { AppChunk0 } from "./AppChunk0";
import { AppChunk1 } from "./AppChunk1";
import { AppChunk2 } from "./AppChunk2";
export function AppView({ b }: { b: GlobeApi }) {
  const standaloneFeed = window.location.pathname.replace(/\/+$/, "") === LIVE_FEED_PATH;
  useEffect(() => {
    if (!standaloneFeed) return;
    const title = document.title;
    document.title = "Live Feed · FederalKey Globe";
    return () => { document.title = title; };
  }, [standaloneFeed]);

  return (
    <div className="App">
      <AppChunk0 b={b} standaloneFeed={standaloneFeed} />
      {!standaloneFeed && <>
        <AppChunk1 b={b} />
        <AppChunk2 b={b} />
      </>}
    </div>
  );
}
