import React, { lazy } from "react";

export const NearbyMap = lazy(() =>
  import("./NearbyMap").then((m) => ({ default: m.NearbyMap })),
);
export const TransitPanelContent = lazy(() =>
  import("./TransitPanelContent").then((m) => ({
    default: m.TransitPanelContent,
  })),
);
