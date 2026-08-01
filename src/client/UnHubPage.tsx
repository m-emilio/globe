import React from "react";
import type {
  TradePulseLayer,
  TradePulsePreview,
  UnGlobalPreview,
  UnodcHotspotsPreview,
  UnodcThemeId,
} from "../shared";

export type UnHubTradePulseStatus = "idle" | "loading" | "ready" | "error";
export type UnHubUnodcStatus = "idle" | "loading" | "ready" | "error";
export type UnHubUnGlobalStatus = "idle" | "loading" | "ready" | "error";

export type UnHubUnGlobalSection =
  | "offices"
  | "activeMissions"
  | "pastMissions"
  | "memberStates"
  | "affiliates"
  | "embassies";

export type UnHubProps = {
  onClose: () => void;
  onViewGlobe: () => void;

  // Trade Pulse
  tradePulseOn: boolean;
  tradePulseStatus: UnHubTradePulseStatus;
  tradePulseError: string;
  tradePulsePreview: TradePulsePreview | null;
  tradePulsePeriod: string;
  tradePulseYearOptions: string[];
  tradePulseLayers: Record<TradePulseLayer, boolean>;
  tradePulseLayerLabels: Record<TradePulseLayer, string>;
  tradePulseLayerShortLabels: Record<TradePulseLayer, string>;
  tradePulseLayerColors: Record<TradePulseLayer, string>;
  tradePulseLayersList: TradePulseLayer[];
  onToggleTradePulse: () => void;
  onSelectTradePulsePeriod: (period: string) => void;
  onToggleTradePulseLayer: (layer: TradePulseLayer) => void;
  onToggleAllTradePulseLayers: () => void;
  onRefreshTradePulse: () => void;

  // UNODC
  unodcOn: boolean;
  unodcStatus: UnHubUnodcStatus;
  unodcError: string;
  unodcPreview: UnodcHotspotsPreview | null;
  unodcThemes: Record<UnodcThemeId, boolean>;
  unodcThemeIds: UnodcThemeId[];
  unodcThemeColors: Record<UnodcThemeId, string>;
  onToggleUnodc: () => void;
  onToggleUnodcTheme: (id: UnodcThemeId) => void;
  onUnodcFocusMode: (mode: "focus" | "all-live" | "none") => void;
  onRefreshUnodc: () => void;

  // UN Global
  unGlobalOn: boolean;
  unGlobalStatus: UnHubUnGlobalStatus;
  unGlobalError: string;
  unGlobalPreview: UnGlobalPreview | null;
  unGlobalSections: Record<UnHubUnGlobalSection, boolean>;
  unGlobalSectionLabels: Record<UnHubUnGlobalSection, string>;
  unGlobalSectionIds: UnHubUnGlobalSection[];
  onToggleUnGlobal: () => void;
  onToggleUnGlobalSection: (section: UnHubUnGlobalSection) => void;
  onToggleAllUnGlobalSections: () => void;
  onRefreshUnGlobal: () => void;
};

function statusLabel(status: string, error: string) {
  if (status === "loading") return "Loading…";
  if (status === "error") return error || "Unavailable";
  if (status === "ready") return "Ready";
  return "Off";
}

export function UnHubPage(props: UnHubProps) {
  const {
    onClose,
    onViewGlobe,
    tradePulseOn,
    tradePulseStatus,
    tradePulseError,
    tradePulsePreview,
    tradePulsePeriod,
    tradePulseYearOptions,
    tradePulseLayers,
    tradePulseLayerLabels,
    tradePulseLayerShortLabels,
    tradePulseLayerColors,
    tradePulseLayersList,
    onToggleTradePulse,
    onSelectTradePulsePeriod,
    onToggleTradePulseLayer,
    onToggleAllTradePulseLayers,
    onRefreshTradePulse,
    unodcOn,
    unodcStatus,
    unodcError,
    unodcPreview,
    unodcThemes,
    unodcThemeIds,
    unodcThemeColors,
    onToggleUnodc,
    onToggleUnodcTheme,
    onUnodcFocusMode,
    onRefreshUnodc,
    unGlobalOn,
    unGlobalStatus,
    unGlobalError,
    unGlobalPreview,
    unGlobalSections,
    unGlobalSectionLabels,
    unGlobalSectionIds,
    onToggleUnGlobal,
    onToggleUnGlobalSection,
    onToggleAllUnGlobalSections,
    onRefreshUnGlobal,
  } = props;

  const tradeLayersOn = tradePulseLayersList.filter((l) => tradePulseLayers[l]).length;
  const unodcThemesOn = unodcThemeIds.filter((id) => unodcThemes[id]).length;
  const unGlobalSectionsOn = unGlobalSectionIds.filter(
    (id) => unGlobalSections[id],
  ).length;

  const activeCount =
    (tradePulseOn ? 1 : 0) + (unodcOn ? 1 : 0) + (unGlobalOn ? 1 : 0);

  return (
    <div className="un-hub" role="dialog" aria-modal="true" aria-label="UN data hub">
      <header className="un-hub-header">
        <div className="un-hub-header-main">
          <button
            type="button"
            className="un-hub-back"
            onClick={onClose}
            aria-label="Back to globe"
          >
            ←
          </button>
          <div>
            <h1>
              <span className="un-hub-emoji" aria-hidden="true">
                🇺🇳
              </span>{" "}
              UN Data Hub
            </h1>
            <p>
              Trade Pulse · UNODC · UN Global · {activeCount}/3 layers on globe
            </p>
          </div>
        </div>
        <button type="button" className="un-hub-globe-btn" onClick={onViewGlobe}>
          View globe
        </button>
      </header>

      <div className="un-hub-scroll">
        <p className="un-hub-intro">
          Toggle layers for the main globe. Designed for phones — scroll, flip
          switches, then return to the map.
        </p>

        {/* —— Trade Pulse —— */}
        <section className="un-hub-card" aria-labelledby="un-hub-trade-title">
          <div className="un-hub-card-head">
            <div>
              <h2 id="un-hub-trade-title">Trade Pulse</h2>
              <span className="un-hub-status">
                {statusLabel(tradePulseStatus, tradePulseError)}
                {tradePulsePreview
                  ? ` · ${tradePulsePreview.routes?.length ?? 0} routes`
                  : ""}
              </span>
            </div>
            <button
              type="button"
              className={`un-hub-master ${tradePulseOn ? "on" : ""}`}
              aria-pressed={tradePulseOn}
              onClick={onToggleTradePulse}
            >
              {tradePulseOn ? "On globe" : "Off"}
            </button>
          </div>
          <p className="un-hub-card-desc">
            Dependency radar arcs from UN Comtrade Free API (preview sample).
          </p>

          {tradePulseOn && (
            <div className="un-hub-card-body">
              <div className="un-hub-row-label">Year</div>
              <div className="un-hub-chip-row" role="group" aria-label="Trade year">
                {tradePulseYearOptions.map((year) => (
                  <button
                    key={year}
                    type="button"
                    className={`un-hub-chip ${tradePulsePeriod === year ? "active" : ""}`}
                    aria-pressed={tradePulsePeriod === year}
                    disabled={tradePulseStatus === "loading"}
                    onClick={() => onSelectTradePulsePeriod(year)}
                  >
                    {year}
                  </button>
                ))}
              </div>

              <div className="un-hub-row-label">
                Layers ({tradeLayersOn}/{tradePulseLayersList.length})
              </div>
              <button
                type="button"
                className="un-hub-linkish"
                onClick={onToggleAllTradePulseLayers}
              >
                Toggle all layers
              </button>
              <div className="un-hub-toggle-list" role="group" aria-label="Trade Pulse layers">
                {tradePulseLayersList.map((layer) => (
                  <button
                    key={layer}
                    type="button"
                    className={`un-hub-toggle ${tradePulseLayers[layer] ? "active" : ""}`}
                    aria-pressed={tradePulseLayers[layer]}
                    onClick={() => onToggleTradePulseLayer(layer)}
                  >
                    <i
                      className="un-hub-swatch"
                      style={{ background: tradePulseLayerColors[layer] }}
                    />
                    <span>
                      <strong>{tradePulseLayerShortLabels[layer]}</strong>
                      <small>{tradePulseLayerLabels[layer]}</small>
                    </span>
                    <em>{tradePulseLayers[layer] ? "On" : "Off"}</em>
                  </button>
                ))}
              </div>

              <button
                type="button"
                className="un-hub-secondary"
                onClick={onRefreshTradePulse}
                disabled={tradePulseStatus === "loading"}
              >
                Refresh Trade Pulse
              </button>
            </div>
          )}
        </section>

        {/* —— UNODC —— */}
        <section className="un-hub-card" aria-labelledby="un-hub-unodc-title">
          <div className="un-hub-card-head">
            <div>
              <h2 id="un-hub-unodc-title">UNODC Hotspots</h2>
              <span className="un-hub-status">
                {statusLabel(unodcStatus, unodcError)}
                {unodcPreview
                  ? ` · ${unodcThemesOn} themes · choropleth / heat`
                  : ""}
              </span>
            </div>
            <button
              type="button"
              className={`un-hub-master ${unodcOn ? "on" : ""}`}
              aria-pressed={unodcOn}
              onClick={onToggleUnodc}
            >
              {unodcOn ? "On globe" : "Off"}
            </button>
          </div>
          <p className="un-hub-card-desc">
            Country-level crime, drugs, justice, and trafficking themes on the
            globe.
          </p>

          {unodcOn && (
            <div className="un-hub-card-body">
              <div className="un-hub-chip-row" role="group" aria-label="Theme focus">
                <button
                  type="button"
                  className="un-hub-chip"
                  onClick={() => onUnodcFocusMode("focus")}
                >
                  Focus
                </button>
                <button
                  type="button"
                  className="un-hub-chip"
                  onClick={() => onUnodcFocusMode("all-live")}
                >
                  All live
                </button>
                <button
                  type="button"
                  className="un-hub-chip"
                  onClick={() => onUnodcFocusMode("none")}
                >
                  None
                </button>
              </div>

              <div className="un-hub-row-label">
                Themes ({unodcThemesOn}/{unodcThemeIds.length})
              </div>
              <div className="un-hub-toggle-list" role="group" aria-label="UNODC themes">
                {unodcThemeIds.map((themeId) => {
                  const theme = unodcPreview?.themes.find((t) => t.id === themeId);
                  return (
                    <button
                      key={themeId}
                      type="button"
                      className={`un-hub-toggle ${unodcThemes[themeId] ? "active" : ""}`}
                      aria-pressed={unodcThemes[themeId]}
                      onClick={() => onToggleUnodcTheme(themeId)}
                    >
                      <i
                        className="un-hub-swatch"
                        style={{ background: unodcThemeColors[themeId] }}
                      />
                      <span>
                        <strong>{theme?.label || themeId}</strong>
                        <small>
                          {theme
                            ? theme.dataMode === "live"
                              ? `${theme.hotspotCount} hotspots`
                              : "Portal tables"
                            : "Load for data"}
                        </small>
                      </span>
                      <em>{unodcThemes[themeId] ? "On" : "Off"}</em>
                    </button>
                  );
                })}
              </div>

              <button
                type="button"
                className="un-hub-secondary"
                onClick={onRefreshUnodc}
                disabled={unodcStatus === "loading"}
              >
                Refresh UNODC
              </button>
            </div>
          )}
        </section>

        {/* —— UN Global —— */}
        <section className="un-hub-card" aria-labelledby="un-hub-global-title">
          <div className="un-hub-card-head">
            <div>
              <h2 id="un-hub-global-title">UN Global</h2>
              <span className="un-hub-status">
                {statusLabel(unGlobalStatus, unGlobalError)}
                {unGlobalPreview
                  ? ` · ${unGlobalSectionsOn}/6 sections`
                  : ""}
              </span>
            </div>
            <button
              type="button"
              className={`un-hub-master ${unGlobalOn ? "on" : ""}`}
              aria-pressed={unGlobalOn}
              onClick={onToggleUnGlobal}
            >
              {unGlobalOn ? "On globe" : "Off"}
            </button>
          </div>
          <p className="un-hub-card-desc">
            HQ offices, missions, member states, affiliates, and embassies as
            markers.
          </p>

          {unGlobalOn && (
            <div className="un-hub-card-body">
              <button
                type="button"
                className="un-hub-linkish"
                onClick={onToggleAllUnGlobalSections}
              >
                Toggle all sections
              </button>
              <div
                className="un-hub-toggle-list"
                role="group"
                aria-label="UN Global sections"
              >
                {unGlobalSectionIds.map((section) => (
                  <button
                    key={section}
                    type="button"
                    className={`un-hub-toggle un-hub-toggle-plain ${
                      unGlobalSections[section] ? "active" : ""
                    }`}
                    aria-pressed={unGlobalSections[section]}
                    onClick={() => onToggleUnGlobalSection(section)}
                  >
                    <span>
                      <strong>{unGlobalSectionLabels[section]}</strong>
                    </span>
                    <em>{unGlobalSections[section] ? "On" : "Off"}</em>
                  </button>
                ))}
              </div>

              <button
                type="button"
                className="un-hub-secondary"
                onClick={onRefreshUnGlobal}
                disabled={unGlobalStatus === "loading"}
              >
                Refresh UN Global
              </button>
            </div>
          )}
        </section>

        <footer className="un-hub-footer">
          <button type="button" className="un-hub-globe-btn wide" onClick={onViewGlobe}>
            Apply &amp; view globe
          </button>
          <p>
            Sources: UN Comtrade, UNODC data portals, UN system locations. Layers
            are previews for situational awareness.
          </p>
        </footer>
      </div>
    </div>
  );
}
