import React from "react";
import type { GlobeApi } from "./useGlobeApp";
import { Cobe } from "./CobeGlobe";
import { FloatingChrome } from "./FloatingChrome";
import { safeGlobeHref } from "./safeUrl";
import type { UnGlobalPreview } from "../shared";
import { formatFingerprint } from "./pgpAuth";
import { GEOCODE_MAX_QUERY, formatCoordPair, formatPreviewDate, formatPreviewNumber, sanitizeAddressQuery } from "./globeModel";
export function AppChunk2({ b }: { b: GlobeApi }) {
  const { applyLocationPreference, applyManualLocation, authBusy, authUser, checkoutBusy, closeContractsHub, closePkiHub, closeUnHub, contractsLayerOn, contractsPreview, counter, disableUnGlobalLayer, enabledUnGlobalSectionCount, globeChoroplethRegions, globeHeatZones, globeMarkerColor, globeOverlayMarkers, globeOverlayRoutes, isAdmin, isFeedPaused, isUnGlobalPanelMinimized, liveFeedAccess, loadLocalTransit, loadNearbyPaths, loadUnGlobalPreview, loadWeatherFeed, locationBusy, locationDraftAddress, locationDraftLabel, locationDraftLat, locationDraftLng, locationMessage, locationPref, logout, lookupAddressLocation, nearbyStatus, openAdminPanel, openContractsHub, openPkiHub, openUnHub, paymentRequired, pkiShowMap, positions, requestBrowserLocation, runRateLimitedButtonAction, setAuthMode, setIsUnGlobalPanelMinimized, setLocationDraftAddress, setLocationDraftLabel, setLocationDraftLat, setLocationDraftLng, setLocationMessage, setShowAbout, setShowActivityMenu, setShowAuthPanel, setShowMenu, showAbout, showActivityMenu, showContractsHub, showMenu, showNearbyPanel, showPkiHub, showPkiPanel, showTradePulsePanel, showTransitPanel, showUnGlobalPanel, showUnHub, showUnodcPanel, socketStatus, startTransitCheckout, transitStatus, unGlobalError, unGlobalPreview, unGlobalSections, unGlobalStatus, visibleUnMissionLocations, weatherFeed, weatherGlow, weatherStatus } = b;
  return (
    <>
{showUnGlobalPanel && !showUnHub && (
        <FloatingChrome
          className={`un-panel un-layer-panel ${
            isUnGlobalPanelMinimized ? "un-panel-minimized" : ""
          }`}
          role="dialog"
          aria-label="UN global location preview"
        >
          <div className="un-panel-header">
            <div>
              <h3>UN Global Layer</h3>
              <span>HQ, missions, states, affiliates</span>
            </div>
            <div className="un-panel-actions">
              <button
                type="button"
                className="un-minimize"
                onClick={() =>
                  runRateLimitedButtonAction("un-global-minimize", () =>
                    setIsUnGlobalPanelMinimized((minimized) => !minimized),
                  )
                }
                aria-label={
                  isUnGlobalPanelMinimized
                    ? "Restore UN global preview"
                    : "Minimize UN global preview"
                }
              >
                {isUnGlobalPanelMinimized ? "+" : "_"}
              </button>
              <button
                type="button"
                className="un-close"
                onClick={() =>
                  runRateLimitedButtonAction("un-global-close", disableUnGlobalLayer)
                }
                aria-label="Disable UN global layer"
              >
                x
              </button>
            </div>
          </div>

          {!isUnGlobalPanelMinimized && unGlobalStatus === "loading" && (
            <div className="un-loading">Loading UN global data...</div>
          )}

          {!isUnGlobalPanelMinimized && unGlobalStatus === "error" && (
            <div className="un-error">
              <span>{unGlobalError}</span>
              <button
                type="button"
                onClick={() =>
                  runRateLimitedButtonAction("un-global-retry", () => {
                    void loadUnGlobalPreview();
                  })
                }
              >
                Retry
              </button>
            </div>
          )}

          {!isUnGlobalPanelMinimized && unGlobalStatus === "ready" && unGlobalPreview && (
            <>
              <div className="un-status-row">
                <span>{unGlobalPreview.source}</span>
                {unGlobalPreview.stale && <strong>Fallback snapshot</strong>}
              </div>
              <div className="un-summary-grid">
                <div className="un-metric">
                  <span>HQ</span>
                  <strong>{formatPreviewNumber(unGlobalPreview.officesTotal)}</strong>
                </div>
                <div className="un-metric">
                  <span>Missions</span>
                  <strong>{formatPreviewNumber(unGlobalPreview.missionCoordinateTotal)}</strong>
                </div>
                <div className="un-metric">
                  <span>Members</span>
                  <strong>{formatPreviewNumber(unGlobalPreview.memberStatesTotal)}</strong>
                </div>
                <div className="un-metric">
                  <span>Affiliates</span>
                  <strong>{formatPreviewNumber(unGlobalPreview.affiliatesTotal)}</strong>
                </div>
                <div className="un-metric">
                  <span>Embassies</span>
                  <strong>{formatPreviewNumber(unGlobalPreview.embassiesTotal)}</strong>
                </div>
              </div>

              <div className="un-update-row">
                <span>{unGlobalPreview.queryLabel}</span>
                <strong>
                  Latest{" "}
                  {unGlobalPreview.latestMissionUpdate
                    ? formatPreviewDate(unGlobalPreview.latestMissionUpdate)
                    : "n/a"}
                </strong>
              </div>

              <div className="un-goal-list" aria-label="UN global location data preview">
                {enabledUnGlobalSectionCount === 0 && (
                  <div className="un-empty-state">
                    Enable a UN global layer section from the menu.
                  </div>
                )}

                {unGlobalSections.offices && (
                  <section className="un-data-section">
                    <div className="un-section-heading">
                      <span>UN HQ and main offices</span>
                      <strong>{unGlobalPreview.offices.length} markers</strong>
                    </div>
                    {unGlobalPreview.offices.map((office) => (
                      <article className="un-compact-row" key={office.id}>
                        <div className="un-compact-heading">
                          <span>{office.name}</span>
                          <strong>{office.category}</strong>
                        </div>
                        <p>
                          {office.city}, {office.country} · {office.lat.toFixed(2)},{" "}
                          {office.lng.toFixed(2)}
                        </p>
                      </article>
                    ))}
                  </section>
                )}

                {visibleUnMissionLocations.length > 0 && (
                  <section className="un-data-section">
                    <div className="un-section-heading">
                      <span>Mission HQ locations</span>
                      <strong>{visibleUnMissionLocations.length} shown</strong>
                    </div>
                    {visibleUnMissionLocations.map((mission) => (
                      <article className="un-goal-row" key={mission.id}>
                        <div className="un-goal-heading">
                          <span>{mission.acronym}</span>
                          <strong>{mission.active ? "Active" : "Historic"}</strong>
                        </div>
                        <p>
                          {mission.name} · {mission.location}
                        </p>
                        <div className="un-goal-meta">
                          <span>Lat {mission.lat.toFixed(2)}</span>
                          <span>Lng {mission.lng.toFixed(2)}</span>
                          <span>
                            Start{" "}
                            {mission.startDate
                              ? formatPreviewDate(mission.startDate)
                              : "n/a"}
                          </span>
                        </div>
                      </article>
                    ))}
                  </section>
                )}

                {unGlobalSections.memberStates && (
                  <section className="un-data-section">
                    <div className="un-section-heading">
                      <span>Member states</span>
                      <strong>{unGlobalPreview.memberStates.length} markers</strong>
                    </div>
                    <div className="un-chip-list">
                      {unGlobalPreview.memberStates.map((state) => (
                        <span className="un-chip" key={state.code}>
                          {state.name} <small>{state.code}</small>
                        </span>
                      ))}
                    </div>
                  </section>
                )}

                {unGlobalSections.affiliates && (
                  <section className="un-data-section">
                    <div className="un-section-heading">
                      <span>Non-member affiliates</span>
                      <strong>{unGlobalPreview.affiliates.length} markers</strong>
                    </div>
                    {unGlobalPreview.affiliates.map((affiliate) => (
                      <article className="un-compact-row" key={affiliate.code}>
                        <div className="un-compact-heading">
                          <span>{affiliate.name}</span>
                          <strong>{affiliate.category}</strong>
                        </div>
                        <p>
                          SDG/M49 area {affiliate.code} · {affiliate.lat.toFixed(2)},{" "}
                          {affiliate.lng.toFixed(2)}
                        </p>
                      </article>
                    ))}
                  </section>
                )}

                {unGlobalSections.embassies && (
                  <section className="un-data-section">
                    <div className="un-section-heading">
                      <span>Permanent missions / embassies</span>
                      <strong>{unGlobalPreview.embassies.length} markers</strong>
                    </div>
                    {unGlobalPreview.embassies.map((embassy) => (
                      <article className="un-compact-row" key={embassy.code}>
                        <div className="un-compact-heading">
                          <span>{embassy.name}</span>
                          <strong>Blue Book</strong>
                        </div>
                        <p>
                          UN diplomatic directory marker · {embassy.lat.toFixed(2)},{" "}
                          {embassy.lng.toFixed(2)}
                        </p>
                      </article>
                    ))}
                  </section>
                )}
              </div>

              <div className="un-footer">
                <span>Updated {formatPreviewDate(unGlobalPreview.updatedAt)}</span>
                <div className="un-footer-actions">
                  <a
                    href={safeGlobeHref(unGlobalPreview.sourceUrl)}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Source
                  </a>
                  <a
                    href={safeGlobeHref(unGlobalPreview.apiUrl)}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    API
                  </a>
                  <button
                    type="button"
                    onClick={() =>
                      runRateLimitedButtonAction("un-global-refresh", () => {
                        void loadUnGlobalPreview();
                      })
                    }
                  >
                    Refresh
                  </button>
                </div>
              </div>
            </>
          )}
        </FloatingChrome>
      )}<div className={`main-content ${showTradePulsePanel ? "trade-pulse-main" : ""}`}>
        <div className="globe-stage">
          <Cobe
            counter={counter}
            positions={positions.current}
            overlayMarkers={globeOverlayMarkers}
            overlayRoutes={globeOverlayRoutes}
            heatZones={globeHeatZones}
            choroplethRegions={globeChoroplethRegions}
            markerColor={globeMarkerColor}
            glowColor={weatherGlow.color}
            glowCssColor={weatherGlow.css}
          />
        </div>
      </div>{/* macOS-style dock — apps (MENU + globe controls stay in the top nav) */}<nav className="mac-dock" aria-label="App tools dock">
        <div className="mac-dock-shelf" aria-hidden="true" />
        <div className="mac-dock-inner">
          <button
            type="button"
            className={`mac-dock-item live-feed-dock-item ${
              showActivityMenu ? "mac-dock-item-open" : ""
            } ${
              liveFeedAccess === "ok" && socketStatus === "connected"
                ? "mac-dock-item-active"
                : liveFeedAccess !== "ok"
                  ? "live-feed-dock-locked"
                  : socketStatus !== "connected"
                    ? "live-feed-dock-offline"
                    : ""
            }`}
            onClick={() =>
              runRateLimitedButtonAction("activity-toggle", () =>
                setShowActivityMenu((open) => !open),
              )
            }
            aria-label="Live Feed app"
            title={
              liveFeedAccess === "ok"
                ? "Live Feed — visitor signals & web support"
                : liveFeedAccess === "login_required"
                  ? "Live Feed — sign in, then Stripe ($20)"
                  : "Live Feed — Stripe unlock required ($20)"
            }
            aria-pressed={showActivityMenu}
            aria-controls="live-feed-menu"
            aria-expanded={showActivityMenu}
          >
            <span className="mac-dock-icon" aria-hidden="true">
              <span
                className={`pulse-dot mac-dock-pulse ${
                  liveFeedAccess !== "ok"
                    ? "pulse-dot-locked"
                    : socketStatus === "connecting"
                      ? "pulse-dot-connecting"
                      : socketStatus !== "connected"
                        ? "pulse-dot-offline"
                        : isFeedPaused
                          ? "pulse-dot-paused"
                          : ""
                }`}
              />
              <svg viewBox="0 0 24 24">
                <path d="M4 6h16" />
                <path d="M4 12h10" />
                <path d="M4 18h13" />
                <circle cx="18.5" cy="12" r="2" />
                <circle cx="20" cy="18" r="1.5" />
              </svg>
            </span>
            <span className="mac-dock-label">Feed</span>
          </button>
          <span className="mac-dock-separator" aria-hidden="true" />
          <button
            type="button"
            className={`mac-dock-item pki-hub-icon-btn ${
              showPkiHub ? "pki-hub-icon-btn-open mac-dock-item-open" : ""
            } ${
              showPkiPanel && pkiShowMap
                ? "pki-hub-icon-btn-active mac-dock-item-active"
                : ""
            }`}
            onClick={() =>
              runRateLimitedButtonAction("pki-hub-open", () => {
                if (showPkiHub) {
                  closePkiHub();
                } else {
                  openPkiHub();
                }
              })
            }
            aria-label="PKI and CVE exposure hub"
            title="PKI / CVE hub"
            aria-pressed={showPkiHub}
          >
            <span className="mac-dock-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24">
                <rect x="6" y="11" width="12" height="10" rx="1.5" />
                <path d="M8.5 11V8a3.5 3.5 0 0 1 7 0v3" />
                <circle cx="12" cy="15.5" r="1.2" />
                <path d="M12 16.7v1.8" />
              </svg>
            </span>
            <span className="mac-dock-label">PKI</span>
          </button>
          <button
            type="button"
            className={`mac-dock-item contracts-hub-icon-btn ${
              showContractsHub
                ? "contracts-hub-icon-btn-open mac-dock-item-open"
                : ""
            } ${
              contractsLayerOn && (contractsPreview?.markerCount ?? 0) > 0
                ? "contracts-hub-icon-btn-active mac-dock-item-active"
                : ""
            }`}
            onClick={() =>
              runRateLimitedButtonAction("contracts-hub-open", () => {
                if (showContractsHub) {
                  closeContractsHub();
                } else {
                  openContractsHub();
                }
              })
            }
            aria-label="Federal contracting — SAM.gov PKI and small business opportunities"
            title="Contracting · SAM.gov"
            aria-pressed={showContractsHub}
          >
            <span className="mac-dock-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24">
                <path d="M7 4h10a1 1 0 0 1 1 1v14l-3-2-3 2-3-2-3 2V5a1 1 0 0 1 1-1Z" />
                <path d="M9 8h6" />
                <path d="M9 11h6" />
                <path d="M9 14h3.5" />
              </svg>
            </span>
            <span className="mac-dock-label">Contracts</span>
          </button>
          <button
            type="button"
            className={`mac-dock-item un-hub-icon-btn ${
              showUnHub ? "un-hub-icon-btn-open mac-dock-item-open" : ""
            } ${
              showTradePulsePanel || showUnodcPanel || showUnGlobalPanel
                ? "un-hub-icon-btn-active mac-dock-item-active"
                : ""
            }`}
            onClick={() =>
              runRateLimitedButtonAction("un-hub-open", () => {
                if (showUnHub) {
                  closeUnHub();
                } else {
                  openUnHub();
                }
              })
            }
            aria-label="UN data hub — Trade Pulse, UNODC, UN Global"
            title="UN data hub"
            aria-pressed={showUnHub}
          >
            <span className="mac-dock-icon mac-dock-emoji" aria-hidden="true">
              🇺🇳
            </span>
            <span className="mac-dock-label">UN</span>
          </button>
          <button
            type="button"
            className={`mac-dock-item transit-icon-btn ${
              transitStatus === "loading" ? "weather-icon-loading" : ""
            } ${showTransitPanel ? "transit-icon-btn-open mac-dock-item-open" : ""}`}
            onClick={() => {
              void loadLocalTransit();
            }}
            aria-label="Local transit options"
            title="Local transit"
            aria-pressed={showTransitPanel}
          >
            <span className="mac-dock-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24">
                <rect x="5" y="3.5" width="14" height="14" rx="2.5" />
                <path d="M5 10.5h14" />
                <path d="M9 17.5v2.5" />
                <path d="M15 17.5v2.5" />
                <path d="M8 20h8" />
                <circle cx="9" cy="13.5" r="1" />
                <circle cx="15" cy="13.5" r="1" />
              </svg>
            </span>
            <span className="mac-dock-label">Transit</span>
          </button>
          <button
            type="button"
            className={`mac-dock-item nearby-icon-btn ${
              nearbyStatus === "loading" ? "weather-icon-loading" : ""
            } ${showNearbyPanel ? "nearby-icon-btn-open mac-dock-item-open" : ""}`}
            onClick={() => {
              void loadNearbyPaths();
            }}
            aria-label="Nearby street traces"
            title="Nearby streets & paths"
            aria-pressed={showNearbyPanel}
          >
            <span className="mac-dock-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24">
                <path d="M4 18V6" />
                <path d="M10 18V9" />
                <path d="M16 18V4" />
                <path d="M20 14H4" />
                <path d="M20 10H10" />
                <circle cx="4" cy="14" r="1.2" />
                <circle cx="10" cy="10" r="1.2" />
                <circle cx="16" cy="14" r="1.2" />
              </svg>
            </span>
            <span className="mac-dock-label">Nearby</span>
          </button>
          <span className="mac-dock-separator" aria-hidden="true" />
          <button
            type="button"
            className={`mac-dock-item ${
              weatherStatus === "loading" ? "weather-icon-loading" : ""
            } ${weatherFeed ? "mac-dock-item-active" : ""}`}
            onClick={() =>
              runRateLimitedButtonAction("weather-load", () => {
                void loadWeatherFeed();
              })
            }
            aria-label="Load current weather"
            title="Current weather"
          >
            <span className="mac-dock-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24">
                <path d="M7.5 17.5H17a4 4 0 0 0 .6-7.95 6 6 0 0 0-11.15 1.9A3.2 3.2 0 0 0 7.5 17.5Z" />
                <path d="m13 11-3 5h3l-2 5 5-7h-3l2-3Z" />
              </svg>
            </span>
            <span className="mac-dock-label">Weather</span>
          </button>
        </div>
      </nav>{showAbout && (
        <div className="modal-overlay" onClick={() => setShowAbout(false)}>
          <FloatingChrome
            className="modal-content"
            onClick={(e) => e.stopPropagation()}
            onPointerDown={(e) => e.stopPropagation()}
          >
            <button
              type="button"
              className="modal-close"
              onClick={() =>
                runRateLimitedButtonAction("about-close", () => setShowAbout(false))
              }
              aria-label="Close about dialog"
            >
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
          </FloatingChrome>
        </div>
      )}{showMenu && (
        <FloatingChrome className="menu-dropdown" aria-label="Global controls menu">
          <div className="menu-dropdown-scroll">
          <div className="menu-dropdown-inner">
          <div
            className="menu-section menu-section-location"
            aria-label="Location settings"
          >
            <div className="menu-section-title">Location</div>
            <div className="menu-section-meta location-pref-summary">
              <strong>
                {locationPref.mode === "browser"
                  ? "Browser GPS"
                  : locationPref.mode === "address"
                    ? "Address lookup"
                    : "Manual coordinates"}
              </strong>
              <span>
                {locationPref.label || "—"} ·{" "}
                {formatCoordPair(locationPref.latitude, locationPref.longitude)}
              </span>
              <span className="location-pref-hint">
                Used by Transit, Nearby, and Weather. Globe visitor dots still
                use network-edge location.
              </span>
            </div>

            <div
              className="location-mode-row location-mode-row-3"
              role="group"
              aria-label="Location source"
            >
              <button
                type="button"
                className={`location-mode-btn ${
                  locationPref.mode === "browser" ? "active" : ""
                }`}
                aria-pressed={locationPref.mode === "browser"}
                disabled={locationBusy}
                onClick={() => {
                  void requestBrowserLocation();
                }}
              >
                {locationBusy && locationPref.mode === "browser"
                  ? "Locating…"
                  : "Browser"}
              </button>
              <button
                type="button"
                className={`location-mode-btn ${
                  locationPref.mode === "manual" ? "active" : ""
                }`}
                aria-pressed={locationPref.mode === "manual"}
                disabled={locationBusy}
                onClick={() => {
                  setLocationMessage("");
                  setLocationDraftLat(String(locationPref.latitude));
                  setLocationDraftLng(String(locationPref.longitude));
                  setLocationDraftLabel(
                    locationPref.mode === "manual"
                      ? locationPref.label
                      : "Custom location",
                  );
                  applyLocationPreference({
                    mode: "manual",
                    latitude: locationPref.latitude,
                    longitude: locationPref.longitude,
                    label:
                      locationPref.mode === "manual"
                        ? locationPref.label
                        : "Custom location",
                  });
                  setLocationMessage(
                    "Manual mode on — edit coordinates below and Apply.",
                  );
                }}
              >
                Coords
              </button>
              <button
                type="button"
                className={`location-mode-btn ${
                  locationPref.mode === "address" ? "active" : ""
                }`}
                aria-pressed={locationPref.mode === "address"}
                disabled={locationBusy}
                onClick={() => {
                  setLocationMessage("");
                  applyLocationPreference({
                    mode: "address",
                    latitude: locationPref.latitude,
                    longitude: locationPref.longitude,
                    label:
                      locationPref.mode === "address"
                        ? locationPref.label
                        : locationPref.label || "Address location",
                  });
                  setLocationMessage(
                    "Enter a city or address, then Look up.",
                  );
                }}
              >
                Address
              </button>
            </div>

            {locationPref.mode === "manual" && (
              <form
                className="location-manual-form"
                onSubmit={(e) => {
                  e.preventDefault();
                  applyManualLocation();
                }}
              >
                <label className="location-field">
                  <span>Latitude</span>
                  <input
                    type="number"
                    inputMode="decimal"
                    step="any"
                    min={-90}
                    max={90}
                    value={locationDraftLat}
                    onChange={(e) => setLocationDraftLat(e.target.value)}
                    placeholder="40.7128"
                    autoComplete="off"
                    aria-label="Latitude"
                  />
                </label>
                <label className="location-field">
                  <span>Longitude</span>
                  <input
                    type="number"
                    inputMode="decimal"
                    step="any"
                    min={-180}
                    max={180}
                    value={locationDraftLng}
                    onChange={(e) => setLocationDraftLng(e.target.value)}
                    placeholder="-74.0060"
                    autoComplete="off"
                    aria-label="Longitude"
                  />
                </label>
                <label className="location-field location-field-full">
                  <span>Label (optional)</span>
                  <input
                    type="text"
                    maxLength={64}
                    value={locationDraftLabel}
                    onChange={(e) =>
                      setLocationDraftLabel(e.target.value.slice(0, 64))
                    }
                    placeholder="Custom location"
                    autoComplete="off"
                    aria-label="Location label"
                  />
                </label>
                <button
                  type="submit"
                  className="location-apply-btn"
                  disabled={locationBusy}
                >
                  Apply location
                </button>
              </form>
            )}

            {locationPref.mode === "address" && (
              <form
                className="location-address-form"
                onSubmit={(e) => {
                  e.preventDefault();
                  void lookupAddressLocation();
                }}
              >
                <label className="location-field location-field-full">
                  <span>City, address, or place</span>
                  <input
                    type="text"
                    inputMode="search"
                    maxLength={GEOCODE_MAX_QUERY}
                    value={locationDraftAddress}
                    onChange={(e) =>
                      setLocationDraftAddress(
                        e.target.value.slice(0, GEOCODE_MAX_QUERY),
                      )
                    }
                    placeholder="e.g. Brooklyn, NY or 1600 Amphitheatre Pkwy"
                    autoComplete="street-address"
                    aria-label="Address or place name"
                    spellCheck={false}
                  />
                </label>
                <button
                  type="submit"
                  className="location-apply-btn"
                  disabled={locationBusy || sanitizeAddressQuery(locationDraftAddress).length < 2}
                >
                  {locationBusy ? "Looking up…" : "Look up address"}
                </button>
                <p className="location-pref-note">
                  Uses Open-Meteo geocoding (HTTPS). Results become your saved
                  location for Transit, Nearby, and Weather.
                </p>
              </form>
            )}

            {locationPref.mode === "browser" && (
              <p className="location-pref-note">
                Tap <strong>Browser</strong> to request permission and refresh
                GPS. If denied, use Coords or Address instead.
              </p>
            )}

            {locationMessage ? (
              <p className="location-pref-message" role="status">
                {locationMessage}
              </p>
            ) : null}
          </div>

          {/* UN hub, Federalkey, Transit, Nearby — available via dock / nav */}
          <div className="menu-section menu-section-links" aria-label="Account and links">
            {authUser ? (
              <button
                type="button"
                className="menu-item menu-item-button billing-menu-item"
                disabled={checkoutBusy || authUser.transitPaid}
                onClick={() => {
                  void startTransitCheckout();
                }}
              >
                {checkoutBusy
                  ? "Opening Stripe…"
                  : authUser.transitPaid
                    ? "Stripe access unlocked ✓"
                    : "Buy Stripe access ($20)"}
              </button>
            ) : null}
            {authUser ? (
              <>
                <div className="menu-section-meta auth-user-meta">
                  <div className="auth-user-meta-status">
                    Signed in
                    {authUser.transitPaid
                      ? " · Transit + Live Feed + support paid"
                      : !paymentRequired
                        ? " · PGP session (Stripe not required)"
                        : ""}
                    {authUser.primaryUserId
                      ? ` · ${authUser.primaryUserId}`
                      : ""}
                  </div>
                  <div
                    className="auth-user-fingerprint"
                    title="Full OpenPGP fingerprint"
                  >
                    {formatFingerprint(authUser.fingerprint)}
                  </div>
                </div>
                <button
                  type="button"
                  className="menu-item menu-item-button"
                  disabled={authBusy}
                  onClick={() => {
                    void logout(false);
                    setShowMenu(false);
                  }}
                >
                  {authBusy ? "Working…" : "Log out"}
                </button>
                <button
                  type="button"
                  className="menu-item menu-item-button"
                  disabled={authBusy}
                  title="Revoke every session for this account (all devices)"
                  onClick={() => {
                    void logout(true);
                    setShowMenu(false);
                  }}
                >
                  Log out all devices
                </button>
              </>
            ) : (
              <button
                type="button"
                className="menu-item menu-item-button"
                disabled={authBusy}
                onClick={() => {
                  setShowMenu(false);
                  setShowAuthPanel(true);
                  setAuthMode("login");
                }}
              >
                Sign in
              </button>
            )}
            {authUser ? (
              <button
                type="button"
                className={`menu-item menu-item-button admin-menu-item ${
                  isAdmin ? "" : "admin-menu-item-locked"
                }`}
                onClick={() => {
                  void openAdminPanel();
                }}
                title={
                  isAdmin
                    ? "Open admin portal"
                    : "Open admin status (this key may not be allowlisted)"
                }
              >
                {isAdmin ? "Admin" : "Admin (locked)"}
              </button>
            ) : null}
            <a
              href="https://104041.webmail.dynadot.com/user/signin.html"
              className="menu-item"
              target="_blank"
              rel="noopener noreferrer"
            >
              Webmail
            </a>
            <a
              href="https://federalkeymarketplace.page.gd"
              className="menu-item"
              target="_blank"
              rel="noopener noreferrer"
            >
              Market
            </a>
          </div>
          </div>
          </div>
        </FloatingChrome>
      )}
    </>
  );
}
