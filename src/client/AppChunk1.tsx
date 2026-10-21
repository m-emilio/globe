import React from "react";
import type { GlobeApi } from "./useGlobeApp";
import { type GlobeArc } from "./CobeGlobe";
import { FloatingChrome } from "./FloatingChrome";
import { UnHubPage } from "./UnHubPage";
import { PkiHubPage } from "./PkiHubPage";
import { ContractsHubPage } from "./ContractsHubPage";
import { safeGlobeHref } from "./safeUrl";
import type { ComtradePreview, PkiVulnSeverity, TradePulseLayer, TradePulsePreview, UnGlobalPreview } from "../shared";
import { PKI_CATEGORY_LABELS, PKI_SEVERITY_COLORS, PKI_SORT_LABELS, PkiSortMode, TRADE_PULSE_LAYERS, TRADE_PULSE_LAYER_COLORS, TRADE_PULSE_LAYER_LABELS, TRADE_PULSE_LAYER_SHORT_LABELS, UNODC_THEME_CSS, UNODC_THEME_IDS, UN_GLOBAL_SECTION_LABELS, countLiveUnodcThemes, formatNullableUsd, formatPercent, formatPreviewDate, formatPreviewNumber, formatSignedUsd, formatUsd, getRoutePulseLayer, previewHotspotLinks } from "./globeModel";
export function AppChunk1({ b }: { b: GlobeApi }) {
  const { checkoutBusy, closeContractsHub, closePkiHub, closeUnHub, comtradeError, comtradePreview, comtradeSections, comtradeStatus, comtradeValueMode, contractsError, contractsLayerOn, contractsPreview, contractsStatus, enabledComtradeSectionCount, enabledTradePulseLayerCount, isPkiPanelMinimized, isTradePulsePanelMinimized, isUnodcPanelMinimized, liveFeedAccess, loadComtradePreview, loadPkiVulns, loadSamContracts, loadTradePulsePreview, loadUnGlobalPreview, loadUnodcHotspots, paymentRequired, pkiArcSelection, pkiCatalog, pkiCategory, pkiDensity, pkiError, pkiFocusCve, pkiGlobeArcs, pkiPreview, pkiSeverities, pkiShowMap, pkiSort, pkiStatus, pkiVisibleCves, runRateLimitedButtonAction, selectTradePulsePeriod, setAuthMessage, setAuthMode, setContractsLayerOn, setIsPkiPanelMinimized, setIsTradePulsePanelMinimized, setIsUnodcPanelMinimized, setPkiArcPage, setPkiCatalog, setPkiCategory, setPkiDensity, setPkiFocusCve, setPkiSeverities, setPkiShowMap, setPkiSort, setShowAuthPanel, setShowComtradePanel, setShowMenu, setShowPkiPanel, setShowTradePulsePanel, setShowUnGlobalPanel, setShowUnodcPanel, setUnodcFocusMode, showComtradePanel, showContractsHub, showPkiHub, showPkiPanel, showTradePulsePanel, showUnGlobalPanel, showUnHub, showUnodcPanel, startTransitCheckout, toggleAllTradePulseLayers, toggleAllUnGlobalSections, toggleTradePulseLayer, toggleUnGlobalSection, toggleUnodcTheme, tradePulseError, tradePulseLayers, tradePulsePeriod, tradePulsePreview, tradePulseStatus, tradePulseYearOptions, unGlobalError, unGlobalPreview, unGlobalSections, unGlobalStatus, unodcCountryPolygons, unodcError, unodcPreview, unodcStatus, unodcThemes, visibleTradePulseRoutes } = b;
  return (
    <>
{showComtradePanel && (
        <FloatingChrome className="un-panel" role="dialog" aria-label="UN Comtrade">
          <div className="un-panel-header">
            <div>
              <h3>Comtrade</h3>
              <span>
                {comtradeStatus === "ready" && comtradePreview
                  ? `${comtradePreview.period} · ${
                      comtradePreview.dataMode === "free-subscription" ||
                      comtradePreview.subscriptionBacked
                        ? "Live"
                        : "Preview"
                    }`
                  : "Annual trade sample"}
              </span>
            </div>
            <button
              type="button"
              className="un-close"
              onClick={() =>
                runRateLimitedButtonAction("comtrade-close", () => {
                  setShowComtradePanel(false);
                  setShowMenu(false);
                })
              }
              aria-label="Close UN Comtrade preview"
            >
              x
            </button>
          </div>

          {comtradeStatus === "loading" && (
            <div className="un-loading">Loading UN Comtrade public sample...</div>
          )}

          {comtradeStatus === "error" && (
            <div className="un-error">
              <span>{comtradeError}</span>
              <button
                type="button"
                onClick={() =>
                  runRateLimitedButtonAction("comtrade-retry", () => {
                    void loadComtradePreview();
                  })
                }
              >
                Retry
              </button>
            </div>
          )}

          {comtradeStatus === "ready" && comtradePreview && (
            <>
              <div className="un-status-row">
                <span>{comtradePreview.source}</span>
                <strong>
                  {comtradePreview.stale
                    ? "Fallback"
                    : comtradePreview.dataMode === "free-subscription" ||
                        comtradePreview.subscriptionBacked
                      ? "Live"
                      : "Preview"}
                </strong>
              </div>
              <div className="un-summary-grid">
                <div className="un-metric">
                  <span>Exports</span>
                  <strong>
                    {formatUsd(
                      comtradePreview.exportsUsd,
                      comtradePreview.stale,
                      comtradeValueMode,
                    )}
                  </strong>
                </div>
                <div className="un-metric">
                  <span>Imports</span>
                  <strong>
                    {formatUsd(
                      comtradePreview.importsUsd,
                      comtradePreview.stale,
                      comtradeValueMode,
                    )}
                  </strong>
                </div>
                <div className="un-metric">
                  <span>Balance</span>
                  <strong>
                    {formatSignedUsd(
                      comtradePreview.tradeBalanceUsd,
                      comtradePreview.stale,
                      comtradeValueMode,
                    )}
                  </strong>
                </div>
                <div className="un-metric">
                  <span>Records</span>
                  <strong>
                    {formatPreviewNumber(
                      comtradePreview.availabilityTotalRecords,
                      comtradePreview.stale,
                    )}
                  </strong>
                </div>
                <div className="un-metric">
                  <span>Refs</span>
                  <strong>
                    {formatPreviewNumber(
                      comtradePreview.referenceTablesTotal,
                      comtradePreview.stale,
                    )}
                  </strong>
                </div>
              </div>

              <div className="un-update-row">
                <span>{comtradePreview.queryLabel}</span>
                <strong>
                  Latest{" "}
                  {comtradePreview.latestRelease
                    ? formatPreviewDate(comtradePreview.latestRelease)
                    : "n/a"}
                </strong>
              </div>

              <div className="un-goal-list" aria-label="UN COMTRADE data preview">
                {enabledComtradeSectionCount === 0 && (
                  <div className="un-empty-state">
                    Enable a Comtrade section from the menu.
                  </div>
                )}

                {comtradeSections.records && (
                  <section className="un-data-section">
                    <div className="un-section-heading">
                      <span>Trade records</span>
                      <strong>{comtradePreview.tradeRecords.length} shown</strong>
                    </div>
                    {comtradePreview.tradeRecords.map((record) => (
                      <article className="un-goal-row" key={`${record.flow}-${record.period}`}>
                        <div className="un-goal-heading">
                          <span>{record.flow}</span>
                          <strong>
                            {formatUsd(
                              record.primaryValueUsd,
                              comtradePreview.stale,
                              comtradeValueMode,
                            )}
                          </strong>
                        </div>
                        <p>
                          {record.reporter} to {record.partner} · {record.commodity} (
                          {record.commodityCode})
                        </p>
                        <div className="un-goal-meta">
                          <span>Period {record.period}</span>
                          <span>
                            CIF{" "}
                            {formatNullableUsd(
                              record.cifValueUsd,
                              comtradePreview.stale,
                              comtradeValueMode,
                            )}
                          </span>
                          <span>
                            FOB{" "}
                            {formatNullableUsd(
                              record.fobValueUsd,
                              comtradePreview.stale,
                              comtradeValueMode,
                            )}
                          </span>
                        </div>
                      </article>
                    ))}
                  </section>
                )}

                {comtradeSections.availability && (
                  <section className="un-data-section">
                    <div className="un-section-heading">
                      <span>Data availability</span>
                      <strong>{comtradePreview.availability.length} shown</strong>
                    </div>
                    {comtradePreview.availability.map((dataset) => (
                      <article className="un-compact-row" key={dataset.datasetCode}>
                        <div className="un-compact-heading">
                          <span>{dataset.classification || "Dataset"}</span>
                          <strong>{formatPreviewNumber(dataset.totalRecords)} records</strong>
                        </div>
                        <p>
                          {dataset.reporter} · {dataset.period} · dataset {dataset.datasetCode}
                        </p>
                        <div className="un-goal-meta">
                          <span>
                            First{" "}
                            {dataset.firstReleased
                              ? formatPreviewDate(dataset.firstReleased)
                              : "n/a"}
                          </span>
                          <span>
                            Last{" "}
                            {dataset.lastReleased
                              ? formatPreviewDate(dataset.lastReleased)
                              : "n/a"}
                          </span>
                        </div>
                      </article>
                    ))}
                  </section>
                )}

                {comtradeSections.references && (
                  <section className="un-data-section">
                    <div className="un-section-heading">
                      <span>Reference tables</span>
                      <strong>{comtradePreview.references.length} shown</strong>
                    </div>
                    {comtradePreview.references.map((reference) => (
                      <article className="un-compact-row" key={reference.category}>
                        <div className="un-compact-heading">
                          <span>{reference.category}</span>
                          <strong>{reference.variable}</strong>
                        </div>
                        <p>{reference.description}</p>
                      </article>
                    ))}
                  </section>
                )}

                {comtradeSections.reporters && (
                  <section className="un-data-section">
                    <div className="un-section-heading">
                      <span>Reporters</span>
                      <strong>{formatPreviewNumber(comtradePreview.reportersTotal)} total</strong>
                    </div>
                    <div className="un-chip-list">
                      {comtradePreview.reporters.map((reporter) => (
                        <span className="un-chip" key={reporter.code}>
                          {reporter.name} <small>{reporter.iso3 || reporter.code}</small>
                        </span>
                      ))}
                    </div>
                  </section>
                )}
              </div>

              <div className="un-footer">
                <span>{formatPreviewDate(comtradePreview.updatedAt)}</span>
                <div className="un-footer-actions">
                  <a
                    href={safeGlobeHref(comtradePreview.sourceUrl)}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Source
                  </a>
                  <button
                    type="button"
                    onClick={() =>
                      runRateLimitedButtonAction("comtrade-refresh", () => {
                        void loadComtradePreview();
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
      )}{showUnHub && (
        <UnHubPage
          onClose={closeUnHub}
          onViewGlobe={closeUnHub}
          tradePulseOn={showTradePulsePanel}
          tradePulseStatus={tradePulseStatus}
          tradePulseError={tradePulseError}
          tradePulsePreview={tradePulsePreview}
          tradePulsePeriod={tradePulsePeriod}
          tradePulseYearOptions={tradePulseYearOptions}
          tradePulseLayers={tradePulseLayers}
          tradePulseLayerLabels={TRADE_PULSE_LAYER_LABELS}
          tradePulseLayerShortLabels={TRADE_PULSE_LAYER_SHORT_LABELS}
          tradePulseLayerColors={TRADE_PULSE_LAYER_COLORS}
          tradePulseLayersList={TRADE_PULSE_LAYERS}
          onToggleTradePulse={() => {
            if (showTradePulsePanel) {
              setShowTradePulsePanel(false);
            } else {
              void loadTradePulsePreview(false);
            }
          }}
          onSelectTradePulsePeriod={(period) => selectTradePulsePeriod(period)}
          onToggleTradePulseLayer={toggleTradePulseLayer}
          onToggleAllTradePulseLayers={toggleAllTradePulseLayers}
          onRefreshTradePulse={() => {
            void loadTradePulsePreview(false, tradePulsePeriod, {
              keepExpanded: true,
            });
          }}
          unodcOn={showUnodcPanel}
          unodcStatus={unodcStatus}
          unodcError={unodcError}
          unodcPreview={unodcPreview}
          unodcThemes={unodcThemes}
          unodcThemeIds={UNODC_THEME_IDS}
          unodcThemeColors={UNODC_THEME_CSS}
          onToggleUnodc={() => {
            if (showUnodcPanel) {
              setShowUnodcPanel(false);
            } else {
              void loadUnodcHotspots(false);
            }
          }}
          onToggleUnodcTheme={toggleUnodcTheme}
          onUnodcFocusMode={setUnodcFocusMode}
          onRefreshUnodc={() => {
            void loadUnodcHotspots(false, { forceRefresh: true });
          }}
          unGlobalOn={showUnGlobalPanel}
          unGlobalStatus={unGlobalStatus}
          unGlobalError={unGlobalError}
          unGlobalPreview={unGlobalPreview}
          unGlobalSections={unGlobalSections}
          unGlobalSectionLabels={UN_GLOBAL_SECTION_LABELS}
          unGlobalSectionIds={[
            "offices",
            "activeMissions",
            "pastMissions",
            "memberStates",
            "affiliates",
            "embassies",
          ]}
          onToggleUnGlobal={() => {
            if (showUnGlobalPanel) {
              setShowUnGlobalPanel(false);
            } else {
              void loadUnGlobalPreview(false);
            }
          }}
          onToggleUnGlobalSection={toggleUnGlobalSection}
          onToggleAllUnGlobalSections={toggleAllUnGlobalSections}
          onRefreshUnGlobal={() => {
            void loadUnGlobalPreview(false);
          }}
        />
      )}{showTradePulsePanel && !showUnHub && (
        <FloatingChrome
          className={`un-panel trade-pulse-panel ${
            isTradePulsePanelMinimized ? "un-panel-minimized" : ""
          }`}
          role="dialog"
          aria-label="Trade Pulse"
        >
          <div className="un-panel-header">
            <div>
              <h3>Trade Pulse</h3>
              <span>
                {tradePulseStatus === "ready" && tradePulsePreview
                  ? `${tradePulsePreview.period} · ${
                      tradePulsePreview.dataMode === "free-subscription" ||
                      tradePulsePreview.subscriptionBacked
                        ? "Live"
                        : "Preview"
                    }`
                  : "Dependency radar"}
              </span>
            </div>
            <div className="un-panel-actions">
              <button
                type="button"
                className="un-minimize"
                onClick={() =>
                  runRateLimitedButtonAction("trade-pulse-minimize", () =>
                    setIsTradePulsePanelMinimized((minimized) => !minimized),
                  )
                }
                aria-label={
                  isTradePulsePanelMinimized
                    ? "Restore Trade Pulse preview"
                    : "Minimize Trade Pulse preview"
                }
              >
                {isTradePulsePanelMinimized ? "+" : "_"}
              </button>
              <button
                type="button"
                className="un-close"
                onClick={() =>
                  runRateLimitedButtonAction("trade-pulse-close", () =>
                    setShowTradePulsePanel(false),
                  )
                }
                aria-label="Close Trade Pulse preview"
              >
                x
              </button>
            </div>
          </div>

          {!isTradePulsePanelMinimized && (
            <div className="trade-pulse-panel-scroll">
              <div className="trade-pulse-panel-inner">
                <div
                  className="trade-pulse-year-row"
                  role="group"
                  aria-label="Trade year"
                >
                  <span className="trade-pulse-year-label">Year</span>
                  <div className="trade-pulse-year-buttons">
                    {tradePulseYearOptions.map((year) => (
                      <button
                        type="button"
                        key={year}
                        className={`trade-pulse-year-btn ${
                          tradePulsePeriod === year ? "active" : ""
                        }`}
                        aria-pressed={tradePulsePeriod === year}
                        disabled={tradePulseStatus === "loading"}
                        onClick={() =>
                          runRateLimitedButtonAction(`trade-pulse-year-${year}`, () => {
                            selectTradePulsePeriod(year);
                          })
                        }
                      >
                        {year}
                      </button>
                    ))}
                  </div>
                </div>

                {tradePulseStatus === "loading" && (
                  <div className="un-loading">Loading {tradePulsePeriod}…</div>
                )}

                {tradePulseStatus === "error" && (
                  <div className="un-error">
                    <span>{tradePulseError}</span>
                    <button
                      type="button"
                      onClick={() =>
                        runRateLimitedButtonAction("trade-pulse-retry", () => {
                          void loadTradePulsePreview(false, tradePulsePeriod, {
                            keepExpanded: true,
                          });
                        })
                      }
                    >
                      Retry
                    </button>
                  </div>
                )}

                {tradePulseStatus === "ready" && tradePulsePreview && (
                  <>
                    <div className="un-status-row trade-pulse-status-row">
                      <span>{tradePulsePreview.source}</span>
                      <strong>
                        {tradePulsePreview.dataMode === "free-subscription" ||
                        tradePulsePreview.subscriptionBacked
                          ? `Live · ${tradePulsePreview.liveRouteCount ?? tradePulsePreview.routes.length} routes`
                          : "Preview"}
                      </strong>
                    </div>

                    <div className="un-summary-grid trade-pulse-summary-grid">
                      {tradePulsePreview.metrics.slice(0, 8).map((metric) => (
                        <div className="un-metric" key={metric.label}>
                          <span>{metric.label}</span>
                          <strong>{metric.value}</strong>
                        </div>
                      ))}
                    </div>

                    <div className="un-update-row">
                      <span>HS annual · {tradePulsePreview.period}</span>
                      <strong>{visibleTradePulseRoutes.length} routes</strong>
                    </div>

                    <div
                      className="trade-pulse-layer-grid"
                      role="group"
                      aria-label="Trade Pulse layers"
                    >
                      {TRADE_PULSE_LAYERS.map((layer) => (
                        <button
                          type="button"
                          key={layer}
                          className={`trade-pulse-layer-toggle ${
                            tradePulseLayers[layer] ? "active" : ""
                          }`}
                          style={
                            {
                              "--layer-color": TRADE_PULSE_LAYER_COLORS[layer],
                            } as React.CSSProperties
                          }
                          aria-pressed={tradePulseLayers[layer]}
                          onClick={() =>
                            runRateLimitedButtonAction(`trade-pulse-layer-${layer}`, () =>
                              toggleTradePulseLayer(layer),
                            )
                          }
                        >
                          <span>{TRADE_PULSE_LAYER_LABELS[layer]}</span>
                          <strong>{tradePulseLayers[layer] ? "On" : "Off"}</strong>
                        </button>
                      ))}
                    </div>

                    <div
                      className="un-goal-list trade-pulse-route-list"
                      aria-label="Trade Pulse routes"
                    >
                      {enabledTradePulseLayerCount === 0 && (
                        <div className="un-empty-state">
                          Enable a Trade Pulse layer from the panel or menu.
                        </div>
                      )}

                      {visibleTradePulseRoutes.map((route) => {
                        const activeLayer = getRoutePulseLayer(route, tradePulseLayers);

                        return (
                          <article
                            className={`un-goal-row trade-pulse-route-card trade-pulse-card-${route.severity}`}
                            key={route.id}
                            style={
                              {
                                "--route-card-color": TRADE_PULSE_LAYER_COLORS[activeLayer],
                              } as React.CSSProperties
                            }
                          >
                            <div className="un-goal-heading trade-pulse-card-heading">
                              <span>
                                {route.origin.iso3} to {route.destination.iso3}
                              </span>
                              <strong>{route.commodity}</strong>
                            </div>
                            <p>
                              {route.origin.name} to {route.destination.name}
                              {route.intermediary
                                ? ` via ${route.intermediary.name}`
                                : ""}{" "}
                              · {route.transportMode} · {route.customsProcedure}
                            </p>
                            <div className="trade-pulse-badge-row">
                              {route.layers
                                .filter((layer) => tradePulseLayers[layer])
                                .map((layer) => (
                                  <span
                                    className="trade-pulse-layer-badge"
                                    key={layer}
                                    style={
                                      {
                                        "--layer-color": TRADE_PULSE_LAYER_COLORS[layer],
                                      } as React.CSSProperties
                                    }
                                  >
                                    {TRADE_PULSE_LAYER_SHORT_LABELS[layer]}
                                  </span>
                                ))}
                            </div>
                            <div className="un-goal-meta trade-pulse-metrics">
                              <span>
                                Value {formatUsd(route.valueUsd, false, comtradeValueMode)}
                              </span>
                              <span>Supplier {formatPercent(route.supplierSharePct)}</span>
                              <span>Mirror gap {formatPercent(route.asymmetryPct)}</span>
                              <span>CIF/FOB {formatPercent(route.frictionPct)}</span>
                              <span>Re-export {formatPercent(route.reExportSharePct)}</span>
                              <span>Confidence {formatPercent(route.confidencePct)}</span>
                            </div>
                            <p className="trade-pulse-insight">{route.insight}</p>
                          </article>
                        );
                      })}
                    </div>

                    <div className="un-footer">
                      <span>{formatPreviewDate(tradePulsePreview.updatedAt)}</span>
                      <div className="un-footer-actions">
                        <a
                          href={safeGlobeHref(tradePulsePreview.sourceUrl)}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          Source
                        </a>
                        <button
                          type="button"
                          onClick={() =>
                            runRateLimitedButtonAction("trade-pulse-refresh", () => {
                              void loadTradePulsePreview(false, tradePulsePeriod, {
                                keepExpanded: true,
                              });
                            })
                          }
                        >
                          Refresh
                        </button>
                      </div>
                    </div>
                  </>
                )}
              </div>
            </div>
          )}
        </FloatingChrome>
      )}{showContractsHub && (
        <ContractsHubPage
          onClose={closeContractsHub}
          onViewGlobe={closeContractsHub}
          status={contractsStatus}
          error={contractsError}
          preview={contractsPreview}
          layerOn={contractsLayerOn}
          access={liveFeedAccess}
          checkoutBusy={checkoutBusy}
          onSignIn={() => {
            setShowAuthPanel(true);
            setAuthMode("login");
            setAuthMessage(
              paymentRequired
                ? "Sign in, then unlock Contracting with Stripe ($20)."
                : "Sign in with your PGP key to use Contracting.",
            );
          }}
          onBuyAccess={() => {
            void startTransitCheckout();
          }}
          onToggleLayer={() => setContractsLayerOn((v) => !v)}
          onSearch={(opts) => {
            void loadSamContracts(opts);
          }}
          formatUpdatedAt={formatPreviewDate}
        />
      )}{showPkiHub && (
        <PkiHubPage
          onClose={closePkiHub}
          onViewGlobe={closePkiHub}
          layerOn={showPkiPanel}
          status={pkiStatus}
          error={pkiError}
          preview={pkiPreview}
          visibleCves={pkiVisibleCves}
          arcStats={{
            visible: pkiGlobeArcs.length,
            total: pkiArcSelection.total,
            page: pkiArcSelection.page,
            pageCount: pkiArcSelection.pageCount,
            kevCount: pkiArcSelection.kevCount,
            nvdCount: pkiArcSelection.nvdCount,
          }}
          showMap={pkiShowMap}
          catalog={pkiCatalog}
          density={pkiDensity}
          sort={pkiSort}
          sortLabels={PKI_SORT_LABELS}
          severities={pkiSeverities}
          severityColors={PKI_SEVERITY_COLORS}
          category={pkiCategory}
          categoryLabels={PKI_CATEGORY_LABELS}
          focusCve={pkiFocusCve}
          onToggleLayer={() => {
            if (showPkiPanel) {
              setShowPkiPanel(false);
              setPkiShowMap(false);
            } else {
              void loadPkiVulns(false);
            }
          }}
          onToggleMap={() => setPkiShowMap((v) => !v)}
          onSetCatalog={(v) => {
            setPkiCatalog(v);
            setPkiFocusCve(null);
            setPkiArcPage(0);
          }}
          onSetDensity={(v) => {
            setPkiDensity(v);
            setPkiArcPage(0);
          }}
          onSetSort={(v) => {
            setPkiSort(v);
            setPkiArcPage(0);
          }}
          onToggleSeverity={(sev) => {
            setPkiSeverities((prev) => {
              const next = new Set(prev);
              if (next.has(sev)) {
                if (next.size > 1) next.delete(sev);
              } else {
                next.add(sev);
              }
              return next;
            });
            setPkiArcPage(0);
          }}
          onSetCategory={(v) => {
            setPkiCategory(v);
            setPkiFocusCve(null);
            setPkiArcPage(0);
          }}
          onPagePrev={() => setPkiArcPage((p) => Math.max(0, p - 1))}
          onPageNext={() => setPkiArcPage((p) => p + 1)}
          onFocusCve={(id) => {
            setPkiFocusCve(id);
            if (id) {
              setShowPkiPanel(true);
              setPkiShowMap(true);
            }
            setPkiArcPage(0);
          }}
          onRefresh={() => {
            void loadPkiVulns(false, { forceRefresh: true });
          }}
          formatUpdatedAt={formatPreviewDate}
          exposureCount={(cve) =>
            cve.exposureIso3s?.length ||
            (pkiPreview ? previewHotspotLinks(pkiPreview, cve.id) : 0)
          }
        />
      )}{showPkiPanel && !showPkiHub && (
        <FloatingChrome
          className={`un-panel pki-panel ${
            isPkiPanelMinimized ? "un-panel-minimized" : ""
          }`}
          role="dialog"
          aria-label="PKI vulnerability feed"
        >
          <div className="un-panel-header">
            <div>
              <h3>Certificate &amp; PKI exposure</h3>
              <span>
                {pkiStatus === "ready" && pkiPreview
                  ? pkiPreview.queryLabel
                  : "CISA KEV + NVD · vendor origin → deployment signal"}
              </span>
            </div>
            <div className="un-panel-actions">
              <button
                type="button"
                className="un-minimize"
                onClick={() =>
                  runRateLimitedButtonAction("pki-minimize", () =>
                    setIsPkiPanelMinimized((m) => !m),
                  )
                }
                aria-label={
                  isPkiPanelMinimized ? "Expand PKI panel" : "Minimize PKI panel"
                }
              >
                {isPkiPanelMinimized ? "+" : "_"}
              </button>
              <button
                type="button"
                className="un-close"
                onClick={() =>
                  runRateLimitedButtonAction("pki-close", () => {
                    setShowPkiPanel(false);
                    setPkiShowMap(false);
                  })
                }
                aria-label="Close PKI panel"
              >
                x
              </button>
            </div>
          </div>

          {!isPkiPanelMinimized && (
            <div className="trade-pulse-panel-scroll">
              <div className="trade-pulse-panel-inner">
                {pkiStatus === "loading" && (
                  <div className="un-loading">Loading PKI / CVE feed…</div>
                )}
                {pkiStatus === "error" && (
                  <div className="un-error">
                    <span>{pkiError}</span>
                    <button
                      type="button"
                      onClick={() =>
                        runRateLimitedButtonAction("pki-retry", () => {
                          void loadPkiVulns(false, { forceRefresh: true });
                        })
                      }
                    >
                      Retry
                    </button>
                  </div>
                )}
                {pkiStatus === "ready" && pkiPreview && (
                  <>
                    <div className="un-status-row">
                      <span>{pkiPreview.source}</span>
                      <strong>
                        {pkiGlobeArcs.length}/{pkiArcSelection.total} arcs ·{" "}
                        {pkiArcSelection.kevCount} KEV · {pkiArcSelection.nvdCount}{" "}
                        dotted · {pkiPreview.cveCount} CVEs
                      </strong>
                    </div>
                    <div className="pki-method-card" aria-label="How to read arcs">
                      <strong>How to read the arcs</strong>
                      <ul>
                        <li>
                          <em>Direction</em> — vendor origin → deployment/exposure
                          countries.
                        </li>
                        <li>
                          <em>Solid</em> — CISA KEV (known exploited).{" "}
                          <em>Dotted</em> — NVD catalog match.
                        </li>
                        <li>
                          <em>Browse</em> — filter, sort, and page arcs so the globe
                          stays smooth. Focus a CVE to see all its destinations.
                        </li>
                      </ul>
                    </div>

                    <div className="pki-controls" aria-label="PKI arc controls">
                      <div className="pki-control-row" role="group" aria-label="Map display">
                        <button
                          type="button"
                          className={`trade-pulse-year-btn ${pkiShowMap ? "active" : ""}`}
                          onClick={() =>
                            runRateLimitedButtonAction("pki-map-toggle", () =>
                              setPkiShowMap((v) => !v),
                            )
                          }
                        >
                          {pkiShowMap ? "Arcs on" : "Arcs off"}
                        </button>
                        {pkiFocusCve && (
                          <button
                            type="button"
                            className="trade-pulse-year-btn active"
                            onClick={() =>
                              runRateLimitedButtonAction("pki-clear-focus", () => {
                                setPkiFocusCve(null);
                                setPkiArcPage(0);
                              })
                            }
                          >
                            Clear focus · {pkiFocusCve}
                          </button>
                        )}
                      </div>

                      <div className="pki-control-label">Catalog</div>
                      <div className="pki-control-row" role="group" aria-label="Catalog filter">
                        {(
                          [
                            ["all", "All"],
                            ["kev", "KEV solid"],
                            ["nvd", "NVD dotted"],
                          ] as const
                        ).map(([id, label]) => (
                          <button
                            key={id}
                            type="button"
                            className={`trade-pulse-year-btn ${pkiCatalog === id ? "active" : ""}`}
                            onClick={() =>
                              runRateLimitedButtonAction(`pki-cat-${id}`, () => {
                                setPkiCatalog(id);
                                setPkiFocusCve(null);
                                setPkiArcPage(0);
                              })
                            }
                          >
                            {label}
                          </button>
                        ))}
                      </div>

                      <div className="pki-control-label">Density (performance)</div>
                      <div className="pki-control-row" role="group" aria-label="Arc density">
                        {(
                          [
                            ["sparse", "Sparse 8"],
                            ["balanced", "Balanced 14"],
                            ["dense", "Dense 22"],
                          ] as const
                        ).map(([id, label]) => (
                          <button
                            key={id}
                            type="button"
                            className={`trade-pulse-year-btn ${pkiDensity === id ? "active" : ""}`}
                            onClick={() =>
                              runRateLimitedButtonAction(`pki-den-${id}`, () => {
                                setPkiDensity(id);
                                setPkiArcPage(0);
                              })
                            }
                          >
                            {label}
                          </button>
                        ))}
                      </div>

                      <div className="pki-control-label">Sort</div>
                      <div className="pki-control-row pki-control-wrap" role="group" aria-label="Sort arcs">
                        {(Object.keys(PKI_SORT_LABELS) as PkiSortMode[]).map(
                          (id) => (
                            <button
                              key={id}
                              type="button"
                              className={`trade-pulse-year-btn ${pkiSort === id ? "active" : ""}`}
                              onClick={() =>
                                runRateLimitedButtonAction(`pki-sort-${id}`, () => {
                                  setPkiSort(id);
                                  setPkiArcPage(0);
                                })
                              }
                            >
                              {PKI_SORT_LABELS[id]}
                            </button>
                          ),
                        )}
                      </div>

                      <div className="pki-control-label">Severity</div>
                      <div className="pki-control-row pki-control-wrap" role="group" aria-label="Severity filter">
                        {(
                          [
                            "critical",
                            "high",
                            "medium",
                            "low",
                          ] as PkiVulnSeverity[]
                        ).map((sev) => {
                          const on = pkiSeverities.has(sev);
                          return (
                            <button
                              key={sev}
                              type="button"
                              className={`trade-pulse-year-btn ${on ? "active" : ""}`}
                              style={
                                on
                                  ? {
                                      borderColor: PKI_SEVERITY_COLORS[sev],
                                    }
                                  : undefined
                              }
                              onClick={() =>
                                runRateLimitedButtonAction(`pki-sev-${sev}`, () => {
                                  setPkiSeverities((prev) => {
                                    const next = new Set(prev);
                                    if (next.has(sev)) {
                                      if (next.size > 1) next.delete(sev);
                                    } else {
                                      next.add(sev);
                                    }
                                    return next;
                                  });
                                  setPkiArcPage(0);
                                })
                              }
                            >
                              {sev}
                            </button>
                          );
                        })}
                      </div>

                      <div className="pki-control-label">Class</div>
                      <div className="pki-control-row pki-control-wrap" role="group" aria-label="Category filter">
                        <button
                          type="button"
                          className={`trade-pulse-year-btn ${pkiCategory === "all" ? "active" : ""}`}
                          onClick={() =>
                            runRateLimitedButtonAction("pki-class-all", () => {
                              setPkiCategory("all");
                              setPkiArcPage(0);
                            })
                          }
                        >
                          All classes
                        </button>
                        {Object.entries(PKI_CATEGORY_LABELS).map(([id, label]) => (
                          <button
                            key={id}
                            type="button"
                            className={`trade-pulse-year-btn ${pkiCategory === id ? "active" : ""}`}
                            onClick={() =>
                              runRateLimitedButtonAction(`pki-class-${id}`, () => {
                                setPkiCategory(id);
                                setPkiFocusCve(null);
                                setPkiArcPage(0);
                              })
                            }
                          >
                            {label}
                          </button>
                        ))}
                      </div>

                      <div className="pki-pager" role="group" aria-label="Arc pages">
                        <button
                          type="button"
                          className="trade-pulse-year-btn"
                          disabled={pkiArcSelection.page <= 0}
                          onClick={() =>
                            runRateLimitedButtonAction("pki-page-prev", () =>
                              setPkiArcPage((p) => Math.max(0, p - 1)),
                            )
                          }
                        >
                          ← Prev
                        </button>
                        <span className="pki-pager-status">
                          Page {pkiArcSelection.page + 1}/
                          {pkiArcSelection.pageCount}
                          {pkiArcSelection.total > 0
                            ? ` · showing ${pkiGlobeArcs.length} of ${pkiArcSelection.total}`
                            : ""}
                        </span>
                        <button
                          type="button"
                          className="trade-pulse-year-btn"
                          disabled={
                            pkiArcSelection.page >= pkiArcSelection.pageCount - 1
                          }
                          onClick={() =>
                            runRateLimitedButtonAction("pki-page-next", () =>
                              setPkiArcPage((p) => p + 1),
                            )
                          }
                        >
                          Next →
                        </button>
                      </div>
                    </div>

                    <div className="pki-legend" aria-label="PKI map legend">
                      <div className="pki-legend-row">
                        <span className="pki-legend-item">
                          <i
                            className="pki-legend-swatch"
                            style={{ background: PKI_SEVERITY_COLORS.critical }}
                          />
                          Critical
                        </span>
                        <span className="pki-legend-item">
                          <i
                            className="pki-legend-swatch"
                            style={{ background: PKI_SEVERITY_COLORS.high }}
                          />
                          High
                        </span>
                        <span className="pki-legend-item">
                          <i
                            className="pki-legend-swatch"
                            style={{ background: PKI_SEVERITY_COLORS.medium }}
                          />
                          Medium
                        </span>
                        <span className="pki-legend-item">
                          <i
                            className="pki-legend-swatch"
                            style={{ background: PKI_SEVERITY_COLORS.low }}
                          />
                          Low
                        </span>
                      </div>
                      <div className="pki-legend-row pki-legend-line-styles">
                        <span className="pki-legend-item">
                          <i className="pki-legend-line solid" />
                          KEV solid
                        </span>
                        <span className="pki-legend-item">
                          <i className="pki-legend-line dashed" />
                          NVD dotted
                        </span>
                      </div>
                    </div>

                    <div className="pki-cve-list" aria-label="PKI-related CVEs">
                      {pkiVisibleCves.slice(0, 60).map((cve) => {
                        const destCount =
                          cve.exposureIso3s?.length ||
                          previewHotspotLinks(pkiPreview, cve.id);
                        const focused = pkiFocusCve === cve.id;
                        return (
                          <article
                            key={cve.id}
                            className={`pki-cve-card severity-${cve.severity}${
                              focused ? " pki-cve-card-focused" : ""
                            }`}
                          >
                            <div className="pki-cve-heading">
                              <strong>{cve.id}</strong>
                              <span
                                className="pki-severity-pill"
                                style={{
                                  background: PKI_SEVERITY_COLORS[cve.severity],
                                }}
                              >
                                {cve.severity}
                                {cve.cvss != null
                                  ? ` · CVSS ${cve.cvss.toFixed(1)}`
                                  : ""}
                              </span>
                              {cve.knownExploited && (
                                <span className="pki-kev-pill">KEV</span>
                              )}
                              {!cve.knownExploited && (
                                <span className="pki-nvd-pill">NVD</span>
                              )}
                            </div>
                            <p className="pki-cve-title">{cve.title}</p>
                            <p className="pki-cve-meta">
                              {[cve.vendor, cve.product]
                                .filter(Boolean)
                                .join(" · ") || "Vendor / product unspecified"}
                              {" · "}
                              {destCount} exposure{" "}
                              {destCount === 1 ? "country" : "countries"}
                            </p>
                            <div className="pki-cve-tags">
                              {cve.categories.map((cat) => (
                                <span key={`${cve.id}-${cat}`}>
                                  {PKI_CATEGORY_LABELS[cat] || cat}
                                </span>
                              ))}
                            </div>
                            <div className="un-goal-meta pki-cve-actions">
                              <button
                                type="button"
                                className={focused ? "active" : ""}
                                onClick={() =>
                                  runRateLimitedButtonAction(
                                    `pki-focus-${cve.id}`,
                                    () => {
                                      setPkiFocusCve(focused ? null : cve.id);
                                      setPkiShowMap(true);
                                      setPkiArcPage(0);
                                    },
                                  )
                                }
                              >
                                {focused ? "Unfocus map" : "Show on map"}
                              </button>
                              <a
                                href={safeGlobeHref(cve.nvdUrl)}
                                target="_blank"
                                rel="noopener noreferrer"
                              >
                                NVD
                              </a>
                              {cve.cisaUrl && (
                                <a
                                  href={safeGlobeHref(cve.cisaUrl)}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                >
                                  CISA KEV
                                </a>
                              )}
                            </div>
                          </article>
                        );
                      })}
                    </div>
                    <div className="un-footer">
                      <span>{formatPreviewDate(pkiPreview.updatedAt)}</span>
                      <div className="un-footer-actions">
                        <a
                          href={safeGlobeHref(pkiPreview.cisaKevUrl)}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          CISA KEV
                        </a>
                        <a
                          href={safeGlobeHref(pkiPreview.nvdUrl)}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          NVD
                        </a>
                        <button
                          type="button"
                          onClick={() =>
                            runRateLimitedButtonAction("pki-refresh", () => {
                              void loadPkiVulns(false, { forceRefresh: true });
                            })
                          }
                        >
                          Refresh
                        </button>
                      </div>
                    </div>
                  </>
                )}
              </div>
            </div>
          )}
        </FloatingChrome>
      )}{showUnodcPanel && !showUnHub && (
        <FloatingChrome
          className={`un-panel unodc-panel ${
            isUnodcPanelMinimized ? "un-panel-minimized" : ""
          }`}
          role="dialog"
          aria-label="UNODC theme hotspots"
        >
          <div className="un-panel-header">
            <div>
              <h3>UNODC Hotspots</h3>
              <span>
                {unodcStatus === "ready" && unodcPreview
                  ? unodcPreview.queryLabel
                  : "Data Portal themes"}
              </span>
            </div>
            <div className="un-panel-actions">
              <button
                type="button"
                className="un-minimize"
                onClick={() =>
                  runRateLimitedButtonAction("unodc-minimize", () =>
                    setIsUnodcPanelMinimized((m) => !m),
                  )
                }
                aria-label={
                  isUnodcPanelMinimized ? "Expand UNODC panel" : "Minimize UNODC panel"
                }
              >
                {isUnodcPanelMinimized ? "+" : "_"}
              </button>
              <button
                type="button"
                className="un-close"
                onClick={() =>
                  runRateLimitedButtonAction("unodc-close", () => {
                    setShowUnodcPanel(false);
                  })
                }
                aria-label="Close UNODC panel"
              >
                x
              </button>
            </div>
          </div>

          {!isUnodcPanelMinimized && (
            <div className="trade-pulse-panel-scroll">
              <div className="trade-pulse-panel-inner">
                {unodcStatus === "loading" && (
                  <div className="un-loading">Loading UNODC themes…</div>
                )}
                {unodcStatus === "error" && (
                  <div className="un-error">
                    <span>{unodcError}</span>
                    <button
                      type="button"
                      onClick={() =>
                        runRateLimitedButtonAction("unodc-retry", () => {
                          void loadUnodcHotspots(false);
                        })
                      }
                    >
                      Retry
                    </button>
                  </div>
                )}
                {unodcStatus === "ready" && unodcPreview && (
                  <>
                    <div className="un-status-row">
                      <span>{unodcPreview.source}</span>
                      <strong>
                        {Object.values(unodcThemes).filter(Boolean).length} on globe
                        · {unodcCountryPolygons ? "choropleth" : "heat"}
                      </strong>
                    </div>
                    <div className="unodc-mode-row" role="group" aria-label="Theme focus">
                      <button
                        type="button"
                        className="trade-pulse-year-btn active"
                        onClick={() =>
                          runRateLimitedButtonAction("unodc-mode-focus", () =>
                            setUnodcFocusMode("focus"),
                          )
                        }
                      >
                        Focus
                      </button>
                      <button
                        type="button"
                        className="trade-pulse-year-btn"
                        onClick={() =>
                          runRateLimitedButtonAction("unodc-mode-all", () =>
                            setUnodcFocusMode("all-live"),
                          )
                        }
                      >
                        All live
                      </button>
                      <button
                        type="button"
                        className="trade-pulse-year-btn"
                        onClick={() =>
                          runRateLimitedButtonAction("unodc-mode-none", () =>
                            setUnodcFocusMode("none"),
                          )
                        }
                      >
                        Clear
                      </button>
                    </div>
                    <div className="un-status-row unodc-live-count">
                      <span>
                        {countLiveUnodcThemes(unodcPreview)}/
                        {unodcPreview.themes.length} themes with country data
                      </span>
                      {countLiveUnodcThemes(unodcPreview) <
                        unodcPreview.themes.length && (
                        <button
                          type="button"
                          className="trade-pulse-year-btn"
                          onClick={() =>
                            runRateLimitedButtonAction("unodc-reload-all", () => {
                              void loadUnodcHotspots(false, {
                                forceRefresh: true,
                              });
                            })
                          }
                        >
                          Reload all themes
                        </button>
                      )}
                    </div>
                    <div className="unodc-legend" aria-label="Theme colors">
                      {unodcPreview.themes.map((theme) => {
                        const canToggle =
                          theme.dataMode === "live" && theme.hotspotCount > 0;
                        return (
                          <button
                            type="button"
                            key={`legend-${theme.id}`}
                            className={`unodc-legend-item ${
                              unodcThemes[theme.id] ? "active" : ""
                            } ${canToggle ? "" : "disabled"}`}
                            disabled={!canToggle}
                            title={
                              canToggle
                                ? theme.label
                                : `${theme.label} — no country series yet`
                            }
                            onClick={() =>
                              runRateLimitedButtonAction(
                                `unodc-legend-${theme.id}`,
                                () => toggleUnodcTheme(theme.id),
                              )
                            }
                          >
                            <i
                              className="unodc-legend-swatch"
                              style={{ background: UNODC_THEME_CSS[theme.id] }}
                            />
                            <span>{theme.label}</span>
                          </button>
                        );
                      })}
                    </div>
                    <div className="un-goal-list" aria-label="UNODC themes">
                      {unodcPreview.themes.map((theme) => {
                        const canToggle =
                          theme.dataMode === "live" && theme.hotspotCount > 0;
                        return (
                          <article
                            className={`un-goal-row unodc-theme-card ${
                              unodcThemes[theme.id] ? "active" : ""
                            } ${canToggle ? "" : "is-unavailable"}`}
                            key={theme.id}
                            style={
                              {
                                "--unodc-theme-color": UNODC_THEME_CSS[theme.id],
                              } as React.CSSProperties
                            }
                          >
                            <div className="un-goal-heading">
                              <span>
                                <i
                                  className="unodc-legend-swatch"
                                  style={{
                                    background: UNODC_THEME_CSS[theme.id],
                                  }}
                                />{" "}
                                {theme.label}
                              </span>
                              <strong>
                                {canToggle
                                  ? `${theme.hotspotCount} areas`
                                  : "No country data"}
                              </strong>
                            </div>
                            <p>
                              {theme.seriesLabel}
                              {theme.period ? ` · ${theme.period}` : ""}
                              {theme.unit ? ` · ${theme.unit}` : ""}
                            </p>
                            {theme.note && (
                              <p className="trade-pulse-insight">{theme.note}</p>
                            )}
                            <div className="un-goal-meta">
                              <button
                                type="button"
                                className={`trade-pulse-year-btn ${
                                  unodcThemes[theme.id] ? "active" : ""
                                }`}
                                aria-pressed={unodcThemes[theme.id]}
                                disabled={!canToggle}
                                title={
                                  canToggle
                                    ? undefined
                                    : "No open country hotspots for this theme yet"
                                }
                                onClick={() =>
                                  runRateLimitedButtonAction(
                                    `unodc-theme-${theme.id}`,
                                    () => toggleUnodcTheme(theme.id),
                                  )
                                }
                              >
                                {unodcThemes[theme.id] ? "On globe" : "Off"}
                              </button>
                              <a
                                href={safeGlobeHref(theme.portalUrl)}
                                target="_blank"
                                rel="noopener noreferrer"
                              >
                                Portal
                              </a>
                            </div>
                            {unodcThemes[theme.id] &&
                              theme.hotspots.length > 0 && (
                                <div className="unodc-hotspot-list">
                                  {theme.hotspots.slice(0, 8).map((spot) => (
                                    <span key={spot.id}>
                                      {spot.iso3} {spot.value}
                                      <small> ({spot.year})</small>
                                    </span>
                                  ))}
                                </div>
                              )}
                          </article>
                        );
                      })}
                    </div>
                    <div className="un-footer">
                      <span>{formatPreviewDate(unodcPreview.updatedAt)}</span>
                      <div className="un-footer-actions">
                        <a
                          href={safeGlobeHref(unodcPreview.datasearchUrl)}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          Datasearch
                        </a>
                        <a
                          href={safeGlobeHref(unodcPreview.sourceUrl)}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          Portal
                        </a>
                        <button
                          type="button"
                          onClick={() =>
                            runRateLimitedButtonAction("unodc-refresh", () => {
                              void loadUnodcHotspots(false, {
                                forceRefresh: true,
                              });
                            })
                          }
                        >
                          Refresh
                        </button>
                      </div>
                    </div>
                  </>
                )}
              </div>
            </div>
          )}
        </FloatingChrome>
      )}
    </>
  );
}
