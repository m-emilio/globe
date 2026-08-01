import React from "react";
import type {
  PkiVulnCve,
  PkiVulnSeverity,
  PkiVulnsPreview,
} from "../shared";
import { safeGlobeHref } from "./safeUrl";

export type PkiHubStatus = "idle" | "loading" | "ready" | "error";
export type PkiHubCatalog = "all" | "kev" | "nvd";
export type PkiHubSort =
  | "priority"
  | "severity"
  | "cvss"
  | "newest"
  | "vendor"
  | "cve";
export type PkiHubDensity = "sparse" | "balanced" | "dense";

export type PkiHubArcStats = {
  visible: number;
  total: number;
  page: number;
  pageCount: number;
  kevCount: number;
  nvdCount: number;
};

export type PkiHubProps = {
  onClose: () => void;
  onViewGlobe: () => void;

  layerOn: boolean;
  status: PkiHubStatus;
  error: string;
  preview: PkiVulnsPreview | null;
  visibleCves: PkiVulnCve[];
  arcStats: PkiHubArcStats;

  showMap: boolean;
  catalog: PkiHubCatalog;
  density: PkiHubDensity;
  sort: PkiHubSort;
  sortLabels: Record<PkiHubSort, string>;
  severities: Set<PkiVulnSeverity>;
  severityColors: Record<PkiVulnSeverity, string>;
  category: string | "all";
  categoryLabels: Record<string, string>;
  focusCve: string | null;

  onToggleLayer: () => void;
  onToggleMap: () => void;
  onSetCatalog: (v: PkiHubCatalog) => void;
  onSetDensity: (v: PkiHubDensity) => void;
  onSetSort: (v: PkiHubSort) => void;
  onToggleSeverity: (s: PkiVulnSeverity) => void;
  onSetCategory: (v: string | "all") => void;
  onPagePrev: () => void;
  onPageNext: () => void;
  onFocusCve: (id: string | null) => void;
  onRefresh: () => void;
  formatUpdatedAt: (iso: string) => string;
  exposureCount: (cve: PkiVulnCve) => number;
};

function statusLabel(status: PkiHubStatus, error: string) {
  if (status === "loading") return "Loading…";
  if (status === "error") return error || "Unavailable";
  if (status === "ready") return "Ready";
  return "Off";
}

export function PkiHubPage(props: PkiHubProps) {
  const {
    onClose,
    onViewGlobe,
    layerOn,
    status,
    error,
    preview,
    visibleCves,
    arcStats,
    showMap,
    catalog,
    density,
    sort,
    sortLabels,
    severities,
    severityColors,
    category,
    categoryLabels,
    focusCve,
    onToggleLayer,
    onToggleMap,
    onSetCatalog,
    onSetDensity,
    onSetSort,
    onToggleSeverity,
    onSetCategory,
    onPagePrev,
    onPageNext,
    onFocusCve,
    onRefresh,
    formatUpdatedAt,
    exposureCount,
  } = props;

  return (
    <div
      className="un-hub pki-hub"
      role="dialog"
      aria-modal="true"
      aria-label="PKI and CVE exposure hub"
    >
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
                🔐
              </span>{" "}
              PKI / CVE Hub
            </h1>
            <p>
              Certificate · TLS · crypto-key exposure ·{" "}
              {layerOn && showMap
                ? `${arcStats.visible}/${arcStats.total} arcs`
                : layerOn
                  ? "layer on, arcs off"
                  : "layer off"}
            </p>
          </div>
        </div>
        <button type="button" className="un-hub-globe-btn" onClick={onViewGlobe}>
          View globe
        </button>
      </header>

      <div className="un-hub-scroll">
        <p className="un-hub-intro">
          Toggle certificate and PKI vulnerability arcs on the globe. Filter,
          sort, and page for performance — then return to the map.
        </p>

        <section className="un-hub-card" aria-labelledby="pki-hub-main-title">
          <div className="un-hub-card-head">
            <div>
              <h2 id="pki-hub-main-title">Exposure layer</h2>
              <span className="un-hub-status">
                {statusLabel(status, error)}
                {preview
                  ? ` · ${preview.cveCount} CVEs · ${arcStats.kevCount} KEV · ${arcStats.nvdCount} NVD`
                  : ""}
              </span>
            </div>
            <button
              type="button"
              className={`un-hub-master ${layerOn ? "on" : ""}`}
              aria-pressed={layerOn}
              onClick={onToggleLayer}
            >
              {layerOn ? "On globe" : "Off"}
            </button>
          </div>
          <p className="un-hub-card-desc">
            Vendor origin → deployment/exposure countries. Solid = CISA KEV
            (known exploited). Dotted = NVD catalog.
          </p>

          {layerOn && (
            <div className="un-hub-card-body">
              {status === "loading" && (
                <p className="un-hub-status">Loading CISA KEV + NVD feed…</p>
              )}
              {status === "error" && (
                <div className="pki-hub-error">
                  <span>{error || "Feed unavailable"}</span>
                  <button type="button" className="un-hub-secondary" onClick={onRefresh}>
                    Retry
                  </button>
                </div>
              )}

              {(status === "ready" || preview) && (
                <>
                  <div className="un-hub-row-label">Map display</div>
                  <div className="un-hub-chip-row" role="group" aria-label="Map display">
                    <button
                      type="button"
                      className={`un-hub-chip ${showMap ? "active" : ""}`}
                      aria-pressed={showMap}
                      onClick={onToggleMap}
                    >
                      {showMap ? "Arcs on" : "Arcs off"}
                    </button>
                    {focusCve && (
                      <button
                        type="button"
                        className="un-hub-chip active"
                        onClick={() => onFocusCve(null)}
                      >
                        Clear focus · {focusCve}
                      </button>
                    )}
                  </div>

                  <div className="un-hub-row-label">Catalog</div>
                  <div className="un-hub-chip-row" role="group" aria-label="Catalog filter">
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
                        className={`un-hub-chip ${catalog === id ? "active" : ""}`}
                        aria-pressed={catalog === id}
                        onClick={() => onSetCatalog(id)}
                      >
                        {label}
                      </button>
                    ))}
                  </div>

                  <div className="un-hub-row-label">Density (performance)</div>
                  <div className="un-hub-chip-row" role="group" aria-label="Arc density">
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
                        className={`un-hub-chip ${density === id ? "active" : ""}`}
                        aria-pressed={density === id}
                        onClick={() => onSetDensity(id)}
                      >
                        {label}
                      </button>
                    ))}
                  </div>

                  <div className="un-hub-row-label">Sort</div>
                  <div className="un-hub-chip-row" role="group" aria-label="Sort arcs">
                    {(Object.keys(sortLabels) as PkiHubSort[]).map((id) => (
                      <button
                        key={id}
                        type="button"
                        className={`un-hub-chip ${sort === id ? "active" : ""}`}
                        aria-pressed={sort === id}
                        onClick={() => onSetSort(id)}
                      >
                        {sortLabels[id]}
                      </button>
                    ))}
                  </div>

                  <div className="un-hub-row-label">Severity</div>
                  <div className="un-hub-chip-row" role="group" aria-label="Severity filter">
                    {(
                      ["critical", "high", "medium", "low"] as PkiVulnSeverity[]
                    ).map((sev) => {
                      const on = severities.has(sev);
                      return (
                        <button
                          key={sev}
                          type="button"
                          className={`un-hub-chip ${on ? "active" : ""}`}
                          aria-pressed={on}
                          style={
                            on
                              ? { borderColor: severityColors[sev] }
                              : undefined
                          }
                          onClick={() => onToggleSeverity(sev)}
                        >
                          {sev}
                        </button>
                      );
                    })}
                  </div>

                  <div className="un-hub-row-label">Class</div>
                  <div className="un-hub-chip-row" role="group" aria-label="Category filter">
                    <button
                      type="button"
                      className={`un-hub-chip ${category === "all" ? "active" : ""}`}
                      aria-pressed={category === "all"}
                      onClick={() => onSetCategory("all")}
                    >
                      All classes
                    </button>
                    {Object.entries(categoryLabels).map(([id, label]) => (
                      <button
                        key={id}
                        type="button"
                        className={`un-hub-chip ${category === id ? "active" : ""}`}
                        aria-pressed={category === id}
                        onClick={() => onSetCategory(id)}
                      >
                        {label}
                      </button>
                    ))}
                  </div>

                  <div className="un-hub-row-label">Arc pages</div>
                  <div className="pki-hub-pager" role="group" aria-label="Arc pages">
                    <button
                      type="button"
                      className="un-hub-chip"
                      disabled={arcStats.page <= 0}
                      onClick={onPagePrev}
                    >
                      ← Prev
                    </button>
                    <span className="pki-hub-pager-status">
                      Page {arcStats.page + 1}/{arcStats.pageCount}
                      {arcStats.total > 0
                        ? ` · ${arcStats.visible} of ${arcStats.total}`
                        : ""}
                    </span>
                    <button
                      type="button"
                      className="un-hub-chip"
                      disabled={arcStats.page >= arcStats.pageCount - 1}
                      onClick={onPageNext}
                    >
                      Next →
                    </button>
                  </div>

                  <div className="pki-hub-legend" aria-label="Severity legend">
                    <span>
                      <i style={{ background: severityColors.critical }} /> Critical
                    </span>
                    <span>
                      <i style={{ background: severityColors.high }} /> High
                    </span>
                    <span>
                      <i style={{ background: severityColors.medium }} /> Medium
                    </span>
                    <span>
                      <i style={{ background: severityColors.low }} /> Low
                    </span>
                    <span className="pki-hub-legend-line solid">KEV solid</span>
                    <span className="pki-hub-legend-line dotted">NVD dotted</span>
                  </div>

                  <div className="un-hub-row-label">
                    CVEs ({visibleCves.length}
                    {preview ? ` / ${preview.cveCount}` : ""})
                  </div>
                  <div className="pki-hub-cve-list" aria-label="PKI-related CVEs">
                    {visibleCves.slice(0, 60).map((cve) => {
                      const destCount = exposureCount(cve);
                      const focused = focusCve === cve.id;
                      return (
                        <article
                          key={cve.id}
                          className={`pki-hub-cve-card severity-${cve.severity}${
                            focused ? " focused" : ""
                          }`}
                        >
                          <div className="pki-hub-cve-heading">
                            <strong>{cve.id}</strong>
                            <span
                              className="pki-hub-sev-pill"
                              style={{ background: severityColors[cve.severity] }}
                            >
                              {cve.severity}
                              {cve.cvss != null
                                ? ` · CVSS ${cve.cvss.toFixed(1)}`
                                : ""}
                            </span>
                            {cve.knownExploited ? (
                              <span className="pki-hub-kev-pill">KEV</span>
                            ) : (
                              <span className="pki-hub-nvd-pill">NVD</span>
                            )}
                          </div>
                          <p className="pki-hub-cve-title">{cve.title}</p>
                          <p className="pki-hub-cve-meta">
                            {[cve.vendor, cve.product]
                              .filter(Boolean)
                              .join(" · ") || "Vendor / product unspecified"}
                            {" · "}
                            {destCount} exposure{" "}
                            {destCount === 1 ? "country" : "countries"}
                          </p>
                          <div className="pki-hub-cve-tags">
                            {cve.categories.map((cat) => (
                              <span key={`${cve.id}-${cat}`}>
                                {categoryLabels[cat] || cat}
                              </span>
                            ))}
                          </div>
                          <div className="pki-hub-cve-actions">
                            <button
                              type="button"
                              className={focused ? "active" : ""}
                              onClick={() =>
                                onFocusCve(focused ? null : cve.id)
                              }
                            >
                              {focused ? "Unfocus map" : "Show on map"}
                            </button>
                            {safeGlobeHref(cve.nvdUrl) && (
                              <a
                                href={safeGlobeHref(cve.nvdUrl)}
                                target="_blank"
                                rel="noopener noreferrer"
                              >
                                NVD
                              </a>
                            )}
                            {safeGlobeHref(cve.cisaUrl) && (
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

                  <button
                    type="button"
                    className="un-hub-secondary"
                    onClick={onRefresh}
                    disabled={status === "loading"}
                  >
                    Refresh feed
                  </button>

                  {preview && (
                    <div className="pki-hub-sources">
                      <span>{formatUpdatedAt(preview.updatedAt)}</span>
                      {safeGlobeHref(preview.cisaKevUrl) && (
                        <a
                          href={safeGlobeHref(preview.cisaKevUrl)}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          CISA KEV
                        </a>
                      )}
                      {safeGlobeHref(preview.nvdUrl) && (
                        <a
                          href={safeGlobeHref(preview.nvdUrl)}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          NVD
                        </a>
                      )}
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </section>

        <footer className="un-hub-footer">
          <button
            type="button"
            className="un-hub-globe-btn wide"
            onClick={onViewGlobe}
          >
            Apply &amp; view globe
          </button>
          <p>
            Situational awareness only — not exploit geolocation or attacker
            attribution. Sources: CISA KEV + NVD.
          </p>
        </footer>
      </div>
    </div>
  );
}
