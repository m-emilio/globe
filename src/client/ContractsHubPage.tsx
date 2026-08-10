import React, { useMemo, useState } from "react";
import type { SamContractsPreview, SamOpportunityPreview } from "../shared";
import { safeGlobeHref } from "./safeUrl";

export type ContractsHubStatus = "idle" | "loading" | "ready" | "error";
/** Same entitlement as Transit / Live Feed (login + Stripe when enforced). */
export type ContractsAccess = "ok" | "login_required" | "payment_required";

export type ContractsHubProps = {
  onClose: () => void;
  onViewGlobe: () => void;
  status: ContractsHubStatus;
  error: string;
  preview: SamContractsPreview | null;
  layerOn: boolean;
  access: ContractsAccess;
  checkoutBusy?: boolean;
  onSignIn: () => void;
  onBuyAccess: () => void;
  onToggleLayer: () => void;
  onSearch: (opts: {
    preset: string;
    q: string;
    days: number;
    setAside: string;
    naicsGroup: string;
    includeAwards: boolean;
    force?: boolean;
  }) => void;
  formatUpdatedAt: (iso: string) => string;
};

function statusLabel(status: ContractsHubStatus, error: string) {
  if (status === "loading") return "Loading…";
  if (status === "error") return error || "Unavailable";
  if (status === "ready") return "Ready";
  return "Idle";
}

function OppCard({
  opp,
  onFocus,
}: {
  opp: SamOpportunityPreview;
  onFocus?: () => void;
}) {
  const href = safeGlobeHref(opp.url);
  return (
    <article className="contracts-opp-card">
      <div className="contracts-opp-head">
        <h3>{opp.title}</h3>
        {opp.setAsideCode ? (
          <span className="contracts-badge contracts-badge-sb">
            {opp.setAsideCode}
          </span>
        ) : null}
      </div>
      <p className="contracts-opp-meta">
        {opp.solicitationNumber ? (
          <>
            Sol #: <code>{opp.solicitationNumber}</code>
            {" · "}
          </>
        ) : null}
        {opp.type ? <>{opp.type} · </> : null}
        Posted: {opp.postedDate || "—"}
        {opp.responseDeadline ? <> · Due: {opp.responseDeadline}</> : null}
      </p>
      {opp.department ? (
        <p className="contracts-opp-dept">{opp.department}</p>
      ) : null}
      <div className="contracts-opp-tags">
        {opp.naics ? (
          <span className="contracts-tag">
            NAICS {opp.naics}
            {opp.naicsLabel ? ` · ${opp.naicsLabel}` : ""}
          </span>
        ) : null}
        {opp.setAside ? (
          <span className="contracts-tag">{opp.setAside}</span>
        ) : null}
        {opp.placeLabel ? (
          <span className="contracts-tag contracts-tag-geo">
            📍 {opp.placeLabel}
          </span>
        ) : (
          <span className="contracts-tag muted">No map location</span>
        )}
      </div>
      {opp.descriptionExcerpt ? (
        <p className="contracts-opp-desc">{opp.descriptionExcerpt}</p>
      ) : null}
      <div className="contracts-opp-actions">
        {opp.lat != null && opp.lng != null && onFocus ? (
          <button type="button" className="un-hub-linkish" onClick={onFocus}>
            Show on globe
          </button>
        ) : null}
        {href ? (
          <a
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            className="un-hub-linkish"
          >
            Open on SAM.gov
          </a>
        ) : null}
      </div>
    </article>
  );
}

export function ContractsHubPage(props: ContractsHubProps) {
  const {
    onClose,
    onViewGlobe,
    status,
    error,
    preview,
    layerOn,
    access,
    checkoutBusy = false,
    onSignIn,
    onBuyAccess,
    onToggleLayer,
    onSearch,
    formatUpdatedAt,
  } = props;
  const locked = access !== "ok";

  const catalog = preview?.catalog;
  const presets = catalog?.presets ?? {
    pki: "Public Key Infrastructure (PKI)",
    cyber: "Cybersecurity & zero trust",
    software: "Software design & engineering",
    awards: "Awards & small business notices",
  };
  const groups = catalog?.groups ?? {
    fk_pki: { label: "PKI / identity / cyber", codes: [] },
    fk_core: { label: "Software & systems design", codes: [] },
    fk_all: { label: "All FederalKey-relevant NAICS", codes: [] },
  };
  const setAsides = catalog?.setAsides ?? {
    any: "Any (no set-aside filter)",
    ANY_SB: "Any small business set-aside",
    SBA: "Total Small Business Set-Aside (SBA)",
    "8A": "8(a) Set-Aside",
    HZC: "HUBZone Set-Aside",
    SDVOSBC: "SDVOSB Set-Aside",
    WOSB: "Women-Owned Small Business (WOSB)",
  };

  const [preset, setPreset] = useState(preview?.preset || "pki");
  const [q, setQ] = useState(preview?.filters?.q || "");
  const [days, setDays] = useState(preview?.filters?.days || 30);
  const [setAside, setSetAside] = useState(preview?.filters?.setAside || "");
  const [naicsGroup, setNaicsGroup] = useState(
    preview?.filters?.naicsGroup || "fk_pki",
  );
  const [includeAwards, setIncludeAwards] = useState(
    preview?.filters?.includeAwards ?? true,
  );
  const [filterLocal, setFilterLocal] = useState("");

  const opps = useMemo(() => {
    const list = preview?.opportunities ?? [];
    const f = filterLocal.trim().toLowerCase();
    if (!f) return list;
    return list.filter((o) => {
      const hay = [
        o.title,
        o.department,
        o.naics,
        o.setAside,
        o.placeLabel,
        o.solicitationNumber,
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(f);
    });
  }, [preview, filterLocal]);

  const runSearch = (force = false) => {
    onSearch({
      preset,
      q,
      days,
      setAside,
      naicsGroup,
      includeAwards,
      force,
    });
  };

  return (
    <div
      className="un-hub contracts-hub"
      role="dialog"
      aria-modal="true"
      aria-label="Federal contracting opportunities"
    >
      <header className="un-hub-header">
        <div className="un-hub-header-main">
          <button
            type="button"
            className="un-hub-back"
            onClick={onClose}
            aria-label="Close contracting hub"
          >
            ←
          </button>
          <div>
            <h1>Contracting</h1>
            <p>SAM.gov · PKI · NAICS · small business set-asides</p>
          </div>
        </div>
        <button
          type="button"
          className="un-hub-globe-btn"
          onClick={onViewGlobe}
        >
          Globe
        </button>
      </header>

      <div className="un-hub-scroll contracts-hub-scroll">
        <section className="un-hub-intro">
          <p>
            Search official{" "}
            <strong>SAM.gov contract opportunities</strong> for PKI, cyber, and
            FederalKey-aligned NAICS. Small business set-asides and awards are
            first-class filters. Results plot on the globe by place of
            performance. Notices remain public on SAM.gov — you pay for
            FederalKey search, map pins, and workflow (same unlock as Transit /
            Live Feed). API keys stay in Cloudflare secrets only.
          </p>
        </section>

        {locked ? (
          <section className="un-hub-card contracts-gate-card">
            <div className="un-hub-card-head">
              <h2>Paid unlock required</h2>
              <span className="un-hub-status">
                {access === "login_required" ? "Sign in" : "Payment"}
              </span>
            </div>
            <p className="un-hub-card-desc">
              {access === "login_required"
                ? "Sign in with your device-local OpenPGP key, then unlock with Stripe ($20) to use Contracting."
                : "Stripe access ($20) unlocks Contracting, Transit, Nearby maps, Live Feed, and support chat. Source data is public SAM.gov opportunities."}
            </p>
            <div className="contracts-actions">
              {access === "login_required" ? (
                <button
                  type="button"
                  className="un-hub-master on"
                  onClick={onSignIn}
                >
                  Sign in
                </button>
              ) : (
                <button
                  type="button"
                  className="un-hub-master on"
                  disabled={checkoutBusy}
                  onClick={onBuyAccess}
                >
                  {checkoutBusy ? "Opening Stripe…" : "Buy Stripe access ($20)"}
                </button>
              )}
              <a
                className="un-hub-linkish"
                href="https://sam.gov/opportunities"
                target="_blank"
                rel="noopener noreferrer"
              >
                Browse free on SAM.gov
              </a>
            </div>
            {error ? (
              <p className="contracts-error" role="alert" style={{ marginTop: 12 }}>
                {error}
              </p>
            ) : null}
          </section>
        ) : null}

        <section className="un-hub-card">
          <div className="un-hub-card-head">
            <h2>Search</h2>
            <span className="un-hub-status">
              {locked ? "Locked" : statusLabel(status, error)}
            </span>
          </div>
          <div className="un-hub-card-body contracts-search-form">
            <label className="contracts-field">
              <span>Sector preset</span>
              <select
                value={preset}
                onChange={(e) => setPreset(e.target.value)}
              >
                {Object.entries(presets).map(([id, label]) => (
                  <option key={id} value={id}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
            <label className="contracts-field">
              <span>Keywords</span>
              <input
                type="search"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="e.g. certificate authority, HSM, ICAM"
                enterKeyHint="search"
                onKeyDown={(e) => {
                  if (e.key === "Enter") runSearch(false);
                }}
              />
            </label>
            <div className="contracts-field-row">
              <label className="contracts-field">
                <span>Lookback (days)</span>
                <input
                  type="number"
                  min={1}
                  max={180}
                  value={days}
                  onChange={(e) =>
                    setDays(
                      Math.max(
                        1,
                        Math.min(180, Number(e.target.value) || 30),
                      ),
                    )
                  }
                />
              </label>
              <label className="contracts-field">
                <span>Set-aside</span>
                <select
                  value={setAside || "any"}
                  onChange={(e) => {
                    const v = e.target.value;
                    setSetAside(v === "any" ? "" : v);
                  }}
                >
                  {Object.entries(setAsides).map(([code, label]) => (
                    <option key={code} value={code}>
                      {label}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <label className="contracts-field">
              <span>NAICS group</span>
              <select
                value={naicsGroup}
                onChange={(e) => setNaicsGroup(e.target.value)}
              >
                <option value="">None (keywords only)</option>
                {Object.entries(groups).map(([id, g]) => (
                  <option key={id} value={id}>
                    {g.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="contracts-check">
              <input
                type="checkbox"
                checked={includeAwards}
                onChange={(e) => setIncludeAwards(e.target.checked)}
              />
              <span>Include award notices</span>
            </label>
            <div className="contracts-quick-chips" role="group" aria-label="Quick set-aside">
              {(
                [
                  ["", "Any"],
                  ["ANY_SB", "Any SB"],
                  ["SBA", "SBA"],
                  ["8A", "8(a)"],
                  ["HZC", "HUBZone"],
                  ["SDVOSBC", "SDVOSB"],
                  ["WOSB", "WOSB"],
                ] as const
              ).map(([code, label]) => (
                <button
                  key={code || "any"}
                  type="button"
                  className={`un-hub-chip ${setAside === code ? "active" : ""}`}
                  onClick={() => setSetAside(code)}
                >
                  {label}
                </button>
              ))}
            </div>
            <div className="contracts-actions">
              <button
                type="button"
                className="un-hub-master on"
                disabled={locked || status === "loading"}
                onClick={() => runSearch(false)}
              >
                {status === "loading" ? "Searching…" : "Search SAM.gov"}
              </button>
              <button
                type="button"
                className="un-hub-chip"
                disabled={locked || status === "loading"}
                onClick={() => runSearch(true)}
              >
                Force refresh
              </button>
            </div>
          </div>
        </section>

        <section className="un-hub-card">
          <div className="un-hub-card-head">
            <h2>Globe layer</h2>
            <span className="un-hub-status">
              {layerOn
                ? `${preview?.markerCount ?? 0} pins`
                : "Off"}
            </span>
          </div>
          <p className="un-hub-card-desc">
            Plot each opportunity with place-of-performance coordinates on the
            3D globe. Small-business set-asides use slightly larger pins.
          </p>
          <div className="un-hub-card-body">
            <button
              type="button"
              className={`un-hub-master ${layerOn ? "on" : ""}`}
              onClick={onToggleLayer}
              disabled={!preview || (preview.markerCount ?? 0) === 0}
            >
              {layerOn ? "Hide pins on globe" : "Show pins on globe"}
            </button>
            {layerOn ? (
              <button
                type="button"
                className="un-hub-globe-btn wide"
                style={{ marginTop: 10 }}
                onClick={onViewGlobe}
              >
                View globe with pins
              </button>
            ) : null}
          </div>
        </section>

        {status === "error" && error ? (
          <section className="un-hub-card">
            <p className="contracts-error" role="alert">
              {error}
            </p>
          </section>
        ) : null}

        {preview ? (
          <section className="un-hub-card">
            <div className="un-hub-card-head">
              <h2>
                Results{" "}
                <span className="contracts-count">
                  {opps.length}
                  {filterLocal ? ` / ${preview.opportunityCount}` : ""}
                </span>
              </h2>
              <span className="un-hub-status">
                {preview.dataMode}
                {preview.updatedAt
                  ? ` · ${formatUpdatedAt(preview.updatedAt)}`
                  : ""}
              </span>
            </div>
            <p className="un-hub-card-desc">{preview.queryLabel}</p>
            <label className="contracts-field" style={{ marginBottom: 10 }}>
              <span>Filter this list</span>
              <input
                type="search"
                value={filterLocal}
                onChange={(e) => setFilterLocal(e.target.value)}
                placeholder="Filter by title, NAICS, place…"
              />
            </label>
            {opps.length === 0 ? (
              <p className="muted">
                No opportunities in this result set. Broaden keywords, set-aside,
                or lookback days.
              </p>
            ) : (
              <div className="contracts-opp-list">
                {opps.map((opp) => (
                  <OppCard
                    key={opp.id}
                    opp={opp}
                    onFocus={
                      opp.lat != null
                        ? () => {
                            if (!layerOn) onToggleLayer();
                            onViewGlobe();
                          }
                        : undefined
                    }
                  />
                ))}
              </div>
            )}
            {preview.notes?.length ? (
              <ul className="contracts-notes">
                {preview.notes.map((n, i) => (
                  <li key={i}>{n}</li>
                ))}
              </ul>
            ) : null}
            <p className="contracts-source">
              Source:{" "}
              <a
                href={safeGlobeHref(preview.sourceUrl) || "#"}
                target="_blank"
                rel="noopener noreferrer"
              >
                {preview.source}
              </a>
            </p>
          </section>
        ) : (
          <section className="un-hub-card">
            <p className="un-hub-card-desc">
              Choose filters and tap <strong>Search SAM.gov</strong> to load
              opportunities. Default preset targets PKI with FederalKey NAICS.
            </p>
          </section>
        )}
      </div>
    </div>
  );
}
