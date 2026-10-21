import React, { Suspense } from "react";
import type { GlobeApi } from "./useGlobeApp";
import { Cobe } from "./CobeGlobe";
import { FloatingChrome } from "./FloatingChrome";
import { safeGlobeHref } from "./safeUrl";
import { SiteTour } from "./SiteTour";
import { ActivityFeed, type ActivityFilter } from "./ActivityFeed";
import { formatFingerprint, getKeyGenProfile, keyGenProfilesBySafety, SAFETY_LEVEL_META, shortFingerprint, S2K_PROTOCOLS, SYMMETRIC_CIPHERS, type AeadModeId, type KeyGenProfileId, type S2kProtocolId, type SymmetricCipherId } from "./pgpAuth";
import { NearbyMap, TransitPanelContent } from "./lazyPanels";
import { DEFAULT_WEATHER_LOCATION, formatForecastDay, formatForecastHour } from "./globeModel";

type AccessMark = "stripe" | "admin" | "unrecorded" | null;

function accessMark(
  active: boolean | undefined,
  origin: string | null | undefined,
): AccessMark {
  if (!active) return null;
  if (origin === "stripe" || origin === "admin") return origin;
  return "unrecorded";
}

function accessPhrase(
  active: boolean | undefined,
  origin: string | null | undefined,
): string {
  const mark = accessMark(active, origin);
  if (mark === "stripe") return "Stripe payment";
  if (mark === "admin") return "Admin grant";
  if (mark === "unrecorded") return "Old mark, no Stripe receipt";
  return "Locked";
}

function AccessBadge({
  active,
  origin,
  kind,
}: {
  active: boolean | undefined;
  origin: string | null | undefined;
  kind: "transit" | "keys";
}) {
  const mark = accessMark(active, origin);
  if (kind === "keys" && !mark) return null;
  const label =
    kind === "keys"
      ? mark === "stripe"
        ? "K·STRIPE"
        : mark === "admin"
          ? "K·ADMIN"
          : "K·OLD"
      : mark === "stripe"
        ? "STRIPE"
        : mark === "admin"
          ? "ADMIN"
          : mark === "unrecorded"
            ? "OLD"
            : "LOCKED";
  const title =
    mark === "stripe"
      ? kind === "keys"
        ? "Unlimited keys from a Stripe payment"
        : "Stripe payment"
      : mark === "admin"
        ? kind === "keys"
          ? "Unlimited keys granted by an admin"
          : "Admin grant"
        : mark === "unrecorded"
          ? kind === "keys"
            ? "Unlimited keys marked with no Stripe receipt"
            : "Marked paid with no Stripe receipt"
          : "Locked";
  const style =
    mark === "admin"
      ? { background: "#8a5a12", color: "#fff8e8" }
      : mark === "unrecorded"
        ? { background: "#4a5160", color: "#e8eef6" }
        : undefined;
  const className =
    mark === "stripe"
      ? "admin-user-badge paid"
      : mark === null
        ? "admin-user-badge locked"
        : "admin-user-badge";
  return (
    <span className={className} style={style} title={title}>
      {label}
    </span>
  );
}

export function AppChunk0({ b }: { b: GlobeApi }) {
  const { activityFeed, activityFilter, adminAllowlistConfigured, adminAudit, adminBusy, adminClaim, adminDeleteUser, adminElevationExpiresAt, adminElevationValid, adminError, adminGrant, adminGrantKind, adminLookup, adminLookupUser, adminMessage, adminNote, adminQuery, adminSessionId, adminUsers, adminUsersComplete, adminUsersCursor, adminUsersFilter, authBusy, authError, authMessage, authMode, authUser, chatMessages, checkoutBusy, clearActivityFeed, clearAdminElevation, clearSensitiveAuthState, counter, deviceKeys, dismissSiteTour, exportAead, exportAeadMode, exportAllowUnencrypted, exportArgonMemExp, exportArgonParallel, exportArgonPasses, exportCipher, exportPassphrase, exportPassphrase2, exportS2k, exportS2kIterByte, fetchNearbyMapForTransit, forecastView, generatedPublic, handleActivityFilterChange, handleDeviceSignIn, handleExportPrivateKey, handleGenerateKeypair, handleImportDeviceKey, handleRemoveDeviceKey, isAdmin, isCompactFeed, isFeedPaused, keyGenProfile, keyPassphrase, liveFeedAccess, loadAdminUsers, loadLocalTransit, loadNearbyPaths, loadWeatherFeed, navBarRef, nearbyError, nearbyPreview, nearbyRadiusM, nearbyStatus, paymentRequired, refreshDeviceKeys, regPublicKey, registerWithPublicKey, runRateLimitedButtonAction, selectedDeviceFp, selectedDeviceKey, sendChatMessage, setAdminError, setAdminLookupUser, setAdminMessage, setAdminNote, setAdminQuery, setAdminSessionId, setAdminUsers, setAdminUsersFilter, setAuthError, setAuthMessage, setAuthMode, setExportAead, setExportAeadMode, setExportAllowUnencrypted, setExportArgonMemExp, setExportArgonParallel, setExportArgonPasses, setExportCipher, setExportPassphrase, setExportPassphrase2, setExportS2k, setExportS2kIterByte, setForecastView, setIsCompactFeed, setIsFeedPaused, setKeyGenProfile, setKeyPassphrase, setRegPublicKey, setSelectedDeviceFp, setShowActivityMenu, setShowAdminPanel, setShowAuthPanel, setShowImportDevice, setShowMenu, setShowNearbyPanel, setShowTransitPanel, setShowWeatherForecast, setShowWeatherPanel, setSocketStatus, showActivityMenu, showAdminPanel, showAuthPanel, showImportDevice, showNearbyPanel, showSiteTour, showTransitPanel, showWeatherForecast, showWeatherPanel, socket, socketStatus, startTransitCheckout, transitDistanceM, transitError, transitPreview, transitStatus, unlockAdminPrivileges, weatherError, weatherFeed, weatherGlow, weatherStatus } = b;
  return (
    <>
{(authMessage || authError) && (
        <div
          className={`billing-banner ${authError ? "billing-banner-error" : "billing-banner-ok"}`}
          role="status"
        >
          <span>{authError || authMessage}</span>
          <button
            type="button"
            onClick={() => {
              setAuthMessage("");
              setAuthError("");
            }}
          >
            Dismiss
          </button>
        </div>
      )}{showAuthPanel && (
        <div
          className="auth-modal-backdrop"
          role="presentation"
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              clearSensitiveAuthState();
              setShowAuthPanel(false);
            }
          }}
        >
          <div
            className="auth-modal auth-modal-wide"
            role="dialog"
            aria-label={
              authMode === "register" ? "Create device identity" : "Device sign-in"
            }
          >
            <div className="auth-modal-header">
              <strong>
                {authMode === "register"
                  ? "Create identity · this device"
                  : "Sign in · this device"}
              </strong>
              <button
                type="button"
                className="nearby-close"
                onClick={() => {
                  clearSensitiveAuthState();
                  setShowAuthPanel(false);
                }}
                aria-label="Close"
              >
                ×
              </button>
            </div>
            <p className="auth-modal-copy">
              You do <strong>not</strong> upload a private key to log in. The
              browser keeps the private key on this device; the server only gets
              your public key + a one-time signature. No account password —
              passphrase only if <em>you</em> encrypted the device key.
            </p>
            <p className="auth-field-hint auth-mobile-hint">
              <strong>Mobile:</strong> use Safari or Chrome in a normal tab (not
              private, not Instagram/Facebook/TikTok in-app browsers). New keys
              must be <strong>Registered</strong> once before Sign in works.
              Allow cookies + site data for this domain.
            </p>

            {authMode === "register" ? (
              <>
                <label className="auth-field">
                  <span>Key algorithm / size / protocol</span>
                  <select
                    value={keyGenProfile}
                    onChange={(e) =>
                      setKeyGenProfile(e.target.value as KeyGenProfileId)
                    }
                    disabled={authBusy}
                  >
                    {keyGenProfilesBySafety().map((group) => (
                      <optgroup
                        key={group.safety}
                        label={`${group.label} — ${
                          group.safety === "recommended"
                            ? "best default"
                            : group.safety === "insecure"
                              ? "do not use for real accounts"
                              : group.safety
                        }`}
                      >
                        {group.profiles.map((p) => (
                          <option key={p.id} value={p.id}>
                            [{SAFETY_LEVEL_META[p.safety].short}] {p.label}
                            {!p.canRegister ? " · export-only" : ""}
                          </option>
                        ))}
                      </optgroup>
                    ))}
                  </select>
                </label>
                {(() => {
                  const selected = getKeyGenProfile(keyGenProfile);
                  const meta = SAFETY_LEVEL_META[selected.safety];
                  return (
                    <div
                      className={`auth-safety-card auth-safety-${selected.safety}`}
                    >
                      <div className="auth-safety-header">
                        <span
                          className="auth-safety-badge"
                          style={{
                            borderColor: meta.color,
                            color: meta.color,
                          }}
                        >
                          {meta.short}
                        </span>
                        <strong>{selected.safetyLabel}</strong>
                      </div>
                      <p className="auth-safety-desc">{selected.description}</p>
                      <div className="auth-safety-meta">
                        ~{selected.securityBits}-bit classical · {selected.family}
                        {selected.canRegister
                          ? " · can register on this app"
                          : " · cannot register (export/lab only)"}
                      </div>
                      <ul className="auth-compliance-list">
                        <li>
                          <span>NIST</span> {selected.compliance.nist}
                        </li>
                        <li>
                          <span>BSI</span> {selected.compliance.bsi}
                        </li>
                        <li>
                          <span>ENISA</span> {selected.compliance.enisa}
                        </li>
                        <li>
                          <span>ANSSI</span> {selected.compliance.anssi}
                        </li>
                        <li>
                          <span>CNSA</span> {selected.compliance.cnsa}
                        </li>
                      </ul>
                      {selected.registerNote && (
                        <p className="auth-safety-warn">{selected.registerNote}</p>
                      )}
                      <p className="auth-field-hint">
                        Guidance summarized from NIST SP 800-57, BSI TR-02102,
                        ENISA, ANSSI, and NSA CNSA documents — not legal advice.
                        Quantum threats are out of scope for these classical
                        ratings.
                      </p>
                    </div>
                  );
                })()}
                <div className="auth-modal-actions auth-row">
                  <button
                    type="button"
                    disabled={authBusy}
                    onClick={() => void handleGenerateKeypair()}
                  >
                    {authBusy
                      ? "Working…"
                      : "Generate key on this device"}
                  </button>
                </div>

                {generatedPublic && (
                  <div className="auth-export-panel">
                    <div className="auth-fp-block">
                      <div>
                        Fingerprint:{" "}
                        <code>
                          {formatFingerprint(generatedPublic.fingerprint)}
                        </code>
                      </div>
                      {(() => {
                        const selected = getKeyGenProfile(keyGenProfile);
                        const meta = SAFETY_LEVEL_META[selected.safety];
                        return (
                          <div className="auth-safety-inline">
                            <span
                              className="auth-safety-badge"
                              style={{
                                borderColor: meta.color,
                                color: meta.color,
                              }}
                            >
                              {meta.short}
                            </span>
                            <span>
                              {selected.label} · ~{selected.securityBits}-bit ·{" "}
                              {selected.safetyLabel}
                            </span>
                          </div>
                        );
                      })()}
                      <div>
                        Private key is stored on this device only (IndexedDB).
                        It is never uploaded. Register publishes the public key.
                      </div>
                      {!getKeyGenProfile(keyGenProfile).canRegister && (
                        <p className="auth-safety-warn">
                          This size/protocol is below app registration policy
                          (export-only).
                        </p>
                      )}
                    </div>

                    <div className="auth-section-title">
                      Optional backup file (local only)
                    </div>
                    <label className="auth-field">
                      <span>Symmetric cipher</span>
                      <select
                        value={exportCipher}
                        onChange={(e) =>
                          setExportCipher(e.target.value as SymmetricCipherId)
                        }
                        disabled={authBusy}
                      >
                        {SYMMETRIC_CIPHERS.map((c) => (
                          <option key={c.id} value={c.id}>
                            {c.label}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="auth-field">
                      <span>Passphrase KDF (S2K protocol)</span>
                      <select
                        value={exportS2k}
                        onChange={(e) =>
                          setExportS2k(e.target.value as S2kProtocolId)
                        }
                        disabled={authBusy}
                      >
                        {S2K_PROTOCOLS.map((s) => (
                          <option key={s.id} value={s.id}>
                            {s.label}
                          </option>
                        ))}
                      </select>
                      <span className="auth-field-hint">
                        {
                          S2K_PROTOCOLS.find((s) => s.id === exportS2k)
                            ?.description
                        }
                      </span>
                    </label>
                    {exportS2k === "iterated" && (
                      <label className="auth-field">
                        <span>
                          S2K iteration count byte (0–255, higher = slower)
                        </span>
                        <input
                          type="number"
                          min={0}
                          max={255}
                          value={exportS2kIterByte}
                          onChange={(e) =>
                            setExportS2kIterByte(Number(e.target.value) || 0)
                          }
                          disabled={authBusy}
                        />
                      </label>
                    )}
                    {exportS2k === "argon2" && (
                      <div className="auth-export-grid">
                        <label className="auth-field">
                          <span>Argon2 passes</span>
                          <input
                            type="number"
                            min={1}
                            max={10}
                            value={exportArgonPasses}
                            onChange={(e) =>
                              setExportArgonPasses(
                                Number(e.target.value) || 1,
                              )
                            }
                            disabled={authBusy}
                          />
                        </label>
                        <label className="auth-field">
                          <span>Parallelism</span>
                          <input
                            type="number"
                            min={1}
                            max={16}
                            value={exportArgonParallel}
                            onChange={(e) =>
                              setExportArgonParallel(
                                Number(e.target.value) || 1,
                              )
                            }
                            disabled={authBusy}
                          />
                        </label>
                        <label className="auth-field">
                          <span>Memory exp (2^n KiB)</span>
                          <input
                            type="number"
                            min={16}
                            max={21}
                            value={exportArgonMemExp}
                            onChange={(e) =>
                              setExportArgonMemExp(
                                Number(e.target.value) || 16,
                              )
                            }
                            disabled={authBusy}
                          />
                        </label>
                      </div>
                    )}
                    <label className="auth-check">
                      <input
                        type="checkbox"
                        checked={exportAead}
                        onChange={(e) => setExportAead(e.target.checked)}
                        disabled={authBusy}
                      />
                      AEAD-protect secret key packets
                    </label>
                    {exportAead && (
                      <label className="auth-field">
                        <span>AEAD mode</span>
                        <select
                          value={exportAeadMode}
                          onChange={(e) =>
                            setExportAeadMode(e.target.value as AeadModeId)
                          }
                          disabled={authBusy}
                        >
                          <option value="gcm">GCM</option>
                          <option value="eax">EAX</option>
                          <option value="ocb">OCB</option>
                        </select>
                      </label>
                    )}
                    <label className="auth-field">
                      <span>Export passphrase</span>
                      <input
                        type="password"
                        autoComplete="new-password"
                        value={exportPassphrase}
                        onChange={(e) => setExportPassphrase(e.target.value)}
                        disabled={authBusy}
                        placeholder="Min 8 characters"
                      />
                    </label>
                    <label className="auth-field">
                      <span>Confirm passphrase</span>
                      <input
                        type="password"
                        autoComplete="new-password"
                        value={exportPassphrase2}
                        onChange={(e) => setExportPassphrase2(e.target.value)}
                        disabled={authBusy}
                      />
                    </label>
                    <label className="auth-check">
                      <input
                        type="checkbox"
                        checked={exportAllowUnencrypted}
                        onChange={(e) =>
                          setExportAllowUnencrypted(e.target.checked)
                        }
                        disabled={authBusy}
                      />
                      Allow unencrypted export (not recommended)
                    </label>
                    <div className="auth-modal-actions auth-row">
                      <button
                        type="button"
                        disabled={authBusy || !generatedPublic}
                        onClick={() => void handleExportPrivateKey()}
                      >
                        {authBusy
                          ? "Exporting…"
                          : "Download backup .asc (optional)"}
                      </button>
                    </div>
                  </div>
                )}

                <label className="auth-field">
                  <span>Public key (only thing sent to server)</span>
                  <textarea
                    value={regPublicKey}
                    onChange={(e) => setRegPublicKey(e.target.value)}
                    disabled={authBusy}
                    rows={4}
                    spellCheck={false}
                    placeholder="Generated automatically — public key only"
                  />
                </label>
                {authError && (
                  <div className="auth-inline-error">{authError}</div>
                )}
                <div className="auth-modal-actions">
                  <button
                    type="button"
                    disabled={
                      authBusy ||
                      !regPublicKey.trim() ||
                      (Boolean(generatedPublic) &&
                        !getKeyGenProfile(keyGenProfile).canRegister)
                    }
                    onClick={() => void registerWithPublicKey()}
                  >
                    {authBusy
                      ? "Registering…"
                      : generatedPublic &&
                          !getKeyGenProfile(keyGenProfile).canRegister
                        ? "Cannot register (safety floor)"
                        : "Register & stay signed in"}
                  </button>
                  <button
                    type="button"
                    className="auth-switch"
                    disabled={authBusy}
                    onClick={() => {
                      setAuthError("");
                      void refreshDeviceKeys();
                      setAuthMode("login");
                    }}
                  >
                    Already have a device key? Sign in
                  </button>
                </div>

              </>
            ) : (
              <>
                {deviceKeys.length > 0 ? (
                  <>
                    <label className="auth-field">
                      <span>Device key on this browser</span>
                      <select
                        value={selectedDeviceFp}
                        onChange={(e) => setSelectedDeviceFp(e.target.value)}
                        disabled={authBusy}
                      >
                        {deviceKeys.map((k) => (
                          <option key={k.fingerprint} value={k.fingerprint}>
                            {shortFingerprint(k.fingerprint)}
                            {k.encrypted ? " · encrypted" : " · no passphrase"}
                            {k.profileLabel ? ` · ${k.profileLabel}` : ""}
                          </option>
                        ))}
                      </select>
                    </label>
                    {selectedDeviceKey?.encrypted && (
                      <label className="auth-field">
                        <span>Key passphrase (only because this key is encrypted)</span>
                        <input
                          type="password"
                          value={keyPassphrase}
                          onChange={(e) => setKeyPassphrase(e.target.value)}
                          disabled={authBusy}
                          autoComplete="off"
                          placeholder="OpenPGP key passphrase"
                        />
                      </label>
                    )}
                    {selectedDeviceKey && !selectedDeviceKey.encrypted && (
                      <p className="auth-field-hint">
                        Sign-in needs no password
                        {selectedDeviceKey.deviceBound
                          ? " (private key is AES-wrapped on this device at rest)."
                          : "."}{" "}
                        Session uses an HttpOnly cookie only.
                      </p>
                    )}
                    <div className="auth-modal-actions">
                      <button
                        type="button"
                        disabled={authBusy || !selectedDeviceKey}
                        onClick={() => void handleDeviceSignIn()}
                      >
                        {authBusy
                          ? "Signing in…"
                          : "Continue with device key"}
                      </button>
                      <button
                        type="button"
                        className="auth-switch"
                        disabled={authBusy || !selectedDeviceKey}
                        onClick={() => {
                          if (selectedDeviceKey) {
                            void handleRemoveDeviceKey(
                              selectedDeviceKey.fingerprint,
                            );
                          }
                        }}
                      >
                        Remove key from this device
                      </button>
                    </div>
                  </>
                ) : (
                  <div className="auth-fp-block">
                    No device key on this browser yet. Create one under{" "}
                    <strong>Create identity</strong>, or import a backup once
                    (still never uploaded to the server).
                  </div>
                )}

                <button
                  type="button"
                  className="auth-switch"
                  disabled={authBusy}
                  onClick={() => setShowImportDevice((v) => !v)}
                >
                  {showImportDevice
                    ? "Hide import"
                    : "Import backup onto this device…"}
                </button>
                {showImportDevice && (
                  <div className="auth-export-panel">
                    <p className="auth-field-hint">
                      Only for a new browser/computer. The private key stays
                      here and is never sent to the server.
                    </p>
                    <label className="auth-field">
                      <span>Private key file</span>
                      <input
                        type="file"
                        accept=".asc,.pgp,.gpg,.txt,text/plain"
                        disabled={authBusy}
                        onChange={(e) => {
                          const file = e.target.files?.[0] || null;
                          void handleImportDeviceKey(file);
                          e.target.value = "";
                        }}
                      />
                    </label>
                  </div>
                )}

                {authError && (
                  <div className="auth-inline-error">{authError}</div>
                )}
                <div className="auth-modal-actions">
                  <button
                    type="button"
                    className="auth-switch"
                    disabled={authBusy}
                    onClick={() => {
                      setAuthError("");
                      clearSensitiveAuthState();
                      setAuthMode("register");
                    }}
                  >
                    New here? Create device identity
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}{showAdminPanel && (
        <div
          className="auth-modal-backdrop"
          role="presentation"
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              setShowAdminPanel(false);
              clearAdminElevation();
              setAdminUsers([]);
            }
          }}
        >
          <div
            className="auth-modal auth-modal-wide admin-modal"
            role="dialog"
            aria-label="Admin portal"
          >
            <div className="auth-modal-header">
              <strong>Admin · Transit support</strong>
              <button
                type="button"
                className="nearby-close"
                onClick={() => {
                  setShowAdminPanel(false);
                  clearAdminElevation();
                  setAdminUsers([]);
                }}
                aria-label="Close"
              >
                ×
              </button>
            </div>
            <p className="auth-modal-copy">
              Privileged ops are server-enforced: an allowlisted session, a
              fresh signature from that device key, then an exact{" "}
              <code>ADMIN_FINGERPRINTS</code> match. A shared action secret is
              not used. Lookups need the session only. Audited.
            </p>

            {authUser && (
              <div className="admin-identity-box">
                <span>Signed-in fingerprint (must match ADMIN_FINGERPRINTS)</span>
                <code className="auth-user-fingerprint">
                  {formatFingerprint(authUser.fingerprint)}
                </code>
                <code className="admin-fp-hex">
                  {authUser.fingerprint.replace(/[\s:]/g, "").toLowerCase()}
                </code>
                <span className="admin-identity-status">
                  {isAdmin
                    ? "Allowlist: matched — admin access granted"
                    : adminAllowlistConfigured
                      ? "Allowlist: configured, but this fingerprint is not on it"
                      : "Allowlist: empty / not configured on this Worker"}
                </span>
              </div>
            )}

            {adminError && (
              <div className="auth-error" style={{ whiteSpace: "pre-wrap" }}>
                {adminError}
              </div>
            )}

            {!isAdmin && (
              <p className="auth-modal-copy">
                To fix: Cloudflare Dashboard → Workers → <strong>globe</strong>{" "}
                → Settings → Variables and Secrets → set{" "}
                <code>ADMIN_FINGERPRINTS</code> to the hex fingerprint above
                (no spaces), then sign out and sign in again. Or run:{" "}
                <code>
                  npx wrangler secret put ADMIN_FINGERPRINTS --name globe
                </code>
              </p>
            )}

            {isAdmin && (
              <>
                <div className="auth-section-title">1 · Unlock with your key</div>
                <p className="auth-modal-copy">
                  Signs a one-time server challenge with the private key already
                  on this device. The server keeps the privileged window only
                  when that key's fingerprint is on{" "}
                  <code>ADMIN_FINGERPRINTS</code>. Elevation lasts about 10
                  minutes. The private key is not uploaded.
                </p>
                <div className="auth-modal-actions auth-row">
                  <button
                    type="button"
                    disabled={adminBusy}
                    onClick={() => void unlockAdminPrivileges()}
                  >
                    {adminBusy
                      ? "Working…"
                      : adminElevationValid()
                        ? "Re-unlock privileges"
                        : "Unlock privileges (sign challenge)"}
                  </button>
                  {adminElevationValid() && (
                    <button
                      type="button"
                      className="auth-switch"
                      disabled={adminBusy}
                      onClick={() => {
                        clearAdminElevation();
                        setAdminMessage("Elevation cleared.");
                      }}
                    >
                      Lock again
                    </button>
                  )}
                </div>
                {adminElevationValid() && adminElevationExpiresAt && (
                  <div className="auth-inline-ok">
                    Elevated until{" "}
                    {new Date(adminElevationExpiresAt).toLocaleTimeString()}
                  </div>
                )}
                {adminElevationValid() && authUser && (
                  <div className="auth-modal-actions auth-row">
                    <button
                      type="button"
                      disabled={adminBusy}
                      onClick={() =>
                        void adminGrantKind("keys", true, {
                          id: authUser.id,
                          fingerprint: authUser.fingerprint,
                          primaryUserId: authUser.primaryUserId,
                          transitPaid: authUser.transitPaid,
                          unlimitedKeys: authUser.unlimitedKeys,
                        })
                      }
                    >
                      Grant unlimited keys to this account
                    </button>
                  </div>
                )}

                <div className="auth-section-title">All users</div>
                <p className="auth-modal-copy">
                  Directory for elevated admins. The signed key must be on the
                  fingerprint allowlist. STRIPE is a payment, ADMIN is a grant,
                  and OLD is an earlier mark with no Stripe receipt. Public
                  fields only — no keys.
                </p>
                <div className="auth-modal-actions auth-row admin-users-filters">
                  <button
                    type="button"
                    className={
                      adminUsersFilter === "all" ? "" : "auth-switch"
                    }
                    disabled={adminBusy}
                    onClick={() => setAdminUsersFilter("all")}
                  >
                    All
                  </button>
                  <button
                    type="button"
                    className={
                      adminUsersFilter === "paid" ? "" : "auth-switch"
                    }
                    disabled={adminBusy}
                    onClick={() => setAdminUsersFilter("paid")}
                  >
                    Transit
                  </button>
                  <button
                    type="button"
                    className={
                      adminUsersFilter === "locked" ? "" : "auth-switch"
                    }
                    disabled={adminBusy}
                    onClick={() => setAdminUsersFilter("locked")}
                  >
                    Locked
                  </button>
                  <button
                    type="button"
                    disabled={
                      adminBusy ||
                      !adminElevationValid()
                    }
                    title={
                      adminElevationValid()
                        ? "Load user directory"
                        : "Unlock privileges first"
                    }
                    onClick={() => void loadAdminUsers()}
                  >
                    {adminBusy ? "Loading…" : "Load users"}
                  </button>
                  {!adminUsersComplete && adminUsersCursor && (
                    <button
                      type="button"
                      className="auth-switch"
                      disabled={
                        adminBusy ||
                        !adminElevationValid()
                      }
                      onClick={() =>
                        void loadAdminUsers({
                          append: true,
                          cursor: adminUsersCursor,
                        })
                      }
                    >
                      Load more
                    </button>
                  )}
                </div>
                {adminUsers.length > 0 && (
                  <div className="admin-users-list">
                    <div className="admin-users-meta">
                      {adminUsers.length} shown
                      {!adminUsersComplete ? " · more available" : ""}
                    </div>
                    {adminUsers.map((u) => (
                      <div key={u.id} className="admin-user-row-wrap">
                        <button
                          type="button"
                          className="admin-user-row"
                          onClick={() => {
                            setAdminLookupUser(u);
                            setAdminQuery(u.id);
                            setAdminMessage(
                              `Selected user ${u.id.slice(0, 12)}… for grant/revoke/remove.`,
                            );
                          }}
                          title="Select for grant / revoke / remove"
                        >
                          <AccessBadge
                            active={u.transitPaid}
                            origin={u.transitOrigin}
                            kind="transit"
                          />
                          <AccessBadge
                            active={u.unlimitedKeys}
                            origin={u.unlimitedKeyOrigin}
                            kind="keys"
                          />
                          <code className="admin-user-id">{u.id}</code>
                          <code className="admin-user-fp">
                            {formatFingerprint(u.fingerprint)}
                          </code>
                          {u.primaryUserId && (
                            <span className="admin-user-uid">
                              {u.primaryUserId}
                            </span>
                          )}
                          {u.createdAt && (
                            <span className="admin-user-created">
                              {new Date(u.createdAt).toLocaleString()}
                            </span>
                          )}
                        </button>
                        <button
                          type="button"
                          className="admin-user-remove"
                          disabled={
                            adminBusy ||
                            !adminElevationValid()
                          }
                          title="Permanently delete this user"
                          onClick={(e) => {
                            e.stopPropagation();
                            void adminDeleteUser(u);
                          }}
                        >
                          Remove
                        </button>
                      </div>
                    ))}
                  </div>
                )}

                <div className="auth-section-title">Lookup customer</div>
                <label className="auth-field">
                  <span>User id or fingerprint</span>
                  <input
                    type="text"
                    value={adminQuery}
                    onChange={(e) => setAdminQuery(e.target.value)}
                    placeholder="paste user id or fingerprint"
                    spellCheck={false}
                  />
                </label>
                <div className="auth-modal-actions auth-row">
                  <button
                    type="button"
                    disabled={adminBusy || adminQuery.trim().length < 6}
                    onClick={() => void adminLookup()}
                  >
                    {adminBusy ? "Working…" : "Lookup"}
                  </button>
                </div>

                {adminLookupUser && (
                  <div className="auth-fp-block">
                    <div>
                      <strong>User</strong> <code>{adminLookupUser.id}</code>
                    </div>
                    <div>
                      Fingerprint{" "}
                      <code>
                        {formatFingerprint(adminLookupUser.fingerprint)}
                      </code>
                    </div>
                    {adminLookupUser.primaryUserId && (
                      <div>UID: {adminLookupUser.primaryUserId}</div>
                    )}
                    <div>
                      Transit:{" "}
                      <strong>
                        {accessPhrase(
                          adminLookupUser.transitPaid,
                          adminLookupUser.transitOrigin,
                        )}
                      </strong>
                    </div>
                    <div>
                      Unlimited keys:{" "}
                      <strong>
                        {accessPhrase(
                          adminLookupUser.unlimitedKeys,
                          adminLookupUser.unlimitedKeyOrigin,
                        )}
                      </strong>
                    </div>
                    <label className="auth-field" style={{ marginTop: 10 }}>
                      <span>Note (audit log)</span>
                      <input
                        type="text"
                        value={adminNote}
                        onChange={(e) => setAdminNote(e.target.value)}
                        placeholder="e.g. paid but webhook missed"
                      />
                    </label>
                    <div className="auth-modal-actions auth-row">
                      <button
                        type="button"
                        disabled={
                          adminBusy ||
                          !adminElevationValid()
                        }
                        title={
                          adminElevationValid()
                            ? "Grant Transit (elevated)"
                            : "Unlock privileges first"
                        }
                        onClick={() => void adminGrant(true)}
                      >
                        Grant Transit
                      </button>
                      <button
                        type="button"
                        className="auth-switch"
                        disabled={
                          adminBusy ||
                          !adminElevationValid()
                        }
                        onClick={() => void adminGrant(false)}
                      >
                        Revoke Transit
                      </button>
                      <button
                        type="button"
                        disabled={
                          adminBusy ||
                          !adminElevationValid()
                        }
                        title={
                          adminElevationValid()
                            ? "Grant unlimited sign-in keys (elevated)"
                            : "Unlock privileges first"
                        }
                        onClick={() => void adminGrantKind("keys", true)}
                      >
                        Grant keys to selected account
                      </button>
                      <button
                        type="button"
                        className="auth-switch"
                        disabled={
                          adminBusy ||
                          !adminElevationValid()
                        }
                        onClick={() => void adminGrantKind("keys", false)}
                      >
                        Revoke unlimited keys
                      </button>
                      <button
                        type="button"
                        className="admin-user-remove"
                        disabled={
                          adminBusy ||
                          !adminElevationValid()
                        }
                        title="Permanently delete this user account"
                        onClick={() => void adminDeleteUser(adminLookupUser)}
                      >
                        Remove user
                      </button>
                    </div>
                  </div>
                )}

                <div className="auth-section-title">Recover Stripe session</div>
                <label className="auth-field">
                  <span>Checkout session id (cs_…)</span>
                  <input
                    type="text"
                    value={adminSessionId}
                    onChange={(e) => setAdminSessionId(e.target.value)}
                    placeholder="cs_live_… or cs_test_…"
                    spellCheck={false}
                  />
                </label>
                <div className="auth-modal-actions auth-row">
                  <button
                    type="button"
                    disabled={
                      adminBusy ||
                      !adminSessionId.trim() ||
                      !adminElevationValid()
                    }
                    title={
                      adminElevationValid()
                        ? "Claim paid Stripe session"
                        : "Unlock privileges first"
                    }
                    onClick={() => void adminClaim()}
                  >
                    Claim session → unlock user
                  </button>
                </div>

                {adminMessage && (
                  <div className="auth-fp-block">{adminMessage}</div>
                )}

                <div className="auth-section-title">Recent audit</div>
                <div className="admin-audit-list">
                  {adminAudit.length === 0 ? (
                    <div className="auth-field-hint">No audit entries yet.</div>
                  ) : (
                    adminAudit.slice(0, 12).map((e, i) => (
                      <div key={`${e.at}-${i}`} className="admin-audit-row">
                        <span>{new Date(e.at).toLocaleString()}</span>
                        <strong>{e.action}</strong>
                        <code>
                          {(
                            e.targetFingerprint ||
                            e.targetUserId ||
                            ""
                          ).slice(0, 16)}
                        </code>
                        {e.detail && <em>{e.detail}</em>}
                      </div>
                    ))
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      )}{showSiteTour && <SiteTour onDone={dismissSiteTour} />}<nav className="nav-bar" ref={navBarRef}>
        <div className="nav-left">
          <a
            className="nav-title"
            href="https://federalkey.org"
            target="_blank"
            rel="noopener noreferrer"
            title="Open federalkey.org"
          >
            FEDERALKEY
          </a>
        </div>

        <div className="nav-center">
          {/* Feature buttons live in the bottom macOS-style dock */}
        </div>

        <div className="nav-right">
          {/* Globe view controls — portaled from CobeGlobe into this slot */}
          <div
            id="globe-controls-slot"
            className="globe-controls-slot nav-globe-controls-slot"
          />
          <button
            className="nav-menu-btn"
            onClick={() =>
              runRateLimitedButtonAction("menu-toggle", () =>
                setShowMenu((open) => !open),
              )
            }
          >
            <span>MENU</span>
            <span className="menu-icon">v</span>
          </button>
        </div>
      </nav>{/* Live Feed app window — launched from the bottom dock */}<div className="live-feed-app-host" aria-live="polite">
        <ActivityFeed
          open={showActivityMenu}
          showLauncher={false}
          onToggle={() =>
            runRateLimitedButtonAction("activity-toggle", () =>
              setShowActivityMenu((open) => !open),
            )
          }
          onClose={() =>
            runRateLimitedButtonAction("activity-close", () =>
              setShowActivityMenu(false),
            )
          }
          counter={counter}
          events={activityFeed}
          onClear={() =>
            runRateLimitedButtonAction("activity-clear", clearActivityFeed)
          }
          isPaused={isFeedPaused}
          onTogglePause={() =>
            runRateLimitedButtonAction("activity-pause", () =>
              setIsFeedPaused((paused) => !paused),
            )
          }
          isCompact={isCompactFeed}
          onToggleCompact={() =>
            runRateLimitedButtonAction("activity-compact", () =>
              setIsCompactFeed((compact) => !compact),
            )
          }
          filter={activityFilter}
          onFilterChange={handleActivityFilterChange}
          socketStatus={socketStatus}
          isSocketConnected={socketStatus === "connected"}
          access={liveFeedAccess}
          checkoutBusy={checkoutBusy}
          onReconnectSocket={() => {
            setSocketStatus("connecting");
            try {
              socket.reconnect();
            } catch {
              // PartySocket may already be mid-retry
            }
          }}
          onSignIn={() => {
            setShowActivityMenu(false);
            setShowAuthPanel(true);
            setAuthMode("login");
            setAuthMessage(
              paymentRequired
                ? "Sign in, then buy Stripe access to unlock Live Feed and web support chat."
                : "Sign in with your PGP key to unlock Live Feed and web support chat.",
            );
          }}
          onBuyAccess={() => {
            void startTransitCheckout();
          }}
          chatMessages={chatMessages}
          onSendChat={sendChatMessage}
        />
      </div>{showTransitPanel && (
        <FloatingChrome
          className="transit-panel"
          role="dialog"
          aria-label="Local transit options"
        >
          <div className="transit-panel-header nearby-panel-header">
            <div>
              <h3>LOCAL TRANSIT</h3>
              <span>
                {transitPreview
                  ? `${transitPreview.lat.toFixed(4)}, ${transitPreview.lng.toFixed(4)} · ${transitPreview.maxDistanceM}m`
                  : "Routes & stops near you"}
              </span>
            </div>
            <button
              type="button"
              className="nearby-close"
              onClick={() =>
                runRateLimitedButtonAction("transit-close", () =>
                  setShowTransitPanel(false),
                )
              }
              aria-label="Close local transit"
            >
              x
            </button>
          </div>

          {transitStatus === "loading" && (
            <div className="nearby-loading">Loading local transit...</div>
          )}

          {transitStatus === "error" && (
            <div className="nearby-error">
              <span>{transitError}</span>
              <div className="nearby-footer-actions" style={{ marginTop: 10 }}>
                {!authUser && (
                  <button
                    type="button"
                    onClick={() => {
                      setShowAuthPanel(true);
                      setAuthMode("login");
                    }}
                    disabled={authBusy}
                  >
                    Sign in
                  </button>
                )}
                {authUser && paymentRequired && !authUser.transitPaid && (
                  <button
                    type="button"
                    className="billing-buy-btn"
                    onClick={() => {
                      void startTransitCheckout();
                    }}
                    disabled={checkoutBusy}
                  >
                    {checkoutBusy ? "Opening Stripe…" : "Buy Transit ($20)"}
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => {
                    void loadLocalTransit(false);
                  }}
                >
                  Retry
                </button>
              </div>
            </div>
          )}

          {transitStatus === "ready" && transitPreview && (
            <Suspense
              fallback={
                <div className="auth-field-hint" style={{ padding: 12 }}>
                  Loading transit map…
                </div>
              }
            >
              <TransitPanelContent
                preview={transitPreview}
                distanceM={transitDistanceM}
                onRadius={(m) => {
                  void loadLocalTransit(false, m);
                }}
                onRefresh={() => {
                  void loadLocalTransit(false, transitDistanceM);
                }}
                fetchNearbyMap={fetchNearbyMapForTransit}
              />
            </Suspense>
          )}
        </FloatingChrome>
      )}{showNearbyPanel && (
        <FloatingChrome
          className="nearby-panel"
          role="dialog"
          aria-label="Nearby street and path traces"
        >
          <div className="nearby-panel-header">
            <div>
              <h3>NEARBY MAP</h3>
              <span>
                {nearbyPreview
                  ? `${nearbyPreview.lat.toFixed(4)}, ${nearbyPreview.lng.toFixed(4)} · ${nearbyPreview.radiusM}m · drag header to move`
                  : "Local streets & paths"}
              </span>
            </div>
            <button
              type="button"
              className="nearby-close"
              onClick={() =>
                runRateLimitedButtonAction("nearby-close", () =>
                  setShowNearbyPanel(false),
                )
              }
              aria-label="Close nearby map"
            >
              x
            </button>
          </div>

          {nearbyStatus === "loading" && (
            <div className="nearby-loading">Tracing nearby streets...</div>
          )}

          {nearbyStatus === "error" && (
            <div className="nearby-error">
              <span>{nearbyError}</span>
              <div className="nearby-footer-actions" style={{ marginTop: 10 }}>
                {!authUser && (
                  <button
                    type="button"
                    onClick={() => {
                      setShowAuthPanel(true);
                      setAuthMode("login");
                    }}
                    disabled={authBusy}
                  >
                    Sign in
                  </button>
                )}
                {authUser && paymentRequired && !authUser.transitPaid && (
                  <button
                    type="button"
                    className="billing-buy-btn"
                    onClick={() => {
                      void startTransitCheckout();
                    }}
                    disabled={checkoutBusy}
                  >
                    {checkoutBusy ? "Opening Stripe…" : "Buy access ($20)"}
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => {
                    void loadNearbyPaths(false, nearbyRadiusM, true);
                  }}
                >
                  Retry
                </button>
              </div>
            </div>
          )}

          {nearbyStatus === "ready" && nearbyPreview && (
            <>
              <div className="nearby-metrics">
                <div className="nearby-metric">
                  <span>Segments</span>
                  <strong>{nearbyPreview.paths?.length ?? nearbyPreview.pathCount}</strong>
                </div>
                <div className="nearby-metric">
                  <span>Roads</span>
                  <strong>{nearbyPreview.roadCount}</strong>
                </div>
                <div className="nearby-metric">
                  <span>Paths</span>
                  <strong>{nearbyPreview.footCount}</strong>
                </div>
                <div className="nearby-metric">
                  <span>Parks</span>
                  <strong>{nearbyPreview.parkCount ?? 0}</strong>
                </div>
                <div className="nearby-metric">
                  <span>Radius</span>
                  <strong>{nearbyPreview.radiusM}m</strong>
                </div>
              </div>
              {nearbyPreview.stale || !nearbyPreview.paths?.length ? (
                <div className="nearby-map-status-banner">
                  {nearbyPreview.note ||
                    "No live streets for this location. Allow GPS and retry."}
                  <button
                    type="button"
                    onClick={() => {
                      void loadNearbyPaths(false, nearbyRadiusM, true);
                    }}
                  >
                    Force refresh
                  </button>
                </div>
              ) : null}

              {/*
                Map keeps full square size; this region scrolls if the panel
                is shorter than header+metrics+map+actions. Radius/footer stay
                pinned below so they are never clipped off-screen.
              */}
              <div className="nearby-panel-body">
                <Suspense
                  fallback={
                    <div className="auth-field-hint" style={{ padding: 12 }}>
                      Loading map…
                    </div>
                  }
                >
                  <NearbyMap data={nearbyPreview} />
                </Suspense>
              </div>

              <div className="nearby-panel-actions">
                <div
                  className="nearby-radius-controls"
                  role="group"
                  aria-label="Trace radius"
                >
                  {[250, 500, 750, 1000, 1500].map((radius) => (
                    <button
                      key={radius}
                      type="button"
                      className={nearbyRadiusM === radius ? "active" : ""}
                      onClick={() => {
                        void loadNearbyPaths(false, radius);
                      }}
                    >
                      {radius}m
                    </button>
                  ))}
                </div>

                <div className="nearby-footer">
                  <span>
                    {nearbyPreview.stale
                      ? nearbyPreview.note ?? "Fallback sketch"
                      : nearbyPreview.note ?? "OSM centerlines"}
                  </span>
                  <div className="nearby-footer-actions">
                    <a
                      href={safeGlobeHref(nearbyPreview.sourceUrl)}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      Source
                    </a>
                    <button
                      type="button"
                      onClick={() => {
                        void loadNearbyPaths(false, nearbyRadiusM, true);
                      }}
                    >
                      Refresh
                    </button>
                  </div>
                </div>
              </div>
            </>
          )}
        </FloatingChrome>
      )}{showWeatherPanel && (
        <FloatingChrome
          className={`weather-panel ${showWeatherForecast ? "weather-panel-expanded" : ""}`}
          role="dialog"
          aria-label="Weather forecast"
        >
          <div className="weather-panel-header">
            <div>
              <h3>WEATHER</h3>
              <span>{weatherFeed?.locationLabel ?? DEFAULT_WEATHER_LOCATION.label}</span>
            </div>
            <button
              type="button"
              className="weather-close"
              onClick={() =>
                runRateLimitedButtonAction("weather-close", () =>
                  setShowWeatherPanel(false),
                )
              }
              aria-label="Close weather"
            >
              x
            </button>
          </div>

          <div className="weather-panel-body">
            {weatherStatus === "loading" && (
              <div className="weather-loading">Loading weather...</div>
            )}

            {weatherStatus === "error" && (
              <div className="weather-error">
                <span>{weatherError}</span>
                <button
                  type="button"
                  onClick={() =>
                    runRateLimitedButtonAction("weather-retry", () => {
                      void loadWeatherFeed();
                    })
                  }
                >
                  Retry
                </button>
              </div>
            )}

            {weatherStatus === "ready" && weatherFeed && (
              <>
                <div className="weather-grid">
                  <div className="weather-metric">
                    <span>Temp</span>
                    <strong>{weatherFeed.tempF} F</strong>
                  </div>
                  <div className="weather-metric">
                    <span>Humidity</span>
                    <strong>{weatherFeed.humidityPct}%</strong>
                  </div>
                  <div className="weather-metric">
                    <span>Wind</span>
                    <strong>{weatherFeed.windMph} mph</strong>
                  </div>
                  <div
                    className={`weather-metric weather-condition ${
                      weatherFeed.hasLightning ? "weather-condition-alert" : ""
                    }`}
                    style={
                      {
                        ["--weather-condition-color"]: weatherGlow.text,
                        ["--weather-condition-glow"]: weatherGlow.css,
                      } as React.CSSProperties
                    }
                  >
                    <span>Condition</span>
                    <strong
                      className="weather-condition-value"
                      style={{
                        color: weatherGlow.text,
                        textShadow: `0 0 14px ${weatherGlow.css}`,
                      }}
                    >
                      {weatherFeed.condition}
                    </strong>
                  </div>
                </div>
                <div className="weather-footer">
                  <span>Updated {weatherFeed.updatedAt}</span>
                  <div className="weather-footer-actions">
                    <button
                      type="button"
                      className={`weather-forecast-toggle ${
                        showWeatherForecast ? "active" : ""
                      }`}
                      onClick={() =>
                        runRateLimitedButtonAction(
                          "weather-forecast-toggle",
                          () => setShowWeatherForecast((open) => !open),
                        )
                      }
                      aria-expanded={showWeatherForecast}
                      aria-controls="weather-forecast"
                    >
                      {showWeatherForecast ? "Hide forecast" : "Forecast"}
                    </button>
                    <button
                      type="button"
                      onClick={() =>
                        runRateLimitedButtonAction("weather-refresh", () => {
                          void loadWeatherFeed();
                        })
                      }
                    >
                      Refresh
                    </button>
                  </div>
                </div>
                {showWeatherForecast && (
                  <section
                    id="weather-forecast"
                    className="weather-forecast"
                    aria-label="Detailed weather forecast"
                  >
                    <div className="weather-forecast-header">
                      <span>Detailed outlook</span>
                      <span>7 days / next 7 hours</span>
                    </div>
                    <div
                      className="weather-forecast-tabs"
                      role="tablist"
                      aria-label="Forecast range"
                    >
                      <button
                        type="button"
                        role="tab"
                        aria-selected={forecastView === "daily"}
                        className={forecastView === "daily" ? "active" : ""}
                        onClick={() =>
                          runRateLimitedButtonAction("weather-daily-tab", () =>
                            setForecastView("daily"),
                          )
                        }
                      >
                        7 days
                      </button>
                      <button
                        type="button"
                        role="tab"
                        aria-selected={forecastView === "hourly"}
                        className={forecastView === "hourly" ? "active" : ""}
                        onClick={() =>
                          runRateLimitedButtonAction("weather-hourly-tab", () =>
                            setForecastView("hourly"),
                          )
                        }
                      >
                        7 hours
                      </button>
                    </div>
                    <div className="weather-forecast-list">
                      {forecastView === "daily"
                        ? weatherFeed.dailyForecast.map((day) => (
                            <article
                              className="weather-forecast-row"
                              key={day.date}
                            >
                              <div className="weather-forecast-time">
                                <strong>{formatForecastDay(day.date)}</strong>
                                <span>{day.condition}</span>
                              </div>
                              <div className="weather-forecast-temp">
                                <strong>{day.highF}°</strong>
                                <span>{day.lowF}° low</span>
                              </div>
                              <div className="weather-forecast-details">
                                <span>
                                  Rain {day.precipitationChancePct}% ·{" "}
                                  {day.precipitationIn.toFixed(2)} in
                                </span>
                                <span>
                                  Wind {day.windMph} mph · Gusts {day.gustMph} ·
                                  UV {day.uvIndex}
                                </span>
                              </div>
                            </article>
                          ))
                        : weatherFeed.hourlyForecast.map((hour) => (
                            <article
                              className="weather-forecast-row"
                              key={hour.time}
                            >
                              <div className="weather-forecast-time">
                                <strong>{formatForecastHour(hour.time)}</strong>
                                <span>{hour.condition}</span>
                              </div>
                              <div className="weather-forecast-temp">
                                <strong>{hour.tempF}°</strong>
                                <span>Feels {hour.feelsLikeF}°</span>
                              </div>
                              <div className="weather-forecast-details">
                                <span>
                                  Hum {hour.humidityPct}% · Rain{" "}
                                  {hour.precipitationChancePct}% ·{" "}
                                  {hour.precipitationIn.toFixed(2)} in
                                </span>
                                <span>
                                  Wind {hour.windMph} mph · Gusts {hour.gustMph}{" "}
                                  · Cloud {hour.cloudCoverPct}%
                                </span>
                              </div>
                            </article>
                          ))}
                    </div>
                  </section>
                )}
              </>
            )}
          </div>
        </FloatingChrome>
      )}
    </>
  );
}
