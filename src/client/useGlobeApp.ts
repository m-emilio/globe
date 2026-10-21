import React, { useState, useRef, useEffect, useCallback, useMemo } from "react";
import { rememberAdminElevation } from "./adminElevation";
import { type GlobeArc, type GlobeChoroplethRegion, type GlobeHeatZone } from "./CobeGlobe";
import { SiteTour, markSiteTourSeen, shouldShowSiteTour } from "./SiteTour";
import { ActivityFeed, createActivityEvent, prependActivityEvent, type ActivityEvent, type ActivityFilter, type GlobeSocketStatus, type LiveFeedAccess } from "./ActivityFeed";
import usePartySocket from "partysocket/react";
import { clearPreviewCache, fetchPreviewJson, getPreviewCache, warmPreviewUrl } from "./previewCache";
import type { ComtradePreview, NearbyPathsPreview, PkiVulnCve, PkiVulnSeverity, PkiVulnsPreview, SamContractsPreview, TradePulseLayer, TradePulsePreview, TransitNearbyPreview, UnGlobalPreview, UnodcHotspotsPreview, UnodcThemeId } from "../shared";
import { CHAT_CLIENT_MAX_PER_WINDOW, CHAT_RATE_WINDOW_MS, sanitizeChatDisplayName, sanitizeChatText } from "../shared";
import { authFetch, clearLastFingerprint, clearSessionToken, containsPrivateKeyBlock, deleteDeviceKey, downloadPrivateKeyFile, ensureOpenPgp, exportPrivateKeyToArmoredFile, formatFingerprint, generateAndKeepOnDevice, requestPersistentDeviceStorage, getDeviceKey, getPreferredDeviceKey, listDeviceKeys, preferredExportS2k, privateKeyIsEncrypted, readKeyFile, saveDeviceKey, setLastFingerprint, shortFingerprint, signChallenge, signInWithDeviceKey, type AeadModeId, type DeviceKeyRecord, type KeyGenProfileId, type PrivateKeyExportEncryption, type PublicIdentity, type S2kProtocolId, type SymmetricCipherId } from "./pgpAuth";
import {
  BUTTON_RATE_LIMIT_MS,
  COMTRADE_SECTION_DESCRIPTIONS,
  ComtradeSection,
  ComtradeStatus,
  ComtradeValueMode,
  DEFAULT_COMTRADE_SECTIONS,
  DEFAULT_PKI_SEVERITIES,
  DEFAULT_TRADE_PULSE_LAYERS,
  DEFAULT_UNODC_THEMES,
  DEFAULT_UN_GLOBAL_SECTIONS,
  DEFAULT_WEATHER_LOCATION,
  ForecastView,
  GEOCODE_MIN_MS,
  LIGHTNING_WEATHER_CODES,
  LocationPreference,
  NEARBY_SESSION_MAX_RAW,
  NearbyStatus,
  OpenMeteoForecastResponse,
  PKI_DENSITY_LIMITS,
  PKI_PREVIEW_URL,
  PkiArcSelection,
  PkiCatalogFilter,
  PkiDensity,
  PkiSortMode,
  PkiVulnsStatus,
  SAM_CONTRACTS_PREVIEW_URL,
  TRADE_PULSE_LAYERS,
  TRADE_PULSE_LAYER_COLORS,
  TRADE_PULSE_LAYER_SHORT_LABELS,
  TRADE_PULSE_TRANSPORT_DASHES,
  TradePulseStatus,
  TransitStatus,
  UNODC_FOCUS_THEMES,
  UNODC_PREVIEW_URL,
  UNODC_THEME_CSS,
  UNODC_THEME_IDS,
  UnGlobalSection,
  UnGlobalStatus,
  UnodcStatus,
  WeatherFeed,
  WeatherStatus,
  buildDailyForecast,
  buildHourlyForecast,
  buildPkiGlobeArcs,
  buildUnodcThemeHeatZones,
  buildWeatherUrl,
  clampCoord,
  closeContractsHubRoute,
  closePkiHubRoute,
  closeUnHubRoute,
  describeWeatherCode,
  formatCoordPair,
  formatPreviewDate,
  formatPreviewNumber,
  formatWeatherTime,
  geocodeAddressQuery,
  getBrowserPosition,
  getIsContractsHubRoute,
  getIsPkiHubRoute,
  getIsTradePulsePreview,
  getIsUnHubRoute,
  getRoutePulseLayer,
  getVisibleTradePulseRoutes,
  getWeatherGlow,
  isCompleteUnodcPreview,
  isValidNearbyPathsCache,
  loadLocationPreference,
  normalizeLocationPreference,
  openContractsHubRoute,
  openPkiHubRoute,
  openUnHubRoute,
  parseFiniteCoord,
  parseSocketMessage,
  sanitizeAddressQuery,
  sanitizeLocationLabel,
  saveLocationPreference,
  sortPkiCves,
} from "./globeModel";

export function useGlobeApp() {
const isTradePulsePreview = getIsTradePulsePreview();
  const [showSiteTour, setShowSiteTour] = useState(() => shouldShowSiteTour());
  const dismissSiteTour = useCallback(() => {
    markSiteTourSeen();
    setShowSiteTour(false);
  }, []);
  const [showAbout, setShowAbout] = useState(false);
  const [showMenu, setShowMenu] = useState(false);
  const [locationPref, setLocationPref] = useState<LocationPreference>(() =>
    loadLocationPreference(),
  );
  const [locationDraftLat, setLocationDraftLat] = useState(() =>
    String(loadLocationPreference().latitude),
  );
  const [locationDraftLng, setLocationDraftLng] = useState(() =>
    String(loadLocationPreference().longitude),
  );
  const [locationDraftLabel, setLocationDraftLabel] = useState(() =>
    loadLocationPreference().label,
  );
  const [locationDraftAddress, setLocationDraftAddress] = useState("");
  const [locationBusy, setLocationBusy] = useState(false);
  const [locationMessage, setLocationMessage] = useState("");
  const lastGeocodeAtRef = useRef(0);
  const [showWeatherPanel, setShowWeatherPanel] = useState(false);
  const [weatherStatus, setWeatherStatus] = useState<WeatherStatus>("idle");
  const [weatherFeed, setWeatherFeed] = useState<WeatherFeed | null>(null);
  const [weatherError, setWeatherError] = useState("");
  const [showWeatherForecast, setShowWeatherForecast] = useState(false);
  const [forecastView, setForecastView] = useState<ForecastView>("daily");
  const [showComtradePanel, setShowComtradePanel] = useState(false);
  const [comtradeStatus, setComtradeStatus] = useState<ComtradeStatus>("idle");
  const [comtradePreview, setComtradePreview] = useState<ComtradePreview | null>(null);
  const [comtradeError, setComtradeError] = useState("");
  const [comtradeSections, setComtradeSections] = useState(DEFAULT_COMTRADE_SECTIONS);
  const [comtradeValueMode, setComtradeValueMode] =
    useState<ComtradeValueMode>("compact");
  const [showUnHub, setShowUnHub] = useState(() => getIsUnHubRoute());
  const [showPkiHub, setShowPkiHub] = useState(() => getIsPkiHubRoute());
  const [showContractsHub, setShowContractsHub] = useState(() =>
    getIsContractsHubRoute(),
  );
  type ContractsStatus = "idle" | "loading" | "ready" | "error";
  const [contractsStatus, setContractsStatus] =
    useState<ContractsStatus>("idle");
  const [contractsPreview, setContractsPreview] =
    useState<SamContractsPreview | null>(null);
  const [contractsError, setContractsError] = useState("");
  const [contractsLayerOn, setContractsLayerOn] = useState(true);
  const [contractsQuery, setContractsQuery] = useState({
    preset: "pki",
    q: "",
    days: 30,
    setAside: "",
    naicsGroup: "fk_pki",
    includeAwards: true,
  });
  const [showTradePulsePanel, setShowTradePulsePanel] = useState(isTradePulsePreview);
  /** Start minimized so the globe (and point + popups) stay primary */
  const [isTradePulsePanelMinimized, setIsTradePulsePanelMinimized] =
    useState(true);
  const [tradePulseStatus, setTradePulseStatus] = useState<TradePulseStatus>("idle");
  const [tradePulsePreview, setTradePulsePreview] = useState<TradePulsePreview | null>(
    null,
  );
  const [tradePulseError, setTradePulseError] = useState("");
  const [tradePulsePeriod, setTradePulsePeriod] = useState("2023");
  const [tradePulseLayers, setTradePulseLayers] = useState(DEFAULT_TRADE_PULSE_LAYERS);
  const [showUnGlobalPanel, setShowUnGlobalPanel] = useState(false);
  const [isUnGlobalPanelMinimized, setIsUnGlobalPanelMinimized] = useState(false);
  const [unGlobalStatus, setUnGlobalStatus] = useState<UnGlobalStatus>("idle");
  const [unGlobalPreview, setUnGlobalPreview] = useState<UnGlobalPreview | null>(null);
  const [unGlobalError, setUnGlobalError] = useState("");
  const [unGlobalSections, setUnGlobalSections] = useState(DEFAULT_UN_GLOBAL_SECTIONS);
  const [showUnodcPanel, setShowUnodcPanel] = useState(false);
  const [isUnodcPanelMinimized, setIsUnodcPanelMinimized] = useState(true);
  const [unodcStatus, setUnodcStatus] = useState<UnodcStatus>("idle");
  const [unodcPreview, setUnodcPreview] = useState<UnodcHotspotsPreview | null>(null);
  const [unodcError, setUnodcError] = useState("");
  const [unodcThemes, setUnodcThemes] = useState(DEFAULT_UNODC_THEMES);
  const [unodcCountryPolygons, setUnodcCountryPolygons] = useState<
    Map<string, { iso3: string; name: string; rings: [number, number][][] }> | null
  >(null);
  const [showPkiPanel, setShowPkiPanel] = useState(false);
  const [isPkiPanelMinimized, setIsPkiPanelMinimized] = useState(true);
  const [pkiStatus, setPkiStatus] = useState<PkiVulnsStatus>("idle");
  const [pkiPreview, setPkiPreview] = useState<PkiVulnsPreview | null>(null);
  const [pkiError, setPkiError] = useState("");
  const [pkiShowMap, setPkiShowMap] = useState(true);
  const [pkiCatalog, setPkiCatalog] = useState<PkiCatalogFilter>("all");
  const [pkiSort, setPkiSort] = useState<PkiSortMode>("priority");
  const [pkiDensity, setPkiDensity] = useState<PkiDensity>("sparse");
  const [pkiArcPage, setPkiArcPage] = useState(0);
  const [pkiFocusCve, setPkiFocusCve] = useState<string | null>(null);
  const [pkiCategory, setPkiCategory] = useState<string | "all">("all");
  const [pkiSeverities, setPkiSeverities] = useState<Set<PkiVulnSeverity>>(
    () => new Set<PkiVulnSeverity>(["critical", "high", "medium"]),
  );
  const [showActivityMenu, setShowActivityMenu] = useState(false);
  const [activityFilter, setActivityFilter] = useState<ActivityFilter>("all");
  const [isFeedPaused, setIsFeedPaused] = useState(false);
  const [isCompactFeed, setIsCompactFeed] = useState(false);
  /** Public globe WS — independent of paid Live Feed unlock. */
  const [socketStatus, setSocketStatus] =
    useState<GlobeSocketStatus>("connecting");
  const [counter, setCounter] = useState(0);
  const [activityFeed, setActivityFeed] = useState<ActivityEvent[]>([]);
  /** Ephemeral chat — React memory only; cleared on refresh / navigation */
  const [chatMessages, setChatMessages] = useState<
    Array<{
      id: string;
      fromId: string;
      text: string;
      displayName: string;
      ts: number;
      isSelf?: boolean;
    }>
  >([]);
  const [showNearbyPanel, setShowNearbyPanel] = useState(false);
  const [nearbyStatus, setNearbyStatus] = useState<NearbyStatus>("idle");
  const [nearbyPreview, setNearbyPreview] = useState<NearbyPathsPreview | null>(
    null,
  );
  const [nearbyError, setNearbyError] = useState("");
  const [nearbyRadiusM, setNearbyRadiusM] = useState(750);
  const [showTransitPanel, setShowTransitPanel] = useState(false);
  const [transitStatus, setTransitStatus] = useState<TransitStatus>("idle");
  const [transitPreview, setTransitPreview] = useState<TransitNearbyPreview | null>(
    null,
  );
  const [transitError, setTransitError] = useState("");
  const [transitDistanceM, setTransitDistanceM] = useState(800);
  const [authBusy, setAuthBusy] = useState(false);
  const [checkoutBusy, setCheckoutBusy] = useState(false);
  const [authMessage, setAuthMessage] = useState("");
  const [authError, setAuthError] = useState("");
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [showAuthPanel, setShowAuthPanel] = useState(false);
  // Prefetch OpenPGP (~380KB) only when Auth is open — not on first paint
  useEffect(() => {
    if (!showAuthPanel) return;
    void ensureOpenPgp().catch(() => {
      // Loaded on demand when user signs in / generates; ignore idle prefetch errors
    });
  }, [showAuthPanel]);
  const [authUser, setAuthUser] = useState<{
    id: string;
    fingerprint: string;
    primaryUserId: string | null;
    transitPaid: boolean;
    unlimitedKeys?: boolean;
  } | null>(null);
  /** Mirrors TRANSIT_REQUIRE_PAYMENT. Default off: PGP session is enough. */
  const [paymentRequired, setPaymentRequired] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const [adminAllowlistConfigured, setAdminAllowlistConfigured] =
    useState(false);
  const [showAdminPanel, setShowAdminPanel] = useState(false);
  const [adminQuery, setAdminQuery] = useState("");
  const [adminLookupUser, setAdminLookupUser] = useState<{
    id: string;
    fingerprint: string;
    primaryUserId: string | null;
    transitPaid: boolean;
    transitOrigin?: "stripe" | "admin" | "unrecorded" | null;
    unlimitedKeys?: boolean;
    unlimitedKeyOrigin?: "stripe" | "admin" | "unrecorded" | null;
    createdAt?: string;
  } | null>(null);
  const [adminSessionId, setAdminSessionId] = useState("");
  /** Memory-only elevation after a device-key signature (10 min server TTL). */
  const [adminElevationToken, setAdminElevationToken] = useState<string | null>(
    null,
  );
  const [adminElevationExpiresAt, setAdminElevationExpiresAt] = useState<
    string | null
  >(null);
  useEffect(() => {
    rememberAdminElevation(adminElevationToken);
  }, [adminElevationToken]);
  const [adminNote, setAdminNote] = useState("");
  const [adminAudit, setAdminAudit] = useState<
    {
      at: string;
      action: string;
      targetUserId?: string | null;
      targetFingerprint?: string | null;
      detail?: string;
    }[]
  >([]);
  type AdminUserRow = {
    id: string;
    fingerprint: string;
    primaryUserId: string | null;
    transitPaid: boolean;
    transitOrigin?: "stripe" | "admin" | "unrecorded" | null;
    unlimitedKeys?: boolean;
    unlimitedKeyOrigin?: "stripe" | "admin" | "unrecorded" | null;
    createdAt?: string;
  };
  const [adminUsers, setAdminUsers] = useState<AdminUserRow[]>([]);
  const [adminUsersCursor, setAdminUsersCursor] = useState<string | null>(null);
  const [adminUsersComplete, setAdminUsersComplete] = useState(true);
  const [adminUsersFilter, setAdminUsersFilter] = useState<
    "all" | "paid" | "locked"
  >("all");
  const [adminBusy, setAdminBusy] = useState(false);
  const [adminMessage, setAdminMessage] = useState("");
  const [adminError, setAdminError] = useState("");
  // Register: public key in state; private key lives in device vault (IndexedDB), never uploaded
  const [regPublicKey, setRegPublicKey] = useState("");
  const [generatedPublic, setGeneratedPublic] = useState<PublicIdentity | null>(
    null,
  );
  const [keySavedAck, setKeySavedAck] = useState(false);
  const [keyGenProfile, setKeyGenProfile] =
    useState<KeyGenProfileId>("curve25519");
  const [deviceKeys, setDeviceKeys] = useState<DeviceKeyRecord[]>([]);
  const [selectedDeviceFp, setSelectedDeviceFp] = useState("");
  // Optional key passphrase — only when the *device key* is OpenPGP-encrypted
  const [keyPassphrase, setKeyPassphrase] = useState("");
  // Optional file export of the device private key (still never uploaded)
  const [exportPassphrase, setExportPassphrase] = useState("");
  const [exportPassphrase2, setExportPassphrase2] = useState("");
  const [exportCipher, setExportCipher] =
    useState<SymmetricCipherId>("aes256");
  const [exportS2k, setExportS2k] = useState<S2kProtocolId>(() =>
    preferredExportS2k(),
  );
  const [exportS2kIterByte, setExportS2kIterByte] = useState(224);
  const [exportArgonPasses, setExportArgonPasses] = useState(3);
  const [exportArgonParallel, setExportArgonParallel] = useState(4);
  const [exportArgonMemExp, setExportArgonMemExp] = useState(16);
  const [exportAead, setExportAead] = useState(false);
  const [exportAeadMode, setExportAeadMode] = useState<AeadModeId>("gcm");
  const [exportAllowUnencrypted, setExportAllowUnencrypted] = useState(false);
  const [showImportDevice, setShowImportDevice] = useState(false);
  const [importKeyText, setImportKeyText] = useState("");
  const navBarRef = useRef<HTMLElement | null>(null);

  type AuthUser = {
    id: string;
    fingerprint: string;
    primaryUserId: string | null;
    transitPaid: boolean;
    unlimitedKeys?: boolean;
  };

  const refreshAuth = async (): Promise<AuthUser | null> => {
    try {
      const response = await authFetch("/api/auth/me");
      const data = (await response.json()) as {
        authenticated?: boolean;
        user?: AuthUser | null;
        isAdmin?: boolean;
        adminAllowlistConfigured?: boolean;
        paymentRequired?: boolean;
      };
      if (typeof data.paymentRequired === "boolean") {
        setPaymentRequired(data.paymentRequired);
      }
      if (data.authenticated && data.user?.fingerprint) {
        setAuthUser(data.user);
        setIsAdmin(Boolean(data.isAdmin));
        setAdminAllowlistConfigured(Boolean(data.adminAllowlistConfigured));
        return data.user;
      }
      setAuthUser(null);
      setIsAdmin(false);
      setAdminAllowlistConfigured(false);
      return null;
    } catch {
      setAuthUser(null);
      setIsAdmin(false);
      setAdminAllowlistConfigured(false);
      return null;
    }
  };

  const adminElevationValid = (): boolean => {
    if (!adminElevationToken || !adminElevationExpiresAt) return false;
    return new Date(adminElevationExpiresAt).getTime() > Date.now() + 5_000;
  };

  const adminHeaders = (): HeadersInit => {
    const h: Record<string, string> = {
      accept: "application/json",
      "content-type": "application/json",
    };
    if (adminElevationToken) {
      h["x-admin-elevation"] = adminElevationToken;
    }
    return h;
  };

  const loadAdminAudit = async () => {
    try {
      const res = await authFetch("/api/admin/audit");
      const data = (await res.json()) as { entries?: typeof adminAudit };
      if (res.ok) setAdminAudit(data.entries || []);
    } catch {
      // ignore
    }
  };

  /**
   * Elevated directory: device-key unlock plus the allowlisted fingerprint.
   * Returns public fields only (no keys). Uses POST so the elevation header is sent.
   */
  const loadAdminUsers = async (opts?: {
    append?: boolean;
    cursor?: string | null;
  }) => {
    setAdminBusy(true);
    setAdminError("");
    try {
      if (!adminElevationValid()) {
        throw new Error("Unlock privileges first (device-key signature).");
      }
      const res = await authFetch("/api/admin/users", {
        method: "POST",
        headers: adminHeaders(),
        body: JSON.stringify({
          limit: 100,
          cursor: opts?.cursor ?? null,
          paid: adminUsersFilter === "paid",
          locked: adminUsersFilter === "locked",
        }),
      });
      const data = (await res.json()) as {
        users?: AdminUserRow[];
        cursor?: string | null;
        complete?: boolean;
        count?: number;
        message?: string;
        error?: string;
      };
      if (!res.ok) {
        const code = data.error || "";
        if (code === "rate_limited") {
          throw new Error(
            "Too many admin list requests. Wait about a minute, then Load users again.",
          );
        }
        if (code === "elevation_expired" || code === "elevation_required") {
          throw new Error(
            "Admin elevation expired. Unlock privileges again, then Load users.",
          );
        }
        if (code === "admin_fingerprint_required") {
          throw new Error(
            "This signed-in key is not on ADMIN_FINGERPRINTS. Privileged actions need that key's signature.",
          );
        }
        throw new Error(data.message || data.error || "Could not list users");
      }
      const next = data.users || [];
      setAdminUsers((prev) => {
        const merged = opts?.append ? [...prev, ...next] : next;
        // Dedupe by id (pagination / filter rescans can overlap)
        const seen = new Set<string>();
        const deduped = merged.filter((u) => {
          if (!u?.id || seen.has(u.id)) return false;
          seen.add(u.id);
          return true;
        });
        setAdminMessage(
          `Loaded ${deduped.length} user(s)${
            data.complete === false ? " (more available)" : ""
          }.`,
        );
        return deduped;
      });
      setAdminUsersCursor(data.cursor ?? null);
      setAdminUsersComplete(Boolean(data.complete ?? true));
      try {
        await loadAdminAudit();
      } catch {
        // list still succeeds if audit refresh fails
      }
    } catch (error) {
      setAdminError(
        error instanceof Error ? error.message : "List users failed",
      );
    } finally {
      setAdminBusy(false);
    }
  };

  /** Permanently remove a user (elevated). Confirms in the browser first. */
  const adminDeleteUser = async (target?: AdminUserRow | null) => {
    const user = target || adminLookupUser;
    if (!user) {
      setAdminError("Select or lookup a user before removing.");
      return;
    }
    const short = user.id.slice(0, 12);
    const ok = window.confirm(
      `Permanently DELETE user ${short}…?\n\nFingerprint: ${user.fingerprint}\nThis revokes sessions and removes the account from the app. Cannot be undone.`,
    );
    if (!ok) return;

    setAdminBusy(true);
    setAdminError("");
    setAdminMessage("");
    try {
      if (!adminElevationValid()) {
        throw new Error("Unlock privileges first (device-key signature).");
      }
      const postDelete = async (confirm: string) => {
        const res = await authFetch("/api/admin/delete-user", {
          method: "POST",
          headers: adminHeaders(),
          body: JSON.stringify({
            userId: user.id,
            fingerprint: user.fingerprint,
            confirm,
          }),
        });
        const data = (await res.json()) as {
          ok?: boolean;
          message?: string;
          error?: string;
        };
        return { res, data };
      };
      let { res, data } = await postDelete("DELETE");
      if (!res.ok && data.error === "admin_delete_confirm") {
        const again = window.confirm(
          data.message ||
            "This account is on the admin allowlist. Delete it from the database?",
        );
        if (!again) {
          setAdminMessage("Delete cancelled.");
          return;
        }
        ({ res, data } = await postDelete("DELETE ADMIN"));
      }
      if (!res.ok) {
        throw new Error(data.message || data.error || "Delete failed");
      }
      setAdminLookupUser(null);
      setAdminUsers((prev) => prev.filter((u) => u.id !== user.id));
      setAdminMessage(data.message || "User deleted.");
      if (authUser && user.id === authUser.id) await refreshAuth();
      await loadAdminAudit();
    } catch (error) {
      setAdminError(
        error instanceof Error ? error.message : "Delete user failed",
      );
    } finally {
      setAdminBusy(false);
    }
  };

  const clearAdminElevation = () => {
    setAdminElevationToken(null);
    setAdminElevationExpiresAt(null);
    setAdminUsers([]);
    setAdminUsersCursor(null);
    setAdminUsersComplete(true);
  };

  /**
   * Sign a server challenge with the device private key.
   * The server accepts the window only when that key is on ADMIN_FINGERPRINTS.
   * The private key never leaves the browser.
   */
  const unlockAdminPrivileges = async () => {
    setAdminBusy(true);
    setAdminError("");
    setAdminMessage("");
    try {
      if (!authUser) throw new Error("Sign in first.");

      const chalRes = await authFetch("/api/admin/elevate-challenge", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      const chal = (await chalRes.json()) as {
        challengeId?: string;
        message?: string;
        error?: string;
      };
      if (!chalRes.ok || !chal.challengeId || !chal.message) {
        throw new Error(
          chal.message ||
            chal.error ||
            "Could not start admin elevation. Sign in with an allowlisted admin key.",
        );
      }

      let elevateBody: {
        challengeId: string;
        signatureArmored?: string;
        pqcSignature?: string;
      };
      if (/^[a-f0-9]{64}$/i.test(authUser.fingerprint)) {
        const { signStoredPqcMessage } = await import("./mlDsa");
        elevateBody = {
          challengeId: chal.challengeId,
          pqcSignature: await signStoredPqcMessage(authUser.fingerprint, chal.message),
        };
      } else {
        const dk =
          (await getDeviceKey(authUser.fingerprint)) ||
          (await getPreferredDeviceKey());
        if (!dk) {
          throw new Error(
            "No device private key on this browser for your admin fingerprint. Import the key onto this device first.",
          );
        }
        if (
          dk.fingerprint.replace(/[\s:]/g, "").toLowerCase() !==
          authUser.fingerprint.replace(/[\s:]/g, "").toLowerCase()
        ) {
          throw new Error(
            "Device key fingerprint does not match the signed-in admin account.",
          );
        }
        elevateBody = {
          challengeId: chal.challengeId,
          signatureArmored: await signChallenge(
            chal.message,
            dk.privateKeyArmored,
            dk.encrypted ? keyPassphrase || undefined : undefined,
          ),
        };
      }

      const elevRes = await authFetch("/api/admin/elevate", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(elevateBody),
      });
      const elev = (await elevRes.json()) as {
        elevationToken?: string;
        expiresAt?: string;
        message?: string;
        error?: string;
      };
      if (!elevRes.ok || !elev.elevationToken) {
        throw new Error(
          elev.message || elev.error || "Elevation signature rejected",
        );
      }

      setAdminElevationToken(elev.elevationToken);
      setAdminElevationExpiresAt(elev.expiresAt || null);
      setAdminMessage(
        "Privileged window open for about 10 minutes. Grant unlimited keys to this account is ready.",
      );
      await loadAdminAudit();
    } catch (error) {
      clearAdminElevation();
      setAdminError(
        error instanceof Error ? error.message : "Could not unlock privileges",
      );
    } finally {
      setAdminBusy(false);
    }
  };

  const openAdminPanel = async () => {
    setShowMenu(false);
    setAdminError("");
    setAdminMessage("");
    clearAdminElevation();
    const user = await refreshAuth();
    if (!user) {
      setShowAuthPanel(true);
      setAuthMode("login");
      setAuthMessage("Sign in with your admin key to open Admin.");
      return;
    }
    try {
      const res = await authFetch("/api/auth/me");
      const data = (await res.json()) as {
        isAdmin?: boolean;
        adminAllowlistConfigured?: boolean;
      };
      setIsAdmin(Boolean(data.isAdmin));
      setAdminAllowlistConfigured(Boolean(data.adminAllowlistConfigured));
      if (!data.isAdmin) {
        const fp = formatFingerprint(user.fingerprint);
        const hex = user.fingerprint.replace(/[\s:]/g, "").toLowerCase();
        setAdminError(
          !data.adminAllowlistConfigured
            ? `No admin allowlist on the server. Set Cloudflare secret ADMIN_FINGERPRINT_SECRET to your fingerprint (no spaces):\n${hex}`
            : `This signed-in key is not on ADMIN_FINGERPRINT_SECRET.\n\nYour full fingerprint (copy into Cloudflare Worker secret ADMIN_FINGERPRINT_SECRET):\n${hex}\n\nFormatted:\n${fp}`,
        );
        // Still open panel so the message + fingerprint are visible
        setShowAdminPanel(true);
        return;
      }
    } catch {
      setAdminError("Could not verify admin status. Try signing out and back in.");
      setShowAdminPanel(true);
      return;
    }
    try {
      const st = await authFetch("/api/admin/status");
      const stData = (await st.json()) as {
        error?: string;
        message?: string;
      };
      if (!st.ok) {
        setAdminError(
          stData.message ||
            stData.error ||
            "Admin status denied by server (allowlist or session).",
        );
      }
    } catch {
      // ignore
    }
    setShowAdminPanel(true);
    if (isAdmin || true) {
      // load audit only when server allows (fails closed otherwise)
      try {
        await loadAdminAudit();
      } catch {
        // ignore
      }
    }
  };

  const adminLookup = async () => {
    setAdminBusy(true);
    setAdminError("");
    setAdminMessage("");
    try {
      const res = await authFetch(
        `/api/admin/lookup?q=${encodeURIComponent(adminQuery.trim())}`,
      );
      const data = (await res.json()) as {
        found?: boolean;
        user?: typeof adminLookupUser;
        message?: string;
        error?: string;
      };
      if (!res.ok) {
        throw new Error(data.message || data.error || "Lookup failed");
      }
      setAdminLookupUser(data.found ? data.user || null : null);
      setAdminMessage(data.found ? "User found." : "No user matched that query.");
    } catch (error) {
      setAdminError(error instanceof Error ? error.message : "Lookup failed");
    } finally {
      setAdminBusy(false);
    }
  };

  const signUnlimitedKeyPrivilege = async (
    action: "grant" | "revoke",
    targetFingerprint: string,
  ) => {
    const target = targetFingerprint.replace(/[\s:]/g, "").toLowerCase();
    const adminFp = (authUser?.fingerprint || "").replace(/[\s:]/g, "").toLowerCase();
    if (
      !/^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(target) ||
      !/^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(adminFp)
    ) {
      throw new Error("Unlimited keys follow a fingerprint. Use this account, or look the key up again.");
    }
    const message = `globe-unlimited-keys:v1|${action}|${target}|${adminFp}`;
    if (/^[a-f0-9]{64}$/.test(adminFp)) {
      const { signStoredPqcMessage } = await import("./mlDsa");
      return { fingerprint: target, pqcSignature: await signStoredPqcMessage(adminFp, message) };
    }
    const device =
      (await getDeviceKey(adminFp)) || (await getPreferredDeviceKey());
    if (!device) {
      throw new Error("No device private key on this browser matches this admin key.");
    }
    return {
      fingerprint: target,
      signatureArmored: await signChallenge(
        message,
        device.privateKeyArmored,
        device.encrypted ? keyPassphrase || undefined : undefined,
      ),
    };
  };

  const adminGrantKind = async (
    kind: "transit" | "keys",
    grant: boolean,
    explicitTarget?: AdminUserRow | null,
  ) => {
    setAdminBusy(true);
    setAdminError("");
    setAdminMessage("");
    try {
      const target = explicitTarget || adminLookupUser;
      if (!target) throw new Error("Lookup a user first.");
      if (!adminElevationValid()) {
        throw new Error(
          "Unlock privileges first. Grant and revoke need a fresh signature from the allowlisted key.",
        );
      }
      const signed =
        kind === "keys"
          ? await signUnlimitedKeyPrivilege(grant ? "grant" : "revoke", target.fingerprint)
          : null;
      const path =
        kind === "transit"
          ? grant
            ? "/api/admin/grant-transit"
            : "/api/admin/revoke-transit"
          : grant
            ? "/api/admin/grant-unlimited-keys"
            : "/api/admin/revoke-unlimited-keys";
      const res = await authFetch(
        path,
        {
          method: "POST",
          headers: adminHeaders(),
          body: JSON.stringify({
            userId: target.id,
            fingerprint: signed?.fingerprint || target.fingerprint,
            note: adminNote.trim() || undefined,
            pqcSignature: signed && "pqcSignature" in signed ? signed.pqcSignature : undefined,
            signatureArmored: signed && "signatureArmored" in signed ? signed.signatureArmored : undefined,
          }),
        },
      );
      const data = (await res.json()) as {
        user?: typeof adminLookupUser;
        message?: string;
        error?: string;
      };
      if (!res.ok) {
        throw new Error(data.message || data.error || "Action failed");
      }
      if (data.user) setAdminLookupUser(data.user);
      setAdminMessage(data.message || (grant ? "Granted." : "Revoked."));
      await loadAdminAudit();
      if (authUser && data.user && data.user.id === authUser.id) {
        await refreshAuth();
      }
    } catch (error) {
      setAdminError(error instanceof Error ? error.message : "Action failed");
    } finally {
      setAdminBusy(false);
    }
  };

  const adminGrant = async (grant: boolean) => adminGrantKind("transit", grant);

  const adminClaim = async () => {
    setAdminBusy(true);
    setAdminError("");
    setAdminMessage("");
    try {
      if (!adminElevationValid()) {
        throw new Error(
          "Unlock privileges first. Claim needs a fresh signature from the allowlisted key.",
        );
      }
      const res = await authFetch("/api/admin/claim-session", {
        method: "POST",
        headers: adminHeaders(),
        body: JSON.stringify({
          session_id: adminSessionId.trim(),
          userId: adminLookupUser?.id,
          fingerprint: adminLookupUser?.fingerprint,
        }),
      });
      const data = (await res.json()) as {
        user?: typeof adminLookupUser;
        message?: string;
        error?: string;
        paymentStatus?: string;
        kind?: string;
      };
      if (!res.ok) {
        throw new Error(data.message || data.error || "Claim failed");
      }
      if (data.user) setAdminLookupUser(data.user);
      setAdminMessage(
        data.kind === "unlimited_keys"
          ? `Claimed session (${data.paymentStatus || "paid"}). Unlimited keys granted.`
          : `Claimed session (${data.paymentStatus || "paid"}). Transit granted.`,
      );
      await loadAdminAudit();
      if (authUser && data.user && data.user.id === authUser.id) {
        await refreshAuth();
      }
    } catch (error) {
      setAdminError(error instanceof Error ? error.message : "Claim failed");
    } finally {
      setAdminBusy(false);
    }
  };

  const adminClaimAll = async () => {
    setAdminBusy(true);
    setAdminError("");
    setAdminMessage("");
    try {
      if (!adminElevationValid()) {
        throw new Error(
          "Unlock privileges first. Claiming Stripe sessions needs a fresh signature from the allowlisted key.",
        );
      }
      const res = await authFetch("/api/admin/claim-stripe-all", {
        method: "POST",
        headers: adminHeaders(),
        body: "{}",
      });
      const data = (await res.json()) as {
        message?: string;
        error?: string;
        claimed?: number;
        already?: number;
        skipped?: number;
        unmatched?: number;
      };
      if (!res.ok) {
        throw new Error(data.message || data.error || "Stripe claim failed");
      }
      setAdminMessage(
        data.message ||
          `Claimed ${data.claimed ?? 0}. Already matched ${data.already ?? 0}.`,
      );
      await loadAdminAudit();
      await refreshAuth();
    } catch (error) {
      setAdminError(error instanceof Error ? error.message : "Stripe claim failed");
    } finally {
      setAdminBusy(false);
    }
  };

  const refreshDeviceKeys = async () => {
    try {
      const keys = await listDeviceKeys();
      setDeviceKeys(keys);
      if (!selectedDeviceFp && keys[0]) {
        setSelectedDeviceFp(keys[0].fingerprint);
      }
    } catch {
      setDeviceKeys([]);
    }
  };

  const selectedDeviceKey =
    deviceKeys.find((k) => k.fingerprint === selectedDeviceFp) || null;

  const clearSensitiveAuthState = () => {
    setKeyPassphrase("");
    setExportPassphrase("");
    setExportPassphrase2("");
    setImportKeyText("");
    setGeneratedPublic(null);
    setKeySavedAck(false);
  };

  const buildExportEncryption = (): PrivateKeyExportEncryption | null => {
    if (exportAllowUnencrypted && !exportPassphrase) {
      return null;
    }
    if (!exportPassphrase) {
      throw new Error(
        "Set an export passphrase (or allow unencrypted export).",
      );
    }
    if (exportPassphrase !== exportPassphrase2) {
      throw new Error("Export passphrases do not match.");
    }
    return {
      passphrase: exportPassphrase,
      cipher: exportCipher,
      s2k: exportS2k,
      s2kIterationCountByte: exportS2kIterByte,
      argon2: {
        passes: exportArgonPasses,
        parallelism: exportArgonParallel,
        memoryExponent: exportArgonMemExp,
      },
      aeadProtect: exportAead,
      aeadMode: exportAeadMode,
    };
  };

  /**
   * Create identity on this device:
   * - private key stays in IndexedDB (never uploaded)
   * - OpenPGP layer unencrypted by default → login needs no password
   * - At rest: AES-GCM wrapped with non-extractable device-bound WebCrypto key
   */
  const handleGenerateKeypair = async () => {
    setAuthBusy(true);
    setAuthError("");
    try {
      await requestPersistentDeviceStorage();
      const result = await generateAndKeepOnDevice({
        profile: keyGenProfile,
      });
      setGeneratedPublic(result.public);
      setRegPublicKey(result.public.publicKeyArmored);
      setSelectedDeviceFp(result.deviceKey.fingerprint);
      setKeySavedAck(true); // device already holds the key
      await refreshDeviceKeys();
      // Confirm vault can list the key (mobile storage races)
      const listed = await listDeviceKeys();
      const found = listed.some(
        (k) =>
          k.fingerprint.replace(/[\s:]/g, "").toLowerCase() ===
          result.deviceKey.fingerprint.replace(/[\s:]/g, "").toLowerCase(),
      );
      if (!found) {
        throw new Error(
          "Key was generated but is not visible in this browser’s vault yet. Leave private mode, allow site data, and tap Generate again — or download a backup .asc.",
        );
      }
      setAuthMessage(
        `Created ${result.profileLabel} on this device. Private key never leaves the browser; stored device-bound (AES-wrapped). Next: tap Register & stay signed in (public key only) — required before Sign in works.`,
      );
    } catch (error) {
      setAuthError(
        error instanceof Error ? error.message : "Key generation failed",
      );
    } finally {
      setAuthBusy(false);
    }
  };

  /** Optional: export device private key to a file (still never uploaded). */
  const handleExportPrivateKey = async () => {
    setAuthBusy(true);
    setAuthError("");
    try {
      const dk =
        selectedDeviceKey ||
        (generatedPublic
          ? await getDeviceKey(generatedPublic.fingerprint)
          : null);
      if (!dk) {
        throw new Error("No device key to export. Generate one first.");
      }
      const encryption = buildExportEncryption();
      const result = await exportPrivateKeyToArmoredFile({
        privateKeyArmored: dk.privateKeyArmored,
        sourcePassphrase: dk.encrypted
          ? keyPassphrase || undefined
          : undefined,
        encryption,
      });
      downloadPrivateKeyFile(result.armored, result.filename);
      // Device vault stays device-bound (AES wrap). Backup file may add OpenPGP passphrase.
      setAuthMessage(
        `Backup saved as ${result.filename} (${result.encrypted ? "passphrase-encrypted" : "UNENCRYPTED"}).${result.notice ? ` ${result.notice}` : ""} Device vault key unchanged for sign-in.`,
      );
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Export failed");
    } finally {
      setAuthBusy(false);
    }
  };

  const registerWithPublicKey = async () => {
    setAuthBusy(true);
    setAuthError("");
    setAuthMessage("");
    try {
      const publicKeyArmored = regPublicKey.trim();
      if (!publicKeyArmored) {
        throw new Error("Generate a device key first (or paste a public key).");
      }
      if (containsPrivateKeyBlock(publicKeyArmored)) {
        throw new Error("Never paste a private key into registration.");
      }

      const response = await authFetch("/api/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ publicKeyArmored }),
      });
      const data = (await response.json()) as {
        user?: AuthUser;
        sessionToken?: string;
        isAdmin?: boolean;
        message?: string;
        error?: string;
      };
      if (!response.ok || !data.user) {
        throw new Error(data.message || data.error || "Registration failed");
      }
      // Session is HttpOnly cookie from Set-Cookie — never store sessionToken in JS.
      clearSessionToken();
      setLastFingerprint(data.user.fingerprint);
      setSelectedDeviceFp(data.user.fingerprint);
      setGeneratedPublic(null);
      setRegPublicKey("");
      // Re-fetch /me so cookie + admin/transit flags settle (mobile ITP / WebViews).
      const me = await refreshAuth();
      if (!me) {
        setAuthUser(null);
        setIsAdmin(false);
        setAuthMessage(
          "Public key registered, but this browser blocked the session cookie. Allow cookies for this site (not private mode / not an in-app browser), then use Sign in → Continue with device key.",
        );
        setAuthMode("login");
        await refreshDeviceKeys();
        return;
      }
      setAuthUser(me);
      setIsAdmin(Boolean(data.isAdmin));
      setShowAuthPanel(false);
      setAuthMessage(
        "Registered. You are signed in. Next visits: open Sign in → Continue with device key (no private key upload).",
      );
    } catch (error) {
      setAuthError(
        error instanceof Error ? error.message : "Registration failed",
      );
    } finally {
      setAuthBusy(false);
    }
  };

  /** Sign in with key already on this device — never uploads the private key. */
  const handleDeviceSignIn = async () => {
    setAuthBusy(true);
    setAuthError("");
    setAuthMessage("");
    try {
      const dk =
        selectedDeviceKey ||
        (await getPreferredDeviceKey()) ||
        null;
      if (!dk) {
        throw new Error(
          "No device key on this browser. Create one under Create identity, or import a backup onto this device once.",
        );
      }
      const result = await signInWithDeviceKey({
        deviceKey: dk,
        passphrase: dk.encrypted ? keyPassphrase || undefined : undefined,
      });
      setAuthUser(result.user);
      setIsAdmin(result.isAdmin);
      if (typeof result.paymentRequired === "boolean") {
        setPaymentRequired(result.paymentRequired);
      }
      setSelectedDeviceFp(result.user.fingerprint);
      setKeyPassphrase("");
      setShowAuthPanel(false);
      // Confirm admin allowlist + transit flags from server after cookie/token settle.
      await refreshAuth();
      setAuthMessage(
        dk.encrypted
          ? "Signed in with passphrase-protected device key (cookie session; key stays on device)."
          : dk.deviceBound
            ? "Signed in with device-bound key (AES-wrapped at rest; HttpOnly cookie session)."
            : "Signed in with device key — no password, no private key upload.",
      );
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Sign-in failed");
    } finally {
      setAuthBusy(false);
    }
  };

  /** Import a private key onto this device once (for a new browser). Never uploaded. */
  const handleImportDeviceKey = async (file?: File | null) => {
    setAuthBusy(true);
    setAuthError("");
    try {
      await requestPersistentDeviceStorage();
      let text = importKeyText.trim();
      if (file) {
        text = await readKeyFile(file);
      }
      if (!containsPrivateKeyBlock(text)) {
        throw new Error("That is not an OpenPGP private key.");
      }
      const encrypted = await privateKeyIsEncrypted(text);
      const openpgpMod = await import("openpgp");
      const priv = await openpgpMod.readPrivateKey({ armoredKey: text });
      const fingerprint = priv
        .getFingerprint()
        .toLowerCase()
        .replace(/[\s:]/g, "");
      const publicKeyArmored = priv.toPublic().armor();
      await saveDeviceKey({
        fingerprint,
        publicKeyArmored,
        privateKeyArmored: text,
        encrypted,
        profileLabel: "Imported",
      });
      setImportKeyText("");
      setShowImportDevice(false);
      setSelectedDeviceFp(fingerprint);
      await refreshDeviceKeys();
      setAuthMessage(
        encrypted
          ? "Imported encrypted key onto this device. Sign-in asks for the key passphrase only. If the key is new to this site, Register the public key once first."
          : "Imported key onto this device. Sign-in needs no password. If the key is new to this site, Register the public key once first.",
      );
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Import failed");
    } finally {
      setAuthBusy(false);
    }
  };

  const handleRemoveDeviceKey = async (fp: string) => {
    await deleteDeviceKey(fp);
    await refreshDeviceKeys();
    setAuthMessage("Removed key from this device only (server account unchanged).");
  };

  const logout = async (allSessions = false) => {
    setAuthBusy(true);
    setAuthError("");
    try {
      await authFetch("/api/auth/logout", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ all: allSessions }),
      });
      setAuthUser(null);
      setIsAdmin(false);
      setShowAdminPanel(false);
      clearAdminElevation();
      clearSessionToken();
      clearLastFingerprint(); // localStorage remember — not browser “cache”
      clearSensitiveAuthState();
      setActivityFeed([]);
      activeVisitors.current.clear();
      setAuthMessage(
        allSessions
          ? "Logged out of all sessions. Device key still on this browser for next sign-in."
          : "Logged out. Session cleared. Device key still on this browser for next sign-in (clear site data to remove keys).",
      );
      setTransitPreview(null);
      setTransitStatus("idle");
      setNearbyPreview(null);
      setNearbyStatus("idle");
    } catch {
      setAuthError("Logout failed");
    } finally {
      setAuthBusy(false);
    }
  };

  /**
   * Stripe Payment Link checkout for paid API access
   * (Transit + Nearby + Live Feed + Contracting + support chat).
   * Requires an active session so the server can bind client_reference_id.
   * Guests never receive a payment URL — only a sign-in prompt.
   */
  const startTransitCheckout = async () => {
    setAuthError("");
    setAuthMessage("");

    if (!authUser) {
      setShowMenu(false);
      setShowAuthPanel(true);
      setAuthMode("login");
      setAuthMessage("Sign in first, then buy Stripe access ($20).");
      return;
    }
    if (authUser.transitPaid) {
      setAuthMessage(
        "Stripe access already unlocked (Transit, Nearby, Live Feed, Contracting, support chat).",
      );
      return;
    }

    setCheckoutBusy(true);
    setShowMenu(false);
    try {
      await authFetch("/api/billing/ensure-catalog", { method: "POST" });
      const response = await authFetch("/api/billing/payment-link");
      const data = (await response.json()) as {
        url?: string | null;
        amountLabel?: string;
        message?: string;
        error?: string;
      };
      if (!response.ok || !data.url) {
        throw new Error(
          data.message || data.error || "Payment link unavailable",
        );
      }
      // Only allow known Stripe Checkout hosts (open-redirect hard block).
      let checkoutUrl: URL;
      try {
        checkoutUrl = new URL(data.url);
      } catch {
        throw new Error("Invalid payment link from server");
      }
      const host = checkoutUrl.hostname.toLowerCase();
      if (
        checkoutUrl.protocol !== "https:" ||
        checkoutUrl.username ||
        checkoutUrl.password ||
        !(host === "buy.stripe.com" || host === "checkout.stripe.com")
      ) {
        throw new Error("Unexpected payment link host");
      }
      setAuthMessage("Redirecting to Stripe Checkout…");
      window.location.href = checkoutUrl.toString();
    } catch (error) {
      setAuthError(
        error instanceof Error ? error.message : "Could not start checkout",
      );
      setCheckoutBusy(false);
    }
  };

  useEffect(() => {
    void refreshDeviceKeys();
  }, []);

  const positions = useRef<
    Map<
      string,
      {
        location: [number, number];
        size: number;
      }
    >
  >(new Map());
  const activeVisitors = useRef<Map<string, ActivityEvent>>(new Map());
  const isFeedPausedRef = useRef(false);
  /** Server only sends feed-* when paid; this gates client-side record as well */
  const liveFeedUnlockedRef = useRef(false);
  const lastButtonClicks = useRef<Map<string, number>>(new Map());
  const authSocketIdRef = useRef<string | null | undefined>(undefined);

  // UI lock + client-side record gate. Server withholds feed-* unless the
  // session has feature access (PGP login; Stripe only when TRANSIT_REQUIRE_PAYMENT).
  const liveFeedAccess: LiveFeedAccess = !authUser
    ? "login_required"
    : paymentRequired && !authUser.transitPaid
      ? "payment_required"
      : "ok";

  useEffect(() => {
    isFeedPausedRef.current = isFeedPaused;
  }, [isFeedPaused]);

  useEffect(() => {
    liveFeedUnlockedRef.current = liveFeedAccess === "ok";
    if (liveFeedAccess !== "ok") {
      setActivityFeed([]);
      setChatMessages([]);
      activeVisitors.current.clear();
    }
  }, [liveFeedAccess]);

  // Session restore, URL auth_token handoff, optional Stripe return
  useEffect(() => {
    void (async () => {
      const params = new URLSearchParams(window.location.search);
      // One-shot URL handoff → adopt into HttpOnly cookie, never keep token in JS storage.
      const urlToken = params.get("auth_token") || params.get("session_token");
      if (urlToken && /^[a-f0-9]{32,128}$/i.test(urlToken)) {
        clearSessionToken();
        try {
          await authFetch("/api/auth/adopt-token", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ sessionToken: urlToken }),
          });
        } catch {
          // cookie may still work on /me
        }
        params.delete("auth_token");
        params.delete("session_token");
        const next = `${window.location.pathname}${params.toString() ? `?${params}` : ""}${window.location.hash}`;
        window.history.replaceState({}, "", next);
        setAuthMessage(
          "Session adopted into HttpOnly cookie (not stored in the page).",
        );
      }
      clearSessionToken();
      await refreshAuth();
    })();

    const params = new URLSearchParams(window.location.search);
    const billing = params.get("billing");
    // Stripe Payment Link can return session_id even without billing=success if only {CHECKOUT_SESSION_ID} is used
    const sessionId = params.get("session_id");

    if (billing === "cancel") {
      setAuthMessage("Checkout canceled — no charge was made.");
      setAuthError("");
    }

    // Unlock without Stripe CLI: claim paid Checkout Session after redirect
    if (sessionId && /^cs_[a-zA-Z0-9_]+$/.test(sessionId)) {
      setAuthMessage("Payment submitted. Confirming access…");
      setAuthError("");
      void (async () => {
        try {
          const claimRes = await authFetch("/api/billing/claim-session", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ session_id: sessionId }),
          });
          const claimData = (await claimRes.json()) as {
            message?: string;
            error?: string;
            unlimitedKeys?: boolean;
          };
          const user = await refreshAuth();
          if (user?.unlimitedKeys && !user.transitPaid) {
            setAuthMessage(
              "Payment confirmed. This account can register more sign-in keys on every network that already holds it. Transit stays on the $20 checkout.",
            );
            setAuthError("");
          } else if (user?.transitPaid) {
            setAuthMessage(
              "Payment confirmed — Transit, Nearby maps, Live Feed, Contracting, and web support chat unlocked. Refreshing…",
            );
            // Reconnect WebSocket so server re-evaluates feedPaid from session cookie
            window.setTimeout(() => {
              window.location.reload();
            }, 600);
          } else if (!claimRes.ok) {
            setAuthError(
              claimData.message ||
                claimData.error ||
                "Could not claim payment. Stay signed in with the same account you used at checkout.",
            );
            setAuthMessage("");
          } else {
            setAuthMessage(
              "Payment return received. If still locked, wait a moment and hard-refresh.",
            );
          }
        } catch {
          setAuthError(
            "Payment return handling failed. Try Buy access again if still locked.",
          );
        }
      })();
    }

    params.delete("billing");
    params.delete("session_id");
    const next = `${window.location.pathname}${params.toString() ? `?${params}` : ""}${window.location.hash}`;
    window.history.replaceState({}, "", next);
  }, []);

  // Keep menu/panel offsets in sync with the real nav height (prevents overlap/clipping on mobile)
  useEffect(() => {
    const nav = navBarRef.current;
    if (!nav || typeof ResizeObserver === "undefined") {
      return;
    }

    const publishNavHeight = () => {
      const height = Math.ceil(nav.getBoundingClientRect().height);
      if (height > 0) {
        document.documentElement.style.setProperty(
          "--mobile-nav-height",
          `${height}px`,
        );
        document.documentElement.style.setProperty("--nav-offset", `${height}px`);
      }
    };

    publishNavHeight();
    const observer = new ResizeObserver(publishNavHeight);
    observer.observe(nav);
    window.addEventListener("resize", publishNavHeight);
    window.addEventListener("orientationchange", publishNavHeight);

    return () => {
      observer.disconnect();
      window.removeEventListener("resize", publishNavHeight);
      window.removeEventListener("orientationchange", publishNavHeight);
    };
  }, []);

  const addActivityEvent = useCallback(
    (event: ActivityEvent, options?: { force?: boolean }) => {
      // Pause hides new joins from the feed, but leaves always log (ops visibility)
      if (
        isFeedPausedRef.current &&
        !options?.force &&
        event.type !== "disconnect"
      ) {
        return;
      }
      setActivityFeed((prev) => prependActivityEvent(prev, event));
    },
    [],
  );

  const runRateLimitedButtonAction = (actionKey: string, action: () => void) => {
    const now = Date.now();
    const lastClickAt = lastButtonClicks.current.get(actionKey) ?? 0;

    // Per-action debounce only. A global lock swallowed dock clicks (Contracts,
    // PKI, UN, Feed, Weather) right after PGP sign-in / other button presses.
    if (now - lastClickAt < BUTTON_RATE_LIMIT_MS) {
      return;
    }

    lastButtonClicks.current.set(actionKey, now);
    action();
  };

  const clearActivityFeed = useCallback(() => {
    // Keep currently online visitors as connect events; drop history noise
    const activeEvents = Array.from(activeVisitors.current.values()).sort(
      (a, b) => b.timestamp - a.timestamp,
    );
    setActivityFilter("all");
    setActivityFeed(activeEvents);
  }, []);

  const handleActivityFilterChange = useCallback((filter: ActivityFilter) => {
    setActivityFilter(filter);
  }, []);

  const applyLocationPreference = useCallback((next: LocationPreference) => {
    const pref = normalizeLocationPreference(next);
    setLocationPref(pref);
    saveLocationPreference(pref);
    setLocationDraftLat(String(pref.latitude));
    setLocationDraftLng(String(pref.longitude));
    setLocationDraftLabel(pref.label);
    return pref;
  }, []);

  const resolveUserCoordinates = useCallback(
    async (timeoutMs = 5000) => {
      // Manual / address override always wins for transit / nearby / weather
      if (locationPref.mode === "manual" || locationPref.mode === "address") {
        return {
          latitude: locationPref.latitude,
          longitude: locationPref.longitude,
          label:
            locationPref.label ||
            (locationPref.mode === "address"
              ? "Address location"
              : "Custom location"),
        };
      }

      try {
        const position = await getBrowserPosition(timeoutMs);
        const latitude = clampCoord(position.coords.latitude, -90, 90);
        const longitude = clampCoord(position.coords.longitude, -180, 180);
        // Remember last successful browser fix for menu display / fallback
        // (avoid setState churn when coordinates did not change)
        setLocationPref((prev) => {
          if (
            prev.mode === "browser" &&
            Math.abs(prev.latitude - latitude) < 1e-5 &&
            Math.abs(prev.longitude - longitude) < 1e-5
          ) {
            return prev;
          }
          const next: LocationPreference = {
            mode: "browser",
            latitude,
            longitude,
            label: "Your location",
          };
          saveLocationPreference(next);
          return next;
        });
        return {
          latitude,
          longitude,
          label: "Your location",
        };
      } catch {
        // Prefer last known coords over hard-coded NYC when available
        if (
          Number.isFinite(locationPref.latitude) &&
          Number.isFinite(locationPref.longitude) &&
          !(
            locationPref.latitude === DEFAULT_WEATHER_LOCATION.latitude &&
            locationPref.longitude === DEFAULT_WEATHER_LOCATION.longitude
          )
        ) {
          return {
            latitude: locationPref.latitude,
            longitude: locationPref.longitude,
            label: locationPref.label || "Last known location",
          };
        }
        return {
          latitude: DEFAULT_WEATHER_LOCATION.latitude,
          longitude: DEFAULT_WEATHER_LOCATION.longitude,
          label: DEFAULT_WEATHER_LOCATION.label,
        };
      }
    },
    [locationPref],
  );

  const requestBrowserLocation = useCallback(async () => {
    setLocationBusy(true);
    setLocationMessage("");
    try {
      if (!navigator.geolocation) {
        throw new Error("This browser does not support geolocation.");
      }
      const position = await getBrowserPosition(10_000);
      const latitude = clampCoord(position.coords.latitude, -90, 90);
      const longitude = clampCoord(position.coords.longitude, -180, 180);
      applyLocationPreference({
        mode: "browser",
        latitude,
        longitude,
        label: "Your location",
      });
      setLocationMessage(
        `Browser location set · ${formatCoordPair(latitude, longitude)}`,
      );
    } catch (error) {
      const code =
        error && typeof error === "object" && "code" in error
          ? Number((error as GeolocationPositionError).code)
          : 0;
      let message =
        error instanceof Error ? error.message : "Could not read location";
      if (code === 1) {
        message =
          "Location permission denied. Allow location in browser settings, or set coordinates manually.";
      } else if (code === 2) {
        message = "Position unavailable. Try again or set coordinates manually.";
      } else if (code === 3) {
        message = "Location request timed out. Try again or set manually.";
      }
      setLocationMessage(message);
    } finally {
      setLocationBusy(false);
    }
  }, [applyLocationPreference]);

  const applyManualLocation = useCallback(() => {
    setLocationMessage("");
    // Reject oversized draft strings before Number() (DoS / weird coercion)
    if (
      locationDraftLat.trim().length > 24 ||
      locationDraftLng.trim().length > 24
    ) {
      setLocationMessage("Coordinates are too long.");
      return;
    }
    const latitude = parseFiniteCoord(locationDraftLat.trim(), -90, 90);
    const longitude = parseFiniteCoord(locationDraftLng.trim(), -180, 180);
    if (latitude === null) {
      setLocationMessage("Latitude must be a number between −90 and 90.");
      return;
    }
    if (longitude === null) {
      setLocationMessage("Longitude must be a number between −180 and 180.");
      return;
    }
    const label =
      sanitizeLocationLabel(locationDraftLabel) || "Custom location";
    applyLocationPreference({
      mode: "manual",
      latitude,
      longitude,
      label,
    });
    setLocationMessage(
      `Manual location saved · ${formatCoordPair(latitude, longitude)}`,
    );
  }, [
    locationDraftLat,
    locationDraftLng,
    locationDraftLabel,
    applyLocationPreference,
  ]);

  const lookupAddressLocation = useCallback(async () => {
    setLocationMessage("");
    const q = sanitizeAddressQuery(locationDraftAddress);
    if (q.length < 2) {
      setLocationMessage("Enter a city, address, or place name (2+ characters).");
      return;
    }
    const now = Date.now();
    if (now - lastGeocodeAtRef.current < GEOCODE_MIN_MS) {
      setLocationMessage("Please wait a moment before another address lookup.");
      return;
    }
    lastGeocodeAtRef.current = now;
    setLocationBusy(true);
    try {
      const hit = await geocodeAddressQuery(q);
      applyLocationPreference({
        mode: "address",
        latitude: hit.latitude,
        longitude: hit.longitude,
        label: hit.label,
      });
      setLocationDraftAddress(q);
      setLocationMessage(
        `Address set · ${hit.label} · ${formatCoordPair(hit.latitude, hit.longitude)}`,
      );
    } catch (error) {
      setLocationMessage(
        error instanceof Error ? error.message : "Address lookup failed",
      );
    } finally {
      setLocationBusy(false);
    }
  }, [locationDraftAddress, applyLocationPreference]);

  const nearbySessionKey = (latitude: number, longitude: number, radiusM: number) =>
    `globe-nearby-v8:${clampCoord(latitude, -90, 90).toFixed(4)}:${clampCoord(longitude, -180, 180).toFixed(4)}:${Math.round(radiusM)}`;

  const readNearbySessionCache = (
    latitude: number,
    longitude: number,
    radiusM: number,
  ): NearbyPathsPreview | null => {
    try {
      const raw = sessionStorage.getItem(
        nearbySessionKey(latitude, longitude, radiusM),
      );
      if (!raw || raw.length > NEARBY_SESSION_MAX_RAW) return null;
      const data: unknown = JSON.parse(raw);
      // Structural validation — never restore empty/stale/poisoned geometry
      if (!isValidNearbyPathsCache(data)) return null;
      // Cache key must match stored center (prevents cross-location reuse)
      if (
        Math.abs(data.lat - latitude) > 0.00015 ||
        Math.abs(data.lng - longitude) > 0.00015 ||
        Math.abs(data.radiusM - radiusM) > 1
      ) {
        return null;
      }
      return data;
    } catch {
      return null;
    }
  };

  const writeNearbySessionCache = (
    latitude: number,
    longitude: number,
    radiusM: number,
    data: NearbyPathsPreview,
  ) => {
    if (!isValidNearbyPathsCache(data)) return;
    try {
      const payload = JSON.stringify(data);
      if (payload.length > NEARBY_SESSION_MAX_RAW) return;
      sessionStorage.setItem(
        nearbySessionKey(latitude, longitude, radiusM),
        payload,
      );
    } catch {
      // quota / private mode — ignore
    }
  };

  const fetchNearbyPathsAt = async (
    latitude: number,
    longitude: number,
    radiusM: number,
    options?: { allowCache?: boolean },
  ) => {
    if (options?.allowCache !== false) {
      const cached = readNearbySessionCache(latitude, longitude, radiusM);
      if (cached) {
        return cached;
      }
    }

    const params = new URLSearchParams({
      lat: String(latitude),
      lng: String(longitude),
      radius: String(radiusM),
      // Bust intermediaries on forced refresh
      _t: String(Date.now()),
    });
    // Credentials include session cookie (required — nearby is auth-gated)
    const response = await authFetch(
      `/api/nearby-paths?${params.toString()}`,
      {
        headers: { accept: "application/json" },
        cache: "no-store",
      },
    );

    if (!response.ok) {
      let detail = `Nearby paths request failed (${response.status})`;
      try {
        const err = (await response.json()) as {
          message?: string;
          code?: string;
          error?: string;
        };
        if (err.message) detail = err.message;
        else if (err.error) detail = err.error;
      } catch {
        // ignore
      }
      throw new Error(detail);
    }

    const data = (await response.json()) as NearbyPathsPreview;
    if (!data || !Array.isArray(data.paths) || !Number.isFinite(data.lat)) {
      throw new Error("Nearby paths response incomplete");
    }
    if (data.paths.length > 0 && !data.stale) {
      writeNearbySessionCache(latitude, longitude, radiusM, data);
    }
    return data;
  };

  const loadNearbyPaths = async (
    closeMenu = true,
    radiusM = nearbyRadiusM,
    forceRefresh = false,
  ) => {
    // Open immediately — do not depend on the global button rate limiter succeeding twice
    setShowNearbyPanel(true);
    if (closeMenu) {
      setShowMenu(false);
    }
    setNearbyStatus("loading");
    setNearbyError("");

    const clampedRadius = Math.min(1500, Math.max(250, Math.round(radiusM)));
    setNearbyRadiusM(clampedRadius);

    try {
      // Wait for real GPS — do NOT race a short default (wrong city → empty map)
      let location: {
        latitude: number;
        longitude: number;
        label: string;
      };
      try {
        // 4s geo budget — maps should not wait 8s on GPS alone
        location = await resolveUserCoordinates(4000);
      } catch {
        location = {
          latitude: DEFAULT_WEATHER_LOCATION.latitude,
          longitude: DEFAULT_WEATHER_LOCATION.longitude,
          label: DEFAULT_WEATHER_LOCATION.label,
        };
      }

      // Request the full selected radius (server tiles OSM to fill the ring)
      const data = await fetchNearbyPathsAt(
        location.latitude,
        location.longitude,
        clampedRadius,
        { allowCache: !forceRefresh },
      );
      setNearbyPreview(data);
      setNearbyStatus("ready");

      // Optional refinement if GPS improves (non-blocking)
      void resolveUserCoordinates(5000).then(async (precise) => {
        const dLat = Math.abs(precise.latitude - location.latitude);
        const dLng = Math.abs(precise.longitude - location.longitude);
        if (dLat < 0.0015 && dLng < 0.0015) {
          return;
        }
        try {
          const upgraded = await fetchNearbyPathsAt(
            precise.latitude,
            precise.longitude,
            clampedRadius,
            { allowCache: true },
          );
          setNearbyPreview(upgraded);
        } catch {
          // keep first successful result
        }
      });
    } catch (error) {
      setNearbyError(
        error instanceof Error
          ? error.message
          : "Nearby street traces unavailable",
      );
      setNearbyStatus("error");
    }
  };

  const loadLocalTransit = async (
    closeMenu = true,
    maxDistanceM = transitDistanceM,
  ) => {
    setShowTransitPanel(true);
    if (closeMenu) {
      setShowMenu(false);
    }
    setTransitStatus("loading");
    setTransitError("");

    const clamped = Math.min(1500, Math.max(150, Math.round(maxDistanceM)));
    setTransitDistanceM(clamped);

    try {
      const location = await resolveUserCoordinates(3000);
      const params = new URLSearchParams({
        lat: String(location.latitude),
        lon: String(location.longitude),
        max_distance: String(clamped),
      });
      const response = await authFetch(
        `/api/transit-nearby?${params.toString()}`,
      );

      const payload = (await response.json()) as
        | TransitNearbyPreview
        | {
            error?: string;
            message?: string;
            code?: string;
          };

      if (
        response.status === 401 ||
        response.status === 402 ||
        response.status === 503
      ) {
        const errPayload = payload as {
          message?: string;
          error?: string;
          code?: string;
        };
        setShowTransitPanel(true);
        setTransitStatus("error");
        if (response.status === 401) {
          setShowAuthPanel(true);
          setAuthMode("login");
        }
        setTransitError(
          errPayload.message ||
            (response.status === 401
              ? "Sign in with your device key to use Local Transit."
              : response.status === 402
                ? "Local Transit requires a paid unlock on this deployment."
                : errPayload.error || "Transit is not fully configured yet."),
        );
        return;
      }

      if (!response.ok) {
        const errPayload = payload as { message?: string; error?: string };
        const message =
          errPayload.message || errPayload.error || "Local transit unavailable";
        throw new Error(message);
      }

      if (
        !("routes" in payload) ||
        !Array.isArray(payload.routes) ||
        !Array.isArray(payload.stops)
      ) {
        throw new Error("Transit response incomplete");
      }

      setTransitPreview(payload);
      setTransitStatus("ready");
    } catch (error) {
      setTransitError(
        error instanceof Error ? error.message : "Local transit unavailable",
      );
      setTransitStatus("error");
    }
  };

  /** Shared street engine with Nearby traces (session cache first). */
  const fetchNearbyMapForTransit = useCallback(
    (lat: number, lng: number, radiusM: number) =>
      fetchNearbyPathsAt(lat, lng, radiusM, { allowCache: true }),
    // Rebind when auth identity changes so cookie session is always current.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [authUser?.id, authUser?.transitPaid],
  );

  const loadWeatherFeed = async () => {
    setShowWeatherPanel(true);
    setShowMenu(false);
    setWeatherStatus("loading");
    setWeatherError("");

    let latitude = DEFAULT_WEATHER_LOCATION.latitude;
    let longitude = DEFAULT_WEATHER_LOCATION.longitude;
    let locationLabel = DEFAULT_WEATHER_LOCATION.label;

    try {
      const location = await resolveUserCoordinates();
      latitude = location.latitude;
      longitude = location.longitude;
      locationLabel = location.label;
    } catch {
      locationLabel = DEFAULT_WEATHER_LOCATION.label;
    }

    try {
      const response = await fetch(buildWeatherUrl(latitude, longitude));

      if (!response.ok) {
        throw new Error("Weather request failed");
      }

      const data = (await response.json()) as OpenMeteoForecastResponse;
      const current = data.current;
      const tempF = Number(current?.temperature_2m);
      const humidityPct = Number(current?.relative_humidity_2m);
      const windMph = Number(current?.wind_speed_10m);
      const weatherCode = Number(current?.weather_code);

      if (
        !Number.isFinite(tempF) ||
        !Number.isFinite(humidityPct) ||
        !Number.isFinite(windMph) ||
        !Number.isFinite(weatherCode) ||
        !current?.time
      ) {
        throw new Error("Weather response incomplete");
      }

      setWeatherFeed({
        tempF: Math.round(tempF),
        humidityPct: Math.round(humidityPct),
        windMph: Math.round(windMph),
        weatherCode,
        condition: describeWeatherCode(weatherCode),
        hasLightning: LIGHTNING_WEATHER_CODES.has(weatherCode),
        locationLabel,
        updatedAt: formatWeatherTime(current.time),
        dailyForecast: buildDailyForecast(data),
        hourlyForecast: buildHourlyForecast(data),
      });
      setWeatherStatus("ready");
    } catch {
      setWeatherError("Weather feed unavailable");
      setWeatherStatus("error");
    }
  };

  const toggleComtradeSection = (section: ComtradeSection) => {
    setComtradeSections((current) => ({
      ...current,
      [section]: !current[section],
    }));
  };

  const toggleComtradePanelFromMenu = () => {
    if (showComtradePanel) {
      setShowComtradePanel(false);
      return;
    }

    void loadComtradePreview(false);
  };

  const loadComtradePreview = async (closeMenu = true) => {
    // Keep other popups open so multiple panels can be used side by side
    setShowComtradePanel(true);
    if (closeMenu) {
      setShowMenu(false);
    }
    setComtradeError("");

    const url = "/api/comtrade-preview";
    const cached = getPreviewCache<ComtradePreview>(url);
    if (cached?.data && Array.isArray(cached.data.tradeRecords)) {
      setComtradePreview(cached.data);
      setComtradeStatus("ready");
      if (cached.fresh) return;
    } else {
      setComtradeStatus("loading");
    }

    try {
      const data = await fetchPreviewJson<ComtradePreview>(url, {
        validate: (v): v is ComtradePreview =>
          Boolean(
            v &&
              typeof v === "object" &&
              Array.isArray((v as ComtradePreview).tradeRecords),
          ),
        forceNetwork: Boolean(cached?.stale),
      });
      setComtradePreview(data);
      setComtradeStatus("ready");
    } catch {
      if (!cached) {
        setComtradeError("UN COMTRADE preview unavailable");
        setComtradeStatus("error");
      }
    }
  };

  const toggleTradePulseLayer = (layer: TradePulseLayer) => {
    setTradePulseLayers((current) => ({
      ...current,
      [layer]: !current[layer],
    }));
  };

  const toggleAllTradePulseLayers = () => {
    setTradePulseLayers((current) => {
      const shouldEnableAll = Object.values(current).some((enabled) => !enabled);

      return {
        dependency: shouldEnableAll,
        lifelines: shouldEnableAll,
        asymmetry: shouldEnableAll,
        intermediary: shouldEnableAll,
        transport: shouldEnableAll,
        friction: shouldEnableAll,
        hubs: shouldEnableAll,
        confidence: shouldEnableAll,
      };
    });
  };

  const loadTradePulsePreview = async (
    closeMenu = true,
    periodOverride?: string,
    options?: { keepExpanded?: boolean },
  ) => {
    // Keep other popups open so multiple panels can be used side by side
    setShowTradePulsePanel(true);
    if (!options?.keepExpanded) {
      // Always open the Trade Pulse menu minimized (expand with header control)
      setIsTradePulsePanelMinimized(true);
    }
    if (closeMenu) {
      setShowMenu(false);
    }
    const period = periodOverride || tradePulsePeriod || "2023";
    if (periodOverride) {
      setTradePulsePeriod(periodOverride);
    }
    setTradePulseError("");

    const url = `/api/comtrade-pulse-preview?period=${encodeURIComponent(period)}`;
    const cached = getPreviewCache<TradePulsePreview>(url);
    if (cached?.data && Array.isArray(cached.data.routes)) {
      setTradePulsePreview(cached.data);
      if (cached.data.period) setTradePulsePeriod(cached.data.period);
      setTradePulseStatus("ready");
      if (cached.fresh) return;
    } else {
      setTradePulseStatus("loading");
    }

    try {
      const data = await fetchPreviewJson<TradePulsePreview>(url, {
        validate: (v): v is TradePulsePreview =>
          Boolean(
            v &&
              typeof v === "object" &&
              Array.isArray((v as TradePulsePreview).routes),
          ),
        forceNetwork: Boolean(cached?.stale),
      });
      setTradePulsePreview(data);
      if (data.period) {
        setTradePulsePeriod(data.period);
      }
      setTradePulseStatus("ready");
      // Do not prefetch all years here — parallel heavy responses stall the main thread
      // and compete with the globe. Server waitUntil still warms KV/edge in the background.
    } catch {
      if (!cached) {
        setTradePulseError("Trade Pulse unavailable");
        setTradePulseStatus("error");
      }
    }
  };

  const tradePulseYearOptions =
    tradePulsePreview?.availablePeriods?.length
      ? tradePulsePreview.availablePeriods
      : ["2022", "2023", "2024", "2025"];

  const selectTradePulsePeriod = (period: string) => {
    if (period === tradePulsePeriod && tradePulseStatus === "ready") {
      return;
    }
    void loadTradePulsePreview(false, period, { keepExpanded: true });
  };

  useEffect(() => {
    if (isTradePulsePreview) {
      void loadTradePulsePreview(false);
    }
  }, []);

  const openUnHub = useCallback(() => {
    closePkiHubRoute();
    closeContractsHubRoute();
    setShowPkiHub(false);
    setShowContractsHub(false);
    openUnHubRoute();
    setShowUnHub(true);
    setShowMenu(false);
  }, []);

  const closeUnHub = useCallback(() => {
    closeUnHubRoute();
    setShowUnHub(false);
  }, []);

  const openPkiHub = useCallback(() => {
    closeUnHubRoute();
    closeContractsHubRoute();
    setShowUnHub(false);
    setShowContractsHub(false);
    openPkiHubRoute();
    setShowPkiHub(true);
    setShowMenu(false);
  }, []);

  const closePkiHub = useCallback(() => {
    closePkiHubRoute();
    setShowPkiHub(false);
  }, []);

  const openContractsHub = useCallback(() => {
    closeUnHubRoute();
    closePkiHubRoute();
    setShowUnHub(false);
    setShowPkiHub(false);
    openContractsHubRoute();
    setShowContractsHub(true);
    setShowMenu(false);
  }, []);

  const closeContractsHub = useCallback(() => {
    closeContractsHubRoute();
    setShowContractsHub(false);
  }, []);

  useEffect(() => {
    const syncRoute = () => {
      setShowUnHub(getIsUnHubRoute());
      setShowPkiHub(getIsPkiHubRoute());
      setShowContractsHub(getIsContractsHubRoute());
    };
    window.addEventListener("popstate", syncRoute);
    window.addEventListener("hashchange", syncRoute);
    return () => {
      window.removeEventListener("popstate", syncRoute);
      window.removeEventListener("hashchange", syncRoute);
    };
  }, []);

  useEffect(() => {
    if (!showUnHub && !showPkiHub && !showContractsHub) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prev;
    };
  }, [showUnHub, showPkiHub, showContractsHub]);

  const toggleUnGlobalSection = (section: UnGlobalSection) => {
    setUnGlobalSections((current) => ({
      ...current,
      [section]: !current[section],
    }));
  };

  const toggleAllUnGlobalSections = () => {
    setUnGlobalSections((current) => {
      const shouldEnableAll = Object.values(current).some((enabled) => !enabled);

      return {
        offices: shouldEnableAll,
        activeMissions: shouldEnableAll,
        pastMissions: shouldEnableAll,
        memberStates: shouldEnableAll,
        affiliates: shouldEnableAll,
        embassies: shouldEnableAll,
      };
    });
  };

  const toggleUnGlobalPanelFromMenu = () => {
    if (showUnGlobalPanel) {
      setIsUnGlobalPanelMinimized((minimized) => !minimized);
      return;
    }

    void loadUnGlobalPreview(false);
  };

  const toggleUnodcTheme = (themeId: UnodcThemeId) => {
    setUnodcThemes((current) => ({
      ...current,
      [themeId]: !current[themeId],
    }));
  };

  const applyUnodcPreview = (
    data: UnodcHotspotsPreview,
    options?: { keepThemeSelection?: boolean },
  ) => {
    setUnodcPreview(data);
    if (!options?.keepThemeSelection) {
      // Focus mode: only a few high-signal themes on by default (less clutter).
      // All 12 remain toggleable via cards / "All live".
      const nextThemes = { ...DEFAULT_UNODC_THEMES };
      for (const id of UNODC_THEME_IDS) {
        const theme = data.themes.find((t) => t.id === id);
        const hasLive = Boolean(
          theme && theme.dataMode === "live" && theme.hotspotCount > 0,
        );
        nextThemes[id] = hasLive && UNODC_FOCUS_THEMES.includes(id);
      }
      setUnodcThemes(nextThemes);
    }
    setUnodcStatus("ready");

    // Load country polygons after panel is usable — heavy parse must not block first paint.
    const loadGeo = () => {
      void import("./worldCountries")
        .then((m) => m.loadCountryPolygons())
        .then((polygons) => {
          if (polygons) setUnodcCountryPolygons(polygons);
        })
        .catch(() => {});
    };
    if (typeof requestIdleCallback === "function") {
      requestIdleCallback(() => loadGeo(), { timeout: 2000 });
    } else {
      window.setTimeout(loadGeo, 0);
    }
  };

  const loadUnodcHotspots = async (
    closeMenu = true,
    options?: { forceRefresh?: boolean },
  ) => {
    setShowUnodcPanel(true);
    setIsUnodcPanelMinimized(true);
    if (closeMenu) {
      setShowMenu(false);
    }
    setUnodcError("");

    const url = UNODC_PREVIEW_URL;
    // Capture before async setState so refresh keeps the user's theme toggles.
    const keepSelection =
      unodcStatus === "ready" && isCompleteUnodcPreview(unodcPreview);

    if (options?.forceRefresh) {
      clearPreviewCache(url);
    }

    const cached = options?.forceRefresh
      ? null
      : getPreviewCache<UnodcHotspotsPreview>(url);
    const cachedComplete = isCompleteUnodcPreview(cached?.data);
    // Never trust a “fresh” cache that still only has 7 live themes.
    if (cached?.data && Array.isArray(cached.data.themes) && cachedComplete) {
      applyUnodcPreview(cached.data, { keepThemeSelection: keepSelection });
      if (cached.fresh) return;
    } else if (cached?.data && !cachedComplete) {
      clearPreviewCache(url);
      setUnodcStatus("loading");
    } else if (!cached) {
      setUnodcStatus("loading");
    }

    try {
      const data = await fetchPreviewJson<UnodcHotspotsPreview>(url, {
        validate: (v): v is UnodcHotspotsPreview =>
          Boolean(
            v &&
              typeof v === "object" &&
              Array.isArray((v as UnodcHotspotsPreview).themes),
          ),
        // Bust HTTP cache when incomplete or user hit Refresh.
        forceNetwork:
          Boolean(options?.forceRefresh) ||
          !cachedComplete ||
          Boolean(cached?.stale),
      });
      applyUnodcPreview(data, {
        keepThemeSelection: keepSelection && isCompleteUnodcPreview(data),
      });
    } catch {
      if (!cachedComplete) {
        setUnodcError("UNODC hotspots unavailable");
        setUnodcStatus("error");
      }
    }
  };

  const loadPkiVulns = async (
    closeMenu = true,
    options?: { forceRefresh?: boolean },
  ) => {
    setShowPkiPanel(true);
    setIsPkiPanelMinimized(true);
    setPkiShowMap(true);
    if (closeMenu) {
      setShowMenu(false);
    }
    setPkiError("");

    const url = PKI_PREVIEW_URL;
    if (options?.forceRefresh) {
      clearPreviewCache(url);
    }

    const cached = options?.forceRefresh
      ? null
      : getPreviewCache<PkiVulnsPreview>(url);
    if (cached?.data && Array.isArray(cached.data.cves) && cached.fresh) {
      setPkiPreview(cached.data);
      setPkiStatus("ready");
      setPkiShowMap(true);
      return;
    }
    if (cached?.data && Array.isArray(cached.data.cves)) {
      setPkiPreview(cached.data);
      setPkiStatus("ready");
    } else {
      setPkiStatus("loading");
    }

    try {
      const data = await fetchPreviewJson<PkiVulnsPreview>(url, {
        validate: (v): v is PkiVulnsPreview =>
          Boolean(
            v &&
              typeof v === "object" &&
              Array.isArray((v as PkiVulnsPreview).cves) &&
              Array.isArray((v as PkiVulnsPreview).hotspots),
          ),
        forceNetwork: Boolean(options?.forceRefresh) || Boolean(cached?.stale),
      });
      setPkiPreview(data);
      setPkiStatus("ready");
      setPkiShowMap(true);
    } catch {
      if (!cached?.data) {
        setPkiError("PKI vulnerability feed unavailable");
        setPkiStatus("error");
      }
    }
  };

  // Open PKI hub → ensure feed is loading/ready
  useEffect(() => {
    if (!showPkiHub) return;
    if (pkiStatus === "idle" || pkiStatus === "error") {
      void loadPkiVulns(false);
    }
  }, [showPkiHub]);

  const buildSamContractsUrl = (opts: {
    preset: string;
    q: string;
    days: number;
    setAside: string;
    naicsGroup: string;
    includeAwards: boolean;
    force?: boolean;
  }) => {
    const params = new URLSearchParams();
    params.set("preset", opts.preset || "pki");
    if (opts.q.trim()) params.set("q", opts.q.trim().slice(0, 120));
    params.set("days", String(Math.max(1, Math.min(180, opts.days || 30))));
    if (opts.setAside) params.set("set_aside", opts.setAside);
    if (opts.naicsGroup) params.set("naics_group", opts.naicsGroup);
    if (opts.includeAwards) params.set("awards", "1");
    params.set("limit", "30");
    if (opts.force) params.set("force", "1");
    return `${SAM_CONTRACTS_PREVIEW_URL}?${params.toString()}`;
  };

  const loadSamContracts = async (
    opts?: Partial<{
      preset: string;
      q: string;
      days: number;
      setAside: string;
      naicsGroup: string;
      includeAwards: boolean;
      force: boolean;
    }>,
  ) => {
    const next = {
      ...contractsQuery,
      ...opts,
    };
    setContractsQuery({
      preset: next.preset,
      q: next.q,
      days: next.days,
      setAside: next.setAside,
      naicsGroup: next.naicsGroup,
      includeAwards: next.includeAwards,
    });
    setContractsError("");
    setContractsStatus("loading");

    // Paid feature: session cookie required (never public preview cache)
    if (!authUser) {
      setContractsPreview(null);
      setContractsLayerOn(false);
      setContractsStatus("error");
      setContractsError(
        "Sign in with your PGP key to use Contracting (public SAM.gov opportunities via FederalKey).",
      );
      return;
    }
    if (liveFeedAccess !== "ok") {
      setContractsPreview(null);
      setContractsLayerOn(false);
      setContractsStatus("error");
      setContractsError(
        liveFeedAccess === "login_required"
          ? "Sign in with your PGP key to use Contracting (public SAM.gov opportunities via FederalKey)."
          : "Contracting requires Stripe unlock ($20). Unlocks Transit, Nearby, Live Feed, Contracting, and support chat. Data source remains public SAM.gov.",
      );
      return;
    }

    const url = buildSamContractsUrl({
      ...next,
      force: Boolean(opts?.force),
    });
    if (opts?.force) {
      clearPreviewCache(url);
    }

    try {
      const response = await authFetch(url);
      const payload = (await response.json()) as
        | SamContractsPreview
        | {
            error?: string;
            message?: string;
            code?: string;
          };

      if (
        response.status === 401 ||
        response.status === 402 ||
        response.status === 503
      ) {
        const errPayload = payload as {
          message?: string;
          error?: string;
          code?: string;
        };
        setContractsPreview(null);
        setContractsLayerOn(false);
        setContractsStatus("error");
        if (response.status === 401) {
          setShowAuthPanel(true);
          setAuthMode("login");
        }
        setContractsError(
          errPayload.message ||
            (response.status === 401
              ? "Sign in with your device key to use Contracting."
              : response.status === 402
                ? "Contracting requires a paid unlock on this deployment."
                : errPayload.error || "Contracting is not fully configured yet."),
        );
        return;
      }

      if (!response.ok) {
        const errPayload = payload as { message?: string; error?: string };
        throw new Error(
          errPayload.message || errPayload.error || "SAM.gov contracts unavailable",
        );
      }

      const data = payload as SamContractsPreview;
      if (
        !Array.isArray(data.opportunities) ||
        !Array.isArray(data.markers)
      ) {
        throw new Error("Contracting response incomplete");
      }

      setContractsPreview(data);
      setContractsStatus("ready");
      setContractsLayerOn(true);
      if (data.error && data.dataMode === "unavailable") {
        setContractsError(data.error);
        setContractsStatus("error");
      }
    } catch (error) {
      setContractsError(
        error instanceof Error
          ? error.message
          : "SAM.gov contracts feed unavailable",
      );
      setContractsStatus("error");
    }
  };

  // Open Contracts hub → search when the PGP session (and Stripe, if enforced) is ready.
  // Retry after sign-in: an earlier idle pass may have run while authUser was still null.
  useEffect(() => {
    if (liveFeedAccess !== "ok") {
      setContractsPreview(null);
      setContractsLayerOn(false);
      setContractsStatus("idle");
      if (showContractsHub) {
        setContractsError(
          liveFeedAccess === "login_required"
            ? "Sign in with your PGP key to use Contracting (public SAM.gov opportunities via FederalKey)."
            : "Contracting requires Stripe unlock ($20). Unlocks Transit, Nearby, Live Feed, Contracting, and support chat. Data source remains public SAM.gov.",
        );
      }
      return;
    }
    if (!showContractsHub) return;
    if (contractsStatus === "idle") {
      void loadSamContracts({ force: false });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showContractsHub, liveFeedAccess, authUser?.id]);

  const setUnodcFocusMode = (mode: "focus" | "all-live" | "none") => {
    if (!unodcPreview) return;
    const next = { ...DEFAULT_UNODC_THEMES };
    for (const theme of unodcPreview.themes) {
      const hasLive = theme.dataMode === "live" && theme.hotspotCount > 0;
      if (mode === "none") {
        next[theme.id] = false;
      } else if (mode === "all-live") {
        next[theme.id] = hasLive;
      } else {
        next[theme.id] = hasLive && UNODC_FOCUS_THEMES.includes(theme.id);
      }
    }
    setUnodcThemes(next);
  };

  const loadUnGlobalPreview = async (closeMenu = true) => {
    // Keep other popups open so multiple panels can be used side by side
    setShowUnGlobalPanel(true);
    // Minimized by default — full controls live in the UN hub page
    setIsUnGlobalPanelMinimized(true);
    if (closeMenu) {
      setShowMenu(false);
    }
    setUnGlobalError("");

    const url = "/api/un-global-preview";
    const cached = getPreviewCache<UnGlobalPreview>(url);
    if (cached?.data && Array.isArray(cached.data.missionLocations)) {
      setUnGlobalPreview(cached.data);
      setUnGlobalStatus("ready");
      if (cached.fresh) return;
    } else {
      setUnGlobalStatus("loading");
    }

    try {
      const data = await fetchPreviewJson<UnGlobalPreview>(url, {
        validate: (v): v is UnGlobalPreview =>
          Boolean(
            v &&
              typeof v === "object" &&
              Array.isArray((v as UnGlobalPreview).missionLocations),
          ),
        forceNetwork: Boolean(cached?.stale),
      });
      setUnGlobalPreview(data);
      setUnGlobalStatus("ready");
    } catch {
      if (!cached) {
        setUnGlobalError("UN global preview unavailable");
        setUnGlobalStatus("error");
      }
    }
  };

  // After globe first paint: warm edge/browser caches so panel opens are free.
  // Staggered so we never compete with WebGL init.
  useEffect(() => {
    const warm = () => {
      warmPreviewUrl(UNODC_PREVIEW_URL);
      warmPreviewUrl("/api/comtrade-pulse-preview?period=2023");
      // Geo atlas for choropleth — force-cache immutable asset
      void import("./worldCountries")
        .then((m) => m.loadCountryPolygons())
        .catch(() => {});
    };
    let idleId = 0;
    let timeoutId = 0;
    if (typeof requestIdleCallback === "function") {
      idleId = requestIdleCallback(warm, { timeout: 8000 });
    } else {
      timeoutId = window.setTimeout(warm, 4000);
    }
    return () => {
      if (idleId && typeof cancelIdleCallback === "function") {
        cancelIdleCallback(idleId);
      }
      if (timeoutId) window.clearTimeout(timeoutId);
    };
  }, []);

  const disableUnGlobalLayer = () => {
    setShowUnGlobalPanel(false);
    setIsUnGlobalPanelMinimized(false);
  };

  const socket = usePartySocket({
    room: "default",
    party: "globe",
    // Same-origin Worker party (test + prod workers.dev).
    host:
      typeof window !== "undefined" ? window.location.host : undefined,
    // Keep retries snappy when the public link drops.
    minReconnectionDelay: 400,
    maxReconnectionDelay: 8000,
    reconnectionDelayGrowFactor: 1.4,
    maxRetries: Infinity,
    onOpen() {
      setSocketStatus("connected");
    },
    onClose() {
      // PartySocket auto-reconnects — show connecting while it retries.
      setSocketStatus("connecting");
    },
    onError() {
      // Don't stick on "disconnected" forever; reconnect path will open again.
      setSocketStatus((prev) => (prev === "connected" ? "connecting" : prev));
    },
    onMessage(evt) {
      const message = parseSocketMessage(evt.data);

      if (!message) {
        return;
      }

      // Any valid server message implies the public link is up.
      setSocketStatus("connected");

      // Public globe markers
      if (message.type === "add-marker") {
        const visitorId = message.position.id;
        const isYou = visitorId === socket.id;
        positions.current.set(visitorId, {
          location: [message.position.lat, message.position.lng],
          size: isYou ? 0.1 : 0.05,
        });
        setCounter(positions.current.size);

        // Fallback: if paid feed is unlocked but feed-join not yet seen, still
        // record self so Live Feed is never empty for the connected user.
        if (
          isYou &&
          liveFeedUnlockedRef.current &&
          !activeVisitors.current.has(visitorId)
        ) {
          const selfEvent = createActivityEvent({
            id: visitorId,
            type: "connect",
            timestamp: Date.now(),
            userName: "You",
            country: message.position.country,
            isSelf: true,
          });
          activeVisitors.current.set(visitorId, selfEvent);
          addActivityEvent(selfEvent);
        }
        return;
      }

      if (message.type === "remove-marker") {
        const removedId = message.id;
        positions.current.delete(removedId);
        setCounter(positions.current.size);
        // Leaves for the paid feed arrive as feed-leave (not here)
        return;
      }

      // Live Feed channel (server only sends feed-join/leave if the session has feature access)
      if (message.type === "feed-access") {
        // Align client gate with server cookie entitlement (true and false)
        const paid = Boolean(message.paid);
        liveFeedUnlockedRef.current = paid;
        if (!paid) {
          setActivityFeed([]);
          setChatMessages([]);
          activeVisitors.current.clear();
        }
        return;
      }

      if (message.type === "feed-join") {
        // Prefer server paid signal; also allow if UI already unlocked
        if (!liveFeedUnlockedRef.current && !message.meta) return;
        // If server sent feed-join, this client is entitled to the paid feed
        liveFeedUnlockedRef.current = true;
        const meta = message.meta;
        const isYou = meta.id === socket.id;
        // Avoid duplicate "You joined" on reconnect replay
        if (activeVisitors.current.has(meta.id) && isYou) {
          return;
        }
        const activityEvent = createActivityEvent({
          id: meta.id,
          type: "connect",
          timestamp: Date.now(),
          userName: isYou ? "You" : `User ${meta.id.slice(0, 8)}`,
          ip: meta.ipMasked,
          country: meta.country,
          city: meta.city,
          org: meta.org,
          isSelf: isYou,
        });
        activeVisitors.current.set(meta.id, activityEvent);
        addActivityEvent(activityEvent);
        return;
      }

      if (message.type === "feed-leave") {
        if (!liveFeedUnlockedRef.current) return;
        const removedId = message.id;
        const wasSelf = removedId === socket.id;
        const prior = activeVisitors.current.get(removedId);
        const meta = message.meta;
        activeVisitors.current.delete(removedId);
        addActivityEvent(
          createActivityEvent({
            id: removedId,
            type: "disconnect",
            timestamp: Date.now(),
            userName:
              prior?.userName ??
              (wasSelf ? "You" : `User ${removedId.slice(0, 8)}`),
            city: meta?.city ?? prior?.city,
            country: meta?.country ?? prior?.country,
            org: meta?.org ?? prior?.org,
            ip: meta?.ipMasked ?? prior?.ip,
            isSelf: wasSelf,
            sessionMs: message.sessionMs,
          }),
          { force: true },
        );
        return;
      }

      // Paid web-support chat — memory only; isolated so failures never touch feed state
      if (message.type === "chat") {
        if (!liveFeedUnlockedRef.current) return;
        try {
          const isSelf = message.fromId === socket.id;
          setChatMessages((prev) => {
            if (prev.some((m) => m.id === message.id)) return prev;
            return [
              {
                id: message.id,
                fromId: message.fromId,
                text: message.text,
                displayName: isSelf ? "You" : message.displayName,
                ts: message.ts,
                isSelf,
              },
              ...prev,
            ].slice(0, 60);
          });
        } catch {
          // ignore chat UI errors
        }
      }
    },
  });

  const chatSendWindowRef = useRef({ start: 0, count: 0 });

  const sendChatMessage = useCallback(
    (text: string) => {
      const clean = sanitizeChatText(text);
      // Web-support chat — same gate as Live Feed (server enforces feedPaid / feature access)
      if (!clean || socketStatus !== "connected" || liveFeedAccess !== "ok") {
        return false;
      }

      // Client pre-throttle (server still enforces)
      const now = Date.now();
      const win = chatSendWindowRef.current;
      if (now - win.start >= CHAT_RATE_WINDOW_MS) {
        win.start = now;
        win.count = 0;
      }
      win.count += 1;
      if (win.count > CHAT_CLIENT_MAX_PER_WINDOW) return false;

      try {
        const displayName = sanitizeChatDisplayName(
          authUser?.fingerprint
            ? shortFingerprint(authUser.fingerprint)
            : "",
        );
        // Only send allow-listed fields
        const payload: { type: "chat"; text: string; displayName?: string } = {
          type: "chat",
          text: clean,
        };
        if (displayName) payload.displayName = displayName;
        socket.send(JSON.stringify(payload));
        return true;
      } catch {
        return false;
      }
    },
    [socket, socketStatus, authUser, liveFeedAccess],
  );

  // Re-open the globe socket after PGP login/logout so the Worker re-reads
  // the session cookie (feedPaid / feature access). Without this, Support chat
  // and visitor feed stay dead on the pre-login connection.
  useEffect(() => {
    const id = authUser?.id ?? null;
    const prev = authSocketIdRef.current;
    authSocketIdRef.current = id;
    if (prev === undefined || prev === id) return;
    try {
      setSocketStatus("connecting");
      socket.reconnect();
    } catch {
      // PartySocket may already be mid-retry
    }
  }, [authUser?.id, socket]);

  const weatherGlow = getWeatherGlow(weatherFeed);
  const enabledComtradeSectionCount =
    Object.values(comtradeSections).filter(Boolean).length;
  const isFullUsdMode = comtradeValueMode === "full";
  const comtradeMenuStatus =
    comtradeStatus === "ready" && comtradePreview
      ? "Ready"
      : comtradeStatus === "loading"
        ? "Loading"
        : comtradeStatus === "error"
          ? "Offline"
          : "Not loaded";
  const comtradeMenuSource =
    comtradeStatus === "ready" && comtradePreview
      ? comtradePreview.stale
        ? "Fallback"
        : comtradePreview.dataMode === "free-subscription" ||
            comtradePreview.subscriptionBacked
          ? "Live"
          : "Preview"
      : comtradeStatus === "error"
        ? "Unavailable"
        : "Not loaded";
  const comtradeMenuQuery =
    comtradeStatus === "ready" && comtradePreview
      ? `${comtradePreview.reporter} · ${comtradePreview.period}`
      : comtradeStatus === "loading"
        ? "Loading…"
        : "USA annual totals";
  const comtradeMenuUpdated =
    comtradeStatus === "ready" && comtradePreview
      ? formatPreviewDate(comtradePreview.updatedAt)
      : "Awaiting preview";
  const getComtradeSectionDetail = (section: ComtradeSection) => {
    if (comtradeStatus === "loading") {
      return "Loading Comtrade+ preview data";
    }

    if (comtradeStatus === "error") {
      return comtradeError || "Comtrade+ preview unavailable";
    }

    if (!comtradePreview) {
      return COMTRADE_SECTION_DESCRIPTIONS[section];
    }

    if (section === "records") {
      return `${comtradePreview.tradeRecords.length} rows; ${comtradePreview.reporter} ${comtradePreview.period}`;
    }

    if (section === "availability") {
      return `${comtradePreview.availability.length} datasets; ${formatPreviewNumber(
        comtradePreview.availabilityTotalRecords,
        comtradePreview.stale,
      )} records indexed`;
    }

    if (section === "references") {
      return `${comtradePreview.references.length} shown; ${formatPreviewNumber(
        comtradePreview.referenceTablesTotal,
        comtradePreview.stale,
      )} reference tables`;
    }

    return `${comtradePreview.reporters.length} sampled; ${formatPreviewNumber(
      comtradePreview.reportersTotal,
      comtradePreview.stale,
    )} reporters total`;
  };
  const enabledUnGlobalSectionCount =
    Object.values(unGlobalSections).filter(Boolean).length;
  const allUnGlobalSectionsEnabled =
    enabledUnGlobalSectionCount === Object.keys(DEFAULT_UN_GLOBAL_SECTIONS).length;
  const visibleUnMissionLocations =
    unGlobalPreview?.missionLocations.filter((mission) =>
      mission.active ? unGlobalSections.activeMissions : unGlobalSections.pastMissions,
    ) ?? [];
  const unGlobalOverlayMarkers =
    showUnGlobalPanel && unGlobalStatus === "ready" && unGlobalPreview
      ? [
          ...(unGlobalSections.offices
            ? unGlobalPreview.offices.map((office) => ({
                location: [office.lat, office.lng] as [number, number],
                size: office.category === "headquarters" ? 0.09 : 0.07,
              }))
            : []),
          ...visibleUnMissionLocations.map((mission) => ({
            location: [mission.lat, mission.lng] as [number, number],
            size: mission.active ? 0.08 : 0.045,
          })),
          ...(unGlobalSections.memberStates
            ? unGlobalPreview.memberStates.map((state) => ({
                location: [state.lat, state.lng] as [number, number],
                size: 0.045,
              }))
            : []),
          ...(unGlobalSections.affiliates
            ? unGlobalPreview.affiliates.map((affiliate) => ({
                location: [affiliate.lat, affiliate.lng] as [number, number],
                size: affiliate.category === "observer" ? 0.065 : 0.055,
              }))
            : []),
          ...(unGlobalSections.embassies
            ? unGlobalPreview.embassies.map((embassy) => ({
                location: [embassy.lat, embassy.lng] as [number, number],
                size: 0.035,
              }))
            : []),
        ]
      : [];
  /**
   * Multi-theme choropleth: one fill per (theme, country) so several themes
   * stack with semi-transparent colors instead of a single winner-takes-all.
   */
  const unodcChoroplethRegions: GlobeChoroplethRegion[] = useMemo(() => {
    if (
      !showUnodcPanel ||
      unodcStatus !== "ready" ||
      !unodcPreview ||
      !unodcCountryPolygons
    ) {
      return [];
    }
    type Entry = {
      id: string;
      iso3: string;
      intensity: number;
      color: string;
      themeId: UnodcThemeId;
      label: string;
      rings: [number, number][][];
    };
    const entries: Entry[] = [];
    // Per-theme cap keeps “All live” usable; total cap protects frame budget.
    const PER_THEME = 40;
    const MAX_TOTAL = 140;

    for (const theme of unodcPreview.themes) {
      if (!unodcThemes[theme.id] || theme.hotspots.length === 0) continue;
      const color = UNODC_THEME_CSS[theme.id];
      const ranked = [...theme.hotspots]
        .sort((a, b) => b.intensity - a.intensity)
        .slice(0, PER_THEME);
      for (const spot of ranked) {
        const poly = unodcCountryPolygons.get(spot.iso3);
        if (!poly) continue;
        entries.push({
          id: `${theme.id}-${spot.iso3}`,
          iso3: spot.iso3,
          intensity: spot.intensity,
          color,
          themeId: theme.id,
          rings: poly.rings,
          label: `${theme.label}: ${spot.name} · ${spot.value} (${spot.year})`,
        });
      }
    }

    entries.sort((a, b) => b.intensity - a.intensity);
    return entries.slice(0, MAX_TOTAL).map((b) => ({
      id: b.id,
      iso3: b.iso3,
      rings: b.rings,
      color: b.color,
      intensity: b.intensity,
      themeId: b.themeId,
      label: b.label,
    }));
  }, [
    showUnodcPanel,
    unodcStatus,
    unodcPreview,
    unodcCountryPolygons,
    unodcThemes,
  ]);

  /**
   * Heat blobs only when country polygons failed to load.
   * Choropleth alone is calmer and more accurate.
   */
  const unodcHeatZones: GlobeHeatZone[] = useMemo(() => {
    if (
      !showUnodcPanel ||
      unodcStatus !== "ready" ||
      !unodcPreview ||
      unodcCountryPolygons
    ) {
      return [];
    }
    return unodcPreview.themes.flatMap((theme) => {
      if (!unodcThemes[theme.id] || theme.hotspots.length === 0) {
        return [];
      }
      return buildUnodcThemeHeatZones(theme, UNODC_THEME_CSS[theme.id]).map(
        (z) => ({
          ...z,
          intensity: z.intensity * 0.65,
        }),
      );
    });
  }, [
    showUnodcPanel,
    unodcStatus,
    unodcPreview,
    unodcCountryPolygons,
    unodcThemes,
  ]);

  const pkiVisibleCves: PkiVulnCve[] = useMemo(() => {
    if (!pkiPreview) return [];
    let list = pkiPreview.cves.slice();
    if (pkiCatalog === "kev") list = list.filter((c) => c.knownExploited);
    else if (pkiCatalog === "nvd") list = list.filter((c) => !c.knownExploited);
    if (pkiSeverities.size < DEFAULT_PKI_SEVERITIES.length) {
      list = list.filter((c) => pkiSeverities.has(c.severity));
    }
    if (pkiCategory !== "all") {
      list = list.filter((c) =>
        c.categories.includes(pkiCategory as never),
      );
    }
    return sortPkiCves(list, pkiSort);
  }, [pkiPreview, pkiCatalog, pkiSeverities, pkiCategory, pkiSort]);

  /** Filtered / paged PKI arcs — sparse default for globe performance. */
  const pkiArcSelection: PkiArcSelection = useMemo(() => {
    const empty: PkiArcSelection = {
      arcs: [],
      total: 0,
      page: 0,
      pageCount: 1,
      pageSize: PKI_DENSITY_LIMITS[pkiDensity],
      kevCount: 0,
      nvdCount: 0,
    };
    if (
      !showPkiPanel ||
      !pkiShowMap ||
      pkiStatus !== "ready" ||
      !pkiPreview?.cves?.length ||
      !pkiPreview?.hotspots?.length
    ) {
      return empty;
    }
    return buildPkiGlobeArcs(pkiPreview, {
      catalog: pkiCatalog,
      severities: pkiSeverities,
      category: pkiCategory,
      focusCve: pkiFocusCve,
      sort: pkiSort,
      density: pkiDensity,
      page: pkiArcPage,
    });
  }, [
    showPkiPanel,
    pkiShowMap,
    pkiStatus,
    pkiPreview,
    pkiCatalog,
    pkiSeverities,
    pkiCategory,
    pkiFocusCve,
    pkiSort,
    pkiDensity,
    pkiArcPage,
  ]);

  const pkiGlobeArcs = pkiArcSelection.arcs;

  // Clamp page if filters shrink the set
  useEffect(() => {
    if (pkiArcPage > 0 && pkiArcPage >= pkiArcSelection.pageCount) {
      setPkiArcPage(Math.max(0, pkiArcSelection.pageCount - 1));
    }
  }, [pkiArcPage, pkiArcSelection.pageCount]);
  const unGlobalMarkerColor =
    unGlobalOverlayMarkers.length > 0
      ? ([0, 0.65, 1] as [number, number, number])
      : ([0.8, 0.1, 0.1] as [number, number, number]);
  const enabledTradePulseLayerCount =
    Object.values(tradePulseLayers).filter(Boolean).length;
  const allTradePulseLayersEnabled =
    enabledTradePulseLayerCount === TRADE_PULSE_LAYERS.length;
  const visibleTradePulseRoutes =
    showTradePulsePanel && tradePulseStatus === "ready"
      ? getVisibleTradePulseRoutes(tradePulsePreview, tradePulseLayers)
      : [];
  // Endpoint dots come from arc + controls (avoid double markers / z-fight glitch)
  const tradePulseGlobeArcs: GlobeArc[] =
    showTradePulsePanel && tradePulseStatus === "ready"
      ? visibleTradePulseRoutes.map((route) => {
          const layer = getRoutePulseLayer(route, tradePulseLayers);

          return {
            id: route.id,
            from: [route.origin.lat, route.origin.lng] as [number, number],
            to: [route.destination.lat, route.destination.lng] as [number, number],
            via: route.intermediary
              ? ([route.intermediary.lat, route.intermediary.lng] as [number, number])
              : null,
            fromLabel: `${route.origin.name} origin`,
            toLabel: `${route.destination.name} destination`,
            viaLabel: route.intermediary
              ? `${route.intermediary.name} relay`
              : undefined,
            color: TRADE_PULSE_LAYER_COLORS[layer],
            width:
              route.severity === "critical" ? 3.2 : route.severity === "high" ? 2.6 : 2,
            dash: TRADE_PULSE_TRANSPORT_DASHES[route.transportMode],
            severity: route.severity,
            comtrade: {
              routeId: route.id,
              commodity: route.commodity,
              commodityCode: route.commodityCode,
              period: route.period,
              originName: route.origin.name,
              originIso3: route.origin.iso3,
              destName: route.destination.name,
              destIso3: route.destination.iso3,
              hubName: route.intermediary?.name ?? null,
              hubIso3: route.intermediary?.iso3 ?? null,
              transportMode: route.transportMode,
              customsProcedure: route.customsProcedure,
              valueUsd: route.valueUsd,
              quantity: route.quantity,
              supplierSharePct: route.supplierSharePct,
              exportValueUsd: route.exportValueUsd,
              importValueUsd: route.importValueUsd,
              asymmetryPct: route.asymmetryPct,
              fobValueUsd: route.fobValueUsd,
              cifValueUsd: route.cifValueUsd,
              frictionPct: route.frictionPct,
              reExportSharePct: route.reExportSharePct,
              confidencePct: route.confidencePct,
              severity: route.severity,
              layers: route.layers.map(
                (l) => TRADE_PULSE_LAYER_SHORT_LABELS[l] || l,
              ),
              insight: route.insight,
              dataMode: tradePulsePreview?.dataMode,
            },
          };
        })
      : [];
  /** Contracting: + popups via zero-width arcs (same system as PKI / Trade Pulse) */
  const contractsGlobeArcs: GlobeArc[] =
    contractsLayerOn &&
    contractsStatus === "ready" &&
    contractsPreview?.markers?.length
      ? (() => {
          const oppById = new Map(
            (contractsPreview.opportunities || []).map((o) => [o.id, o]),
          );
          return contractsPreview.markers.map((m) => {
            const opp = oppById.get(m.id);
            const title = (opp?.title || m.title || "Opportunity").slice(0, 160);
            const short =
              title.length > 28 ? `${title.slice(0, 26)}…` : title;
            return {
              id: `contract:${m.id}`,
              from: [m.lat, m.lng] as [number, number],
              to: [m.lat, m.lng] as [number, number],
              fromLabel: "PoP",
              toLabel: short,
              color: "#f5c430",
              width: 0,
              dash: "none",
              severity: m.setAsideCode ? "elevated" : "watch",
              comtrade: {
                kind: "contract" as const,
                routeId: m.id,
                commodity: title,
                commodityCode:
                  opp?.solicitationNumber ||
                  opp?.noticeId ||
                  m.id.slice(0, 12),
                period: opp?.postedDate || "",
                originName: opp?.department || "Federal agency",
                originIso3: "USA",
                destName:
                  m.placeLabel ||
                  opp?.placeLabel ||
                  [opp?.city, opp?.state].filter(Boolean).join(", ") ||
                  "Place of performance",
                destIso3: (opp?.state || "US").slice(0, 3),
                transportMode:
                  opp?.naicsLabel ||
                  (m.naics ? `NAICS ${m.naics}` : "") ||
                  "",
                customsProcedure: opp?.type || "",
                valueUsd: 0,
                quantity: opp?.setAside || m.setAsideCode || "—",
                supplierSharePct: 0,
                exportValueUsd: 0,
                importValueUsd: 0,
                asymmetryPct: 0,
                fobValueUsd: 0,
                cifValueUsd: 0,
                frictionPct: 0,
                reExportSharePct: 0,
                confidencePct: 0,
                severity: m.setAsideCode ? "elevated" : "watch",
                layers: [
                  m.setAsideCode || opp?.setAsideCode || "",
                  m.naics || opp?.naics || "",
                ].filter(Boolean),
                insight: (opp?.descriptionExcerpt || "").slice(0, 400),
                referenceUrl: opp?.url || "",
                responseDeadline: opp?.responseDeadline || "",
                setAsideLabel: opp?.setAside || m.setAsideCode || "",
                noticeId: opp?.noticeId || "",
                solicitationNumber: opp?.solicitationNumber || "",
                active: opp?.active || "",
              },
            };
          });
        })()
      : [];
  const globeOverlayMarkers = [...unGlobalOverlayMarkers];
  const globeMarkerColor =
    contractsGlobeArcs.length > 0
      ? ([0.95, 0.72, 0.12] as [number, number, number])
      : tradePulseGlobeArcs.length > 0
        ? ([1, 0.24, 0.18] as [number, number, number])
        : unGlobalMarkerColor;
  const globeHeatZones = unodcHeatZones;
  const globeChoroplethRegions = unodcChoroplethRegions;
  const globeOverlayRoutes: GlobeArc[] = [
    ...tradePulseGlobeArcs,
    ...pkiGlobeArcs,
    ...contractsGlobeArcs,
  ];
  return { activityFeed, activityFilter, adminAllowlistConfigured, adminAudit, adminBusy, adminClaim, adminClaimAll, adminDeleteUser, adminElevationExpiresAt, adminElevationValid, adminError, adminGrant, adminGrantKind, adminLookup, adminLookupUser, adminMessage, adminNote, adminQuery, adminSessionId, adminUsers, adminUsersComplete, adminUsersCursor, adminUsersFilter, applyLocationPreference, applyManualLocation, authBusy, authError, authMessage, authMode, authUser, chatMessages, checkoutBusy, clearActivityFeed, clearAdminElevation, clearSensitiveAuthState, closeContractsHub, closePkiHub, closeUnHub, comtradeError, comtradePreview, comtradeSections, comtradeStatus, comtradeValueMode, contractsError, contractsLayerOn, contractsPreview, contractsStatus, counter, deviceKeys, disableUnGlobalLayer, dismissSiteTour, enabledComtradeSectionCount, enabledTradePulseLayerCount, enabledUnGlobalSectionCount, exportAead, exportAeadMode, exportAllowUnencrypted, exportArgonMemExp, exportArgonParallel, exportArgonPasses, exportCipher, exportPassphrase, exportPassphrase2, exportS2k, exportS2kIterByte, fetchNearbyMapForTransit, forecastView, generatedPublic, globeChoroplethRegions, globeHeatZones, globeMarkerColor, globeOverlayMarkers, globeOverlayRoutes, handleActivityFilterChange, handleDeviceSignIn, handleExportPrivateKey, handleGenerateKeypair, handleImportDeviceKey, handleRemoveDeviceKey, isAdmin, isCompactFeed, isFeedPaused, isPkiPanelMinimized, isTradePulsePanelMinimized, isUnGlobalPanelMinimized, isUnodcPanelMinimized, keyGenProfile, keyPassphrase, liveFeedAccess, loadAdminUsers, loadComtradePreview, loadLocalTransit, loadNearbyPaths, loadPkiVulns, loadSamContracts, loadTradePulsePreview, loadUnGlobalPreview, loadUnodcHotspots, loadWeatherFeed, locationBusy, locationDraftAddress, locationDraftLabel, locationDraftLat, locationDraftLng, locationMessage, locationPref, logout, lookupAddressLocation, navBarRef, nearbyError, nearbyPreview, nearbyRadiusM, nearbyStatus, openAdminPanel, openContractsHub, openPkiHub, openUnHub, paymentRequired, pkiArcSelection, pkiCatalog, pkiCategory, pkiDensity, pkiError, pkiFocusCve, pkiGlobeArcs, pkiPreview, pkiSeverities, pkiShowMap, pkiSort, pkiStatus, pkiVisibleCves, positions, refreshDeviceKeys, regPublicKey, registerWithPublicKey, requestBrowserLocation, runRateLimitedButtonAction, selectTradePulsePeriod, selectedDeviceFp, selectedDeviceKey, sendChatMessage, setAdminError, setAdminLookupUser, setAdminMessage, setAdminNote, setAdminQuery, setAdminSessionId, setAdminUsers, setAdminUsersFilter, setAuthError, setAuthMessage, setAuthMode, setContractsLayerOn, setExportAead, setExportAeadMode, setExportAllowUnencrypted, setExportArgonMemExp, setExportArgonParallel, setExportArgonPasses, setExportCipher, setExportPassphrase, setExportPassphrase2, setExportS2k, setExportS2kIterByte, setForecastView, setIsCompactFeed, setIsFeedPaused, setIsPkiPanelMinimized, setIsTradePulsePanelMinimized, setIsUnGlobalPanelMinimized, setIsUnodcPanelMinimized, setKeyGenProfile, setKeyPassphrase, setLocationDraftAddress, setLocationDraftLabel, setLocationDraftLat, setLocationDraftLng, setLocationMessage, setPkiArcPage, setPkiCatalog, setPkiCategory, setPkiDensity, setPkiFocusCve, setPkiSeverities, setPkiShowMap, setPkiSort, setRegPublicKey, setSelectedDeviceFp, setShowAbout, setShowActivityMenu, setShowAdminPanel, setShowAuthPanel, setShowComtradePanel, setShowImportDevice, setShowMenu, setShowNearbyPanel, setShowPkiPanel, setShowTradePulsePanel, setShowTransitPanel, setShowUnGlobalPanel, setShowUnodcPanel, setShowWeatherForecast, setShowWeatherPanel, setSocketStatus, setUnodcFocusMode, showAbout, showActivityMenu, showAdminPanel, showAuthPanel, showComtradePanel, showContractsHub, showImportDevice, showMenu, showNearbyPanel, showPkiHub, showPkiPanel, showSiteTour, showTradePulsePanel, showTransitPanel, showUnGlobalPanel, showUnHub, showUnodcPanel, showWeatherForecast, showWeatherPanel, socket, socketStatus, startTransitCheckout, toggleAllTradePulseLayers, toggleAllUnGlobalSections, toggleTradePulseLayer, toggleUnGlobalSection, toggleUnodcTheme, tradePulseError, tradePulseLayers, tradePulsePeriod, tradePulsePreview, tradePulseStatus, tradePulseYearOptions, transitDistanceM, transitError, transitPreview, transitStatus, unGlobalError, unGlobalPreview, unGlobalSections, unGlobalStatus, unlockAdminPrivileges, unodcCountryPolygons, unodcError, unodcPreview, unodcStatus, unodcThemes, visibleTradePulseRoutes, visibleUnMissionLocations, weatherError, weatherFeed, weatherGlow, weatherStatus };
}

export type GlobeApi = ReturnType<typeof useGlobeApp>;
