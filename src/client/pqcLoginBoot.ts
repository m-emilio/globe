/**
 * Tiny always-loaded watcher. ML-DSA stays in a separate chunk until the
 * account modal opens. The session label is plain text, so it can update
 * before that chunk loads.
 */
function patchSessionLabel(): void {
  const nodes = document.querySelectorAll(".auth-user-meta");
  for (let i = 0; i < nodes.length; i++) {
    const block = nodes[i];
    if (!(block instanceof HTMLElement)) continue;
    const status = block.querySelector(".auth-user-meta-status");
    if (!(status instanceof HTMLElement)) continue;
    const text = status.textContent || "";
    if (!text.includes("PGP session")) continue;
    const replacement = text.includes("ML-DSA-") || text.includes("SLH-DSA-")
      ? "ML-DSA session"
      : text.includes("ECDHE-") || text.includes("KEM-")
        ? "Key lab session"
        : "";
    if (!replacement) continue;
    status.textContent = text.replace("PGP session", replacement);
    const print = block.querySelector(".auth-user-fingerprint");
    if (print instanceof HTMLElement && print.title === "Full OpenPGP fingerprint") {
      print.title = "Account fingerprint";
    }
  }
}

let arrangeSignIn: (() => void) | null = null;

function ensureIdentityLayer(): void {
  if (document.getElementById("globe-identity-layer")) return;
  const style = document.createElement("style");
  style.id = "globe-identity-layer";
  style.textContent = [
    ".auth-modal-backdrop{z-index:14000!important}",
    ".pki-hub-header-actions{display:flex;flex-wrap:wrap;gap:8px;justify-content:flex-end}",
    ".menu-dropdown .menu-section-location .menu-section-title{padding-right:46px}",
    ".pki-hub .pki-hub-cve-list,.pki-panel .pki-cve-list{max-height:none!important;overflow:visible!important}",
    "#globe-menu-close{width:36px;height:36px;border:1px solid rgba(0,217,255,.65);border-radius:4px;background:rgba(0,0,0,.92);color:#00d9ff;font:22px/1 inherit;cursor:pointer;display:flex;align-items:center;justify-content:center;padding:0}",
    "#globe-feed-resize{z-index:1160;width:36px;height:36px}",
    "#globe-pki-cve-pager{display:flex;align-items:center;gap:8px;box-sizing:border-box;padding:6px 8px;background:rgba(8,10,16,.96);border:1px solid rgba(255,125,160,.55);border-radius:10px}",
    "#globe-pki-cve-pager button{min-height:36px;min-width:64px;border:1px solid rgba(255,255,255,.16);border-radius:999px;background:rgba(255,255,255,.06);color:#f2f4f7;font:600 12px inherit;cursor:pointer}",
    "#globe-pki-cve-pager button:disabled{opacity:.35;cursor:not-allowed}",
    "#globe-pki-cve-pager span{flex:1;min-width:0;font-size:12px;color:#e8edf4}",
    ".nav-center:not(:empty){display:flex!important;flex:1 1 auto!important;width:auto!important;order:0!important;justify-content:center!important;align-items:center!important;min-width:0!important;grid-template-columns:none!important}",
    "#globe-header-identity{height:32px;min-height:32px;max-width:100%;padding:0 12px;border:1.5px solid #6e7681;border-radius:3px;background:rgba(0,0,0,.82);color:#9aa4b2;font:700 11px/1 var(--font-ui,inherit);letter-spacing:.08em;text-transform:uppercase;cursor:pointer;white-space:nowrap;box-sizing:border-box}",
    "#globe-header-identity[data-level=guest]{border-color:#6e7681;color:#9aa4b2;background:rgba(0,0,0,.72);box-shadow:none}",
    "#globe-header-identity[data-level=session]{border-color:#00d9ff;color:#00d9ff;background:rgba(0,217,255,.14);box-shadow:0 0 10px rgba(0,217,255,.28)}",
    "#globe-header-identity[data-level=keys]{border-color:#00ff88;color:#00ff88;background:rgba(0,255,136,.12);box-shadow:0 0 10px rgba(0,255,136,.25)}",
    "#globe-header-identity[data-level=transit]{border-color:#d4af37;color:#f0d78c;background:rgba(212,175,55,.16);box-shadow:0 0 10px rgba(212,175,55,.28)}",
    "#globe-header-identity[data-level=admin]{border-color:#ffb020;color:#1a1206;background:#ffd08a;box-shadow:0 0 12px rgba(255,176,32,.45)}",
    "@media (max-width:480px){#globe-header-identity{height:28px;min-height:28px;padding:0 8px;font-size:10px;letter-spacing:.04em}}",
  ].join("");
  document.head.append(style);
}

function closeMenu(): void {
  const toggle = document.querySelector(".nav-menu-btn");
  if (!(toggle instanceof HTMLElement)) return;
  if (!document.querySelector(".menu-dropdown")) return;
  toggle.click();
  window.setTimeout(() => {
    if (!document.querySelector(".menu-dropdown")) return;
    toggle.click();
  }, 560);
}

function placeMenuClose(): void {
  const menu = document.querySelector(".menu-dropdown");
  const existing = document.getElementById("globe-menu-close");
  if (!(menu instanceof HTMLElement)) {
    existing?.remove();
    return;
  }
  let button: HTMLButtonElement;
  if (existing instanceof HTMLButtonElement) {
    button = existing;
  } else {
    existing?.remove();
    button = document.createElement("button");
    button.type = "button";
    button.id = "globe-menu-close";
    button.setAttribute("aria-label", "Close menu");
    button.textContent = "×";
    button.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      closeMenu();
    });
    document.body.append(button);
  }
  const rect = menu.getBoundingClientRect();
  button.style.position = "fixed";
  button.style.left = `${Math.max(8, rect.right - 44)}px`;
  button.style.top = `${rect.top + 6}px`;
  button.style.zIndex = "1300";
}

type FeedResize = {
  pointerId: number;
  startX: number;
  startY: number;
  width: number;
  height: number;
  left: number;
  top: number;
};

let feedResize: FeedResize | null = null;

function resizeFeed(feed: HTMLElement, width: number, height: number): void {
  const host = feed.closest(".live-feed-app-host");
  if (host instanceof HTMLElement && host.dataset.globeFeedAnchored !== "1") {
    const hostRect = host.getBoundingClientRect();
    host.style.top = `${hostRect.top}px`;
    host.style.left = `${hostRect.left}px`;
    host.style.bottom = "auto";
    host.style.right = "auto";
    host.dataset.globeFeedAnchored = "1";
  }
  feed.style.width = `${width}px`;
  feed.style.height = `${height}px`;
  feed.style.maxWidth = "none";
  feed.style.maxHeight = "none";
  feed.style.overflow = "hidden";
  if (host instanceof HTMLElement) {
    host.style.maxWidth = "none";
    host.style.width = `${width}px`;
  }
  const floating = feed.parentElement;
  if (floating instanceof HTMLElement) {
    floating.style.maxWidth = "none";
    floating.style.width = `${width}px`;
  }
  const regions = feed.querySelectorAll(".activity-list, .un-tv-panel, .activity-lock-panel");
  for (let i = 0; i < regions.length; i++) {
    const region = regions[i];
    if (!(region instanceof HTMLElement)) continue;
    region.style.maxHeight = "none";
    region.style.flex = "1 1 auto";
    region.style.minHeight = "0";
  }
}

function resetFeedHost(): void {
  const host = document.querySelector(".live-feed-app-host");
  if (!(host instanceof HTMLElement) || host.dataset.globeFeedAnchored !== "1") return;
  host.style.top = "";
  host.style.left = "";
  host.style.bottom = "";
  host.style.right = "";
  host.style.width = "";
  host.style.maxWidth = "";
  delete host.dataset.globeFeedAnchored;
  const floating = host.querySelector(".activity-floating");
  if (floating instanceof HTMLElement) {
    floating.style.width = "";
    floating.style.maxWidth = "";
  }
}

function placeFeedResize(): void {
  const feed = document.getElementById("live-feed-menu");
  let grip = document.getElementById("globe-feed-resize");
  if (!(feed instanceof HTMLElement)) {
    grip?.remove();
    if (!feedResize) resetFeedHost();
    return;
  }
  if (!(grip instanceof HTMLElement)) {
    grip = document.createElement("div");
    grip.id = "globe-feed-resize";
    grip.className = "floating-chrome-resize";
    grip.setAttribute("role", "separator");
    grip.setAttribute("aria-label", "Resize live feed");
    grip.title = "Drag to resize";
    grip.addEventListener("pointerdown", (event) => {
      if (event.button !== 0) return;
      const current = document.getElementById("live-feed-menu");
      if (!(current instanceof HTMLElement)) return;
      event.preventDefault();
      event.stopPropagation();
      const rect = current.getBoundingClientRect();
      feedResize = {
        pointerId: event.pointerId,
        startX: event.clientX,
        startY: event.clientY,
        width: rect.width,
        height: rect.height,
        left: rect.left,
        top: rect.top,
      };
      if (grip instanceof HTMLElement) {
        try {
          grip.setPointerCapture(event.pointerId);
        } catch {
          // The window listener still receives the move.
        }
      }
    });
    document.body.append(grip);
  }
  const rect = feed.getBoundingClientRect();
  grip.style.position = "fixed";
  grip.style.left = `${rect.right - 36}px`;
  grip.style.top = `${rect.bottom - 36}px`;
  grip.style.right = "auto";
  grip.style.bottom = "auto";
}

const PANEL_CVE_PAGE_SIZE = 8;
let panelCvePage = 0;
let panelCveKey = "";

function placePanelCvePager(): void {
  const panel = document.querySelector(".pki-panel:not(.un-panel-minimized)");
  const list = panel?.querySelector(".pki-cve-list");
  let bar = document.getElementById("globe-pki-cve-pager");
  if (!(panel instanceof HTMLElement) || !(list instanceof HTMLElement)) {
    bar?.remove();
    panelCvePage = 0;
    panelCveKey = "";
    return;
  }
  const cards = Array.from(list.querySelectorAll(":scope > .pki-cve-card"));
  const key = cards
    .map((card) => card.querySelector("strong")?.textContent || "")
    .join("|");
  if (key !== panelCveKey) {
    panelCveKey = key;
    panelCvePage = 0;
  }
  const pageCount = Math.max(1, Math.ceil(cards.length / PANEL_CVE_PAGE_SIZE));
  if (panelCvePage > pageCount - 1) panelCvePage = pageCount - 1;
  for (let i = 0; i < cards.length; i++) {
    const card = cards[i];
    if (!(card instanceof HTMLElement)) continue;
    const visible = Math.floor(i / PANEL_CVE_PAGE_SIZE) === panelCvePage;
    card.style.display = visible ? "" : "none";
  }
  list.style.maxHeight = "none";
  list.style.overflow = "visible";
  const scroll = panel.querySelector(".trade-pulse-panel-scroll");
  if (scroll instanceof HTMLElement) scroll.style.paddingBottom = "52px";
  if (!(bar instanceof HTMLElement)) {
    bar = document.createElement("div");
    bar.id = "globe-pki-cve-pager";
    bar.setAttribute("role", "group");
    bar.setAttribute("aria-label", "CVE pages");
    const prev = document.createElement("button");
    prev.type = "button";
    prev.id = "globe-pki-cve-prev";
    prev.textContent = "← Prev";
    prev.addEventListener("click", () => {
      panelCvePage = Math.max(0, panelCvePage - 1);
      placePanelCvePager();
    });
    const status = document.createElement("span");
    status.id = "globe-pki-cve-status";
    const next = document.createElement("button");
    next.type = "button";
    next.id = "globe-pki-cve-next";
    next.textContent = "Next →";
    next.addEventListener("click", () => {
      panelCvePage += 1;
      placePanelCvePager();
    });
    bar.append(prev, status, next);
    document.body.append(bar);
  }
  const status = bar.querySelector("#globe-pki-cve-status");
  const prev = bar.querySelector("#globe-pki-cve-prev");
  const next = bar.querySelector("#globe-pki-cve-next");
  const shown = cards.filter((card) => card instanceof HTMLElement && card.style.display !== "none").length;
  const label = cards.length
    ? `Page ${panelCvePage + 1}/${pageCount} · ${shown} of ${cards.length}`
    : "Page 1/1";
  if (status && status.textContent !== label) status.textContent = label;
  if (prev instanceof HTMLButtonElement) prev.disabled = panelCvePage <= 0;
  if (next instanceof HTMLButtonElement) next.disabled = panelCvePage >= pageCount - 1;
  const rect = panel.getBoundingClientRect();
  bar.style.position = "fixed";
  bar.style.left = `${rect.left + 8}px`;
  bar.style.top = `${Math.max(8, rect.bottom - 48)}px`;
  bar.style.width = `${Math.max(160, rect.width - 44)}px`;
  bar.style.zIndex = "1300";
}

function placeFloatingControls(): void {
  placeMenuClose();
  placeFeedResize();
  placePanelCvePager();
}

function dismissSignedInBanner(): void {
  if (!document.querySelector(".auth-user-meta")) return;
  const banner = document.querySelector(".billing-banner");
  if (!(banner instanceof HTMLElement)) return;
  const text = banner.textContent || "";
  if (!/Stripe|Live Feed|support chat/.test(text)) return;
  const dismiss = banner.querySelector("button");
  if (dismiss instanceof HTMLButtonElement) dismiss.click();
}

function openIdentity(): void {
  if (document.querySelector(".menu-dropdown")) {
    const toggle = document.querySelector(".nav-menu-btn");
    if (toggle instanceof HTMLElement) toggle.click();
  }
  window.dispatchEvent(new Event("globe-open-identity"));
}

window.addEventListener("globe-open-identity", () => {
  window.setTimeout(dismissSignedInBanner, 60);
});

type IdentityLevel = "guest" | "session" | "keys" | "transit" | "admin";

const IDENTITY_TITLE: Record<IdentityLevel, string> = {
  guest: "Identity — signed out",
  session: "Identity — signed in",
  keys: "Identity — unlimited keys",
  transit: "Identity — Stripe access",
  admin: "Identity — admin",
};

let identityLevel: IdentityLevel = "guest";
let identityFetchAt = 0;
let identityFetchBusy = false;
let authModalWasOpen = false;

function levelFromMe(data: unknown): IdentityLevel {
  if (!data || typeof data !== "object") return "guest";
  const row = data as {
    authenticated?: unknown;
    isAdmin?: unknown;
    user?: { transitPaid?: unknown; unlimitedKeys?: unknown } | null;
  };
  if (row.authenticated !== true || !row.user) return "guest";
  if (row.isAdmin === true) return "admin";
  if (row.user.transitPaid === true) return "transit";
  if (row.user.unlimitedKeys === true) return "keys";
  return "session";
}

function applyIdentityLevel(button: HTMLButtonElement): void {
  if (button.dataset.level !== identityLevel) button.dataset.level = identityLevel;
  const title = IDENTITY_TITLE[identityLevel];
  if (button.title !== title) button.title = title;
  if (button.getAttribute("aria-label") !== title) button.setAttribute("aria-label", title);
}

function mountHeaderIdentity(): void {
  const center = document.querySelector(".nav-bar .nav-center");
  if (!(center instanceof HTMLElement)) return;
  const existing = document.getElementById("globe-header-identity");
  if (existing instanceof HTMLButtonElement && existing.parentElement === center) {
    applyIdentityLevel(existing);
    return;
  }
  existing?.remove();
  const button = document.createElement("button");
  button.type = "button";
  button.id = "globe-header-identity";
  button.textContent = "Identity";
  button.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    openIdentity();
  });
  applyIdentityLevel(button);
  center.append(button);
}

async function refreshIdentityLevel(force = false): Promise<void> {
  const now = Date.now();
  if (!force && now - identityFetchAt < 8000) return;
  if (identityFetchBusy) return;
  identityFetchBusy = true;
  identityFetchAt = now;
  try {
    const response = await fetch("/api/auth/me", {
      credentials: "same-origin",
      headers: { accept: "application/json" },
    });
    if (!response.ok) {
      if (response.status === 401 || response.status === 403) identityLevel = "guest";
      return;
    }
    identityLevel = levelFromMe(await response.json());
  } catch {
    // Keep the last level when the session check cannot be reached.
  } finally {
    identityFetchBusy = false;
    const button = document.getElementById("globe-header-identity");
    if (button instanceof HTMLButtonElement) applyIdentityLevel(button);
  }
}

function noteAuthModal(): void {
  const open = Boolean(document.querySelector(".auth-modal"));
  if (authModalWasOpen && !open) void refreshIdentityLevel(true);
  authModalWasOpen = open;
}

function mountIdentityMenu(): void {
  const section = document.querySelector(".menu-section-links");
  const signedIn = Boolean(document.querySelector(".auth-user-meta"));
  const existing = document.getElementById("globe-menu-identity");
  if (!signedIn || !(section instanceof HTMLElement)) {
    existing?.remove();
    return;
  }
  if (existing && existing.parentElement === section) return;
  existing?.remove();
  const button = document.createElement("button");
  button.type = "button";
  button.id = "globe-menu-identity";
  button.className = "menu-item menu-item-button";
  button.textContent = "Identity";
  button.title = "Open Identity to create or sign in another key";
  button.addEventListener("click", openIdentity);
  section.insertBefore(button, section.firstChild);
}

function watch(): void {
  ensureIdentityLayer();
  placeFloatingControls();
  mountHeaderIdentity();
  noteAuthModal();
  void refreshIdentityLevel();
  mountIdentityMenu();
  patchSessionLabel();
  const admin = document.querySelector(".admin-modal");
  if (admin instanceof HTMLElement && admin.dataset.globeLoginLog !== "1") {
    admin.dataset.globeLoginLog = "1";
    void import("./adminLoginLog")
      .then((mod) => {
        mod.mountAdminLoginLog();
      })
      .catch(() => {
        delete admin.dataset.globeLoginLog;
      });
  }
  if (admin instanceof HTMLElement && admin.dataset.globeKeyGrant !== "1") {
    admin.dataset.globeKeyGrant = "1";
    void import("./adminKeyGrant")
      .then((mod) => {
        mod.mountAdminKeyGrant();
      })
      .catch(() => {
        delete admin.dataset.globeKeyGrant;
      });
  }
  const modal = document.querySelector(".auth-modal:not(.admin-modal)");
  if (!(modal instanceof HTMLElement)) return;
  if (arrangeSignIn) arrangeSignIn();
  else if (modal.dataset.globeSignIn !== "1") {
    modal.dataset.globeSignIn = "1";
    void import("./signInOne")
      .then((mod) => {
        arrangeSignIn = () => mod.mountUnifiedSignIn();
        arrangeSignIn();
      })
      .catch(() => {
        delete modal.dataset.globeSignIn;
      });
  }
  if (modal.dataset.globePqcLogin === "1") return;
  modal.dataset.globePqcLogin = "1";
  void import("./pqcLogin").catch(() => {
    delete modal.dataset.globePqcLogin;
  });
}

window.addEventListener("globe-mldsa87-import", (event) => {
  const armored = event instanceof CustomEvent && typeof event.detail === "string" ? event.detail : "";
  const status = document.querySelector("#globe-asc-rejected");
  const show = (message: string, isError: boolean) => {
    const panel = document.querySelector(".auth-modal:not(.admin-modal) .auth-export-panel");
    const note = status instanceof HTMLElement ? status : document.createElement("p");
    if (!(status instanceof HTMLElement) && panel instanceof HTMLElement) {
      note.id = "globe-asc-rejected";
      note.setAttribute("role", "status");
      note.style.cssText = "margin:8px 0 0;font-size:13px";
      panel.append(note);
    }
    if (!(note instanceof HTMLElement)) return;
    note.style.color = isError ? "#ffb4b4" : "#d8ffe8";
    note.textContent = message;
  };
  if (!armored) {
    show("That .asc is not the ML-DSA-87 sign-in key.", true);
    return;
  }
  show("Saving the ML-DSA-87 key on this device…", false);
  void import("./mlDsa")
    .then((mod) => mod.importMldsa87PrivateAsc(armored))
    .then(() => {
      show("ML-DSA-87 key is on this device. Choose Post-quantum and sign in. The private key was not uploaded.", false);
    })
    .catch((error: unknown) => {
      show(error instanceof Error ? error.message : "Could not save the ML-DSA-87 key on this device.", true);
    });
});

const observer = new MutationObserver(() => watch());
observer.observe(document.documentElement, { subtree: true, childList: true, characterData: true });
watch();

window.addEventListener("pointermove", (event) => {
  if (feedResize && event.pointerId === feedResize.pointerId) {
    const feed = document.getElementById("live-feed-menu");
    if (feed instanceof HTMLElement) {
      event.preventDefault();
      const minW = 220;
      const minH = 180;
      const maxW = Math.max(minW, window.innerWidth - feedResize.left - 8);
      const maxH = Math.max(minH, window.innerHeight - feedResize.top - 8);
      resizeFeed(
        feed,
        Math.min(maxW, Math.max(minW, feedResize.width + (event.clientX - feedResize.startX))),
        Math.min(maxH, Math.max(minH, feedResize.height + (event.clientY - feedResize.startY))),
      );
    }
  }
  placeFloatingControls();
}, { passive: false });
window.addEventListener("pointerup", (event) => {
  if (!feedResize || event.pointerId !== feedResize.pointerId) return;
  feedResize = null;
  placeFloatingControls();
});
window.addEventListener("pointercancel", (event) => {
  if (!feedResize || event.pointerId !== feedResize.pointerId) return;
  feedResize = null;
  placeFloatingControls();
});
window.addEventListener("resize", () => placeFloatingControls());
window.addEventListener("scroll", () => placeFloatingControls(), true);
window.setInterval(() => {
  void refreshIdentityLevel(true);
}, 20000);
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") void refreshIdentityLevel(true);
});

export {};
