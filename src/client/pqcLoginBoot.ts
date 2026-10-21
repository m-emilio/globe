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
  style.textContent =
    ".auth-modal-backdrop{z-index:14000!important}.pki-hub-header-actions{display:flex;flex-wrap:wrap;gap:8px;justify-content:flex-end}";
  document.head.append(style);
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

export {};
