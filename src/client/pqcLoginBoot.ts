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

function watch(): void {
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

const observer = new MutationObserver(() => watch());
observer.observe(document.documentElement, { subtree: true, childList: true, characterData: true });
watch();

export {};
