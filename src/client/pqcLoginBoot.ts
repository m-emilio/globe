/**
 * Tiny always-loaded watcher. ML-DSA stays in a separate chunk until the
 * account modal opens.
 */
function watch(): void {
  const modal = document.querySelector(".auth-modal:not(.admin-modal)");
  if (!(modal instanceof HTMLElement)) return;
  if (modal.dataset.globePqcLogin === "1") return;
  modal.dataset.globePqcLogin = "1";
  void import("./pqcLogin").catch(() => {
    delete modal.dataset.globePqcLogin;
  });
}

const observer = new MutationObserver(() => watch());
observer.observe(document.documentElement, { subtree: true, childList: true });
watch();
