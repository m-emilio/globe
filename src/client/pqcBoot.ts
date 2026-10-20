/**
 * Loads the post-quantum key lab inside the sign-in window.
 * The agreement code stays in a separate chunk until sign-in opens.
 */
function watch(): void {
  const modal = document.querySelector(".auth-modal:not(.admin-modal)");
  if (!(modal instanceof HTMLElement)) return;
  if (modal.querySelector("#globe-pqc-lab") || modal.querySelector("#globe-pqc-open")) return;
  if (modal.dataset.globePqcLab === "1") return;
  modal.dataset.globePqcLab = "1";
  void import("./pqcPanel")
    .then((mod) => {
      mod.mountPqcLab();
    })
    .catch(() => {
      delete modal.dataset.globePqcLab;
    });
}

const observer = new MutationObserver(() => watch());
observer.observe(document.documentElement, { subtree: true, childList: true });
watch();

export {};
