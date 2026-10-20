/**
 * Tiny always-loaded entry. The key-agreement suites stay in a separate
 * chunk until the visitor opens the lab.
 */
function mountPqcButton(): void {
  if (document.getElementById("globe-pqc-open")) return;
  const button = document.createElement("button");
  button.id = "globe-pqc-open";
  button.type = "button";
  button.textContent = "PQC";
  button.title = "Post-quantum key agreement";
  button.style.cssText = [
    "position:fixed",
    "right:max(12px, env(safe-area-inset-right))",
    "bottom:max(12px, env(safe-area-inset-bottom))",
    "z-index:10000",
    "padding:10px 14px",
    "border-radius:999px",
    "border:1px solid rgba(61,255,168,0.55)",
    "background:#102820",
    "color:#d8ffe8",
    "font:600 13px/1 system-ui,sans-serif",
    "letter-spacing:0.04em",
    "cursor:pointer",
  ].join(";");
  button.addEventListener("click", () => {
    button.disabled = true;
    button.textContent = "Opening…";
    void import("./pqcPanel")
      .then((mod) => {
        button.remove();
        mod.mountPqcLab();
      })
      .catch(() => {
        button.disabled = false;
        button.textContent = "PQC failed";
      });
  });
  document.body.appendChild(button);
}

window.addEventListener("globe-pqc-closed", mountPqcButton);

if (document.body) mountPqcButton();
else document.addEventListener("DOMContentLoaded", mountPqcButton);
