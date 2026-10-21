/**
 * Download the OpenPGP private key already stored in this browser.
 * The file is not uploaded.
 */
const BUTTON = [
  "min-height:44px",
  "width:100%",
  "margin-top:8px",
  "font:600 15px/1.2 system-ui,sans-serif",
  "border-radius:10px",
  "border:1px solid rgba(61,255,168,0.45)",
  "background:#16382c",
  "color:#e7fff3",
].join(";");

export function mountDeviceKeyExport(): void {
  const modal = document.querySelector(".auth-modal:not(.admin-modal)");
  if (!(modal instanceof HTMLElement)) return;
  const found = modal.querySelector("#globe-device-export");
  const root = found instanceof HTMLElement ? found : document.createElement("section");
  if (!(found instanceof HTMLElement)) {
    root.id = "globe-device-export";
    root.style.cssText = "margin:0 0 12px";
    const button = document.createElement("button");
    button.type = "button";
    button.id = "globe-device-export-key";
    button.textContent = "Export stored private key";
    button.style.cssText = BUTTON;
    const status = document.createElement("p");
    status.id = "globe-device-export-status";
    status.setAttribute("role", "status");
    status.style.cssText = "min-height:1.2em;margin:6px 0 0;font-size:13px;color:#d8ffe8";
    root.append(button, status);
    button.addEventListener("click", () => {
      button.disabled = true;
      status.style.color = "#d8ffe8";
      status.textContent = "Reading the device key stored in this browser…";
      void import("./pgpAuth")
        .then(async (mod) => {
          const stored = await mod.getPreferredDeviceKey();
          const armored = stored?.privateKeyArmored ?? "";
          if (!armored.includes("BEGIN PGP PRIVATE KEY")) {
            throw new Error("No device private key is stored in this browser.");
          }
          mod.downloadPrivateKeyFile(armored, "globe-device-private.asc");
          status.textContent = "Saved globe-device-private.asc. The private key was not uploaded.";
        })
        .catch((error: unknown) => {
          status.style.color = "#ffb4b4";
          status.textContent = error instanceof Error ? error.message : "Could not export the device private key.";
        })
        .finally(() => {
          button.disabled = false;
        });
    });
  }
  const shell = modal.querySelector("#globe-sign-in");
  if (shell instanceof HTMLElement && root.previousElementSibling !== shell) {
    shell.insertAdjacentElement("afterend", root);
  } else if (!root.parentElement) {
    modal.append(root);
  }
}
