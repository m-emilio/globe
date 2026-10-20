/**
 * Key lab outside the sign-in form.
 * Generate, import a sanitized .asc or private JWK, derive, and run local checks.
 * OpenPGP login keys stay on the sign-in screen.
 */

import {
  deriveEcdheFromPrivateMaterial,
  ecdhePrivateKeyAsc,
  ecdhePrivateKeyAscFilename,
  generateEcdheKeyPair,
  loadEcdhePrivateMaterial,
  runEcdheSecurityChecks,
  type EcdheCurveId,
} from "./ecdhe";
import { describeKeyMaterial, peerPublicMaterial, sanitizeKeyMaterial } from "./keyMaterial";

type EcdheExportDetail = {
  curve: string;
  privateKeyPkcs8Pem: string;
  privateKeyJwk: JsonWebKey;
  privateKeyRawB64?: string;
  publicKeySpkiB64?: string;
  publicKeyJwk?: JsonWebKey;
};

const CURVES: readonly EcdheCurveId[] = ["P-256", "P-384", "P-521", "X25519"];

function asCurve(value: string): EcdheCurveId {
  if ((CURVES as readonly string[]).includes(value)) return value as EcdheCurveId;
  throw new Error(`Unsupported ECDHE curve: ${value}`);
}

const OLD_READY =
  "Private key is non-extractable in memory only (not for OpenPGP login).";
const NEW_READY =
  "Private key is extractable (PKCS#8 and JWK in the key lab). This is not an OpenPGP login key.";
const OLD_HINT =
  "private material stays non-extractable in memory and is never uploaded";
const NEW_HINT =
  "the key lab holds the ECDHE private key on this device. It is not uploaded";

function hideInlineLab(): void {
  const title = document.querySelector(".auth-ecdhe-title");
  if (!(title instanceof HTMLElement)) return;
  title.style.display = "none";
  let sibling = title.nextElementSibling;
  if (sibling instanceof HTMLElement && sibling.classList.contains("auth-field-hint")) {
    sibling.style.display = "none";
    sibling = sibling.nextElementSibling;
  }
  if (sibling instanceof HTMLElement && sibling.classList.contains("auth-modal-actions")) {
    sibling.style.display = "none";
  }
  const labs = document.querySelectorAll(".auth-ecdhe-lab");
  for (let i = 0; i < labs.length; i++) {
    const lab = labs[i];
    if (lab instanceof HTMLElement) lab.style.display = "none";
  }
}

let applyingCopy = false;

function applyCopy(): void {
  if (applyingCopy) return;
  if (!document.querySelector(".auth-modal, .auth-ecdhe-title")) return;
  applyingCopy = true;
  try {
    hideInlineLab();
    const nodes = document.querySelectorAll(".auth-inline-ok, .auth-field-hint");
    for (let i = 0; i < nodes.length; i++) {
      const node = nodes[i]!;
      const text = node.textContent ?? "";
      if (text.includes(OLD_READY)) node.textContent = text.replace(OLD_READY, NEW_READY);
      if (text.includes(OLD_HINT)) node.textContent = text.replace(OLD_HINT, NEW_HINT);
      if (text.includes("Cleared ephemeral material.")) hidePanel();
    }
  } finally {
    applyingCopy = false;
  }
}

let panel: HTMLElement | null = null;
let selectedCurve: EcdheCurveId = "X25519";

function mountLauncher(): void {
  if (document.getElementById("globe-key-lab-open") || panel) return;
  const button = document.createElement("button");
  button.id = "globe-key-lab-open";
  button.type = "button";
  button.textContent = "Key lab";
  button.style.cssText = [
    "position:fixed",
    "left:max(12px, env(safe-area-inset-left))",
    "bottom:max(108px, calc(env(safe-area-inset-bottom) + 100px))",
    "z-index:1200",
    "min-height:44px",
    "padding:10px 14px",
    "border-radius:999px",
    "border:1px solid rgba(160,150,255,0.55)",
    "background:#1c1830",
    "color:#eef0ff",
    "font:600 13px/1 system-ui,sans-serif",
    "cursor:pointer",
  ].join(";");
  button.addEventListener("click", () => showPanel(null, false));
  document.body.append(button);
}

function hidePanel(): void {
  panel?.remove();
  panel = null;
  mountLauncher();
}

const AREA_STYLE = [
  "width:100%",
  "box-sizing:border-box",
  "font:16px/1.35 ui-monospace,monospace",
  "color:#eef0ff",
  "background:#12141f",
  "border:1px solid rgba(160,150,255,0.35)",
  "border-radius:6px",
  "padding:8px",
].join(";");

const BUTTON_STYLE = [
  "min-height:44px",
  "padding:8px 12px",
  "border-radius:8px",
  "border:1px solid rgba(160,150,255,0.45)",
  "background:#2a2650",
  "color:#eef0ff",
  "cursor:pointer",
  "font:600 14px/1.2 system-ui,sans-serif",
].join(";");

function bindKeyField(area: HTMLTextAreaElement): void {
  area.maxLength = 512_000;
  area.addEventListener("input", () => {
    if (!area.value.includes("\0")) return;
    const next = area.value.replace(/\0/g, "");
    if (next !== area.value) area.value = next;
  });
}

function field(label: string, value: string, id?: string): HTMLLabelElement {
  const wrap = document.createElement("label");
  wrap.style.cssText = "display:flex;flex-direction:column;gap:6px;margin:10px 0";
  const span = document.createElement("span");
  span.textContent = label;
  span.style.cssText = "font-size:12px;color:#d7dcff";
  const area = document.createElement("textarea");
  if (id) area.id = id;
  area.readOnly = true;
  area.rows = 3;
  area.spellcheck = false;
  area.value = value;
  area.style.cssText = AREA_STYLE;
  area.addEventListener("focus", () => area.select());
  wrap.append(span, area);
  return wrap;
}

function peerField(): HTMLLabelElement {
  const wrap = document.createElement("label");
  wrap.style.cssText = "display:flex;flex-direction:column;gap:6px;margin:10px 0";
  const span = document.createElement("span");
  span.textContent = "Peer public key (JWK or SPKI base64)";
  span.style.cssText = "font-size:12px;color:#d7dcff";
  const area = document.createElement("textarea");
  area.id = "globe-ecdhe-peer";
  area.rows = 3;
  area.spellcheck = false;
  area.placeholder = "Paste a public key only";
  area.autocomplete = "off";
  area.style.cssText = AREA_STYLE;
  bindKeyField(area);
  wrap.append(span, area);
  return wrap;
}

async function runDerive(
  detail: EcdheExportDetail,
  status: HTMLElement,
  button: HTMLButtonElement,
): Promise<void> {
  const peerEl = panel?.querySelector("#globe-ecdhe-peer");
  if (!(peerEl instanceof HTMLTextAreaElement)) return;
  button.disabled = true;
  setDeriveStatus(status, "pending", "Deriving…");
  try {
    const peer = peerPublicMaterial(peerEl.value);
    const curve = asCurve(detail.curve);
    const fromPem = await deriveEcdheFromPrivateMaterial(
      curve,
      detail.privateKeyPkcs8Pem,
      peer,
    );
    const fromJwk = await deriveEcdheFromPrivateMaterial(
      curve,
      JSON.stringify(detail.privateKeyJwk),
      peer,
    );
    if (
      fromPem.sessionKey.extractable ||
      fromJwk.sessionKey.extractable ||
      fromPem.sharedSecretSha256Hex !== fromJwk.sharedSecretSha256Hex
    ) {
      throw new Error("PKCS#8 and the private JWK did not agree, or the session key was extractable.");
    }
    setDeriveStatus(
      status,
      "agreed",
      `Shared secret fingerprint (SHA-256): ${fromPem.sharedSecretSha256Hex}. AES-GCM session key stays non-extractable.`,
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "ECDHE derive failed";
    setDeriveStatus(
      status,
      message.startsWith("Paste the peer public key") ? "empty-peer" : "error",
      message,
    );
  } finally {
    button.disabled = false;
  }
}

function setDeriveStatus(
  status: HTMLElement,
  kind: "pending" | "empty-peer" | "agreed" | "error",
  message: string,
): void {
  status.hidden = false;
  status.id =
    kind === "agreed"
      ? "globe-ecdhe-derive-agreed"
      : kind === "empty-peer"
        ? "globe-ecdhe-derive-empty"
        : kind === "error"
          ? "globe-ecdhe-derive-error"
          : "globe-ecdhe-derive-status";
  status.textContent = message;
}

function saveAsc(detail: EcdheExportDetail, note: HTMLElement): void {
  let filename = "globe-ecdhe-private.asc";
  try {
    filename = ecdhePrivateKeyAscFilename(asCurve(detail.curve));
    const asc = ecdhePrivateKeyAsc(detail.privateKeyPkcs8Pem);
    const blob = new Blob([asc], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.rel = "noopener";
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    note.hidden = false;
    note.id = "globe-ecdhe-asc-saved";
    note.textContent = `Saved ${filename}. This is not an OpenPGP login key.`;
  } catch (error) {
    note.hidden = false;
    note.id = "globe-ecdhe-asc-error";
    note.textContent = error instanceof Error ? error.message : "Could not save the .asc file.";
  }
}

function showPanel(detail: EcdheExportDetail | null, autoDownload: boolean): void {
  if (detail?.curve) {
    try {
      selectedCurve = asCurve(detail.curve);
    } catch {
      selectedCurve = "X25519";
    }
  }
  hidePanel();
  document.getElementById("globe-key-lab-open")?.remove();
  const root = document.createElement("section");
  panel = root;
  root.id = "globe-ecdhe-export";
  root.style.cssText = [
    "position:fixed",
    "left:max(12px, env(safe-area-inset-left))",
    "bottom:max(108px, calc(env(safe-area-inset-bottom) + 100px))",
    "z-index:1002",
    "width:min(440px, calc(100vw - 24px))",
    "max-height:min(62dvh, 640px)",
    "overflow:auto",
    "padding:14px",
    "border-radius:12px",
    "border:1px solid rgba(160,150,255,0.4)",
    "background:rgba(18,16,32,0.96)",
    "color:#eef0ff",
    "box-shadow:0 12px 40px rgba(0,0,0,0.35)",
    "font:14px/1.4 system-ui,sans-serif",
  ].join(";");

  const title = document.createElement("h2");
  title.textContent = "ECDHE key lab";
  title.style.cssText = "margin:0 0 6px;font-size:16px";
  const hint = document.createElement("p");
  hint.textContent =
    "Ephemeral key agreement on this device. Not an OpenPGP login key and not uploaded. Import a sanitized .asc or private JWK, derive with a peer public key, and run the local checks.";
  hint.style.cssText = "margin:0 0 8px;color:#c9c6ea;font-size:13px";

  const curveLabel = document.createElement("label");
  curveLabel.style.cssText = "display:flex;flex-direction:column;gap:6px;margin:8px 0";
  const curveSpan = document.createElement("span");
  curveSpan.textContent = "Curve";
  curveSpan.style.cssText = "font-size:12px;color:#d7dcff";
  const curveSelect = document.createElement("select");
  curveSelect.id = "globe-ecdhe-curve";
  curveSelect.style.cssText = `${AREA_STYLE};font-family:system-ui,sans-serif`;
  for (let i = 0; i < CURVES.length; i++) {
    const curve = CURVES[i]!;
    const option = document.createElement("option");
    option.value = curve;
    option.textContent = curve;
    if (curve === selectedCurve) option.selected = true;
    curveSelect.append(option);
  }
  curveSelect.addEventListener("change", () => {
    selectedCurve = asCurve(curveSelect.value);
  });
  curveLabel.append(curveSpan, curveSelect);

  const actions = document.createElement("div");
  actions.style.cssText = "display:flex;flex-wrap:wrap;gap:8px;margin:8px 0";

  const generate = document.createElement("button");
  generate.type = "button";
  generate.id = "globe-ecdhe-generate";
  generate.textContent = "Generate";
  generate.style.cssText = BUTTON_STYLE;
  generate.addEventListener("click", () => {
    generate.disabled = true;
    void generateEcdheKeyPair(selectedCurve)
      .catch((error: unknown) => {
        setDeriveStatus(
          status,
          "error",
          error instanceof Error ? error.message : "ECDHE generate failed",
        );
      })
      .finally(() => {
        generate.disabled = false;
      });
  });

  const checks = document.createElement("button");
  checks.type = "button";
  checks.id = "globe-ecdhe-run-checks";
  checks.textContent = "Run derivation checks";
  checks.style.cssText = BUTTON_STYLE;

  const checkList = document.createElement("div");
  checkList.id = "globe-ecdhe-checks";
  checkList.style.cssText = "margin:8px 0;font-size:12px;line-height:1.45;color:#d7dcff";
  checks.addEventListener("click", () => {
    checks.disabled = true;
    checkList.id = "globe-ecdhe-checks";
    checkList.textContent = "Running derivation checks…";
    void runEcdheSecurityChecks(selectedCurve)
      .then((results) => {
        checkList.textContent = "";
        for (let i = 0; i < results.length; i++) {
          const row = document.createElement("div");
          const item = results[i]!;
          row.textContent = `${item.pass ? "pass" : "fail"} · ${item.label}`;
          checkList.append(row);
        }
        checkList.id = results.every((item) => item.pass)
          ? "globe-ecdhe-checks-pass"
          : "globe-ecdhe-checks-fail";
      })
      .catch((error: unknown) => {
        checkList.id = "globe-ecdhe-checks-fail";
        checkList.textContent = error instanceof Error ? error.message : "Checks failed";
      })
      .finally(() => {
        checks.disabled = false;
      });
  });

  const importLabel = document.createElement("label");
  importLabel.style.cssText = "display:flex;flex-direction:column;gap:6px;margin:8px 0";
  const importSpan = document.createElement("span");
  importSpan.textContent = "Import ECDHE .asc or private JWK";
  importSpan.style.cssText = "font-size:12px;color:#d7dcff";
  const importFile = document.createElement("input");
  importFile.type = "file";
  importFile.id = "globe-ecdhe-import-file";
  importFile.accept = "*/*";
  importFile.style.cssText = "font-size:16px;min-height:44px";
  const importText = document.createElement("textarea");
  importText.id = "globe-ecdhe-import-text";
  importText.rows = 3;
  importText.spellcheck = false;
  importText.autocomplete = "off";
  importText.placeholder = "Paste PKCS#8 or a private JWK";
  importText.style.cssText = AREA_STYLE;
  const importButton = document.createElement("button");
  importButton.type = "button";
  importButton.id = "globe-ecdhe-import";
  importButton.textContent = "Import into lab";
  importButton.style.cssText = BUTTON_STYLE;
  const inspectImport = document.createElement("button");
  inspectImport.type = "button";
  inspectImport.id = "globe-ecdhe-inspect-import";
  inspectImport.textContent = "Inspect import";
  inspectImport.style.cssText = BUTTON_STYLE;
  bindKeyField(importText);
  importLabel.append(importSpan, importFile, importText, importButton, inspectImport);

  const importNote = document.createElement("p");
  importNote.id = "globe-ecdhe-import-note";
  importNote.hidden = true;
  importNote.setAttribute("role", "status");
  importNote.style.cssText = "margin:0 0 8px;font-size:12px;color:#ffb4b4";
  const fieldCheck = document.createElement("p");
  fieldCheck.id = "globe-ecdhe-field-check";
  fieldCheck.hidden = true;
  fieldCheck.setAttribute("role", "status");
  fieldCheck.style.cssText = "margin:0 0 8px;font-size:12px;color:#d7dcff";
  inspectImport.addEventListener("click", () => {
    fieldCheck.hidden = false;
    fieldCheck.textContent = describeKeyMaterial(importText.value);
  });

  async function importMaterial(raw: string): Promise<void> {
    importNote.hidden = true;
    const clean = sanitizeKeyMaterial(raw);
    if (clean.kind === "openpgp-private") {
      importNote.hidden = false;
      importNote.textContent = "That .asc is an OpenPGP login key. Import it on the sign-in screen.";
      return;
    }
    if (clean.kind !== "pkcs8" && clean.kind !== "private-jwk") {
      importNote.hidden = false;
      importNote.textContent =
        clean.kind === "rejected"
          ? clean.reason
          : "The lab needs an ECDHE private key, not a public key.";
      return;
    }
    const loaded = await loadEcdhePrivateMaterial(
      clean.kind === "pkcs8" ? clean.pem : clean.json,
      selectedCurve,
    );
    showPanel(
      {
        curve: loaded.curve,
        privateKeyPkcs8Pem: loaded.pem,
        privateKeyJwk: loaded.privateJwk,
        publicKeyJwk: loaded.publicJwk,
        publicKeySpkiB64: loaded.publicSpkiB64,
      },
      false,
    );
  }

  importButton.addEventListener("click", () => {
    void importMaterial(importText.value).catch((error: unknown) => {
      importNote.hidden = false;
      importNote.textContent = error instanceof Error ? error.message : "Could not import that key.";
    });
  });
  importFile.addEventListener("change", () => {
    const file = importFile.files?.[0];
    if (!file) return;
    if (file.size > 512_000) {
      importNote.hidden = false;
      importNote.textContent = "Key material is too large.";
      importFile.value = "";
      return;
    }
    void file.text().then((text) => importMaterial(text)).catch((error: unknown) => {
      importNote.hidden = false;
      importNote.textContent = error instanceof Error ? error.message : "Could not read that file.";
    }).finally(() => {
      importFile.value = "";
    });
  });

  actions.append(generate, checks);
  root.append(title, hint, curveLabel, actions, checkList, importLabel, importNote, fieldCheck);

  const ascNote = document.createElement("p");
  ascNote.id = "globe-ecdhe-asc-note";
  ascNote.hidden = true;
  ascNote.setAttribute("role", "status");
  ascNote.style.cssText = "margin:0 0 8px;font-size:12px;color:#d7dcff";

  const derive = document.createElement("button");
  derive.type = "button";
  derive.id = "globe-ecdhe-derive";
  derive.textContent = "Derive with peer public key";
  derive.style.cssText = BUTTON_STYLE;
  const status = document.createElement("p");
  status.id = "globe-ecdhe-derive-status";
  status.hidden = true;
  status.setAttribute("role", "status");
  status.style.cssText =
    "min-height:1.2em;margin:8px 0;font:12px/1.4 ui-monospace,monospace;color:#d7dcff;word-break:break-all";
  const close = document.createElement("button");
  close.type = "button";
  close.textContent = "Close lab";
  close.style.cssText = BUTTON_STYLE;
  close.addEventListener("click", hidePanel);

  if (detail?.privateKeyPkcs8Pem && detail.privateKeyJwk?.d) {
    const downloadButton = document.createElement("button");
    downloadButton.type = "button";
    downloadButton.id = "globe-ecdhe-download-asc";
    downloadButton.textContent = "Download .asc";
    downloadButton.style.cssText = BUTTON_STYLE;
    downloadButton.addEventListener("click", () => saveAsc(detail, ascNote));
    derive.addEventListener("click", () => {
      void runDerive(detail, status, derive);
    });
    root.append(downloadButton, ascNote);
    root.append(
      field("Private key (PKCS#8 PEM)", detail.privateKeyPkcs8Pem),
      field("Private key (JWK, includes d)", JSON.stringify(detail.privateKeyJwk, null, 2)),
    );
    if (detail.privateKeyRawB64) {
      root.append(field("Private key (raw base64)", detail.privateKeyRawB64));
    }
    if (detail.publicKeySpkiB64) {
      root.append(field("Your public key (SPKI base64)", detail.publicKeySpkiB64, "globe-ecdhe-public-spki"));
    }
    if (detail.publicKeyJwk) {
      root.append(field("Your public key (JWK)", JSON.stringify(detail.publicKeyJwk)));
    }
    const peer = peerField();
    const inspectPeer = document.createElement("button");
    inspectPeer.type = "button";
    inspectPeer.id = "globe-ecdhe-inspect-peer";
    inspectPeer.textContent = "Inspect peer";
    inspectPeer.style.cssText = BUTTON_STYLE;
    inspectPeer.addEventListener("click", () => {
      const peerArea = peer.querySelector("textarea");
      fieldCheck.hidden = false;
      fieldCheck.textContent = describeKeyMaterial(
        peerArea instanceof HTMLTextAreaElement ? peerArea.value : "",
      );
    });
    root.append(peer, inspectPeer, derive, status);
  } else {
    const waiting = document.createElement("p");
    waiting.style.cssText = "margin:8px 0;font-size:13px;color:#c9c6ea";
    waiting.textContent = "Generate a pair or import an ECDHE private key to derive.";
    root.append(waiting);
  }
  root.append(close);
  document.body.append(root);
  if (autoDownload && detail?.privateKeyPkcs8Pem && detail.privateKeyJwk?.d) {
    saveAsc(detail, ascNote);
  }
}

function onExport(event: Event): void {
  const detail = (event as CustomEvent<EcdheExportDetail>).detail;
  if (!detail?.privateKeyPkcs8Pem || !detail.privateKeyJwk?.d) return;
  showPanel(detail, true);
  applyCopy();
}

function onImport(event: Event): void {
  const material = (event as CustomEvent<{ material?: string }>).detail?.material;
  if (!material) return;
  showPanel(null, false);
  const note = panel?.querySelector("#globe-ecdhe-import-note");
  const clean = sanitizeKeyMaterial(material);
  if (clean.kind !== "pkcs8" && clean.kind !== "private-jwk") {
    if (note instanceof HTMLElement) {
      note.hidden = false;
      note.textContent = "That file is not an ECDHE private key.";
    }
    return;
  }
  void loadEcdhePrivateMaterial(clean.kind === "pkcs8" ? clean.pem : clean.json, selectedCurve)
    .then((loaded) => {
      showPanel(
        {
          curve: loaded.curve,
          privateKeyPkcs8Pem: loaded.pem,
          privateKeyJwk: loaded.privateJwk,
          publicKeyJwk: loaded.publicJwk,
          publicKeySpkiB64: loaded.publicSpkiB64,
        },
        false,
      );
    })
    .catch((error: unknown) => {
      const current = panel?.querySelector("#globe-ecdhe-import-note");
      if (current instanceof HTMLElement) {
        current.hidden = false;
        current.textContent = error instanceof Error ? error.message : "Could not import that key.";
      }
    });
}

window.addEventListener("globe-ecdhe-export", onExport);
window.addEventListener("globe-ecdhe-import", onImport);

let modalCopyWatch: MutationObserver | null = null;

function watchAuthCopy(): void {
  const modal = document.querySelector(".auth-modal");
  if (!(modal instanceof HTMLElement)) {
    modalCopyWatch?.disconnect();
    modalCopyWatch = null;
    return;
  }
  if (modal.dataset.globeCopyWatch === "1") return;
  modal.dataset.globeCopyWatch = "1";
  modalCopyWatch?.disconnect();
  modalCopyWatch = new MutationObserver(() => applyCopy());
  modalCopyWatch.observe(modal, { subtree: true, childList: true, characterData: true });
  applyCopy();
}

const shellObserver = new MutationObserver(() => watchAuthCopy());
shellObserver.observe(document.documentElement, { subtree: true, childList: true });
watchAuthCopy();
mountLauncher();
