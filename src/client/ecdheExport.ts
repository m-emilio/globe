/**
 * Shows the extractable ECDHE private key outside the React tree.
 * The sign-in bundle still has the older "non-extractable" sentence;
 * this script replaces that sentence and renders PKCS#8 / JWK here.
 * Derive uses that copied private key plus a pasted peer public key.
 */

import {
  deriveEcdheFromPrivateMaterial,
  type EcdheCurveId,
} from "./ecdhe";

type EcdheExportDetail = {
  curve: string;
  privateKeyPkcs8Pem: string;
  privateKeyJwk: JsonWebKey;
  privateKeyRawB64?: string;
};

const CURVES: readonly EcdheCurveId[] = ["P-256", "P-384", "P-521", "X25519"];

function asCurve(value: string): EcdheCurveId {
  if ((CURVES as readonly string[]).includes(value)) return value as EcdheCurveId;
  throw new Error(`Unsupported ECDHE curve: ${value}`);
}

const OLD_READY =
  "Private key is non-extractable in memory only (not for OpenPGP login).";
const NEW_READY =
  "Private key is extractable (PKCS#8 and JWK in the export panel). This is not an OpenPGP login key.";
const OLD_HINT =
  "private material stays non-extractable in memory and is never uploaded";
const NEW_HINT =
  "the private key is extractable in this lab and is shown in the export panel. It is not uploaded";

function applyCopy(): void {
  const nodes = document.querySelectorAll(".auth-inline-ok, .auth-field-hint");
  for (let i = 0; i < nodes.length; i++) {
    const node = nodes[i]!;
    const text = node.textContent ?? "";
    if (text.includes(OLD_READY)) node.textContent = text.replace(OLD_READY, NEW_READY);
    if (text.includes(OLD_HINT)) node.textContent = text.replace(OLD_HINT, NEW_HINT);
    if (text.includes("Cleared ephemeral material.")) hidePanel();
  }
}

let panel: HTMLElement | null = null;

function hidePanel(): void {
  panel?.remove();
  panel = null;
}

const AREA_STYLE = [
  "width:100%",
  "box-sizing:border-box",
  "font:11px/1.35 ui-monospace,monospace",
  "color:#eef0ff",
  "background:#12141f",
  "border:1px solid rgba(160,150,255,0.35)",
  "border-radius:6px",
  "padding:8px",
].join(";");

function field(label: string, value: string): HTMLLabelElement {
  const wrap = document.createElement("label");
  wrap.style.cssText = "display:flex;flex-direction:column;gap:6px;margin:10px 0";
  const span = document.createElement("span");
  span.textContent = label;
  span.style.cssText = "font-size:12px;color:#d7dcff";
  const area = document.createElement("textarea");
  area.readOnly = true;
  area.rows = 4;
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
  span.textContent = "Peer public key for this export (JWK or SPKI base64)";
  span.style.cssText = "font-size:12px;color:#d7dcff";
  const area = document.createElement("textarea");
  area.id = "globe-ecdhe-peer";
  area.rows = 3;
  area.spellcheck = false;
  area.placeholder = "Paste peer SPKI base64 or JWK JSON";
  area.autocomplete = "off";
  area.style.cssText = AREA_STYLE;
  wrap.append(span, area);
  return wrap;
}

const BUTTON_STYLE = [
  "padding:8px 12px",
  "border-radius:8px",
  "border:1px solid rgba(160,150,255,0.45)",
  "background:#2a2650",
  "color:#eef0ff",
  "cursor:pointer",
  "font:600 13px/1.2 system-ui,sans-serif",
].join(";");

async function runDerive(
  detail: EcdheExportDetail,
  status: HTMLElement,
  button: HTMLButtonElement,
): Promise<void> {
  const peerEl = panel?.querySelector("#globe-ecdhe-peer");
  if (!(peerEl instanceof HTMLTextAreaElement)) return;
  button.disabled = true;
  status.textContent = "Deriving…";
  try {
    const curve = asCurve(detail.curve);
    const peer = peerEl.value;
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
    status.textContent = `Shared secret fingerprint (SHA-256): ${fromPem.sharedSecretSha256Hex}. AES-GCM session key stays non-extractable.`;
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : "ECDHE derive failed";
  } finally {
    button.disabled = false;
  }
}

function showPanel(detail: EcdheExportDetail): void {
  hidePanel();
  const root = document.createElement("section");
  panel = root;
  root.id = "globe-ecdhe-export";
  root.style.cssText = [
    "position:fixed",
    "left:max(12px, env(safe-area-inset-left))",
    "bottom:max(12px, env(safe-area-inset-bottom))",
    "z-index:10001",
    "width:min(420px, calc(100vw - 24px))",
    "max-height:min(78vh, 720px)",
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
  title.textContent = `Extractable ${detail.curve} private key`;
  title.style.cssText = "margin:0 0 6px;font-size:16px";
  const hint = document.createElement("p");
  hint.textContent =
    "Ephemeral ECDHE only. This is not an OpenPGP login key and it is not uploaded. Copy PKCS#8 or the private JWK, then derive with the peer public key.";
  hint.style.cssText = "margin:0 0 8px;color:#c9c6ea;font-size:13px";

  const derive = document.createElement("button");
  derive.type = "button";
  derive.id = "globe-ecdhe-derive";
  derive.textContent = "Derive with peer public key";
  derive.style.cssText = BUTTON_STYLE;

  const status = document.createElement("p");
  status.id = "globe-ecdhe-derive-status";
  status.setAttribute("role", "status");
  status.style.cssText =
    "min-height:1.2em;margin:8px 0;font:12px/1.4 ui-monospace,monospace;color:#d7dcff;word-break:break-all";

  const close = document.createElement("button");
  close.type = "button";
  close.textContent = "Hide private key";
  close.style.cssText = BUTTON_STYLE;
  close.addEventListener("click", hidePanel);
  derive.addEventListener("click", () => {
    void runDerive(detail, status, derive);
  });

  root.append(
    title,
    hint,
    field("Private key (PKCS#8 PEM)", detail.privateKeyPkcs8Pem),
    field("Private key (JWK, includes d)", JSON.stringify(detail.privateKeyJwk, null, 2)),
  );
  if (detail.privateKeyRawB64) {
    root.append(field("Private key (raw base64)", detail.privateKeyRawB64));
  }
  root.append(peerField(), derive, status, close);
  document.body.append(root);
}

function onExport(event: Event): void {
  const detail = (event as CustomEvent<EcdheExportDetail>).detail;
  if (!detail?.privateKeyPkcs8Pem || !detail.privateKeyJwk?.d) return;
  showPanel(detail);
  applyCopy();
}

window.addEventListener("globe-ecdhe-export", onExport);
const observer = new MutationObserver(() => applyCopy());
observer.observe(document.documentElement, {
  subtree: true,
  childList: true,
  characterData: true,
});
applyCopy();
