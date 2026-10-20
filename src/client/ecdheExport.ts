/**
 * Shows the extractable ECDHE private key outside the React tree.
 * The sign-in bundle still has the older "non-extractable" sentence;
 * this script replaces that sentence and renders PKCS#8 / JWK here.
 */

type EcdheExportDetail = {
  curve: string;
  privateKeyPkcs8Pem: string;
  privateKeyJwk: JsonWebKey;
  privateKeyRawB64?: string;
};

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
  area.style.cssText = [
    "width:100%",
    "box-sizing:border-box",
    "font:11px/1.35 ui-monospace,monospace",
    "color:#eef0ff",
    "background:#12141f",
    "border:1px solid rgba(160,150,255,0.35)",
    "border-radius:6px",
    "padding:8px",
  ].join(";");
  area.addEventListener("focus", () => area.select());
  wrap.append(span, area);
  return wrap;
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
    "max-height:min(70vh, 560px)",
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

  const close = document.createElement("button");
  close.type = "button";
  close.textContent = "Hide private key";
  close.style.cssText = [
    "padding:8px 12px",
    "border-radius:8px",
    "border:1px solid rgba(160,150,255,0.45)",
    "background:#2a2650",
    "color:#eef0ff",
    "cursor:pointer",
    "font:600 13px/1.2 system-ui,sans-serif",
  ].join(";");
  close.addEventListener("click", hidePanel);

  root.append(
    title,
    hint,
    field("Private key (PKCS#8 PEM)", detail.privateKeyPkcs8Pem),
    field("Private key (JWK, includes d)", JSON.stringify(detail.privateKeyJwk, null, 2)),
  );
  if (detail.privateKeyRawB64) {
    root.append(field("Private key (raw base64)", detail.privateKeyRawB64));
  }
  root.append(close);
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
