/**
 * One identity banner for the device key, post-quantum sign-in, and both labs.
 * The private key stays on the device in every method. The server issues one session.
 */

type Method = "device" | "pqc" | "agreement" | "ecdhe";

const METHODS: ReadonlyArray<readonly [Method, string, string]> = [
  ["device", "Device key", "OpenPGP key on this device. Create one if you are new, or sign in."],
  ["pqc", "Post-quantum", "ML-DSA or SLH-DSA. Create the key here, then sign in. It is not uploaded."],
  ["agreement", "Key agreement", "Post-quantum lab. Sign-in sends a proof. The secret stays here."],
  ["ecdhe", "ECDHE", "Elliptic-curve lab. The private key stays in this browser."],
];

const TIGHT_STYLE = [
  ".auth-modal:not(.admin-modal) > .auth-modal-copy,",
  ".auth-modal:not(.admin-modal) > .auth-mobile-hint,",
  ".auth-modal:not(.admin-modal) .auth-compliance-list,",
  ".auth-modal:not(.admin-modal) .auth-safety-card > .auth-field-hint { display: none !important; }",
  ".auth-modal:not(.admin-modal) .auth-safety-card { margin: 0 0 10px; padding: 8px 10px; }",
  ".auth-modal:not(.admin-modal) .auth-safety-desc { margin: 4px 0 0; font-size: 13px; line-height: 1.35; }",
  ".auth-modal:not(.admin-modal) .auth-field-hint { font-size: 13px; line-height: 1.35; }",
  "#globe-sign-in-methods { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }",
  "#globe-sign-in-methods button { width: 100%; }",
].join("");

function isMethod(value: string): value is Method {
  return value === "device" || value === "pqc" || value === "agreement" || value === "ecdhe";
}

function deviceNodes(modal: HTMLElement): HTMLElement[] {
  const nodes: HTMLElement[] = [];
  const children = modal.children;
  for (let i = 0; i < children.length; i++) {
    const child = children[i];
    if (!(child instanceof HTMLElement)) continue;
    if (child.classList.contains("auth-modal-header")) continue;
    if (
      child.id === "globe-sign-in" ||
      child.id === "globe-pqc-login" ||
      child.id === "globe-pqc-lab" ||
      child.id === "globe-pqc-open" ||
      child.id === "globe-ecdhe-export" ||
      child.id === "globe-key-lab-open"
    ) {
      continue;
    }
    nodes.push(child);
  }
  return nodes;
}

function show(node: Element | null, visible: boolean): void {
  if (node instanceof HTMLElement) node.hidden = !visible;
}

function applyMethod(modal: HTMLElement, method: Method): void {
  const device = deviceNodes(modal);
  for (let i = 0; i < device.length; i++) device[i]!.hidden = method !== "device";
  show(modal.querySelector("#globe-pqc-login"), method === "pqc");
  show(modal.querySelector("#globe-pqc-lab"), method === "agreement");
  show(modal.querySelector("#globe-pqc-open"), method === "agreement");
  show(modal.querySelector("#globe-ecdhe-export"), method === "ecdhe");
  show(modal.querySelector("#globe-key-lab-open"), method === "ecdhe");
}

const METHOD_BUTTON =
  "min-height:44px;padding:8px 10px;border-radius:10px;border:1px solid rgba(61,255,168,0.45);background:#16382c;color:#e7fff3;font:600 14px/1.2 system-ui,sans-serif";

function captionFor(method: Method): string {
  for (let i = 0; i < METHODS.length; i++) {
    if (METHODS[i]![0] === method) return METHODS[i]![2];
  }
  return METHODS[0]![2];
}

function ensureTightStyle(): void {
  if (document.getElementById("globe-identity-style")) return;
  const style = document.createElement("style");
  style.id = "globe-identity-style";
  style.textContent = TIGHT_STYLE;
  document.head.append(style);
}

function tighten(modal: HTMLElement): void {
  modal.setAttribute("aria-label", "Identity");
  const title = modal.querySelector(".auth-modal-header strong");
  if (title && title.textContent !== "Identity") title.textContent = "Identity";
  const buttons = modal.querySelectorAll("button");
  for (let i = 0; i < buttons.length; i++) {
    const button = buttons[i]!;
    if (button.textContent === "New here? Create device identity") {
      button.textContent = "New here? Create identity";
    }
  }
}

function choose(shell: HTMLElement, method: Method): void {
  const buttons = shell.querySelectorAll<HTMLButtonElement>("[data-sign-method]");
  for (let i = 0; i < buttons.length; i++) {
    const button = buttons[i]!;
    const on = button.dataset.signMethod === method;
    button.setAttribute("aria-pressed", on ? "true" : "false");
    button.style.outline = on ? "2px solid #3dffa8" : "none";
  }
  shell.dataset.method = method;
  const caption = shell.querySelector("#globe-sign-in-caption");
  if (caption) caption.textContent = captionFor(method);
  const modal = shell.closest(".auth-modal");
  if (modal instanceof HTMLElement) applyMethod(modal, method);
}

function methodButton(method: Method, label: string): HTMLButtonElement {
  const button = document.createElement("button");
  button.type = "button";
  button.dataset.signMethod = method;
  button.textContent = label;
  button.style.cssText = METHOD_BUTTON;
  return button;
}

function buildShell(): HTMLElement {
  const shell = document.createElement("section");
  shell.id = "globe-sign-in";
  shell.style.cssText = [
    "margin:0 0 14px",
    "padding:12px",
    "border:1px solid rgba(61,255,168,0.45)",
    "border-radius:12px",
    "background:#102820",
    "color:#e7fff3",
  ].join(";");
  const copy = document.createElement("p");
  copy.id = "globe-sign-in-caption";
  copy.style.cssText = "margin:0 0 10px;font-size:14px;line-height:1.35;color:#d5ffe9";
  copy.textContent = captionFor("device");

  const row = document.createElement("div");
  row.id = "globe-sign-in-methods";
  row.setAttribute("role", "group");
  row.setAttribute("aria-label", "Identity method");
  for (let i = 0; i < METHODS.length; i++) {
    const method = METHODS[i]![0];
    const button = methodButton(method, METHODS[i]![1]);
    button.addEventListener("click", () => choose(shell, method));
    row.append(button);
  }

  const note = document.createElement("p");
  note.style.cssText = "margin:10px 0 0;font-size:12px;line-height:1.35;color:#b7ebcf";
  note.textContent = "One session either way. A network can register 3 keys.";

  shell.append(copy, row, note);
  choose(shell, "device");
  return shell;
}

export function mountUnifiedSignIn(): void {
  ensureTightStyle();
  const modal = document.querySelector(".auth-modal:not(.admin-modal)");
  if (!(modal instanceof HTMLElement)) return;
  tighten(modal);
  let shell = modal.querySelector("#globe-sign-in");
  if (!(shell instanceof HTMLElement) || !shell.querySelector("#globe-sign-in-caption")) {
    const next = buildShell();
    if (shell instanceof HTMLElement) shell.replaceWith(next);
    else {
      const header = modal.querySelector(".auth-modal-header");
      if (header) header.insertAdjacentElement("afterend", next);
      else modal.prepend(next);
    }
    shell = next;
  }
  if (!(shell instanceof HTMLElement)) return;
  const method = shell.dataset.method ?? "";
  applyMethod(modal, isMethod(method) ? method : "device");
}
