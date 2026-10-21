/**
 * One sign-in for the device key, the post-quantum signature, and key agreement.
 * The private key stays on the device in every method. The server issues one session.
 */

type Method = "device" | "pqc" | "agreement" | "ecdhe";

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
  "min-height:44px;padding:8px 12px;border-radius:10px;border:1px solid rgba(61,255,168,0.45);background:#16382c;color:#e7fff3;font:600 15px/1.2 system-ui,sans-serif";

function choose(shell: HTMLElement, method: Method): void {
  const buttons = shell.querySelectorAll<HTMLButtonElement>("[data-sign-method]");
  for (let i = 0; i < buttons.length; i++) {
    const button = buttons[i]!;
    const on = button.dataset.signMethod === method;
    button.setAttribute("aria-pressed", on ? "true" : "false");
    button.style.outline = on ? "2px solid #3dffa8" : "none";
  }
  shell.dataset.method = method;
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
  const title = document.createElement("h2");
  title.id = "globe-sign-in-title";
  title.textContent = "Sign in";
  title.style.cssText = "margin:0 0 6px;font-size:18px";
  const copy = document.createElement("p");
  copy.style.cssText = "margin:0 0 10px;font-size:14px;line-height:1.4;color:#d5ffe9";
  copy.textContent = "The private key stays on this device. Sign-in sends a proof, then you get one session.";

  const row = document.createElement("div");
  row.id = "globe-sign-in-methods";
  row.setAttribute("role", "group");
  row.setAttribute("aria-label", "Sign-in method");
  row.style.cssText = "display:flex;flex-wrap:wrap;gap:8px";
  const choices: Array<[Method, string]> = [
    ["device", "This device"],
    ["pqc", "Post-quantum"],
    ["agreement", "Key agreement"],
  ];
  for (let i = 0; i < choices.length; i++) {
    const button = methodButton(choices[i]![0], choices[i]![1]);
    button.addEventListener("click", () => choose(shell, choices[i]![0]));
    row.append(button);
  }

  const more = document.createElement("details");
  more.style.cssText = "margin-top:8px";
  const summary = document.createElement("summary");
  summary.textContent = "Other ways";
  summary.style.cssText = "cursor:pointer;font-size:13px;color:#d5ffe9";
  const ecdhe = methodButton("ecdhe", "ECDHE key lab");
  ecdhe.style.marginTop = "8px";
  ecdhe.addEventListener("click", () => choose(shell, "ecdhe"));
  more.append(summary, ecdhe);

  const note = document.createElement("p");
  note.style.cssText = "margin:10px 0 0;font-size:12px;line-height:1.4;color:#b7ebcf";
  note.textContent = "A network can register 3 keys. A paid checkout under $20 can unlock more.";

  shell.append(title, copy, row, more, note);
  choose(shell, "device");
  return shell;
}

export function mountUnifiedSignIn(): void {
  const modal = document.querySelector(".auth-modal:not(.admin-modal)");
  if (!(modal instanceof HTMLElement)) return;
  let shell = modal.querySelector("#globe-sign-in");
  if (!(shell instanceof HTMLElement) || !shell.querySelector("#globe-sign-in-methods")) {
    const next = buildShell();
    if (shell instanceof HTMLElement) shell.replaceWith(next);
    else {
      const header = modal.querySelector(".auth-modal-header");
      if (header) header.insertAdjacentElement("afterend", next);
      else modal.prepend(next);
    }
    shell = next;
  }
  const method = shell.dataset.method;
  applyMethod(modal, isMethod(method || "") ? (method as Method) : "device");
}
