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
  title.textContent = "Sign in";
  title.style.cssText = "margin:0 0 6px;font-size:16px";
  const copy = document.createElement("p");
  copy.style.cssText = "margin:0 0 10px;font-size:13px;line-height:1.45;color:#d5ffe9";
  copy.textContent = "Device key, post-quantum signature, and post-quantum key agreement are one sign-in. Each one proves this device holds the private key. The server stores the public key and, after the proof matches, sets the same session cookie. The private key is not uploaded. One network can register 3 keys, then it has to sign in with a key it already created.";
  const label = document.createElement("label");
  label.style.cssText = "display:flex;flex-direction:column;gap:6px;font-size:13px";
  const span = document.createElement("span");
  span.textContent = "Sign-in method";
  const select = document.createElement("select");
  select.id = "globe-sign-in-method";
  select.style.cssText = "min-height:48px;font-size:16px;padding:8px";
  const options: Array<[Method, string]> = [
    ["device", "Device key"],
    ["pqc", "Post-quantum signature"],
    ["agreement", "Post-quantum key agreement"],
    ["ecdhe", "ECDHE key agreement"],
  ];
  for (let i = 0; i < options.length; i++) {
    const option = document.createElement("option");
    option.value = options[i]![0];
    option.textContent = options[i]![1];
    select.append(option);
  }
  label.append(span, select);
  shell.append(title, copy, label);
  select.addEventListener("change", () => {
    const modal = shell.closest(".auth-modal");
    if (modal instanceof HTMLElement && isMethod(select.value)) applyMethod(modal, select.value);
  });
  return shell;
}

export function mountUnifiedSignIn(): void {
  const modal = document.querySelector(".auth-modal:not(.admin-modal)");
  if (!(modal instanceof HTMLElement)) return;
  let shell = modal.querySelector("#globe-sign-in");
  if (!(shell instanceof HTMLElement)) {
    shell = buildShell();
    const header = modal.querySelector(".auth-modal-header");
    if (header) header.insertAdjacentElement("afterend", shell);
    else modal.prepend(shell);
  }
  const select = shell.querySelector("#globe-sign-in-method");
  const method = select instanceof HTMLSelectElement && isMethod(select.value) ? select.value : "device";
  applyMethod(modal, method);
}
