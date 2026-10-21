/**
 * OpenPGP import on the sign-in screen.
 * Desktop lists .asc, .pgp, and .gpg. iOS also allows public.data, because
 * an extension-only list is treated as text/plain and the .asc stays disabled.
 * The file name and the armor both have to be an OpenPGP private key.
 * An ECDHE .pem stays in the key lab.
 */

import {
  acceptLoginPaste,
  appleTouchPicker,
  KEY_MATERIAL_MAX_CHARS,
  LAB_FILE_ACCEPT,
  LOGIN_FILE_ACCEPT,
  pickerAccept,
  readLoginKeyFile,
} from "./keyMaterial";

const FILE_STYLE = [
  "display:block",
  "width:100%",
  "min-height:48px",
  "font-size:16px",
  "padding:8px 0",
].join(";");

function rejectNote(panel: HTMLElement, message: string): void {
  const existing = panel.querySelector("#globe-asc-rejected");
  const note = existing instanceof HTMLElement ? existing : document.createElement("p");
  if (!(existing instanceof HTMLElement)) {
    note.id = "globe-asc-rejected";
    note.setAttribute("role", "status");
    note.style.cssText = "margin:8px 0 0;font-size:13px;color:#ffb4b4";
    panel.append(note);
  }
  note.textContent = message;
}

function clearReject(panel: HTMLElement): void {
  panel.querySelector("#globe-asc-rejected")?.remove();
}

async function readBounded(file: File): Promise<string> {
  if (file.size > KEY_MATERIAL_MAX_CHARS) {
    throw new Error("Key material is too large.");
  }
  return file.text();
}

function passToLogin(input: HTMLInputElement, armored: string): void {
  const next = new File([armored], "key.asc", { type: "application/pgp-keys" });
  const transfer = new DataTransfer();
  transfer.items.add(next);
  input.dataset.globeAscPass = "1";
  input.files = transfer.files;
  input.dispatchEvent(new Event("change", { bubbles: true }));
  input.value = "";
  delete input.dataset.globeAscPass;
}

async function acceptPaste(panel: HTMLElement, input: HTMLInputElement, raw: string): Promise<void> {
  clearReject(panel);
  const clean = acceptLoginPaste(raw);
  if (clean.kind === "mldsa87-private") {
    window.dispatchEvent(new CustomEvent("globe-mldsa87-import", { detail: clean.armored }));
    return;
  }
  if (clean.kind === "openpgp-private") {
    try {
      passToLogin(input, clean.armored);
    } catch {
      rejectNote(panel, "Could not read that file on this browser. Paste the armored key instead.");
    }
    return;
  }
  rejectNote(panel, clean.kind === "rejected" ? clean.reason : "Sign-in needs an OpenPGP private key (.asc, .pgp, or .gpg).");
  input.value = "";
}

function acceptLoginFiles(input: HTMLInputElement): void {
  input.accept = pickerAccept(LOGIN_FILE_ACCEPT, appleTouchPicker());
}

function bindInput(panel: HTMLElement, input: HTMLInputElement): void {
  acceptLoginFiles(input);
  input.style.cssText = FILE_STYLE;
  if (input.dataset.globeKeyFile === "1") return;
  input.dataset.globeKeyFile = "1";
  input.addEventListener(
    "change",
    (event) => {
      if (input.dataset.globeAscPass === "1") return;
      event.stopPropagation();
      const file = input.files?.[0];
      if (!file) return;
      void readBounded(file)
        .then((text) => {
          clearReject(panel);
          const clean = readLoginKeyFile({ name: file.name, type: file.type, text });
          if (clean.kind === "mldsa87-private") {
            window.dispatchEvent(new CustomEvent("globe-mldsa87-import", { detail: clean.armored }));
            input.value = "";
            return;
          }
          if (clean.kind === "openpgp-private") {
            passToLogin(input, clean.armored);
            return;
          }
          rejectNote(
            panel,
            clean.kind === "rejected"
              ? clean.reason
              : "Sign-in needs an OpenPGP private key (.asc, .pgp, or .gpg).",
          );
          input.value = "";
        })
        .catch((error: unknown) => {
          rejectNote(
            panel,
            error instanceof Error ? error.message : "Could not read that file.",
          );
          input.value = "";
        });
    },
    true,
  );
}

function ensurePaste(panel: HTMLElement, input: HTMLInputElement): void {
  if (panel.querySelector("#globe-asc-paste")) return;
  const wrap = document.createElement("label");
  wrap.style.cssText = "display:flex;flex-direction:column;gap:6px;margin-top:10px";
  const span = document.createElement("span");
  span.textContent = "Or paste the OpenPGP key";
  span.style.cssText = "font-size:13px";
  const area = document.createElement("textarea");
  area.id = "globe-asc-paste";
  area.rows = 4;
  area.spellcheck = false;
  area.autocomplete = "off";
  area.placeholder = "Paste an OpenPGP private key";
  area.maxLength = KEY_MATERIAL_MAX_CHARS;
  area.addEventListener("input", () => {
    if (!area.value.includes("\0")) return;
    area.value = area.value.replace(/\0/g, "");
  });
  area.style.cssText = [
    "width:100%",
    "box-sizing:border-box",
    "min-height:96px",
    "font:16px/1.35 ui-monospace,monospace",
    "padding:8px",
  ].join(";");
  const button = document.createElement("button");
  button.type = "button";
  button.id = "globe-asc-choose";
  button.textContent = "Import pasted key";
  button.style.cssText = [
    "margin-top:8px",
    "min-height:48px",
    "width:100%",
    "font:600 16px/1.2 system-ui,sans-serif",
    "border-radius:10px",
    "border:1px solid rgba(0,255,136,0.45)",
    "background:#10281c",
    "color:#e8fff2",
  ].join(";");
  button.addEventListener("click", () => {
    void acceptPaste(panel, input, area.value).finally(() => {
      area.value = "";
    });
  });
  const hint = document.createElement("p");
  hint.style.cssText = "margin:8px 0 0;font-size:13px;line-height:1.4";
  hint.textContent =
    "Paste an OpenPGP or ML-DSA-87 private key. It stays on this device and is not uploaded.";
  wrap.append(span, area, button, hint);
  panel.append(wrap);
}

function patchPasswords(): void {
  const modal = document.querySelector(".auth-modal:not(.admin-modal)");
  if (!(modal instanceof HTMLElement)) return;
  const nodes = modal.querySelectorAll('input[type="password"]');
  for (let i = 0; i < nodes.length; i++) {
    const node = nodes[i];
    if (!(node instanceof HTMLInputElement)) continue;
    node.maxLength = 1024;
    node.autocomplete = "off";
  }
}

let patchingLogin = false;

function patchLoginImport(): void {
  if (patchingLogin) return;
  const modal = document.querySelector(".auth-modal:not(.admin-modal)");
  if (!(modal instanceof HTMLElement)) return;
  patchingLogin = true;
  loginObserver.disconnect();
  try {
    patchPasswords();
    const panels = modal.querySelectorAll(".auth-export-panel");
    for (let i = 0; i < panels.length; i++) {
      const panel = panels[i];
      if (!(panel instanceof HTMLElement)) continue;
      const input = panel.querySelector('input[type="file"]');
      if (!(input instanceof HTMLInputElement)) continue;
      bindInput(panel, input);
      ensurePaste(panel, input);
    }
  } finally {
    patchingLogin = false;
    loginObserver.observe(document.documentElement, { subtree: true, childList: true });
  }
}

function openFilePicker(event: Event): void {
  const target = event.target;
  if (!(target instanceof HTMLInputElement) || target.type !== "file") return;
  if (target.dataset.globeKeyFile === "1") {
    acceptLoginFiles(target);
    return;
  }
  if (target.id === "globe-ecdhe-import-file") {
    target.accept = pickerAccept(LAB_FILE_ACCEPT, appleTouchPicker());
  }
}

function stripPassphraseNulls(event: Event): void {
  const target = event.target;
  if (!(target instanceof HTMLInputElement) || target.type !== "password") return;
  if (!target.closest(".auth-modal")) return;
  if (!target.value.includes("\0")) return;
  const next = target.value.replace(/\0/g, "").slice(0, 1024);
  if (next !== target.value) target.value = next;
}

document.addEventListener("input", stripPassphraseNulls, true);
document.addEventListener("pointerdown", openFilePicker, true);
document.addEventListener("click", openFilePicker, true);
const loginObserver = new MutationObserver(() => patchLoginImport());
loginObserver.observe(document.documentElement, { subtree: true, childList: true });
patchLoginImport();
