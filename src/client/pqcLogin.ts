/**
 * ML-DSA sign-in inside the existing account modal.
 * OpenPGP file rules stay on the import panel. This block never accepts a file.
 */
import {
  ML_DSA_SUITES,
  SLH_DSA_SUITES,
  isPqcSigSuite,
  type MlDsaSuiteId,
  type PqcSigSuiteId,
  type SlhDsaSuiteId,
} from "../server/pqcVerify";
import {
  createMlDsaDeviceKey,
  deleteMlDsaDeviceKey,
  exportStoredPqcPrivateKey,
  listMlDsaDeviceKeys,
  signMlDsaLogin,
} from "./mlDsa";
import { downloadLocalPrivateFile } from "./privateKeyFile";
import { mountDeviceKeyExport } from "./deviceKeyExport";

const ML_ORDER: MlDsaSuiteId[] = ["ml-dsa65", "ml-dsa87", "ml-dsa44"];
const SLH_SHA2: SlhDsaSuiteId[] = [
  "slh-dsa-sha2-128s",
  "slh-dsa-sha2-128f",
  "slh-dsa-sha2-192s",
  "slh-dsa-sha2-192f",
  "slh-dsa-sha2-256s",
  "slh-dsa-sha2-256f",
];
const SLH_SHAKE: SlhDsaSuiteId[] = [
  "slh-dsa-shake-128s",
  "slh-dsa-shake-128f",
  "slh-dsa-shake-192s",
  "slh-dsa-shake-192f",
  "slh-dsa-shake-256s",
  "slh-dsa-shake-256f",
];

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  return node;
}

async function postJson(
  path: string,
  body: Record<string, string>,
): Promise<{ ok: boolean; status: number; code: string }> {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  let code = "";
  try {
    const data = (await response.json()) as { error?: unknown; challengeId?: unknown; message?: unknown; suite?: unknown; fingerprint?: unknown };
    if (typeof data.error === "string") code = data.error;
    if (response.ok && path.endsWith("/challenge")) {
      const challengeId = typeof data.challengeId === "string" ? data.challengeId : "";
      const message = typeof data.message === "string" ? data.message : "";
      const suite = typeof data.suite === "string" ? data.suite : "";
      const fingerprint = typeof data.fingerprint === "string" ? data.fingerprint : "";
      return { ok: true, status: response.status, code: `${challengeId}\n${suite}\n${fingerprint}\n${message}` };
    }
  } catch {
    code = "";
  }
  return { ok: response.ok, status: response.status, code };
}

function suiteLabelFor(suite: PqcSigSuiteId): string {
  if (suite in ML_DSA_SUITES) return ML_DSA_SUITES[suite as MlDsaSuiteId].label;
  return SLH_DSA_SUITES[suite as SlhDsaSuiteId].label;
}

function fixedError(code: string, status: number): string {
  if (code === "rate_limited" || status === 429) return "Too many sign-in attempts. Wait a minute and try again.";
  if (code === "private_key_rejected") return "The private key stays on this device.";
  if (code === "fingerprint_taken") return "This key is already registered. Sign in with this device.";
  if (code === "invalid_challenge") return "That sign-in challenge expired. Try again.";
  if (code === "auth_failed") return "Could not verify the ML-DSA signature.";
  if (code === "key_limit") return "This network already has 3 sign-in keys. Sign in with an existing key from this device.";
  if (code === "kv_missing") return "Sign-in storage is not available right now.";
  if (status === 0) return "Could not reach sign-in.";
  return "ML-DSA sign-in failed.";
}

function patchSessionLabel(): void {
  const nodes = document.querySelectorAll(".auth-user-meta");
  for (let i = 0; i < nodes.length; i++) {
    const block = nodes[i];
    if (!(block instanceof HTMLElement)) continue;
    const status = block.querySelector(".auth-user-meta-status");
    if (!(status instanceof HTMLElement)) continue;
    const text = status.textContent || "";
    if (!text.includes("PGP session")) continue;
    const replacement = text.includes("ML-DSA-") || text.includes("SLH-DSA-")
      ? "ML-DSA session"
      : text.includes("ECDHE-") || text.includes("KEM-")
        ? "Key lab session"
        : "";
    if (!replacement) continue;
    status.textContent = text.replace("PGP session", replacement);
    const print = block.querySelector(".auth-user-fingerprint");
    if (print instanceof HTMLElement && print.title === "Full OpenPGP fingerprint") {
      print.title = "Account fingerprint";
    }
  }
}

export function mountPqcLogin(): void {
  const modal = document.querySelector(".auth-modal:not(.admin-modal)");
  if (!(modal instanceof HTMLElement)) return;
  patchSessionLabel();
  if (modal.querySelector("#globe-pqc-login")) return;

  const root = el("section");
  root.id = "globe-pqc-login";
  root.style.cssText = [
    "margin-top:16px",
    "padding:12px",
    "border:1px solid rgba(61,255,168,0.35)",
    "border-radius:12px",
    "background:#102820",
    "color:#e7fff3",
  ].join(";");

  const title = el("h3", "Post-quantum");
  title.style.cssText = "margin:0 0 6px;font-size:15px";
  const hint = el("p", "ML-DSA-65 is the usual choice. Export downloads the private key stored in this browser.");
  hint.style.cssText = "margin:0 0 10px;font-size:13px;line-height:1.4;color:#d5ffe9";

  const suiteLabel = el("label");
  suiteLabel.style.cssText = "display:flex;flex-direction:column;gap:6px";
  suiteLabel.append(el("span", "Post-quantum suite"));
  const suiteSelect = el("select");
  suiteSelect.id = "globe-pqc-login-suite";
  suiteSelect.style.cssText = "min-height:48px;font-size:16px;padding:8px";
  const addGroup = (label: string, ids: readonly PqcSigSuiteId[]) => {
    const group = el("optgroup");
    group.label = label;
    for (let i = 0; i < ids.length; i++) {
      const id = ids[i]!;
      const row = id in ML_DSA_SUITES ? ML_DSA_SUITES[id as MlDsaSuiteId] : SLH_DSA_SUITES[id as SlhDsaSuiteId];
      const option = el("option", row.label);
      option.value = id;
      group.append(option);
    }
    suiteSelect.append(group);
  };
  addGroup("ML-DSA", ML_ORDER);
  addGroup("SLH-DSA SHA2", SLH_SHA2);
  addGroup("SLH-DSA SHAKE", SLH_SHAKE);
  suiteLabel.append(suiteSelect);

  const status = el("p", "");
  status.id = "globe-pqc-login-status";
  status.setAttribute("role", "status");
  status.style.cssText = "min-height:1.2em;margin:8px 0;font-size:13px";

  const buttonStyle = [
    "min-height:48px",
    "width:100%",
    "margin-top:8px",
    "font:600 16px/1.2 system-ui,sans-serif",
    "border-radius:10px",
    "border:1px solid rgba(61,255,168,0.45)",
    "background:#16382c",
    "color:#e7fff3",
  ].join(";");
  const create = el("button", "Create key");
  create.type = "button";
  create.id = "globe-pqc-login-create";
  create.style.cssText = buttonStyle;
  const signIn = el("button", "Sign in");
  signIn.type = "button";
  signIn.id = "globe-pqc-login-signin";
  signIn.style.cssText = buttonStyle;
  const exportKey = el("button", "Export stored private key");
  exportKey.type = "button";
  exportKey.id = "globe-pqc-login-export";
  exportKey.style.cssText = buttonStyle;
  const remove = el("button", "Remove key");
  remove.type = "button";
  remove.id = "globe-pqc-login-remove";
  remove.style.cssText = buttonStyle;

  root.append(title, hint, suiteLabel, status, create, signIn, exportKey, remove);
  modal.append(root);

  const selected = (): PqcSigSuiteId => {
    const value = suiteSelect.value;
    return isPqcSigSuite(value) ? value : "ml-dsa65";
  };
  const setStatus = (message: string, isError = false) => {
    status.textContent = message;
    status.style.color = isError ? "#ffb4b4" : "#d8ffe8";
  };
  const setBusy = (busy: boolean) => {
    create.disabled = busy;
    signIn.disabled = busy;
    exportKey.disabled = busy;
    remove.disabled = busy;
    suiteSelect.disabled = busy;
  };
  const refresh = () => {
    void listMlDsaDeviceKeys()
      .then((rows) => {
        const suite = selected();
        const label = suiteLabelFor(suite);
        create.textContent = `Create ${label}`;
        signIn.textContent = `Sign in`;
        remove.textContent = `Remove ${label}`;
        const here = rows.some((row) => row.suite === suite);
        setStatus(
          here
            ? `${label} is on this device.`
            : `No ${label} key yet. Create it, then sign in.`,
        );
      })
      .catch((error: unknown) => {
        setStatus(error instanceof Error ? error.message : "Could not read the device key.", true);
      });
  };

  const signInWith = async (suite: PqcSigSuiteId): Promise<void> => {
    const rows = await listMlDsaDeviceKeys();
    const row = rows.find((item) => item.suite === suite);
    if (!row) throw new Error(`Create a ${suiteLabelFor(suite)} key on this device first.`);
    const challenge = await postJson("/api/auth/pqc/challenge", {
      suite,
      fingerprint: row.fingerprint,
    });
    if (!challenge.ok) throw new Error(fixedError(challenge.code, challenge.status));
    const parts = challenge.code.split("\n");
    const challengeId = parts[0] || "";
    const message = parts.slice(3).join("\n");
    if (!/^[\da-f]{16,128}$/i.test(challengeId) || !message) {
      throw new Error("ML-DSA sign-in failed.");
    }
    const signed = await signMlDsaLogin(suite, message, location.origin);
    const login = await postJson("/api/auth/pqc/login", {
      suite,
      fingerprint: signed.fingerprint,
      challengeId,
      signatureB64: signed.signatureB64,
    });
    if (!login.ok) throw new Error(fixedError(login.code, login.status));
    location.reload();
  };

  suiteSelect.addEventListener("change", refresh);
  create.addEventListener("click", () => {
    const suite = selected();
    setBusy(true);
    setStatus("Creating the ML-DSA key on this device…");
    void createMlDsaDeviceKey(suite)
      .then(async (created) => {
        const registered = await postJson("/api/auth/pqc/register", {
          suite: created.suite,
          publicKeyB64: created.publicKeyB64,
        });
        if (registered.ok) {
          location.reload();
          return;
        }
        if (registered.code === "fingerprint_taken") {
          await signInWith(suite);
          return;
        }
        if (registered.code === "invalid_public_key" || registered.code === "private_key_rejected") {
          await deleteMlDsaDeviceKey(suite);
        }
        throw new Error(fixedError(registered.code, registered.status));
      })
      .catch((error: unknown) => {
        setStatus(error instanceof Error ? error.message : "ML-DSA sign-in failed.", true);
        setBusy(false);
      });
  });
  signIn.addEventListener("click", () => {
    setBusy(true);
    setStatus("Checking the ML-DSA signature…");
    void signInWith(selected()).catch((error: unknown) => {
      setStatus(error instanceof Error ? error.message : "ML-DSA sign-in failed.", true);
      setBusy(false);
    });
  });
  exportKey.addEventListener("click", () => {
    const suite = selected();
    setBusy(true);
    setStatus("Exporting the private key stored in this browser…");
    void exportStoredPqcPrivateKey(suite)
      .then((file) => {
        downloadLocalPrivateFile(file);
        setStatus(`Saved ${file.filename}. The private key was not uploaded.`);
      })
      .catch((error: unknown) => {
        setStatus(error instanceof Error ? error.message : "Could not export that private key.", true);
      })
      .finally(() => setBusy(false));
  });
  remove.addEventListener("click", () => {
    const suite = selected();
    setBusy(true);
    void deleteMlDsaDeviceKey(suite)
      .then(() => {
        setStatus(`Removed the ${suiteLabelFor(suite)} key from this device.`);
      })
      .catch((error: unknown) => {
        setStatus(error instanceof Error ? error.message : "Could not remove the device key.", true);
      })
      .finally(() => setBusy(false));
  });
  refresh();
}

let patching = false;
function watchLogin(): void {
  if (patching) return;
  patching = true;
  try {
    patchSessionLabel();
    const modal = document.querySelector(".auth-modal:not(.admin-modal)");
    if (modal instanceof HTMLElement && !modal.querySelector("#globe-pqc-login")) {
      mountPqcLogin();
    }
    if (modal instanceof HTMLElement) mountDeviceKeyExport();
  } finally {
    patching = false;
  }
}

const observer = new MutationObserver(() => watchLogin());
observer.observe(document.documentElement, { subtree: true, childList: true });
watchLogin();
