/**
 * ML-DSA sign-in inside the existing account modal.
 * OpenPGP file rules stay on the import panel. This block never accepts a file.
 */
import { ML_DSA_SUITES, isMlDsaSuite, type MlDsaSuiteId } from "../server/pqcVerify";
import {
  createMlDsaDeviceKey,
  deleteMlDsaDeviceKey,
  listMlDsaDeviceKeys,
  signMlDsaLogin,
} from "./mlDsa";

const SUITE_ORDER: MlDsaSuiteId[] = ["ml-dsa65", "ml-dsa87", "ml-dsa44"];

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

function fixedError(code: string, status: number): string {
  if (code === "rate_limited" || status === 429) return "Too many sign-in attempts. Wait a minute and try again.";
  if (code === "private_key_rejected") return "The private key stays on this device.";
  if (code === "fingerprint_taken") return "This key is already registered. Sign in with this device.";
  if (code === "invalid_challenge") return "That sign-in challenge expired. Try again.";
  if (code === "auth_failed") return "Could not verify the ML-DSA signature.";
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
    if (!text.includes("ML-DSA-") || !text.includes("PGP session")) continue;
    status.textContent = text.replace("PGP session", "ML-DSA session");
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

  const title = el("h3", "Post-quantum sign-in");
  title.style.cssText = "margin:0 0 6px;font-size:16px";
  const hint = el(
    "p",
    "ML-DSA-65 is the default. ML-DSA-87 is the set still recommended after 2030. The private key is wrapped in this browser and is not uploaded. OpenPGP sign-in above is separate.",
  );
  hint.style.cssText = "margin:0 0 10px;font-size:13px;line-height:1.4;color:#d5ffe9";

  const suiteLabel = el("label");
  suiteLabel.style.cssText = "display:flex;flex-direction:column;gap:6px";
  suiteLabel.append(el("span", "ML-DSA suite"));
  const suiteSelect = el("select");
  suiteSelect.id = "globe-pqc-login-suite";
  suiteSelect.style.cssText = "min-height:48px;font-size:16px;padding:8px";
  for (let i = 0; i < SUITE_ORDER.length; i++) {
    const id = SUITE_ORDER[i]!;
    const option = el("option", ML_DSA_SUITES[id].label);
    option.value = id;
    suiteSelect.append(option);
  }
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
  const create = el("button", "Create ML-DSA key on this device");
  create.type = "button";
  create.id = "globe-pqc-login-create";
  create.style.cssText = buttonStyle;
  const signIn = el("button", "Sign in with this device key");
  signIn.type = "button";
  signIn.id = "globe-pqc-login-signin";
  signIn.style.cssText = buttonStyle;
  const remove = el("button", "Remove ML-DSA key from this device");
  remove.type = "button";
  remove.id = "globe-pqc-login-remove";
  remove.style.cssText = buttonStyle;

  root.append(title, hint, suiteLabel, status, create, signIn, remove);
  modal.append(root);

  const selected = (): MlDsaSuiteId => {
    const value = suiteSelect.value;
    return isMlDsaSuite(value) ? value : "ml-dsa65";
  };
  const setStatus = (message: string, isError = false) => {
    status.textContent = message;
    status.style.color = isError ? "#ffb4b4" : "#d8ffe8";
  };
  const setBusy = (busy: boolean) => {
    create.disabled = busy;
    signIn.disabled = busy;
    remove.disabled = busy;
    suiteSelect.disabled = busy;
  };
  const refresh = () => {
    void listMlDsaDeviceKeys()
      .then((rows) => {
        const here = rows.some((row) => row.suite === selected());
        setStatus(
          here
            ? `${ML_DSA_SUITES[selected()].label} key is on this device.`
            : `No ${ML_DSA_SUITES[selected()].label} key on this device yet.`,
        );
      })
      .catch((error: unknown) => {
        setStatus(error instanceof Error ? error.message : "Could not read the device key.", true);
      });
  };

  const signInWith = async (suite: MlDsaSuiteId): Promise<void> => {
    const rows = await listMlDsaDeviceKeys();
    const row = rows.find((item) => item.suite === suite);
    if (!row) throw new Error(`Create an ${ML_DSA_SUITES[suite].label} key on this device first.`);
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
  remove.addEventListener("click", () => {
    const suite = selected();
    setBusy(true);
    void deleteMlDsaDeviceKey(suite)
      .then(() => {
        setStatus(`Removed the ${ML_DSA_SUITES[suite].label} key from this device.`);
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
  } finally {
    patching = false;
  }
}

const observer = new MutationObserver(() => watchLogin());
observer.observe(document.documentElement, { subtree: true, childList: true });
watchLogin();
