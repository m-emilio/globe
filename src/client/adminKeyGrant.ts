/**
 * Admin grant and revoke for unlimited sign-in keys.
 * Uses the same session, action secret, and device-key step-up as transit.
 * The action secret and elevation token stay in this page's memory.
 */

const ELEVATION_PREFIX = "globe-admin-elevate:v1|";
const PRIVILEGE_PROTOCOL = "globe-unlimited-keys:v1";

let elevationToken = "";
let elevationExpiresAt = 0;
let adminFingerprint = "";

function normalizeKeyId(value: string): string {
  const hexId = value.replace(/[\s:]/g, "").toLowerCase();
  return /^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(hexId) ? hexId : "";
}

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

async function signPrivilege(
  action: "grant" | "revoke",
  target: string,
): Promise<{ pqcSignature?: string; signatureArmored?: string }> {
  if (!adminFingerprint) {
    throw new Error("Unlock privileges first so the signature is tied to this admin key.");
  }
  const message = `${PRIVILEGE_PROTOCOL}|${action}|${target}|${adminFingerprint}`;
  if (/^[a-f0-9]{64}$/.test(adminFingerprint)) {
    const { signStoredPqcMessage } = await import("./mlDsa");
    return { pqcSignature: await signStoredPqcMessage(adminFingerprint, message) };
  }
  const pgp = await import("./pgpAuth");
  const device = (await pgp.getDeviceKey(adminFingerprint)) || (await pgp.getPreferredDeviceKey());
  if (!device) throw new Error("No device private key on this browser matches the admin account.");
  const passphrase = document.querySelector("#globe-admin-key-grant-passphrase");
  const passphraseValue = passphrase instanceof HTMLInputElement ? passphrase.value : "";
  if (device.encrypted && !passphraseValue) {
    const wrap = passphrase?.parentElement;
    if (wrap instanceof HTMLElement) wrap.hidden = false;
    throw new Error("This OpenPGP key is encrypted. Enter its passphrase, then try again.");
  }
  return {
    signatureArmored: await pgp.signChallenge(
      message,
      device.privateKeyArmored,
      device.encrypted ? passphraseValue : undefined,
    ),
  };
}

function installPrivilegeFetch(): void {
  const holder = window as unknown as { __globePrivilegeFetch?: boolean };
  if (holder.__globePrivilegeFetch) return;
  holder.__globePrivilegeFetch = true;
  const nativeFetch = window.fetch.bind(window);
  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = requestUrl(input);
    let nextInit = init;
    const action = url.includes("/api/admin/grant-unlimited-keys")
      ? "grant"
      : url.includes("/api/admin/revoke-unlimited-keys")
        ? "revoke"
        : "";
    if (action && typeof init?.body === "string" && (init.method || "GET").toUpperCase() === "POST") {
      const parsed = JSON.parse(init.body) as Record<string, unknown>;
      const target = typeof parsed.fingerprint === "string" ? normalizeKeyId(parsed.fingerprint) : "";
      if (target && typeof parsed.pqcSignature !== "string" && typeof parsed.signatureArmored !== "string") {
        const signed = await signPrivilege(action, target);
        nextInit = { ...init, body: JSON.stringify({ ...parsed, fingerprint: target, ...signed }) };
      }
    }
    const response = await nativeFetch(input, nextInit);
    if (response.ok && url.includes("/api/admin/elevate-challenge")) {
      try {
        const data = (await response.clone().json()) as { fingerprint?: unknown };
        if (typeof data.fingerprint === "string") {
          const fp = normalizeKeyId(data.fingerprint);
          if (fp) adminFingerprint = fp;
        }
      } catch {
        // The caller still receives the challenge response.
      }
    }
    return response;
  };
}

function field(label: string, input: HTMLInputElement): HTMLLabelElement {
  const wrap = document.createElement("label");
  wrap.style.cssText = "display:flex;flex-direction:column;gap:4px;margin:8px 0;font-size:13px";
  const span = document.createElement("span");
  span.textContent = label;
  wrap.append(span, input);
  return wrap;
}

function inputBox(type: string): HTMLInputElement {
  const input = document.createElement("input");
  input.type = type;
  input.autocomplete = "off";
  input.spellcheck = false;
  input.style.cssText = "min-height:44px;font-size:16px;padding:8px";
  return input;
}

function button(label: string): HTMLButtonElement {
  const node = document.createElement("button");
  node.type = "button";
  node.textContent = label;
  node.style.cssText = [
    "min-height:44px",
    "font:600 14px/1.2 system-ui,sans-serif",
    "border-radius:8px",
    "border:1px solid rgba(61,255,168,0.45)",
    "background:#16382c",
    "color:#e7fff3",
  ].join(";");
  return node;
}

async function postJson(path: string, body: unknown, headers: Record<string, string> = {}): Promise<{
  ok: boolean;
  status: number;
  data: Record<string, unknown>;
}> {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  let data: Record<string, unknown> = {};
  try {
    const parsed = await response.json();
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) data = parsed as Record<string, unknown>;
  } catch {
    data = {};
  }
  return { ok: response.ok, status: response.status, data };
}

function messageOf(data: Record<string, unknown>, fallback: string): string {
  return typeof data.message === "string" && data.message ? data.message : fallback;
}

export function mountAdminKeyGrant(): void {
  installPrivilegeFetch();
  const modal = document.querySelector(".admin-modal");
  if (!(modal instanceof HTMLElement) || modal.querySelector("#globe-admin-key-grant")) return;

  const root = document.createElement("section");
  root.id = "globe-admin-key-grant";
  root.style.cssText = [
    "margin-top:16px",
    "padding:12px",
    "border:1px solid rgba(61,255,168,0.35)",
    "border-radius:12px",
    "background:#102820",
    "color:#e7fff3",
  ].join(";");
  const title = document.createElement("h3");
  title.textContent = "Unlimited sign-in keys";
  title.style.cssText = "margin:0 0 6px;font-size:16px";
  const note = document.createElement("p");
  note.style.cssText = "margin:0 0 8px;font-size:13px;line-height:1.45;color:#d5ffe9";
  note.textContent = "Unlock privileges signs a challenge with the key on this device. The server stores a SHAKE256 seal of that key, not the raw fingerprint. Grant and revoke sign the target account fingerprint with the same key, and the unlimited-key seal is stored on that account. A swapped account id does not match the signature. A paid Stripe checkout under $20 seals the paying account. Networks that already hold the sealed key can register more keys. No key passphrase unless the OpenPGP key itself is encrypted. The private key is not uploaded.";
  const status = document.createElement("p");
  status.id = "globe-admin-key-grant-status";
  status.setAttribute("role", "status");
  status.style.cssText = "min-height:1.2em;margin:8px 0;font-size:13px;white-space:pre-wrap";
  const account = inputBox("text");
  account.id = "globe-admin-key-grant-account";
  account.placeholder = "user id or fingerprint";
  const auditNote = inputBox("text");
  auditNote.placeholder = "audit note";
  const secret = inputBox("password");
  secret.placeholder = "ADMIN_ACTION_SECRET";
  const passphrase = inputBox("password");
  passphrase.id = "globe-admin-key-grant-passphrase";
  passphrase.placeholder = "only if this OpenPGP key is encrypted";
  const passphraseField = field("Key passphrase", passphrase);
  passphraseField.hidden = true;
  const unlock = button("Unlock privileges");
  const grant = button("Grant unlimited keys");
  const revoke = button("Revoke unlimited keys");
  const row = document.createElement("div");
  row.style.cssText = "display:flex;flex-wrap:wrap;gap:8px;margin-top:8px";
  row.append(unlock, grant, revoke);
  root.append(
    title,
    note,
    field("Account", account),
    field("Note", auditNote),
    field("Action secret", secret),
    passphraseField,
    status,
    row,
  );
  modal.append(root);

  const setStatus = (text: string, isError = false) => {
    status.textContent = text;
    status.style.color = isError ? "#ffb4b4" : "#d8ffe8";
  };
  const elevated = () => Boolean(elevationToken) && elevationExpiresAt > Date.now();

  unlock.addEventListener("click", () => {
    setStatus("Asking for an elevation challenge…");
    void (async () => {
      const challenge = await postJson("/api/admin/elevate-challenge", {});
      const challengeId = challenge.data.challengeId;
      const challengeMessage = challenge.data.message;
      const fingerprint = challenge.data.fingerprint;
      if (!challenge.ok || typeof challengeId !== "string" || typeof challengeMessage !== "string") {
        elevationToken = "";
        setStatus(messageOf(challenge.data, "An admin session is required to unlock privileges."), true);
        return;
      }
      if (!challengeMessage.startsWith(ELEVATION_PREFIX)) {
        setStatus("The elevation challenge was not recognized.", true);
        return;
      }
      let body: { challengeId: string; signatureArmored?: string; pqcSignature?: string };
      if (typeof fingerprint === "string" && /^[a-f0-9]{64}$/i.test(fingerprint)) {
        const { signStoredPqcMessage } = await import("./mlDsa");
        body = { challengeId, pqcSignature: await signStoredPqcMessage(fingerprint, challengeMessage) };
      } else {
        const pgp = await import("./pgpAuth");
        const fp = typeof fingerprint === "string" ? fingerprint : "";
        const device = (await pgp.getDeviceKey(fp)) || (await pgp.getPreferredDeviceKey());
        if (!device) {
          setStatus("No device private key on this browser matches the admin account.", true);
          return;
        }
        if (device.encrypted && !passphrase.value) {
          passphraseField.hidden = false;
          setStatus("This OpenPGP key is encrypted. Enter its passphrase, then unlock again.", true);
          return;
        }
        body = {
          challengeId,
          signatureArmored: await pgp.signChallenge(
            challengeMessage,
            device.privateKeyArmored,
            device.encrypted ? passphrase.value : undefined,
          ),
        };
      }
      const elevatedResponse = await postJson("/api/admin/elevate", body);
      const token = elevatedResponse.data.elevationToken;
      if (!elevatedResponse.ok || typeof token !== "string") {
        elevationToken = "";
        setStatus(messageOf(elevatedResponse.data, "Elevation signature rejected."), true);
        return;
      }
      elevationToken = token;
      const expires = elevatedResponse.data.expiresAt;
      elevationExpiresAt = typeof expires === "string" ? Date.parse(expires) : Date.now() + 10 * 60 * 1000;
      setStatus(messageOf(elevatedResponse.data, "Privileged window unlocked. Grant and revoke are available."));
    })().catch((error: unknown) => {
      elevationToken = "";
      setStatus(error instanceof Error ? error.message : "Could not unlock privileges.", true);
    });
  });

  const mutate = (grantKeys: boolean) => {
    setStatus(grantKeys ? "Granting unlimited keys…" : "Revoking unlimited keys…");
    void (async () => {
      if (!elevated()) {
        setStatus("Unlock privileges first. Grant and revoke need a fresh device-key step-up.", true);
        return;
      }
      if (secret.value.trim().length < 16) {
        setStatus("Enter the action secret before granting or revoking.", true);
        return;
      }
      const query = account.value.trim();
      if (query.length < 6) {
        setStatus("Enter the user id or fingerprint first.", true);
        return;
      }
      const lookedUp = await fetch(`/api/admin/lookup?q=${encodeURIComponent(query)}`, {
        credentials: "same-origin",
        headers: { accept: "application/json" },
      });
      const looked = (await lookedUp.json()) as {
        found?: boolean;
        user?: { id?: string; fingerprint?: string };
      };
      const target = lookedUp.ok && looked.found && typeof looked.user?.fingerprint === "string"
        ? normalizeKeyId(looked.user.fingerprint)
        : "";
      const typed = normalizeKeyId(query);
      const lookedId = typeof looked.user?.id === "string" ? looked.user.id.toLowerCase() : "";
      if (!target || (typed && typed !== target && typed !== lookedId)) {
        setStatus("No account fingerprint matched that user id.", true);
        return;
      }
      const response = await postJson(
        grantKeys ? "/api/admin/grant-unlimited-keys" : "/api/admin/revoke-unlimited-keys",
        {
          fingerprint: target,
          note: auditNote.value.trim() || undefined,
        },
        {
          "x-admin-action-secret": secret.value.trim(),
          "x-admin-elevation": elevationToken,
        },
      );
      if (!response.ok) {
        setStatus(messageOf(response.data, "Grant or revoke failed."), true);
        return;
      }
      setStatus(messageOf(response.data, grantKeys ? "Unlimited keys granted." : "Unlimited keys revoked."));
    })().catch((error: unknown) => {
      setStatus(error instanceof Error ? error.message : "Grant or revoke failed.", true);
    });
  };

  grant.addEventListener("click", () => mutate(true));
  revoke.addEventListener("click", () => mutate(false));
}
