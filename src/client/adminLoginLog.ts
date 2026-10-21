/**
 * Admin-only view of hashed sign-in attempts, plus a local export of the security log.
 * Renders text only. It does not show private keys, signatures, or session cookies.
 */

type Attempt = {
  at?: string;
  family?: string;
  phase?: string;
  suite?: string;
  result?: string;
  code?: string;
  detail?: string;
  networkHash?: string;
  accountHash?: string;
  recordHash?: string;
  prevHash?: string;
  chain?: string;
};

function text(value: unknown, max = 180): string {
  return typeof value === "string" ? value.slice(0, max) : "";
}

function line(label: string, value: string): HTMLElement {
  const row = document.createElement("div");
  row.style.cssText = "margin:2px 0;font-size:12px;line-height:1.4";
  const name = document.createElement("strong");
  name.textContent = `${label}: `;
  const body = document.createElement("span");
  body.style.cssText = "word-break:break-all";
  body.textContent = value || "—";
  row.append(name, body);
  return row;
}

function hashLine(label: string, value: unknown): HTMLElement {
  const hash = text(value, 64);
  return line(label, /^[a-f0-9]{64}$/.test(hash) ? hash : "");
}

export function mountAdminLoginLog(): void {
  const modal = document.querySelector(".admin-modal");
  if (!(modal instanceof HTMLElement) || modal.querySelector("#globe-admin-login-log")) return;

  const root = document.createElement("section");
  root.id = "globe-admin-login-log";
  root.style.cssText = [
    "margin-top:16px",
    "padding:12px",
    "border:1px solid rgba(61,255,168,0.35)",
    "border-radius:12px",
    "background:#102820",
    "color:#e7fff3",
  ].join(";");
  const title = document.createElement("h3");
  title.textContent = "Sign-in attempts";
  title.style.cssText = "margin:0 0 6px;font-size:16px";
  const note = document.createElement("p");
  note.style.cssText = "margin:0 0 8px;font-size:13px;line-height:1.4;color:#d5ffe9";
  note.textContent =
    "Visible to an admin session only. Attempts are kept for 30 days and audits for 180 days. Each new row stores a SHAKE256 digest of the network and the account, plus a record hash and a hash chain. SHAKE256 is the hash inside ML-DSA and SLH-DSA. The raw network and account are not stored. An unsalted digest of an IPv4 can still be guessed if this export leaks. After 8 rejected sign-ins in 10 minutes, that network is paused for 15 minutes. Private keys, signatures, MACs, challenges, and session cookies are not stored.";
  const status = document.createElement("p");
  status.id = "globe-admin-login-log-status";
  status.setAttribute("role", "status");
  status.style.cssText = "min-height:1.2em;margin:8px 0;font-size:13px";
  const list = document.createElement("div");
  list.id = "globe-admin-login-log-list";
  const buttonStyle = [
    "min-height:44px",
    "width:100%",
    "margin-top:8px",
    "font:600 14px/1.2 system-ui,sans-serif",
    "border-radius:8px",
    "border:1px solid rgba(61,255,168,0.45)",
    "background:#16382c",
    "color:#e7fff3",
  ].join(";");
  const refresh = document.createElement("button");
  refresh.type = "button";
  refresh.textContent = "Reload sign-in attempts";
  refresh.style.cssText = buttonStyle;
  const exportLog = document.createElement("button");
  exportLog.type = "button";
  exportLog.id = "globe-admin-security-export";
  exportLog.textContent = "Export security log";
  exportLog.style.cssText = buttonStyle;
  root.append(title, note, status, list, refresh, exportLog);
  modal.append(root);

  const showAttempts = (attempts: Attempt[]) => {
    list.replaceChildren();
    if (attempts.length === 0) {
      const empty = document.createElement("p");
      empty.style.cssText = "margin:0;font-size:13px;color:#d5ffe9";
      empty.textContent = "No sign-in attempts are stored yet.";
      list.append(empty);
      return;
    }
    for (let i = 0; i < attempts.length; i++) {
      const attempt = attempts[i]!;
      const card = document.createElement("article");
      card.style.cssText = "margin:0 0 10px;padding:8px;border:1px solid rgba(61,255,168,0.2);border-radius:8px";
      card.append(
        line("When", text(attempt.at, 40)),
        line("Result", text(attempt.result, 20)),
        line("Method", text(attempt.family, 20)),
        line("Step", text(attempt.phase, 20)),
        line("Suite", text(attempt.suite, 40)),
        line("Code", text(attempt.code, 40)),
        hashLine("Network hash", attempt.networkHash),
        hashLine("Account hash", attempt.accountHash),
        hashLine("Record hash", attempt.recordHash),
        line("Chain", /^[a-f0-9]{64}$/.test(text(attempt.chain, 64)) ? text(attempt.chain, 64) : "predates the hash chain"),
        line("What happened", text(attempt.detail, 240)),
      );
      list.append(card);
    }
  };

  const load = () => {
    refresh.disabled = true;
    status.textContent = "Loading sign-in attempts…";
    void fetch("/api/admin/login-attempts", {
      credentials: "same-origin",
      headers: { accept: "application/json" },
    })
      .then(async (response) => {
        if (response.status === 401 || response.status === 403) {
          status.textContent = "An admin session is required to read sign-in attempts.";
          list.replaceChildren();
          return;
        }
        if (!response.ok) {
          status.textContent = "Sign-in attempts could not be loaded.";
          list.replaceChildren();
          return;
        }
        const data = (await response.json()) as { attempts?: Attempt[]; stored?: string };
        const attempts = Array.isArray(data.attempts) ? data.attempts : [];
        status.textContent = data.stored || `${attempts.length} stored attempt${attempts.length === 1 ? "" : "s"}.`;
        showAttempts(attempts);
      })
      .catch(() => {
        status.textContent = "Sign-in attempts could not be loaded.";
        list.replaceChildren();
      })
      .finally(() => {
        refresh.disabled = false;
      });
  };

  const download = () => {
    exportLog.disabled = true;
    status.textContent = "Preparing the security log…";
    void fetch("/api/admin/security-export", {
      credentials: "same-origin",
      headers: { accept: "application/json" },
    })
      .then(async (response) => {
        if (response.status === 401 || response.status === 403) {
          status.textContent = "An admin session is required to export the security log.";
          return;
        }
        if (!response.ok) {
          status.textContent = "The security log could not be exported.";
          return;
        }
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = "globe-security-log.json";
        anchor.rel = "noopener";
        document.body.append(anchor);
        anchor.click();
        anchor.remove();
        URL.revokeObjectURL(url);
        status.textContent = "Security log downloaded to this device.";
      })
      .catch(() => {
        status.textContent = "The security log could not be exported.";
      })
      .finally(() => {
        exportLog.disabled = false;
      });
  };

  refresh.addEventListener("click", load);
  exportLog.addEventListener("click", download);
  load();
}
