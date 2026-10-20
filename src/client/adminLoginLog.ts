/**
 * Admin-only view of stored sign-in attempts.
 * Renders text only. It does not show private keys, signatures, or session cookies.
 */

type Attempt = {
  at?: string;
  ip?: string;
  family?: string;
  phase?: string;
  suite?: string;
  result?: string;
  code?: string;
  accountPrefix?: string;
  detail?: string;
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
  body.textContent = value || "—";
  row.append(name, body);
  return row;
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
  note.textContent = "Visible to an admin session only. Attempts are kept for 30 days. The log stores the result, method, suite, network, and an 8-character account prefix. It does not store private keys, signatures, MACs, challenges, or session cookies.";
  const status = document.createElement("p");
  status.id = "globe-admin-login-log-status";
  status.setAttribute("role", "status");
  status.style.cssText = "min-height:1.2em;margin:8px 0;font-size:13px";
  const list = document.createElement("div");
  list.id = "globe-admin-login-log-list";
  const refresh = document.createElement("button");
  refresh.type = "button";
  refresh.textContent = "Reload sign-in attempts";
  refresh.style.cssText = [
    "min-height:44px",
    "width:100%",
    "margin-top:8px",
    "font:600 14px/1.2 system-ui,sans-serif",
    "border-radius:8px",
    "border:1px solid rgba(61,255,168,0.45)",
    "background:#16382c",
    "color:#e7fff3",
  ].join(";");
  root.append(title, note, status, list, refresh);
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
        line("Network", text(attempt.ip, 64)),
        line("Account prefix", text(attempt.accountPrefix, 8)),
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

  refresh.addEventListener("click", load);
  load();
}
