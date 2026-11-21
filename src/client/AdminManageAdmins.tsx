/**
 * Manage admins — shown inside the Admin portal only when the session is an
 * admin. UI hint only: every /api/admin/admins call is re-checked server-side
 * (admin session + fresh device-key elevation + allowlisted signing key).
 * Never sends private keys; the input is rejected locally if it looks like one.
 */
import React, { useCallback, useEffect, useState } from "react";
import { authFetch } from "./pgpAuth";
import { adminElevationHeader } from "./adminElevation";

type AdminRow = {
  id: string;
  masked: string;
  label: string;
  addedAt: string;
  addedBy: string;
  isYou: boolean;
};

type AdminList = {
  bootstrap: { fingerprints: number; userIds: number; note: string };
  admins: AdminRow[];
  max: number;
  you: { masked: string; bootstrap: boolean; id: string | null };
};

type Props = {
  adminElevationValid: () => boolean;
  adminBusy: boolean;
  unlockAdminPrivileges: () => Promise<void> | void;
  onSelfRemoved: () => void;
};

const ROW_STYLE: React.CSSProperties = { cursor: "default", display: "block" };

const PRIVATE_BLOCK_RE = /BEGIN PGP PRIVATE KEY BLOCK|PRIVATE KEY-----/i;

function messageOf(data: unknown, fallback: string): string {
  if (data && typeof data === "object") {
    const d = data as { message?: unknown; error?: unknown };
    if (typeof d.message === "string" && d.message) return d.message;
    if (typeof d.error === "string" && d.error) return d.error.replace(/_/g, " ");
  }
  return fallback;
}

async function call(path: string, init: RequestInit = {}) {
  const headers: Record<string, string> = {
    accept: "application/json",
    ...adminElevationHeader(),
  };
  if (init.body) headers["content-type"] = "application/json";
  const res = await authFetch(path, { ...init, headers, credentials: "same-origin" });
  let data: unknown = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  return { ok: res.ok, status: res.status, data };
}

export function AdminManageAdmins({
  adminElevationValid,
  adminBusy,
  unlockAdminPrivileges,
  onSelfRemoved,
}: Props) {
  const [list, setList] = useState<AdminList | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [keyInput, setKeyInput] = useState("");
  const [label, setLabel] = useState("");
  const elevated = adminElevationValid();

  const load = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const r = await call("/api/admin/admins");
      if (!r.ok) {
        setList(null);
        setError(messageOf(r.data, `Could not load admins (HTTP ${r.status}).`));
        return;
      }
      setList(r.data as AdminList);
    } catch {
      setError("Network error while loading admins.");
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    if (!elevated) {
      setList(null);
      return;
    }
    // The parent publishes the new elevation token in its own effect, which
    // runs after this child effect. Wait one tick so the header is set.
    const t = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [elevated]);

  const add = async () => {
    setError("");
    setMessage("");
    const raw = keyInput.trim();
    if (!raw) {
      setError("Paste a fingerprint or a public key.");
      return;
    }
    if (PRIVATE_BLOCK_RE.test(raw)) {
      setKeyInput("");
      setError("That is a PRIVATE key. It was cleared and not sent. Paste the public key or fingerprint only.");
      return;
    }
    const isArmored = /BEGIN PGP PUBLIC KEY BLOCK/i.test(raw);
    if (!isArmored && !/^[0-9a-fA-F\s:]{40,100}$/.test(raw)) {
      setError("Enter a 40- or 64-character hex fingerprint, or paste an armored PUBLIC KEY BLOCK.");
      return;
    }
    setBusy(true);
    try {
      const r = await call("/api/admin/admins", {
        method: "POST",
        body: JSON.stringify(
          isArmored ? { publicKey: raw, label: label.trim() } : { fingerprint: raw, label: label.trim() },
        ),
      });
      if (!r.ok) {
        setError(messageOf(r.data, `Could not add admin (HTTP ${r.status}).`));
        return;
      }
      setMessage(messageOf(r.data, "Admin added."));
      setKeyInput("");
      setLabel("");
      await load();
    } catch {
      setError("Network error while adding admin.");
    } finally {
      setBusy(false);
    }
  };

  const remove = async (row: AdminRow) => {
    setError("");
    setMessage("");
    const who = `${row.masked}${row.label ? ` (${row.label})` : ""}`;
    if (!window.confirm(`Remove admin ${who}? They lose admin access.`)) return;
    let confirmSelf = false;
    if (row.isYou) {
      if (!window.confirm("This is YOUR admin entry. Remove yourself and lose admin access now?")) return;
      confirmSelf = true;
    }
    setBusy(true);
    try {
      const r = await call(`/api/admin/admins/${encodeURIComponent(row.id)}`, {
        method: "DELETE",
        body: JSON.stringify({ confirmSelf }),
      });
      if (!r.ok) {
        setError(messageOf(r.data, `Could not remove admin (HTTP ${r.status}).`));
        return;
      }
      setMessage(messageOf(r.data, "Admin removed."));
      if ((r.data as { selfRemoved?: boolean } | null)?.selfRemoved) {
        onSelfRemoved();
        return;
      }
      await load();
    } catch {
      setError("Network error while removing admin.");
    } finally {
      setBusy(false);
    }
  };

  const working = busy || adminBusy;

  return (
    <div id="admin-manage-admins" className="admin-manage-admins">
      <div className="auth-section-title">Manage admins</div>
      <p className="auth-modal-copy">
        Add or remove admins. Permanent admins live in Cloudflare secrets and
        cannot be removed here. Added admins are stored as a one-way digest
        plus a masked fingerprint. Needs an unlocked (device-key) session.
      </p>
      {!elevated ? (
        <div className="auth-modal-actions auth-row">
          <button type="button" disabled={working} onClick={() => void unlockAdminPrivileges()}>
            {working ? "Working…" : "Unlock privileges to manage admins"}
          </button>
        </div>
      ) : (
        <>
          {list && (
            <div className="admin-users-list admin-admins-list">
              <div className="admin-user-row-wrap">
                <div className="admin-user-row" style={ROW_STYLE}>
                  <strong>
                    {list.bootstrap.fingerprints} permanent key
                    {list.bootstrap.fingerprints === 1 ? "" : "s"}
                  </strong>
                  {list.bootstrap.userIds > 0
                    ? ` + ${list.bootstrap.userIds} user id${list.bootstrap.userIds === 1 ? "" : "s"}`
                    : ""}{" "}
                  · {list.bootstrap.note}
                  {list.you.bootstrap ? " · includes you" : ""}
                </div>
              </div>
              {list.admins.length === 0 && (
                <div className="admin-users-meta">No added admins yet.</div>
              )}
              {list.admins.map((row) => (
                <div key={row.id} className="admin-user-row-wrap">
                  <div className="admin-user-row" style={ROW_STYLE}>
                    <code>{row.masked}</code>
                    {row.label ? ` · ${row.label}` : ""}
                    {row.isYou ? " · you" : ""}
                    <div className="admin-users-meta" style={{ padding: "2px 0 0" }}>
                      added {row.addedAt ? new Date(row.addedAt).toLocaleString() : "?"}
                      {row.addedBy ? ` by ${row.addedBy}` : ""}
                    </div>
                  </div>
                  <button
                    type="button"
                    className="admin-user-remove"
                    disabled={working}
                    onClick={() => void remove(row)}
                  >
                    Remove
                  </button>
                </div>
              ))}
            </div>
          )}
          <label className="auth-field">
            <span>Fingerprint (40/64 hex) or PUBLIC key block</span>
            <textarea
              value={keyInput}
              onChange={(e) => setKeyInput(e.target.value)}
              disabled={working}
              rows={3}
              spellCheck={false}
              autoComplete="off"
              placeholder="e.g. ABCD 1234 … or -----BEGIN PGP PUBLIC KEY BLOCK-----"
            />
          </label>
          <label className="auth-field">
            <span>Label (optional)</span>
            <input
              type="text"
              value={label}
              maxLength={60}
              onChange={(e) => setLabel(e.target.value)}
              disabled={working}
              autoComplete="off"
              placeholder="e.g. Alex laptop"
            />
          </label>
          <div className="auth-modal-actions auth-row">
            <button type="button" disabled={working || !keyInput.trim()} onClick={() => void add()}>
              {busy ? "Working…" : "Add admin"}
            </button>
            <button type="button" className="auth-switch" disabled={working} onClick={() => void load()}>
              Refresh list
            </button>
          </div>
        </>
      )}
      {error && (
        <div className="auth-error" style={{ whiteSpace: "pre-wrap" }}>
          {error}
        </div>
      )}
      {message && <div className="auth-inline-ok">{message}</div>}
    </div>
  );
}
