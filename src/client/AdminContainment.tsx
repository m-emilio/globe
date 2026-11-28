import React, { useEffect, useState } from "react";
import { adminElevationHeader } from "./adminElevation";
import { authFetch } from "./pgpAuth";

type Session = {
  reference: string;
  createdAt: string | null;
  expiresAt: string;
  current: boolean;
  revoked: boolean;
};
type AccountSessions = { account: string; fingerprint: string; sessions: Session[] };
type Retest = { revoked: boolean; open: number; unknownRooms: number };

async function containment<T>(body: Record<string, unknown>): Promise<T> {
  const response = await authFetch("/api/admin/containment", {
    method: "POST",
    headers: { ...adminElevationHeader(), "content-type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(15_000),
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.message || "Containment request returned HTTP " + response.status + ".");
  }
  return data as T;
}

export function AdminContainment({ elevated }: { elevated: boolean }) {
  const [paused, setPaused] = useState<boolean | null>(null);
  const [lookup, setLookup] = useState("");
  const [account, setAccount] = useState<AccountSessions | null>(null);
  const [selected, setSelected] = useState("");
  const [lastRevoked, setLastRevoked] = useState("");
  const [canRetry, setCanRetry] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (elevated) return;
    setPaused(null);
    setLookup("");
    setAccount(null);
    setSelected("");
    setLastRevoked("");
    setCanRetry(false);
    setNotice("");
    setError("");
  }, [elevated]);

  async function run(task: () => Promise<void>) {
    if (busy || !elevated) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await task();
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Containment request failed.");
    } finally {
      setBusy(false);
    }
  }

  async function loadPause() {
    const data = await containment<{ paused: boolean }>({ action: "status" });
    setPaused(data.paused);
  }

  async function togglePause() {
    if (paused === null || !window.confirm(paused ? "Resume new Live Feed peer requests?" : "Pause new Live Feed peer requests?")) return;
    await run(async () => {
      const data = await containment<{ paused: boolean; auditRecorded: boolean }>({ action: "pause", paused: !paused });
      setPaused(data.paused);
      setNotice((data.paused ? "New peer requests paused." : "New peer requests enabled.") +
        (data.auditRecorded ? "" : " Audit receipt unavailable."));
    });
  }

  async function findSessions() {
    setSelected("");
    setAccount(null);
    const data = await containment<AccountSessions>({ action: "sessions", account: lookup.trim() });
    setAccount(data);
  }

  async function revoke() {
    if (!account || !selected ||
        !window.confirm("Revoke session " + selected.slice(0, 12) + " for account " + account.fingerprint + "?")) return;
    await run(async () => {
      type Result = { reference: string; disconnected: number; unknownRooms: number; auditRecorded: boolean; kvRemoved: boolean };
      const data = await containment<Result>({ action: "revoke", account: account.account, reference: selected });
      setLastRevoked(data.reference);
      setCanRetry(data.unknownRooms > 0);
      setSelected("");
      setAccount({ ...account, sessions: account.sessions.filter(session => session.reference !== data.reference) });
      setNotice("Session revoked. Disconnected " + data.disconnected + " sockets." +
        (data.unknownRooms ? " Unconfirmed rooms: " + data.unknownRooms + "." : "") +
        (data.kvRemoved ? "" : " The revocation guard is active while session-record cleanup is pending.") +
        (data.auditRecorded ? "" : " Audit receipt unavailable."));
    });
  }

  async function retest(retry = false) {
    const result = await containment<Retest>({
      action: retry ? "finish_disconnect" : "retest", reference: lastRevoked,
    });
    setCanRetry(result.unknownRooms > 0 || result.open > 0);
    setNotice("Revocation confirmed. Matching open sockets: " + result.open +
      ". Unconfirmed rooms: " + result.unknownRooms + ".");
  }

  return (
    <section id="admin-containment" aria-label="Live containment">
      <div className="auth-section-title">Live containment</div>
      <p className="auth-modal-copy">
        <a href="/admin/purple-team/operations">Open Purple Team</a>
      </p>
      {elevated ? <>
        <div className="auth-modal-actions auth-row">
          <button type="button" disabled={busy} onClick={() => void run(loadPause)}>
            {paused === null ? "Read peer request status" : "Refresh peer request status"}
          </button>
          {paused !== null && (
            <button type="button" disabled={busy} onClick={() => void togglePause()}>
              {paused ? "Resume new peer requests" : "Pause new peer requests"}
            </button>
          )}
        </div>
        {paused !== null && <p className="auth-modal-copy" role="status">New peer requests {paused ? "paused" : "enabled"}.</p>}
        <form onSubmit={event => { event.preventDefault(); void run(findSessions); }}>
          <label htmlFor="containment-account">Exact account ID or fingerprint</label>
          <input
            id="containment-account" className="auth-input" type="text" autoComplete="off"
            maxLength={128} value={lookup} disabled={busy} onChange={event => setLookup(event.target.value)}
          />
          <div className="auth-modal-actions auth-row">
            <button type="submit" disabled={busy || !lookup.trim()}>Find active sessions</button>
          </div>
        </form>
        {account && (
          <div>
            <p className="auth-modal-copy">Account {account.fingerprint}</p>
            {account.sessions.length ? <>
              <label htmlFor="containment-session">Session</label>
              <select
                id="containment-session" className="auth-input" value={selected}
                disabled={busy} onChange={event => setSelected(event.target.value)}
              >
                <option value="">Choose a session</option>
                {account.sessions.map(session => (
                  <option key={session.reference} value={session.reference} disabled={session.current || session.revoked}>
                    {session.reference.slice(0, 12)} · {session.createdAt ? new Date(session.createdAt).toLocaleString() : "Creation time unavailable"}
                    {session.current ? " · This session" : session.revoked ? " · Revoked" : ""}
                  </option>
                ))}
              </select>
              <div className="auth-modal-actions auth-row">
                <button type="button" disabled={busy || !selected} onClick={() => void revoke()}>Revoke selected session</button>
              </div>
            </> : <p className="auth-modal-copy">No active sessions found.</p>}
          </div>
        )}
        {lastRevoked && (
          <div className="auth-modal-actions auth-row">
            <button type="button" disabled={busy} onClick={() => void run(() => retest())}>Retest containment</button>
            {canRetry && <button type="button" disabled={busy} onClick={() => void run(() => retest(true))}>Retry disconnection</button>}
          </div>
        )}
        {notice && <p className="auth-inline-ok" role="status">{notice}</p>}
        {error && <p className="auth-error" role="alert">{error}</p>}
      </> : <p className="auth-modal-copy">Unlock privileges with your device key to use containment controls.</p>}
    </section>
  );
}
