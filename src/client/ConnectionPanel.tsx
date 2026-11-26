import React, { useEffect, useState } from "react";
import {
  CONNECTION_CHECK_PATH,
  CONNECTION_CHECKS,
  isConnectionCheck,
  signalPeerLabel,
  type CheckOutcome,
  type ConnectionCheck,
  type ConnectionDetails,
  type SignalInvitation,
} from "../connectionSignals";
import type { GlobeSocketStatus, LiveFeedAccess } from "./ActivityFeed";
import type { ConnectionSignals } from "./useConnectionSignals";

type HttpCheck = { ms: number; details: ConnectionDetails };
type LocalChecks = { http: HttpCheck | null; websocketMs: number | null; webRtc: boolean; checkedAt: number };

async function checkGlobeHttp(): Promise<HttpCheck | null> {
  const started = performance.now();
  try {
    const response = await fetch(CONNECTION_CHECK_PATH, {
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(5_000),
    });
    if (!response.ok) return null;
    const details = await response.json() as ConnectionDetails;
    if (!details || !["verified", "no-session", "unknown"].includes(details.sessionCookie)) return null;
    return { ms: Math.max(0, Math.round(performance.now() - started)), details };
  } catch {
    return null;
  }
}

function checkWebRtc(): boolean {
  if (typeof RTCPeerConnection === "undefined") return false;
  let peer: RTCPeerConnection | undefined;
  try {
    peer = new RTCPeerConnection({ iceServers: [] });
    // A local API check. No offer, ICE gathering, or media permission.
    peer.createDataChannel("globe-check").close();
    return true;
  } catch {
    return false;
  } finally {
    peer?.close();
  }
}

async function runSharedCheck(check: ConnectionCheck, pingSocket: ConnectionSignals["pingSocket"]): Promise<CheckOutcome> {
  if (check === "websocket") return await pingSocket() === null ? "unknown" : "passed";
  if (check === "webrtc") return checkWebRtc() ? "passed" : "unavailable";
  const http = await checkGlobeHttp();
  if (!http) return "unknown";
  if (check === "http") return "passed";
  if (http.details.sessionCookie === "unknown") return "unknown";
  return http.details.sessionCookie === "verified" ? "passed" : "unavailable";
}

const RESULT_TEXT = {
  passed: "Passed",
  unavailable: "Unavailable on the peer’s connection",
  unknown: "No conclusive result",
  declined: "Declined by peer",
  expired: "Request timed out",
  cancelled: "Request ended",
};

export function ConnectionPanel({ signals, socketStatus, access, onSignIn }: {
  signals: ConnectionSignals;
  socketStatus: GlobeSocketStatus;
  access: LiveFeedAccess;
  onSignIn?: () => void;
}) {
  const { canRequest, self, peers, incoming, outgoing, notice, setAvailability, requestCheck, reply, pingSocket } = signals;
  const [online, setOnline] = useState(() => navigator.onLine);
  const [results, setResults] = useState<LocalChecks | null>(null);
  const [checking, setChecking] = useState(false);
  const [replying, setReplying] = useState(false);
  const [selectedPeer, setSelectedPeer] = useState("");
  const [check, setCheck] = useState<ConnectionCheck>("http");
  const to = peers.includes(selectedPeer) ? selectedPeer : "";

  useEffect(() => {
    const update = () => setOnline(navigator.onLine);
    window.addEventListener("online", update);
    window.addEventListener("offline", update);
    return () => {
      window.removeEventListener("online", update);
      window.removeEventListener("offline", update);
    };
  }, []);

  async function refresh() {
    setChecking(true);
    try {
      const [http, websocketMs] = await Promise.all([checkGlobeHttp(), pingSocket()]);
      setResults({ http, websocketMs, webRtc: checkWebRtc(), checkedAt: Date.now() });
    } finally {
      setChecking(false);
    }
  }

  async function checkAndReply(invitation: SignalInvitation) {
    setReplying(true);
    try {
      let outcome: CheckOutcome;
      try {
        outcome = await runSharedCheck(invitation.check, pingSocket);
      } catch {
        outcome = "unknown";
      }
      reply(invitation.id, outcome);
    } finally {
      setReplying(false);
    }
  }

  const http = results?.http;
  const details = http?.details;
  const cookie = details?.sessionCookie === "verified" ? "Session verified"
    : details?.sessionCookie === "no-session" ? "No active Globe session" : "Unknown";

  return (
    <div className="feed-connection">
      <section className="feed-connection-card" aria-labelledby="feed-current-connection">
        <div className="feed-connection-heading">
          <h4 id="feed-current-connection">Current connection</h4>
          <button type="button" onClick={() => void refresh()} disabled={checking}>
            {checking ? "Checking…" : "Run checks"}
          </button>
        </div>
        <dl className="feed-connection-details">
          <div><dt>Browser network</dt><dd>{online ? "Online" : "Offline"}</dd></div>
          <div><dt>Globe WebSocket</dt><dd>{socketStatus}{socketStatus === "connected" && results?.websocketMs != null ? " · " + results.websocketMs + " ms" : ""}</dd></div>
          {results && <>
            <div><dt>HTTPS to Globe</dt><dd>{http ? http.ms + " ms" : "Unknown"}</dd></div>
            <div><dt>HTTP / TLS</dt><dd>{[details?.httpProtocol, details?.tlsVersion].filter(Boolean).join(" · ") || "Unknown"}</dd></div>
            <div><dt>Cloudflare edge</dt><dd>{[details?.edge, details?.country].filter(Boolean).join(" · ") || "Unknown"}</dd></div>
            <div><dt>Globe session cookie</dt><dd>{cookie}</dd></div>
            <div><dt>WebRTC data channels</dt><dd>{results.webRtc ? "Browser support available" : "Unavailable"}</dd></div>
          </>}
        </dl>
        {results
          ? <p className="feed-connection-note" role="status">Checked at {new Date(results.checkedAt).toLocaleTimeString()}.</p>
          : <p className="feed-connection-note">Run checks for latency, edge protocol, session cookie, and WebRTC support.</p>}
      </section>

      <section className="feed-connection-card" aria-labelledby="feed-peer-requests">
        <h4 id="feed-peer-requests">Connection requests</h4>
        <p className="feed-connection-note">Requests travel through Globe. Each peer chooses whether to run the check and share its status.</p>
        {!canRequest ? (
          <div className="feed-connection-heading">
            <p>{access === "login_required" ? "Sign in to send and receive requests."
              : access === "payment_required" ? "Live Feed access is required."
                : "Waiting for the signed-in Globe connection."}</p>
            {access === "login_required" && onSignIn && <button type="button" onClick={onSignIn}>Sign in</button>}
          </div>
        ) : (
          <>
            <label className="feed-connection-consent">
              <input type="checkbox" checked={Boolean(self)} onChange={e => setAvailability(e.target.checked)} />
              Join the list of peers who accept requests
            </label>
            {self && (
              <>
                <p className="feed-connection-note">Your label is <strong>{signalPeerLabel(self)}</strong> for this connection.</p>
                <form className="feed-connection-form" onSubmit={e => { e.preventDefault(); requestCheck(to, check); }}>
                  <div className="feed-connection-field">
                    <label htmlFor="feed-connection-peer">Peer</label>
                    <select id="feed-connection-peer" value={to} onChange={e => setSelectedPeer(e.target.value)} disabled={!peers.length}>
                      <option value="">{peers.length ? "Choose a peer" : "No opted-in peers online"}</option>
                      {peers.map(id => <option key={id} value={id}>{signalPeerLabel(id)}</option>)}
                    </select>
                  </div>
                  <div className="feed-connection-field">
                    <label htmlFor="feed-connection-check">Check</label>
                    <select id="feed-connection-check" value={check} onChange={e => { if (isConnectionCheck(e.target.value)) setCheck(e.target.value); }}>
                      {Object.entries(CONNECTION_CHECKS).map(([key, label]) => <option key={key} value={key}>{label}</option>)}
                    </select>
                  </div>
                  <button type="submit" disabled={!to || Boolean(outgoing && !outgoing.outcome)}>Send request</button>
                </form>
              </>
            )}
          </>
        )}
        {incoming && self && (
          <div className="feed-connection-invite">
            <p><strong>{signalPeerLabel(incoming.from)}</strong> requested <strong>{CONNECTION_CHECKS[incoming.check]}</strong>.</p>
            <p className="feed-connection-note">The peer will receive only the check status.</p>
            <div className="feed-connection-buttons">
              <button type="button" disabled={replying} onClick={() => void checkAndReply(incoming)}>
                {replying ? "Checking…" : "Check and share status"}
              </button>
              <button type="button" disabled={replying} onClick={() => reply(incoming.id, "declined")}>Decline</button>
            </div>
          </div>
        )}
        {outgoing && self && (
          <p className="feed-connection-result" role="status">
            {CONNECTION_CHECKS[outgoing.check]} · {signalPeerLabel(outgoing.to)} · {outgoing.outcome ? RESULT_TEXT[outgoing.outcome] : "Awaiting response"}
          </p>
        )}
        {notice && <p className="feed-connection-note" role="status">{notice}</p>}
      </section>
    </div>
  );
}
