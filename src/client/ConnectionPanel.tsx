import React, { useEffect, useRef, useState } from "react";
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
type LocalChecks = {
  http: HttpCheck | null;
  websocketMs: number | null;
  socketConnectedAt: number | null;
  webRtc: boolean;
  checkedAt: number;
};

type BrowserNetwork = EventTarget & {
  effectiveType?: string;
  rtt?: number;
  downlink?: number;
  saveData?: boolean;
};

function browserNetwork(): BrowserNetwork | undefined {
  return (navigator as Navigator & { connection?: BrowserNetwork }).connection;
}

function browserEstimate(network: BrowserNetwork | undefined): string {
  if (!network) return "";
  return [
    network.effectiveType?.toUpperCase(),
    typeof network.rtt === "number" && Number.isFinite(network.rtt) ? network.rtt + " ms RTT" : "",
    typeof network.downlink === "number" && Number.isFinite(network.downlink) ? network.downlink + " Mb/s" : "",
    network.saveData ? "Data Saver on" : "",
  ].filter(Boolean).join(" · ");
}

async function checkGlobeHttp(cancel?: AbortSignal): Promise<HttpCheck | null> {
  const started = performance.now();
  const controller = new AbortController();
  const abort = () => controller.abort();
  const timeout = window.setTimeout(abort, 5_000);
  if (cancel?.aborted) abort();
  else cancel?.addEventListener("abort", abort, { once: true });
  try {
    const response = await fetch(CONNECTION_CHECK_PATH, {
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal: controller.signal,
    });
    if (!response.ok) return null;
    const details = await response.json() as ConnectionDetails;
    if (!details || !["verified", "no-session", "unknown"].includes(details.sessionCookie)) return null;
    return { ms: Math.max(0, Math.round(performance.now() - started)), details };
  } catch {
    return null;
  } finally {
    window.clearTimeout(timeout);
    cancel?.removeEventListener("abort", abort);
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
  if (check === "tls") {
    const version = http.details.tlsVersion;
    if (!version) return "unknown";
    return version === "TLSv1.2" || version === "TLSv1.3" ? "passed" : "unavailable";
  }
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
  const { canRequest, self, peers, incoming, outgoing, notice, setAvailability, requestCheck, reply, pingSocket, socketHistory } = signals;
  const [online, setOnline] = useState(() => navigator.onLine);
  const [estimate, setEstimate] = useState(() => browserEstimate(browserNetwork()));
  const [results, setResults] = useState<LocalChecks | null>(null);
  const [checking, setChecking] = useState(true);
  const [checkRun, setCheckRun] = useState(0);
  const [replying, setReplying] = useState(false);
  const [selectedPeer, setSelectedPeer] = useState("");
  const [check, setCheck] = useState<ConnectionCheck>("http");
  const requestSection = useRef<HTMLElement>(null);
  const to = peers.includes(selectedPeer) ? selectedPeer : "";

  useEffect(() => {
    const network = browserNetwork();
    const update = () => {
      setOnline(navigator.onLine);
      setEstimate(browserEstimate(network));
    };
    window.addEventListener("online", update);
    window.addEventListener("offline", update);
    network?.addEventListener("change", update);
    return () => {
      window.removeEventListener("online", update);
      window.removeEventListener("offline", update);
      network?.removeEventListener("change", update);
    };
  }, []);

  useEffect(() => {
    const run = new AbortController();
    setChecking(true);
    void Promise.all([checkGlobeHttp(run.signal), pingSocket()]).then(([http, websocketMs]) => {
      if (run.signal.aborted) return;
      setResults({
        http,
        websocketMs,
        socketConnectedAt: socketHistory.connectedAt,
        webRtc: checkWebRtc(),
        checkedAt: Date.now(),
      });
      setChecking(false);
    });
    return () => run.abort();
  }, [checkRun, pingSocket, socketHistory.connectedAt]);

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
  const websocketMs = socketStatus === "connected" && results?.socketConnectedAt === socketHistory.connectedAt
    ? results?.websocketMs : null;
  const network = [details?.networkOrganization, details?.networkAsn ? "AS" + details.networkAsn : null]
    .filter(Boolean).join(" · ");
  const socketLabel = socketStatus === "connected" ? "Connected" : socketStatus === "connecting" ? "Connecting" : "Offline";
  const cookie = details?.sessionCookie === "verified" ? "Session verified"
    : details?.sessionCookie === "no-session" ? "No active Globe session" : "Unknown";

  return (
    <div className="feed-connection">
      <section className="feed-connection-card" aria-labelledby="feed-current-connection">
        <div className="feed-connection-heading">
          <h4 id="feed-current-connection">Current connection</h4>
          <div className="feed-connection-buttons">
            <button type="button" onClick={() => requestSection.current?.focus()}>
              Requests
            </button>
            <button type="button" onClick={() => setCheckRun(run => run + 1)} disabled={checking}>
              {checking ? "Checking…" : "Run checks"}
            </button>
          </div>
        </div>
        <dl className="feed-connection-details">
          <div><dt>Browser network</dt><dd>{online ? "Online" : "Offline"}</dd></div>
          {estimate && <div><dt>Browser estimate</dt><dd>{estimate}</dd></div>}
          <div><dt>Globe WebSocket</dt><dd>{socketLabel}{websocketMs != null ? " · " + websocketMs + " ms" : ""}</dd></div>
          {socketStatus === "connected" && socketHistory.connectedAt !== null && (
            <div><dt>Connected since</dt><dd>{new Date(socketHistory.connectedAt).toLocaleTimeString()}</dd></div>
          )}
          <div><dt>Reconnects this tab</dt><dd>{Math.max(0, socketHistory.connections - 1)}</dd></div>
          {socketHistory.disconnectedAt !== null && (
            <div><dt>Last disconnect</dt><dd>{new Date(socketHistory.disconnectedAt).toLocaleTimeString()}</dd></div>
          )}
        </dl>
        {results ? <>
          <h5 className="feed-connection-subheading">Last check</h5>
          <dl className="feed-connection-details">
            <div><dt>HTTPS round trip</dt><dd>{http ? http.ms + " ms" : "Unknown"}</dd></div>
            <div><dt>HTTP / TLS</dt><dd>{[details?.httpProtocol, details?.tlsVersion].filter(Boolean).join(" · ") || "Unknown"}</dd></div>
            <div><dt>TLS cipher</dt><dd>{details?.tlsCipher || "Unavailable"}</dd></div>
            <div><dt>Cloudflare edge</dt><dd>{[details?.edge, details?.country].filter(Boolean).join(" · ") || "Unknown"}</dd></div>
            <div><dt>Edge TCP estimate</dt><dd>{details?.edgeTcpMs != null ? details.edgeTcpMs + " ms" : "Unavailable"}</dd></div>
            <div><dt>Network</dt><dd>{network || "Unavailable"}</dd></div>
            <div><dt>Globe session cookie</dt><dd>{cookie}</dd></div>
            <div><dt>WebRTC data channels</dt><dd>{results.webRtc ? "Browser support available" : "Unavailable"}</dd></div>
          </dl>
          <p className="feed-connection-note" role="status">Checked at {new Date(results.checkedAt).toLocaleTimeString()}.</p>
        </> : <p className="feed-connection-note" role="status">Checking your connection to Globe…</p>}
      </section>

      <section className="feed-connection-card" aria-labelledby="feed-peer-requests" ref={requestSection} tabIndex={-1}>
        <h4 id="feed-peer-requests">Connection requests</h4>
        <p className="feed-connection-note">Requests travel through Globe. Each peer chooses whether to run the check and share its status.</p>
        {!canRequest ? (
          <div className="feed-connection-heading">
            <p>{access === "login_required" ? "Sign in to send and receive requests."
              : access === "payment_required" ? "Live Feed access is required."
                : socketStatus === "connected" ? "Waiting for the signed-in Globe connection."
                  : "Reconnect to Globe to use requests."}</p>
            {access === "login_required" && onSignIn && <button type="button" onClick={onSignIn}>Sign in</button>}
          </div>
        ) : (
          <>
            <label className="feed-connection-consent">
              <input type="checkbox" checked={Boolean(self)} onChange={e => setAvailability(e.target.checked)} />
              Join the list of peers who accept requests
            </label>
            {self && <p className="feed-connection-note">Your label is <strong>{signalPeerLabel(self)}</strong> for this connection.</p>}
            <form className="feed-connection-form" onSubmit={e => {
              e.preventDefault();
              if (self && to && (!outgoing || outgoing.outcome)) requestCheck(to, check);
            }}>
              <div className="feed-connection-field">
                <label htmlFor="feed-connection-check">Check</label>
                <select id="feed-connection-check" value={check} onChange={e => { if (isConnectionCheck(e.target.value)) setCheck(e.target.value); }}>
                  {Object.entries(CONNECTION_CHECKS).map(([key, label]) => <option key={key} value={key}>{label}</option>)}
                </select>
              </div>
              <div className="feed-connection-field">
                <label htmlFor="feed-connection-peer">Peer</label>
                <select id="feed-connection-peer" value={to} onChange={e => setSelectedPeer(e.target.value)} disabled={!self || !peers.length}>
                  <option value="">{!self ? "Join the request list first" : peers.length ? "Choose a peer" : "No opted-in peers online"}</option>
                  {peers.map(id => <option key={id} value={id}>{signalPeerLabel(id)}</option>)}
                </select>
              </div>
              <button type="submit" disabled={!self || !to || Boolean(outgoing && !outgoing.outcome)}>Send request</button>
            </form>
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
