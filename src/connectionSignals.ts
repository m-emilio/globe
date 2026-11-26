export const CONNECTION_CHECKS = {
  http: "HTTPS to Globe",
  cookie: "Globe session cookie",
  webrtc: "WebRTC data-channel support",
  websocket: "Globe WebSocket",
} as const;

export type ConnectionCheck = keyof typeof CONNECTION_CHECKS;
export type CheckOutcome = "passed" | "unavailable" | "unknown" | "declined";
export const SIGNAL_TTL_MS = 45_000;
export const CONNECTION_CHECK_PATH = "/api/live-feed/connection";

export type ConnectionDetails = {
  httpProtocol: string | null;
  tlsVersion: string | null;
  edge: string | null;
  country: string | null;
  sessionCookie: "verified" | "no-session" | "unknown";
};

export type SignalInvitation = {
  id: string;
  from: string;
  check: ConnectionCheck;
};

export type SignalClientMessage =
  | { type: "connection-ping"; id: string }
  | { type: "signal-availability"; accepting: boolean }
  | { type: "signal-request"; to: string; check: ConnectionCheck }
  | { type: "signal-reply"; id: string; outcome: CheckOutcome };

export type SignalServerMessage =
  | { type: "signal-capabilities"; canRequest: boolean }
  | { type: "connection-pong"; id: string }
  | { type: "signal-roster"; self: string | null; peers: string[] }
  | { type: "signal-peer"; id: string; online: boolean }
  | { type: "signal-invite"; invitation: SignalInvitation }
  | { type: "signal-sent"; id: string; to: string; check: ConnectionCheck }
  | { type: "signal-result"; id: string; outcome: CheckOutcome }
  | { type: "signal-cancel"; id: string }
  | { type: "signal-error"; reason: "unavailable" | "busy" | "rate-limit" };

export function isConnectionCheck(value: unknown): value is ConnectionCheck {
  return typeof value === "string" && Object.hasOwn(CONNECTION_CHECKS, value);
}

export function isCheckOutcome(value: unknown): value is CheckOutcome {
  return value === "passed" || value === "unavailable" || value === "unknown" || value === "declined";
}

export function isSignalId(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(value);
}

export function signalPeerLabel(id: string): string {
  return "Peer " + id.slice(0, 8);
}
