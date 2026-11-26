import { useCallback, useEffect, useRef, useState } from "react";
import type PartySocket from "partysocket";
import {
  isSignalId,
  SIGNAL_TTL_MS,
  type CheckOutcome,
  type ConnectionCheck,
  type SignalClientMessage,
  type SignalInvitation,
  type SignalServerMessage,
} from "../connectionSignals";

type OutgoingSignal = {
  id: string;
  to: string;
  check: ConnectionCheck;
  outcome?: CheckOutcome | "expired" | "cancelled";
};
type Ping = { id: string; promise: Promise<number | null>; finish: (ms: number | null) => void };

const SIGNAL_ERRORS = {
  unavailable: "That peer is unavailable. Choose an online peer and try again.",
  busy: "A check is already pending. Try again when it finishes.",
  "rate-limit": "Please wait a few seconds before trying again.",
};

export function useConnectionSignals(socket: PartySocket, hasFeedAccess: boolean) {
  const [allowed, setAllowed] = useState(false);
  const [self, setSelf] = useState<string | null>(null);
  const [peers, setPeers] = useState<string[]>([]);
  const [incoming, setIncoming] = useState<SignalInvitation | null>(null);
  const [outgoing, setOutgoing] = useState<OutgoingSignal | null>(null);
  const [notice, setNotice] = useState("");
  const ping = useRef<Ping | null>(null);

  const send = useCallback((message: SignalClientMessage) => {
    if (socket.readyState !== WebSocket.OPEN) return false;
    try {
      socket.send(JSON.stringify(message));
      return true;
    } catch {
      return false;
    }
  }, [socket]);

  const clearRoster = useCallback(() => {
    setSelf(null);
    setPeers([]);
    setIncoming(null);
    setOutgoing(null);
    setNotice("");
  }, []);

  useEffect(() => {
    const onClose = () => {
      setAllowed(false);
      clearRoster();
      ping.current?.finish(null);
    };
    const onMessage = (event: MessageEvent) => {
      if (typeof event.data !== "string" || event.data.length > 24_000) return;
      let message: SignalServerMessage;
      try {
        message = JSON.parse(event.data);
        if (!message || typeof message !== "object") return;
      } catch {
        return;
      }
      switch (message.type) {
        case "signal-capabilities":
          setAllowed(message.canRequest === true);
          if (!message.canRequest) clearRoster();
          break;
        case "connection-pong": {
          const waiting = ping.current;
          if (waiting?.id === message.id) waiting.finish(performance.now());
          break;
        }
        case "signal-roster":
          if (isSignalId(message.self)) {
            setSelf(message.self);
            setPeers(message.peers.filter(isSignalId));
            setNotice("");
          } else clearRoster();
          break;
        case "signal-peer":
          if (!isSignalId(message.id)) return;
          setPeers(prev => message.online
            ? prev.includes(message.id) ? prev : [...prev, message.id]
            : prev.filter(id => id !== message.id));
          break;
        case "signal-invite":
          setIncoming(message.invitation);
          break;
        case "signal-sent":
          setNotice("");
          setOutgoing({ id: message.id, to: message.to, check: message.check });
          break;
        case "signal-result":
          setOutgoing(prev => prev?.id === message.id ? { ...prev, outcome: message.outcome } : prev);
          break;
        case "signal-cancel":
          setIncoming(prev => prev?.id === message.id ? null : prev);
          setOutgoing(prev => prev?.id === message.id && !prev.outcome ? { ...prev, outcome: "cancelled" } : prev);
          break;
        case "signal-error":
          setNotice(SIGNAL_ERRORS[message.reason] ?? SIGNAL_ERRORS.unavailable);
          break;
      }
    };
    socket.addEventListener("message", onMessage);
    socket.addEventListener("close", onClose);
    return () => {
      socket.removeEventListener("message", onMessage);
      socket.removeEventListener("close", onClose);
      ping.current?.finish(null);
    };
  }, [socket, clearRoster]);

  useEffect(() => {
    if (hasFeedAccess || !self) return;
    send({ type: "signal-availability", accepting: false });
    clearRoster();
  }, [hasFeedAccess, self, send, clearRoster]);

  useEffect(() => {
    if (!incoming) return;
    const timer = window.setTimeout(() => setIncoming(null), SIGNAL_TTL_MS);
    return () => window.clearTimeout(timer);
  }, [incoming]);

  useEffect(() => {
    if (!outgoing || outgoing.outcome) return;
    const timer = window.setTimeout(() => {
      setOutgoing(prev => prev?.id === outgoing.id ? { ...prev, outcome: "expired" } : prev);
    }, SIGNAL_TTL_MS);
    return () => window.clearTimeout(timer);
  }, [outgoing]);

  const canRequest = allowed && hasFeedAccess;

  function setAvailability(accepting: boolean) {
    if (!canRequest || !send({ type: "signal-availability", accepting })) {
      setNotice("Connect to Globe and sign in to use connection requests.");
      return;
    }
    if (!accepting) clearRoster();
    else setNotice("Joining the connection check list…");
  }

  function requestCheck(to: string, check: ConnectionCheck) {
    if (!canRequest || !self || !peers.includes(to) || !send({ type: "signal-request", to, check })) {
      setNotice(SIGNAL_ERRORS.unavailable);
      return;
    }
    setNotice("Requesting check…");
  }

  function reply(id: string, outcome: CheckOutcome) {
    if (!canRequest || !self || !send({ type: "signal-reply", id, outcome })) {
      setNotice("Globe disconnected before the result could be shared.");
    }
    setIncoming(prev => prev?.id === id ? null : prev);
  }

  const pingSocket = useCallback((): Promise<number | null> => {
    if (ping.current) return ping.current.promise;
    if (socket.readyState !== WebSocket.OPEN || typeof crypto.randomUUID !== "function") {
      return Promise.resolve(null);
    }
    const started = performance.now();
    const id = crypto.randomUUID();
    let resolve!: (ms: number | null) => void;
    const promise = new Promise<number | null>(done => { resolve = done; });
    const timer = window.setTimeout(() => finish(null), 4_000);
    function finish(time: number | null) {
      window.clearTimeout(timer);
      if (ping.current?.id === id) ping.current = null;
      resolve(time === null ? null : Math.max(0, Math.round(time - started)));
    }
    ping.current = { id, promise, finish };
    if (!send({ type: "connection-ping", id })) finish(null);
    return promise;
  }, [send, socket]);

  return { canRequest, self, peers, incoming, outgoing, notice, setAvailability, requestCheck, reply, pingSocket };
}

export type ConnectionSignals = ReturnType<typeof useConnectionSignals>;
