import {
  isCheckOutcome,
  isConnectionCheck,
  isSignalId,
  SIGNAL_TTL_MS,
  type SignalServerMessage,
} from "../connectionSignals";
import { getSessionUser, userHasFeatureAccess, type AuthEnv } from "./auth";

type Socket = Pick<WebSocket, "send" | "readyState">;
type Peer = {
  id: string;
  socket: Socket;
  incoming?: string;
  outgoing?: string;
  nextRequestAt: number;
};
type PendingSignal = {
  id: string;
  sender: Peer;
  recipient: Peer;
  expiresAt: number;
};

/** Scoped to the existing Globe room. Consent and pending requests end with the socket. */
export class FeedConnectionSignals {
  private sessions = new WeakMap<Socket, string>();
  private bySocket = new Map<Socket, Peer>();
  private peers = new Map<string, Peer>();
  private pending = new Map<string, PendingSignal>();
  private lastPing = new WeakMap<Socket, number>();
  private lastAction = new WeakMap<Socket, number>();
  private enabling = new WeakMap<Socket, symbol>();

  constructor(private env: AuthEnv) {}

  connect(socket: Socket, sessionId?: string) {
    if (sessionId) this.sessions.set(socket, sessionId);
    this.send(socket, { type: "signal-capabilities", canRequest: Boolean(sessionId) });
  }

  disconnect(socket: Socket) {
    this.sessions.delete(socket);
    this.enabling.delete(socket);
    this.leave(socket);
  }

  async handle(socket: Socket, message: Record<string, unknown>) {
    if (socket.readyState !== WebSocket.OPEN) return;
    const now = Date.now();
    const fields = Object.keys(message).length;
    if (message.type === "connection-ping" && fields === 2 && isSignalId(message.id)) {
      if (now - (this.lastPing.get(socket) ?? 0) < 1_000) return;
      this.lastPing.set(socket, now);
      this.send(socket, { type: "connection-pong", id: message.id });
      return;
    }
    if (!this.sessions.has(socket)) return;
    if (message.type === "signal-availability" && fields === 2 && message.accepting === false) {
      this.enabling.delete(socket);
      this.leave(socket);
      this.send(socket, { type: "signal-roster", self: null, peers: [] });
      return;
    }
    if (message.type !== "signal-availability" && message.type !== "signal-request" && message.type !== "signal-reply") return;
    if (now - (this.lastAction.get(socket) ?? 0) < 350) {
      this.send(socket, { type: "signal-error", reason: "rate-limit" });
      return;
    }
    this.lastAction.set(socket, now);
    this.expireSignals(now);

    if (message.type === "signal-availability" && fields === 2 && message.accepting === true) {
      const attempt = Symbol();
      this.enabling.set(socket, attempt);
      const allowed = await this.authorized(socket);
      if (this.enabling.get(socket) !== attempt || socket.readyState !== WebSocket.OPEN) return;
      this.enabling.delete(socket);
      if (!allowed) {
        this.disconnect(socket);
        this.send(socket, { type: "signal-capabilities", canRequest: false });
        return;
      }
      let peer = this.bySocket.get(socket);
      if (!peer) {
        peer = { id: crypto.randomUUID(), socket, nextRequestAt: 0 };
        this.bySocket.set(socket, peer);
        this.peers.set(peer.id, peer);
        this.publishPeer(peer, true);
      }
      this.send(socket, {
        type: "signal-roster", self: peer.id, peers: [...this.peers.keys()].filter(id => id !== peer.id),
      });
      return;
    }

    const peer = this.bySocket.get(socket);
    if (!peer) return;
    if (message.type === "signal-request" && fields === 3 && isSignalId(message.to) && isConnectionCheck(message.check)) {
      const recipient = this.peers.get(message.to);
      if (!recipient || peer === recipient) return this.send(socket, { type: "signal-error", reason: "unavailable" });
      if (peer.nextRequestAt > now) return this.send(socket, { type: "signal-error", reason: "rate-limit" });
      peer.nextRequestAt = now + 10_000;
      if (peer.outgoing || recipient.incoming) return this.send(socket, { type: "signal-error", reason: "busy" });
      if (!(await this.canExchange(peer, recipient))) {
        return this.send(socket, { type: "signal-error", reason: "unavailable" });
      }
      if (peer.outgoing || recipient.incoming) return this.send(socket, { type: "signal-error", reason: "busy" });
      const id = crypto.randomUUID();
      const invitation = { id, from: peer.id, check: message.check };
      if (!this.send(recipient.socket, { type: "signal-invite", invitation })) {
        return this.send(socket, { type: "signal-error", reason: "unavailable" });
      }
      peer.outgoing = id;
      recipient.incoming = id;
      this.pending.set(id, { id, sender: peer, recipient, expiresAt: Date.now() + SIGNAL_TTL_MS });
      this.send(socket, { type: "signal-sent", id, to: recipient.id, check: message.check });
      return;
    }
    if (message.type === "signal-reply" && fields === 3 && isSignalId(message.id) && isCheckOutcome(message.outcome)) {
      const signal = this.pending.get(message.id);
      if (!signal || signal.recipient !== peer) return;
      const allowed = await this.canExchange(signal.sender, peer);
      if (this.pending.get(signal.id) !== signal) return;
      this.clear(signal);
      this.send(socket, { type: "signal-cancel", id: signal.id });
      if (!allowed || signal.expiresAt <= Date.now()) {
        this.send(signal.sender.socket, { type: "signal-cancel", id: signal.id });
        return;
      }
      this.send(signal.sender.socket, { type: "signal-result", id: signal.id, outcome: message.outcome });
    }
  }

  private async authorized(socket: Socket): Promise<boolean> {
    const sessionId = this.sessions.get(socket);
    if (!sessionId) return false;
    try {
      const request = new Request("https://globe.internal/", { headers: { authorization: "Bearer " + sessionId } });
      const session = await getSessionUser(request, this.env);
      return Boolean(session && userHasFeatureAccess(session.user, this.env));
    } catch {
      return false;
    }
  }

  private async canExchange(sender: Peer, recipient: Peer): Promise<boolean> {
    const [senderAllowed, recipientAllowed] = await Promise.all([
      this.authorized(sender.socket), this.authorized(recipient.socket),
    ]);
    return senderAllowed && recipientAllowed &&
      this.bySocket.get(sender.socket) === sender && this.bySocket.get(recipient.socket) === recipient &&
      sender.socket.readyState === WebSocket.OPEN && recipient.socket.readyState === WebSocket.OPEN;
  }

  private send(socket: Socket, message: SignalServerMessage): boolean {
    if (socket.readyState !== WebSocket.OPEN) return false;
    try {
      socket.send(JSON.stringify(message));
      return true;
    } catch {
      return false;
    }
  }

  private publishPeer(peer: Peer, online: boolean) {
    for (const other of this.peers.values()) {
      if (other !== peer) this.send(other.socket, { type: "signal-peer", id: peer.id, online });
    }
  }

  private leave(socket: Socket) {
    const peer = this.bySocket.get(socket);
    if (!peer) return;
    this.bySocket.delete(socket);
    this.peers.delete(peer.id);
    for (const id of [peer.incoming, peer.outgoing]) {
      const signal = id && this.pending.get(id);
      if (signal) this.cancel(signal);
    }
    this.publishPeer(peer, false);
  }

  private expireSignals(now: number) {
    for (const signal of this.pending.values()) {
      if (signal.expiresAt <= now) this.cancel(signal);
    }
  }

  private cancel(signal: PendingSignal) {
    this.clear(signal);
    this.send(signal.sender.socket, { type: "signal-cancel", id: signal.id });
    this.send(signal.recipient.socket, { type: "signal-cancel", id: signal.id });
  }

  private clear(signal: PendingSignal) {
    this.pending.delete(signal.id);
    signal.sender.outgoing = undefined;
    signal.recipient.incoming = undefined;
  }
}
