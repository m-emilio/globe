import type { SignalServerMessage } from "../connectionSignals";
import { authSessionStorageKey, authUserStorageKey, getSessionUser, type SessionAuthEnv } from "./auth";
import { FeedConnectionSignals } from "./feedConnectionSignals";
import { closeSessionSockets, sessionReference } from "./sessionContainment";
import type { ToolFinding } from "./verifiedDomainScan";

function testResult(check: string, passed: boolean, evidence: string): ToolFinding {
  return { check, status: passed ? "pass" : "review", evidence };
}

function fixtureSessions() {
  const records = new Map<string, string>();
  const revoked = new Set<string>();
  const env: SessionAuthEnv = {
    BILLING_KV: {
      async get(key) { return records.get(key) ?? null; },
      async delete(key) { records.delete(key); },
    },
    sessionRevocations: { async isSessionRevoked(ref) { return revoked.has(ref); } },
  };
  const at = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 60_000).toISOString();
  const sessions = ["one", "two", "observer"].map(label => {
    const sessionId = crypto.randomUUID().replaceAll("-", "") + crypto.randomUUID().replaceAll("-", "");
    const userId = "exercise-" + label;
    records.set(authUserStorageKey(userId), JSON.stringify({
      id: userId, fingerprint: "f".repeat(40), publicKeyArmored: "exercise fixture",
      primaryUserId: null, createdAt: at,
    }));
    records.set(authSessionStorageKey(sessionId), JSON.stringify({ userId, createdAt: at, expiresAt }));
    return sessionId;
  });
  return { env, revoked, sessions, records };
}

export async function runSessionContainmentDrill(): Promise<ToolFinding[]> {
  const { env, revoked, sessions, records } = fixtureSessions();
  const reference = await sessionReference(sessions[0]);
  const other = await sessionReference(sessions[1]);
  const request = (sessionId: string) => new Request("https://globe.internal/api/admin/status", {
    headers: { authorization: "Bearer " + sessionId },
  });
  const before = await getSessionUser(request(sessions[0]), env);
  const testRoom = [
    { state: { sessionRef: reference }, open: true },
    { state: { sessionRef: other }, open: true },
  ];
  const started = Date.now();
  revoked.add(reference);
  const closed = closeSessionSockets(testRoom, reference, socket => { socket.open = false; });
  const after = await getSessionUser(request(sessions[0]), env);
  const unaffected = await getSessionUser(request(sessions[1]), env);
  return [
    testResult("Disposable session denied", Boolean(before && !after && records.has(authSessionStorageKey(sessions[0]))),
      (after ? "Session accepted after revocation." : "Session denied after revocation.") +
      " The test retained a stale session record to verify the revocation check."),
    testResult("Open socket matched for disconnect", closed === 1 && !testRoom[0].open,
      "Matched " + closed + " socket in the isolated exercise in " + (Date.now() - started) + " ms."),
    testResult("Other session and socket remain active", Boolean(unaffected && testRoom[1].open),
      "The second exercise identity and socket served as the control."),
  ];
}

function exerciseSocket() {
  const events: SignalServerMessage[] = [];
  return {
    readyState: WebSocket.OPEN,
    events,
    send(payload: string) { events.push(JSON.parse(payload)); },
  };
}

export async function runFeedIsolationDrill(): Promise<ToolFinding[]> {
  const { env, sessions } = fixtureSessions();
  const [sender, recipient, observer] = sessions.map(() => exerciseSocket());
  const engine = new FeedConnectionSignals(env);
  for (const [index, socket] of [sender, recipient, observer].entries()) engine.connect(socket, sessions[index]);
  await engine.handle(sender, { type: "signal-availability", accepting: true });
  const before = sender.events.find(event => event.type === "signal-roster");
  await engine.handle(recipient, { type: "signal-availability", accepting: true });
  await engine.handle(observer, { type: "signal-availability", accepting: true });
  const to = recipient.events.find(event => event.type === "signal-roster")?.self;
  const from = sender.events.find(event => event.type === "signal-roster")?.self;
  await engine.handle(sender, { type: "signal-request", to, check: "http" });
  const incoming = recipient.events.find(event => event.type === "signal-invite")?.invitation;
  const privateDelivery = Boolean(incoming && ![sender, observer].some(socket =>
    socket.events.some(event => event.type === "signal-invite")));
  if (incoming) await engine.handle(recipient, { type: "signal-reply", id: incoming.id, outcome: "passed" });
  const accepted = sender.events.find(event => event.type === "signal-result");
  const privateReply = accepted?.outcome === "passed" && Object.keys(accepted).length === 3 &&
    !observer.events.some(event => event.type === "signal-result");

  await engine.handle(recipient, { type: "signal-request", to: from, check: "cookie" });
  const reverse = sender.events.find(event => event.type === "signal-invite")?.invitation;
  if (reverse) await engine.handle(sender, { type: "signal-reply", id: reverse.id, outcome: "declined" });
  const declined = recipient.events.some(event => event.type === "signal-result" && event.outcome === "declined");

  await engine.handle(recipient, { type: "signal-availability", accepting: false });
  await engine.handle(observer, { type: "signal-request", to, check: "http" });
  const optedOut = observer.events.some(event => event.type === "signal-peer" && event.id === to && !event.online) &&
    observer.events.some(event => event.type === "signal-error" && event.reason === "unavailable") &&
    recipient.events.filter(event => event.type === "signal-invite").length === 1;
  return [
    testResult("Opt-in before visibility", Boolean(before?.self && before.peers.length === 0), "A recipient is listed after joining the exercise room’s request roster."),
    testResult("Invitation and status stay private", privateDelivery && privateReply, "The selected peer received the invitation and the requester received the typed status."),
    testResult("Decline and opt-out", declined && optedOut, "The decline reached its requester. The opted-out peer left the roster and received no subsequent invitation."),
  ];
}
