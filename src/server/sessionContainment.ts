type SessionRevocationReader = {
  isSessionRevoked(reference: string): Promise<boolean>;
};

export type SessionGuard = {
  PURPLE_TEAM_DIRECTORY?: DurableObjectNamespace<import("./purpleTeamDirectory").PurpleTeamDirectory>;
  sessionRevocations?: SessionRevocationReader;
};

export async function sessionReference(sessionId: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(sessionId));
  return Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, "0")).join("");
}

export function validSessionReference(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

export function closeSessionSockets<Socket extends { state: { sessionRef?: string } | null }>(
  sockets: Iterable<Socket>,
  reference: string,
  close: (socket: Socket) => void,
): number {
  let closed = 0;
  for (const socket of sockets) {
    if (socket.state?.sessionRef !== reference) continue;
    close(socket);
    closed++;
  }
  return closed;
}
