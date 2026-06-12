import { routePartykitRequest, Server } from "partyserver";

import type { OutgoingMessage, Position } from "../shared";
import type { Connection, ConnectionContext } from "partyserver";

const MAX_ACTIVE_CONNECTIONS = 500;
const MAX_CONNECTIONS_PER_IP = 8;
const CONNECTION_RATE_WINDOW_MS = 10_000;
const MAX_CONNECTIONS_PER_WINDOW = 20;
const MAX_CONNECTION_ATTEMPT_BUCKETS = 1_000;
const MAX_REPLAY_MARKERS = MAX_ACTIVE_CONNECTIONS;
const CLOSE_POLICY_VIOLATION = 1008;
const CLOSE_TRY_AGAIN_LATER = 1013;

// This is the state that we'll store on each connection
type ConnectionState = {
  position: Position;
};

type ConnectionAttemptBucket = {
  windowStart: number;
  count: number;
};

function parseBoundedCoordinate(
  value: string | undefined,
  min: number,
  max: number,
) {
  if (!value) {
    return null;
  }

  const coordinate = Number.parseFloat(value);

  if (!Number.isFinite(coordinate) || coordinate < min || coordinate > max) {
    return null;
  }

  return coordinate;
}

function limitText(value: string | undefined, maxLength: number) {
  return value ? value.trim().slice(0, maxLength) : undefined;
}

export class Globe extends Server {
  private connectionAttempts = new Map<string, ConnectionAttemptBucket>();

  private getConnectionLimitReason(clientKey: string) {
    const now = Date.now();
    this.pruneConnectionAttempts(now);

    const bucket = this.connectionAttempts.get(clientKey);

    if (!bucket && this.connectionAttempts.size >= MAX_CONNECTION_ATTEMPT_BUCKETS) {
      return "server rate limit busy";
    }

    if (!bucket || now - bucket.windowStart >= CONNECTION_RATE_WINDOW_MS) {
      this.connectionAttempts.set(clientKey, {
        windowStart: now,
        count: 1,
      });
      return null;
    }

    bucket.count += 1;

    if (bucket.count > MAX_CONNECTIONS_PER_WINDOW) {
      return "too many connection attempts";
    }

    return null;
  }

  private pruneConnectionAttempts(now: number) {
    if (this.connectionAttempts.size < MAX_CONNECTION_ATTEMPT_BUCKETS) {
      return;
    }

    for (const [clientKey, bucket] of this.connectionAttempts) {
      if (now - bucket.windowStart >= CONNECTION_RATE_WINDOW_MS) {
        this.connectionAttempts.delete(clientKey);
      }
    }
  }

  private closeConnection(conn: Connection, code: number, reason: string) {
    try {
      conn.close(code, reason);
    } catch {
      // The connection may already be closing.
    }
  }

  onConnect(conn: Connection<ConnectionState>, ctx: ConnectionContext) {
    // Whenever a fresh connection is made, we'll
    // send the entire state to the new connection

    // First, let's extract the position from the Cloudflare headers
    const latitude = ctx.request.cf?.latitude as string | undefined;
    const longitude = ctx.request.cf?.longitude as string | undefined;
    const lat = parseBoundedCoordinate(latitude, -90, 90);
    const lng = parseBoundedCoordinate(longitude, -180, 180);
    if (lat === null || lng === null) {
      console.warn(`Missing position information for connection ${conn.id}`);
      this.closeConnection(conn, CLOSE_POLICY_VIOLATION, "invalid location");
      return;
    }
    const ip = limitText(ctx.request.cf?.clientIp as string | undefined, 45);
    const clientKey = ip ?? "unknown";
    const rateLimitReason = this.getConnectionLimitReason(clientKey);

    if (rateLimitReason) {
      this.closeConnection(conn, CLOSE_TRY_AGAIN_LATER, rateLimitReason);
      return;
    }

    const connections = Array.from(this.getConnections<ConnectionState>());

    if (connections.length > MAX_ACTIVE_CONNECTIONS) {
      this.closeConnection(conn, CLOSE_TRY_AGAIN_LATER, "server at capacity");
      return;
    }

    const matchingIpConnections = connections.filter((connection) => {
      const state = connection.state as ConnectionState | undefined;
      return state?.position.ip === ip;
    });

    if (ip && matchingIpConnections.length >= MAX_CONNECTIONS_PER_IP) {
      this.closeConnection(conn, CLOSE_TRY_AGAIN_LATER, "too many connections");
      return;
    }

    const country = limitText(ctx.request.cf?.country as string | undefined, 4);
    const city = limitText(ctx.request.cf?.city as string | undefined, 80);
    const org = limitText(ctx.request.cf?.org as string | undefined, 120);

    const position = {
      lat,
      lng,
      id: conn.id,
      ip,
      country,
      city,
      org,
    };
    // And save this on the connection's state
    conn.setState({
      position,
    });

    // Now, let's send the entire state to the new connection
    let replayedMarkers = 0;
    for (const connection of connections) {
      try {
        const state = connection.state as ConnectionState | undefined;

        if (!state?.position) {
          continue;
        }

        if (replayedMarkers >= MAX_REPLAY_MARKERS) {
          break;
        }

        conn.send(
          JSON.stringify({
              type: "add-marker",
              position: state.position,
        } satisfies OutgoingMessage),
      );
        replayedMarkers += 1;

        // And let's send the new connection's position to all other connections
        if (connection.id !== conn.id) {
          connection.send(
            JSON.stringify({
              type: "add-marker",
              position,
            } satisfies OutgoingMessage),
          );
        }
      } catch {
        this.onCloseOrError(connection);
      }
    }
  }

  // Whenever a connection closes (or errors), we'll broadcast a message to all
  // other connections to remove the marker.
  onCloseOrError(connection: Connection) {
    const state = connection.state as ConnectionState | undefined;

    if (!state?.position) {
      return;
    }

    this.broadcast(
      JSON.stringify({
        type: "remove-marker",
        id: connection.id,
      } satisfies OutgoingMessage),
      [connection.id],
    );
  }

  onClose(connection: Connection): void | Promise<void> {
    this.onCloseOrError(connection);
  }

  onError(connection: Connection): void | Promise<void> {
    this.onCloseOrError(connection);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return (
      (await routePartykitRequest(request, { ...env })) ||
      new Response("Not Found", { status: 404 })
    );
  },
} satisfies ExportedHandler<Env>;
