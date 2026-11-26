import { DurableObject } from "cloudflare:workers";
import type { AlertRow, AlertState, OperationsAlert } from "./securityOperationsModel";
import { validSessionReference } from "./sessionContainment";

export const CANARY_PATH = "/purple-team/canary/";

export class PurpleTeamDirectory extends DurableObject {
  constructor(ctx: DurableObjectState, env: unknown) {
    super(ctx, env);
    this.ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS hosts (hostname TEXT PRIMARY KEY)");
    this.ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS canaries (id TEXT PRIMARY KEY, armed INTEGER, hit INTEGER)");
    this.ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS revoked_sessions (reference TEXT PRIMARY KEY, expires INTEGER NOT NULL)");
    this.ctx.storage.sql.exec("CREATE INDEX IF NOT EXISTS revoked_session_expiry ON revoked_sessions(expires)");
    this.ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS session_rooms (reference TEXT NOT NULL, room TEXT NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY (reference, room))");
    this.ctx.storage.sql.exec("CREATE INDEX IF NOT EXISTS session_room_expiry ON session_rooms(expires)");
    this.ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS operations_settings (name TEXT PRIMARY KEY, value INTEGER NOT NULL)");
    this.ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS operations_alerts (
      id TEXT PRIMARY KEY, at INTEGER NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL,
      exercise INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'open',
      updatedAt INTEGER NOT NULL DEFAULT 0, updatedBy TEXT NOT NULL DEFAULT ''
    )`);
  }

  addHost(hostname: string): void {
    this.ctx.storage.sql.exec("INSERT OR IGNORE INTO hosts (hostname) VALUES (?)", hostname);
  }

  hostnames(): string[] {
    return this.ctx.storage.sql.exec<{ hostname: string }>("SELECT hostname FROM hosts ORDER BY hostname")
      .toArray().map((item) => item.hostname);
  }

  armCanary(id: string): void {
    const now = Date.now();
    this.ctx.storage.sql.exec("DELETE FROM canaries WHERE armed < ?", now - 300_000);
    this.ctx.storage.sql.exec("INSERT INTO canaries (id, armed, hit) VALUES (?, ?, NULL)", id, now);
  }

  hitCanary(id: string): void {
    const now = Date.now();
    this.ctx.storage.sql.exec("UPDATE canaries SET hit = ? WHERE id = ? AND hit IS NULL AND armed >= ?", now, id, now - 60_000);
  }

  canaryReceipt(id: string): { armed: number; hit: number | null } | null {
    const row = this.ctx.storage.sql.exec<{ armed: number; hit: number | null }>(
      "SELECT armed, hit FROM canaries WHERE id = ?",
      id,
    ).toArray()[0];
    return row ?? null;
  }

  isSessionRevoked(reference: string): boolean {
    const result = this.ctx.storage.sql.exec("SELECT 1 FROM revoked_sessions WHERE reference = ? AND expires > ?", reference, Date.now());
    return result.toArray().length > 0;
  }

  registerSessionRoom(reference: string, room: string, expires: number): boolean {
    const now = Date.now();
    if (!validSessionReference(reference) || !room || room.length > 200 ||
        !Number.isFinite(expires) || expires <= now || this.isSessionRevoked(reference)) return false;
    const sql = this.ctx.storage.sql;
    sql.exec("DELETE FROM session_rooms WHERE expires <= ?", now);
    const rooms = this.sessionRooms(reference);
    if (!rooms.includes(room) && rooms.length >= 8) return false;
    sql.exec("INSERT OR IGNORE INTO session_rooms (reference, room, expires) VALUES (?, ?, ?)", reference, room, expires);
    return true;
  }

  sessionRooms(reference: string): string[] {
    return this.ctx.storage.sql.exec<{ room: string }>(
      "SELECT room FROM session_rooms WHERE reference = ? AND expires > ? ORDER BY room",
      reference, Date.now(),
    ).toArray().map(row => row.room);
  }

  revokeSession(reference: string, expires: number): void {
    const now = Date.now();
    if (!validSessionReference(reference) || !Number.isFinite(expires) || expires <= now) {
      throw new Error("Invalid session revocation");
    }
    const sql = this.ctx.storage.sql;
    sql.exec("DELETE FROM revoked_sessions WHERE expires <= ?", now);
    sql.exec(`INSERT INTO revoked_sessions (reference, expires) VALUES (?, ?)
      ON CONFLICT(reference) DO UPDATE SET expires = MAX(expires, excluded.expires)`, reference, expires);
  }

  peerRequestsPaused(): boolean {
    const row = this.ctx.storage.sql.exec<{ value: number }>(
      "SELECT value FROM operations_settings WHERE name = 'peer_requests_paused'",
    ).toArray()[0];
    return row?.value === 1;
  }

  setPeerRequestsPaused(paused: boolean): void {
    this.ctx.storage.sql.exec(`INSERT INTO operations_settings (name, value) VALUES ('peer_requests_paused', ?)
      ON CONFLICT(name) DO UPDATE SET value = excluded.value`, Number(paused));
  }

  recordOperationsAlerts(alerts: OperationsAlert[]): void {
    const sql = this.ctx.storage.sql;
    for (const event of alerts.slice(0, 20)) {
      sql.exec(`INSERT INTO operations_alerts (id, at, kind, detail, exercise)
        VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET
        at = MAX(at, excluded.at), detail = CASE WHEN excluded.at >= at THEN excluded.detail ELSE detail END`,
        event.id, event.at, event.kind, event.detail, Number(event.exercise));
    }
    sql.exec("DELETE FROM operations_alerts WHERE at < ?", Date.now() - 14 * 86_400_000);
    sql.exec("DELETE FROM operations_alerts WHERE id IN (SELECT id FROM operations_alerts ORDER BY at DESC, id LIMIT -1 OFFSET 120)");
  }

  operationsAlerts(): AlertRow[] {
    return this.ctx.storage.sql.exec<Omit<AlertRow, "exercise"> & { exercise: number }>(`SELECT *
      FROM operations_alerts WHERE at >= ? ORDER BY state = 'resolved', at DESC, id LIMIT 32`,
      Date.now() - 14 * 86_400_000).toArray().map(row => ({ ...row, exercise: row.exercise === 1 }));
  }

  setOperationsAlertState(id: string, state: AlertState, actor: string): boolean {
    const result = this.ctx.storage.sql.exec(`UPDATE operations_alerts SET state = ?, updatedBy = ?, updatedAt = ?
      WHERE id = ? AND at >= ? AND state != ?`, state, actor, Date.now(), id, Date.now() - 14 * 86_400_000, state);
    return result.rowsWritten > 0;
  }
}

export type PurpleTeamBindings = {
  PURPLE_TEAM_HOSTS: DurableObjectNamespace<import("./purpleTeamHost").PurpleTeamHost>;
  PURPLE_TEAM_DIRECTORY: DurableObjectNamespace<PurpleTeamDirectory>;
};

export function purpleTeamDirectory(env: PurpleTeamBindings) {
  const namespace = env.PURPLE_TEAM_DIRECTORY;
  return namespace.get(namespace.idFromName("directory"));
}

export function purpleTeamHost(env: PurpleTeamBindings, hostname: string) {
  const namespace = env.PURPLE_TEAM_HOSTS;
  return namespace.get(namespace.idFromName(hostname));
}
