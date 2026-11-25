import { DurableObject } from "cloudflare:workers";

export const CANARY_PATH = "/purple-team/canary/";

export class PurpleTeamDirectory extends DurableObject {
  constructor(ctx: DurableObjectState, env: unknown) {
    super(ctx, env);
    this.ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS hosts (hostname TEXT PRIMARY KEY)");
    this.ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS canaries (id TEXT PRIMARY KEY, armed INTEGER, hit INTEGER)");
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
