/** In-memory elevation token so the login-log overlay can send it. Not stored. */
let elevationToken = "";

export function rememberAdminElevation(token: string | null): void {
  elevationToken = token && /^[a-f0-9]{64}$/.test(token) ? token : "";
}

export function adminElevationHeader(): Record<string, string> {
  return elevationToken ? { "x-admin-elevation": elevationToken } : {};
}
