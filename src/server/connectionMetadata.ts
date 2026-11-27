import type { ConnectionDetails } from "../connectionSignals";

export function getCloudflareClientIp(request: Request): string | undefined {
  const address = request.headers.get("cf-connecting-ip") ??
    (typeof request.cf?.clientIp === "string" ? request.cf.clientIp : undefined);
  return address ? address.trim().slice(0, 45) : undefined;
}

export function limitApiText(value: unknown, maxLength: number): string {
  if (typeof value === "string") return value.trim().replace(/\s+/g, " ").slice(0, maxLength);
  if (typeof value === "number" || typeof value === "boolean") return String(value).slice(0, maxLength);
  return "";
}

export function readConnectionMetadata(request: Request): Omit<ConnectionDetails, "sessionCookie"> {
  const tcpMs = request.cf?.clientTcpRtt;
  const asn = request.cf?.asn;
  return {
    httpProtocol: limitApiText(request.cf?.httpProtocol, 24) || null,
    tlsVersion: limitApiText(request.cf?.tlsVersion, 24) || null,
    tlsCipher: limitApiText(request.cf?.tlsCipher, 64) || null,
    edge: limitApiText(request.cf?.colo, 8) || null,
    country: limitApiText(request.cf?.country, 4) || null,
    edgeTcpMs: typeof tcpMs === "number" && Number.isFinite(tcpMs) && tcpMs >= 0 ? Math.round(tcpMs) : null,
    networkAsn: typeof asn === "number" && Number.isSafeInteger(asn) && asn > 0 ? asn : null,
    networkOrganization: limitApiText(request.cf?.asOrganization, 96) || null,
  };
}
