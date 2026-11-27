import type { ReconAddress } from "../reconAddress";
import { normalizeReconDomain, readPublicJson, readReconPtr } from "./purpleTeamRecon";

export type IpRecon = {
  address: ReconAddress;
  names: string[] | null;
  routing: { prefix: string | null; asns: number[] } | null;
};

async function readRouting(address: string): Promise<IpRecon["routing"]> {
  const url = new URL("https://stat.ripe.net/data/network-info/data.json");
  url.searchParams.set("resource", address);
  try {
    const response = await readPublicJson(url, "application/json", 65_536, 5000) as {
      status?: string;
      data?: { prefix?: string | null; asns?: unknown[] };
    };
    if (response.status !== "ok" || !response.data || !Array.isArray(response.data.asns)) return null;
    const prefix = response.data.prefix;
    const asns = response.data.asns.flatMap(value => {
      if (typeof value !== "number" && (typeof value !== "string" || !/^\d{1,10}$/.test(value))) return [];
      const asn = Number(value);
      return Number.isSafeInteger(asn) && asn > 0 && asn <= 4_294_967_295 ? [asn] : [];
    });
    return {
      prefix: typeof prefix === "string" && /^[a-f0-9:.]{1,45}\/\d{1,3}$/i.test(prefix) ? prefix : null,
      asns: [...new Set(asns)].slice(0, 8),
    };
  } catch {
    return null;
  }
}

export async function lookupIpRecon(address: ReconAddress): Promise<IpRecon> {
  if (!address.isPublic) return { address, names: null, routing: null };
  const [reverse, routing] = await Promise.all([
    readReconPtr(address.reverseName), readRouting(address.value),
  ]);
  return {
    address,
    names: reverse.values && [...new Set(reverse.values.flatMap(value => {
      const name = normalizeReconDomain(value);
      return name ? [name] : [];
    }))],
    routing,
  };
}
