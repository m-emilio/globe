import { readBoundedText } from "./boundedBody";

export const PROOF_LABEL = "_globe-verify.";
const HOSTNAME = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
const RESERVED_SUFFIX = /\.(?:localhost|local|internal|test|invalid|example|onion|arpa)$/;
const RESERVED_EXAMPLE = /(?:^|\.)example\.(?:com|net|org)$/;

export function scanHostname(input: string): string | null {
  const name = input.trim().toLowerCase().replace(/\.$/, "");
  return name.length <= 253 - PROOF_LABEL.length && HOSTNAME.test(name) &&
      !RESERVED_SUFFIX.test(name) && !RESERVED_EXAMPLE.test(name)
    ? name
    : null;
}

export type DnsProof = "present" | "missing" | "unavailable";

export async function checkDnsProof(hostname: string, token: string): Promise<DnsProof> {
  const owner = PROOF_LABEL + hostname;
  const url = new URL("https://cloudflare-dns.com/dns-query");
  url.searchParams.set("name", owner);
  url.searchParams.set("type", "TXT");
  try {
    const response = await fetch(url, {
      headers: { accept: "application/dns-json" },
      redirect: "manual",
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) {
      await response.body?.cancel();
      return "unavailable";
    }
    const data = JSON.parse(await readBoundedText(response.body, 64 * 1024)) as {
      Status?: number;
      TC?: boolean;
      Answer?: { name?: string; type?: number; data?: string }[];
    };
    if (data.TC || (data.Status !== 0 && data.Status !== 3)) return "unavailable";
    if (data.Status === 3 || !Array.isArray(data.Answer)) return "missing";

    const exact = data.Answer.some((record) => {
      if (record.type !== 16 || record.name?.toLowerCase().replace(/\.$/, "") !== owner) return false;
      const value = record.data?.trim() ?? "";
      if (/^(?:"[a-z0-9-]+"[ \t]*)+$/i.test(value)) {
        return value.match(/"[^"]+"/g)?.map((segment) => segment.slice(1, -1)).join("") === token;
      }
      return value === token;
    });
    return exact ? "present" : "missing";
  } catch {
    return "unavailable";
  }
}
