import { readBoundedText } from "./boundedBody";
import { parseReconAddress, type ReconAddress } from "../reconAddress";
import type { PurpleFinding } from "./purpleTeamFindings";
import type { MailPolicyReview } from "./purpleTeamMail";

export const RECON_PATH = "/admin/purple-team/recon";
export const RECON_CERTIFICATE_PATH = RECON_PATH + "/certificate";

const PUBLIC_DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;
const PRIVATE_SUFFIX = /\.(?:arpa|example|internal|invalid|local|localhost|onion|test)$/;
export const DNS_TYPES = { A: 1, AAAA: 28, CNAME: 5, DNAME: 39, MX: 15, NS: 2, PTR: 12, CAA: 257, TXT: 16, SOA: 6, DS: 43, DNSKEY: 48 };
type DnsType = keyof typeof DNS_TYPES;
type DnsAnswer = { type?: number; name?: unknown; data?: unknown };

export type DnsRecordGroup = {
  label: string;
  values: string[] | null;
  limited: boolean;
  responseCode?: 0 | 3;
};

export type LoggedCertificate = {
  names: string[];
  issuer: string | null;
  issuerKeySha256?: string;
  issued: string | null;
  expires: string | null;
  revoked: boolean;
  matchesAddress?: boolean | null;
};

export type CertificateResults = {
  records: LoggedCertificate[];
  recordCount: number;
  names: string[];
  nameCount: number;
};

export type ReconResults = {
  dns: DnsRecordGroup[];
  certificates: CertificateResults | null;
  mail?: MailPolicyReview;
  purpleFindings?: PurpleFinding[];
};

export type AddressPki = {
  hostname: string;
  forward: "confirmed" | "different" | "unknown";
  caa: DnsRecordGroup | null;
  certificates: CertificateResults | null;
};

export function normalizeReconDomain(input: string): string | null {
  const domain = input.trim().toLowerCase().replace(/\.$/, "");
  return PUBLIC_DOMAIN.test(domain) && !PRIVATE_SUFFIX.test(domain) ? domain : null;
}

export async function readPublicJson(url: URL, accept: string, maxBytes: number, timeoutMs = 5500): Promise<unknown> {
  const ctl = new AbortController();
  const timeout = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const response = await fetch(url, { headers: { accept }, redirect: "manual", signal: ctl.signal });
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error("Lookup source unavailable.");
    }
    return JSON.parse(await readBoundedText(response.body, maxBytes));
  } finally {
    clearTimeout(timeout);
  }
}

export async function readReconDns(
  name: string,
  type: DnsType,
  { timeoutMs, dnssec = false }: { timeoutMs?: number; dnssec?: boolean } = {},
): Promise<{ status: 0 | 3; authenticated: boolean; answer: DnsAnswer[]; authority: DnsAnswer[] }> {
  const url = new URL("https://cloudflare-dns.com/dns-query");
  url.search = new URLSearchParams({ name, type }).toString();
  if (dnssec) {
    url.searchParams.set("do", "true");
    url.searchParams.set("cd", "false");
  }
  const body = await readPublicJson(url, "application/dns-json", 65_536, timeoutMs) as {
    Status?: number;
    TC?: boolean;
    AD?: boolean;
    Answer?: DnsAnswer[];
    Authority?: DnsAnswer[];
  };
  if (body.TC || (body.Status !== 0 && body.Status !== 3) ||
      (body.Answer !== undefined && !Array.isArray(body.Answer)) ||
      (body.Authority !== undefined && !Array.isArray(body.Authority))) {
    throw new Error("Incomplete DNS response.");
  }
  return {
    status: body.Status,
    authenticated: body.AD === true,
    answer: body.Answer ?? [],
    authority: body.Authority ?? [],
  };
}

async function readDns(
  name: string, type: DnsType, label: string = type, policy?: RegExp, timeoutMs?: number,
): Promise<DnsRecordGroup> {
  try {
    const response = await readReconDns(name, type, { timeoutMs });
    const answers = response.status === 0 ? response.answer : [];
    const values = [...new Set(answers.flatMap((answer) =>
      answer?.type === DNS_TYPES[type] && typeof answer.data === "string" && (!policy || policy.test(answer.data))
        ? [answer.data] : [],
    ))];
    return { label, values: values.slice(0, 10).map(value => value.slice(0, 640)), responseCode: response.status,
      limited: values.length > 10 || values.some(value => value.length > 640) ||
        answers.some(answer => answer?.type === DNS_TYPES[type] && typeof answer.data !== "string") };
  } catch {
    return { label, values: null, limited: false };
  }
}

export function readReconTxt(name: string, timeoutMs?: number) {
  return readDns(name, "TXT", "TXT", undefined, timeoutMs);
}

export function readReconPtr(name: string) {
  return readDns(name, "PTR");
}

function certificateName(value: unknown, domain: string): string | null {
  if (typeof value !== "string") return null;
  const wildcard = value.startsWith("*.");
  const name = normalizeReconDomain(wildcard ? value.slice(2) : value);
  if (!name || (name !== domain && !name.endsWith("." + domain))) return null;
  return wildcard ? "*." + name : name;
}

function certificateDate(value: unknown): string | null {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T/.test(value)) return null;
  const time = Date.parse(value);
  return Number.isFinite(time) ? new Date(time).toISOString().slice(0, 10) : null;
}

function matchIpIdentity(identities: unknown, address: ReconAddress): boolean | null {
  if (!Array.isArray(identities)) return null;
  const parsed = identities.map(value => typeof value === "string" ? parseReconAddress(value) : null);
  if (parsed.some(value => value?.value === address.value)) return true;
  return parsed.includes(null) ? null : false;
}

async function readCertificates(domain: string, address?: ReconAddress): Promise<CertificateResults | null> {
  const url = new URL("https://api.certspotter.com/v1/issuances");
  url.search = new URLSearchParams([
    ["domain", domain], ["include_subdomains", address ? "false" : "true"], ["expand", "dns_names"], ["expand", "issuer"],
  ]).toString();
  if (address) url.searchParams.append("expand", "ip_addresses");
  try {
    const body = await readPublicJson(url, "application/json", 1_500_000, address ? 4000 : 5500);
    if (!Array.isArray(body)) return null;
    const matches: LoggedCertificate[] = [];
    for (const row of body) {
      if (!Array.isArray(row?.dns_names)) continue;
      const names = [...new Set<string>(row.dns_names.flatMap((raw: unknown) => {
        const name = certificateName(raw, domain);
        return name ? [name] : [];
      }))];
      if (!names.length) continue;
      const issuer = row.issuer?.friendly_name ?? row.issuer?.name;
      const issuerKey = row.issuer?.pubkey_sha256;
      matches.push({
        names,
        issuer: typeof issuer === "string" ? issuer.slice(0, 180) : null,
        issuerKeySha256: typeof issuerKey === "string" && /^[a-f0-9]{64}$/i.test(issuerKey)
          ? issuerKey.toLowerCase() : undefined,
        issued: certificateDate(row.not_before),
        expires: certificateDate(row.not_after),
        revoked: row.revoked === true,
        matchesAddress: address ? matchIpIdentity(row.ip_addresses, address) : undefined,
      });
    }
    if (body.length && !matches.length) return null;
    const names = [...new Set(matches.flatMap(record => record.names))].sort();
    matches.sort((a, b) => (b.issued ?? "").localeCompare(a.issued ?? ""));
    return { records: matches.slice(0, 12), recordCount: matches.length, names: names.slice(0, 80), nameCount: names.length };
  } catch {
    return null;
  }
}

export async function lookupAddressPki(hostname: string, address: ReconAddress): Promise<AddressPki> {
  const family = address.family === 4 ? "A" : "AAAA";
  const forward = await readDns(hostname, family, family, undefined, 3000);
  if (!forward.values?.some(value => parseReconAddress(value)?.value === address.value)) {
    return {
      hostname,
      forward: forward.values === null || forward.limited ? "unknown" : "different",
      caa: null,
      certificates: null,
    };
  }
  const [caa, certificates] = await Promise.all([
    readDns(hostname, "CAA", "CAA", undefined, 3000), readCertificates(hostname, address),
  ]);
  return { hostname, forward: "confirmed", caa, certificates };
}

async function readDomainDns(domain: string): Promise<DnsRecordGroup[]> {
  const addressTypes = ["A", "AAAA", "CNAME", "MX", "NS"] as const;
  const records = await Promise.all(addressTypes.map(type => readDns(domain, type)));
  const policies = await Promise.all([
    readDns(domain, "CAA"),
    readDns(domain, "TXT", "SPF", /^"?v=spf1(?:[\s";]|$)/i),
    readDns("_dmarc." + domain, "TXT", "DMARC", /^"?v=dmarc1(?:[\s";]|$)/i),
  ]);
  return [...records, ...policies];
}

export async function lookupPublicRecon(domain: string): Promise<ReconResults> {
  const [dns, certificates] = await Promise.all([readDomainDns(domain), readCertificates(domain)]);
  return { dns, certificates };
}
