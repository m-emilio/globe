import { readBoundedText } from "./boundedBody";

export const RECON_PATH = "/admin/purple-team/recon";

const PUBLIC_DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;
const PRIVATE_SUFFIX = /\.(?:arpa|example|internal|invalid|local|localhost|onion|test)$/;
const DNS_TYPES = { A: 1, AAAA: 28, CNAME: 5, MX: 15, NS: 2, CAA: 257, TXT: 16 };
type DnsType = keyof typeof DNS_TYPES;

export type DnsRecordGroup = {
  label: string;
  values: string[] | null;
  limited: boolean;
};

type LoggedCertificate = {
  names: string[];
  issuer: string | null;
  issued: string | null;
  expires: string | null;
  revoked: boolean;
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
};

export function normalizeReconDomain(input: string): string | null {
  const domain = input.trim().toLowerCase().replace(/\.$/, "");
  return PUBLIC_DOMAIN.test(domain) && !PRIVATE_SUFFIX.test(domain) ? domain : null;
}

async function readPublicJson(url: URL, accept: string, maxBytes: number): Promise<unknown> {
  const ctl = new AbortController();
  const timeout = setTimeout(() => ctl.abort(), 5500);
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

async function readDns(
  name: string, type: DnsType, label: string = type, policy?: RegExp,
): Promise<DnsRecordGroup> {
  const url = new URL("https://cloudflare-dns.com/dns-query");
  url.search = new URLSearchParams({ name, type }).toString();
  try {
    const body = await readPublicJson(url, "application/dns-json", 65_536) as {
      Status?: number;
      TC?: boolean;
      Answer?: { type?: number; data?: unknown }[];
    };
    if (body.TC || (body.Status !== 0 && body.Status !== 3) ||
        (body.Answer !== undefined && !Array.isArray(body.Answer))) {
      throw new Error("Incomplete DNS response.");
    }
    const answers = body.Status === 0 ? (body.Answer ?? []) : [];
    const values = [...new Set(answers.flatMap((answer) =>
      answer?.type === DNS_TYPES[type] && typeof answer.data === "string" && (!policy || policy.test(answer.data))
        ? [answer.data] : [],
    ))];
    return { label, values: values.slice(0, 10).map(value => value.slice(0, 640)),
      limited: values.length > 10 || values.some(value => value.length > 640) };
  } catch {
    return { label, values: null, limited: false };
  }
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

async function readCertificates(domain: string): Promise<CertificateResults | null> {
  const url = new URL("https://api.certspotter.com/v1/issuances");
  url.search = new URLSearchParams([
    ["domain", domain], ["include_subdomains", "true"], ["expand", "dns_names"], ["expand", "issuer"],
  ]).toString();
  try {
    const body = await readPublicJson(url, "application/json", 1_500_000);
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
      matches.push({
        names,
        issuer: typeof issuer === "string" ? issuer.slice(0, 180) : null,
        issued: certificateDate(row.not_before),
        expires: certificateDate(row.not_after),
        revoked: row.revoked === true,
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
