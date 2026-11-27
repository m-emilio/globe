import { normalizeReconDomain, readReconTxt, type DnsRecordGroup } from "./purpleTeamRecon";

type SpfPolicy = { domain: string; parent: string | null; terms: number; status: "published" | "none" | "multiple" | "unknown" };
export type MailPolicyReview = {
  spf: { policies: SpfPolicy[]; terms: number; partial: boolean };
  dmarc: { domains: string[]; unknownDestinations: number; status: "published" | "none" | "unknown" };
  dkim: { selector: string; status: "Public key present" | "Revoked key" | "No key returned" | "Unknown" } | null;
};

export function normalizeDkimSelector(input: string): string | null {
  const selector = input.trim().toLowerCase();
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(selector) ? selector : null;
}

function txtValue(value: string): string {
  return value.trim().replace(/"\s*"/g, "").replace(/^"|"$/g, "");
}

function mailHost(input: string): string | null {
  const domain = input.toLowerCase().replace(/\.$/, "");
  const dot = domain.lastIndexOf(".");
  return dot > 0 && normalizeReconDomain(domain.slice(0, dot).replace(/_/g, "a") + domain.slice(dot)) ? domain : null;
}

async function inspectSpf(domain: string, initial: DnsRecordGroup | undefined): Promise<MailPolicyReview["spf"]> {
  const deadline = Date.now() + 5000;
  const pending: { domain: string; ancestors: string[] }[] = [{ domain, ancestors: [] }];
  const visited = new Set<string>();
  const policies: SpfPolicy[] = [];
  let partial = false;
  let terms = 0;
  while (pending.length && policies.length < 11 && Date.now() < deadline) {
    const { domain: name, ancestors } = pending.shift()!;
    if (visited.has(name)) continue;
    visited.add(name);
    const response = name === domain ? initial : await readReconTxt(name, Math.max(1, deadline - Date.now()));
    const records = response?.values?.map(txtValue).filter(value => /^v=spf1(?:\s|$)/i.test(value));
    const parent = ancestors.at(-1) ?? null;
    if (!records || response?.limited) {
      policies.push({ domain: name, parent, terms: 0, status: "unknown" });
      partial = true;
      continue;
    }
    if (records.length !== 1) {
      policies.push({ domain: name, parent, terms: 0, status: records.length ? "multiple" : "none" });
      partial ||= records.length > 1 || ancestors.length > 0;
      continue;
    }
    const directives = records[0].split(/\s+/).slice(1);
    const dnsTerms = directives.filter(term => /^(?:[+?~-]?(?:include|a|mx|ptr|exists)(?=[:/]|$)|redirect=)/i.test(term)).length;
    policies.push({ domain: name, parent, terms: dnsTerms, status: "published" });
    terms += dnsTerms;
    for (const term of directives) {
      const ref = term.match(/^(?:[+?~-]?include:|redirect=)(.+)$/i);
      if (!ref) continue;
      const target = mailHost(ref[1]);
      if (!target || target === name || ancestors.includes(target)) {
        partial = true;
        continue;
      }
      if (!visited.has(target) && !pending.some(entry => entry.domain === target)) {
        pending.push({ domain: target, ancestors: [...ancestors, name] });
      }
    }
  }
  return { policies, terms, partial: partial || pending.length > 0 };
}

function tags(value: string): Map<string, string> {
  const entries = txtValue(value).split(";").flatMap(tag => {
    const equals = tag.indexOf("=");
    return equals > 0 ? [[tag.slice(0, equals).trim().toLowerCase(), tag.slice(equals + 1).trim()] as const] : [];
  });
  return new Map(entries);
}

function inspectDmarc(initial: DnsRecordGroup | undefined): MailPolicyReview["dmarc"] {
  if (!initial?.values || initial.limited || initial.values.length > 1) {
    return { domains: [], unknownDestinations: 0, status: "unknown" };
  }
  if (!initial.values.length) return { domains: [], unknownDestinations: 0, status: "none" };
  const policy = tags(initial.values[0]);
  const domains = new Set<string>();
  let unknownDestinations = 0;
  for (const field of ["rua", "ruf"]) {
    for (const destination of (policy.get(field) ?? "").split(",").map(part => part.trim()).filter(Boolean)) {
      const match = destination.match(/^mailto:[^@\s!]+@([^\s!]+)(?:!\d+[kmgt]?)?$/i);
      const domain = match ? normalizeReconDomain(match[1]) : null;
      if (domain) domains.add(domain);
      else unknownDestinations++;
    }
  }
  return { domains: [...domains].sort(), unknownDestinations, status: "published" };
}

async function inspectDkim(domain: string, selector: string): Promise<NonNullable<MailPolicyReview["dkim"]>> {
  const result = await readReconTxt(selector + "._domainkey." + domain);
  if (!result.values || result.limited) return { selector, status: "Unknown" };
  const keys = result.values.map(tags).flatMap(row => row.has("p") ? [row.get("p")!] : []);
  if (!keys.length) return { selector, status: "No key returned" };
  if (keys.length !== 1) return { selector, status: "Unknown" };
  const key = keys[0].replace(/\s/g, "");
  if (!key) return { selector, status: "Revoked key" };
  return { selector, status: /^[A-Za-z0-9+/]+={0,2}$/.test(key) ? "Public key present" : "Unknown" };
}

export async function inspectMailPolicies(domain: string, dns: DnsRecordGroup[], selector?: string): Promise<MailPolicyReview> {
  const [spf, dkim] = await Promise.all([
    inspectSpf(domain, dns.find(record => record.label === "SPF")),
    selector ? inspectDkim(domain, selector) : Promise.resolve(null),
  ]);
  return { spf, dkim, dmarc: inspectDmarc(dns.find(record => record.label === "DMARC")) };
}
