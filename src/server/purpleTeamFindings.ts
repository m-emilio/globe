import { inspectDkim, type MailPolicyReview } from "./purpleTeamMail";
import { DNS_TYPES, normalizeReconDomain, readReconDns, type DnsRecordGroup } from "./purpleTeamRecon";

export type PurpleFinding = {
  control: "DKIM" | "DNSSEC" | "CAA";
  status: "low" | "unknown" | "observed";
  red: string;
  blue: string;
  technique: "T1566" | "T1584.002" | "T1588.004";
};

const COMMON_SELECTORS = ["default", "google", "selector1", "selector2"];
const DNSSEC_QUERY = { dnssec: true, timeoutMs: 3500 };

async function checkDkim(domain: string, selected: MailPolicyReview["dkim"]): Promise<PurpleFinding> {
  const checks = selected ? [selected] : await Promise.all(
    COMMON_SELECTORS.map(selector => inspectDkim(domain, selector, 3500)),
  );
  const published = checks.filter(entry => entry.status === "Public key present").map(entry => entry.selector);
  const unknown = checks.filter(entry => entry.status === "Unknown").map(entry => entry.selector);
  const checked = checks.map(entry => entry.selector).join(", ");
  return {
    control: "DKIM",
    technique: "T1566",
    status: published.length ? "observed" : unknown.length ? "unknown" : "low",
    red: published.length ? "Public DKIM key records were returned for " + published.join(", ") + "."
      : unknown.length ? "DKIM lookup was incomplete for " + unknown.join(", ") + ". Selectors checked included " + checked + "."
        : "No usable DKIM key was returned for the checked selectors " + checked + ".",
    blue: published.length ? "Confirm an outgoing message uses one of the published selectors."
      : "Confirm DKIM signing with your mail provider and check the active selector from an outgoing message.",
  };
}

function dnsOwner(value: unknown): string {
  return typeof value === "string" ? value.trim().toLowerCase().replace(/\.$/, "") : "";
}

async function checkDnssec(domain: string): Promise<PurpleFinding> {
  const verification = "Check zone signing at the DNS host and the DS record at the registrar.";
  const finding = (status: PurpleFinding["status"], red: string, blue = verification): PurpleFinding =>
    ({ control: "DNSSEC", technique: "T1584.002", status, red, blue });
  try {
    const soa = await readReconDns(domain, "SOA", DNSSEC_QUERY);
    const zones = [...soa.answer, ...soa.authority].flatMap(record => {
      if (record?.type !== DNS_TYPES.SOA) return [];
      const name = normalizeReconDomain(dnsOwner(record.name));
      return name && (name === domain || domain.endsWith("." + name)) ? [name] : [];
    });
    const zone = zones.sort((a, b) => b.length - a.length)[0];
    if (soa.status !== 0 || !zone) return finding("unknown", "The DNS zone could not be confirmed.");

    const [keys, delegation] = await Promise.all([
      readReconDns(zone, "DNSKEY", DNSSEC_QUERY).catch(() => null),
      readReconDns(zone, "DS", DNSSEC_QUERY).catch(() => null),
    ]);
    if (keys?.status === 0 && keys.authenticated &&
      keys.answer.some(record => record?.type === DNS_TYPES.DNSKEY && dnsOwner(record.name) === zone)) {
      return finding("observed", "The validating resolver authenticated the DNSKEY records for " + zone + ".",
        "Monitor signing-key rotation and registrar DS updates.");
    }

    const parentSoa = delegation?.authority.some(record => {
      const parent = dnsOwner(record?.name);
      return record?.type === DNS_TYPES.SOA && parent && zone.endsWith("." + parent);
    });
    if (delegation?.status === 0 && delegation.authenticated && parentSoa &&
      !delegation.answer.some(record => record?.type === DNS_TYPES.DS ||
        record?.type === DNS_TYPES.CNAME || record?.type === DNS_TYPES.DNAME)) {
      return finding("low", "The authenticated parent lookup returned no DS record for " + zone + ".",
        "Enable signing at the DNS host, publish the matching DS at the registrar, and verify validation.");
    }
    return finding("unknown", "The resolver did not confirm a DNSSEC result for " + zone + ".");
  } catch {
    return finding("unknown", "DNSSEC verification data was unavailable.");
  }
}

async function checkCaa(domain: string, initial: DnsRecordGroup | undefined): Promise<PurpleFinding> {
  const action = "Publish CAA records for the certificate authorities you use and review wildcard issuance policy.";
  const finding = (status: PurpleFinding["status"], red: string, blue = action): PurpleFinding =>
    ({ control: "CAA", technique: "T1588.004", status, red, blue });
  const incomplete = "CAA lookup did not establish the policy for this name and its DNS parents.";
  const reviewExisting = "Confirm the published issuers match the CAs you use for your certificates.";
  if (initial?.responseCode !== 0 || !initial.values) return finding("unknown", incomplete);
  if (initial.values.length) return finding("observed", "CAA records were returned in the query for " + domain + ".", reviewExisting);
  if (initial.limited) return finding("unknown", incomplete);

  const labels = domain.split(".");
  const parents = labels.slice(1).map((_, index) => labels.slice(index + 1).join("."));
  const deadline = Date.now() + 4500;
  try {
    for (const parent of parents.slice(0, 5)) {
      const timeoutMs = deadline - Date.now();
      if (timeoutMs <= 0) return finding("unknown", incomplete);
      const response = await readReconDns(parent, "CAA", { timeoutMs });
      if (response.status !== 0) return finding("unknown", incomplete);
      if (response.answer.some(record => record?.type === DNS_TYPES.CAA && typeof record.data === "string")) {
        return finding("observed", "The CAA search found records when it checked parent name " + parent + ".", reviewExisting);
      }
      if (response.answer.some(record => record?.type === DNS_TYPES.CAA)) return finding("unknown", incomplete);
    }
    return parents.length > 5 ? finding("unknown", incomplete)
      : finding("low", "No CAA records were returned for " + domain + " or its DNS parents.");
  } catch {
    return finding("unknown", incomplete);
  }
}

export async function inspectPurpleFindings(
  domain: string, dns: DnsRecordGroup[], selected: MailPolicyReview["dkim"],
): Promise<PurpleFinding[]> {
  return Promise.all([
    checkDkim(domain, selected),
    checkDnssec(domain),
    checkCaa(domain, dns.find(record => record.label === "CAA")),
  ]);
}
