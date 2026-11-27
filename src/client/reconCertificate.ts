import "reflect-metadata";
import { DNS, IP, SubjectAlternativeNameExtension, X509Certificate } from "@peculiar/x509";
import { parseReconAddress } from "../reconAddress";

const MAX_CERTIFICATE_BYTES = 32_768;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

type Finding = { label: string; status: "pass" | "review" | "unknown"; evidence: string };
type AltName = { type: typeof DNS | typeof IP; value: string };

function dnsName(raw: string): string | null {
  const name = raw.trim().toLowerCase().replace(/\.$/, "");
  if (!name || name.length > 253 || /^\d+(?:\.\d+){3}$/.test(name)) return null;
  return name.split(".").every(label => DNS_LABEL.test(label)) ? name : null;
}

function nameMatches(expected: string, names: AltName[]): boolean {
  const address = parseReconAddress(expected);
  if (address) return names.some(name => name.type === IP && parseReconAddress(name.value)?.value === address.value);
  const hostname = dnsName(expected);
  if (!hostname) return false;
  return names.some(name => {
    if (name.type !== DNS) return false;
    if (!name.value.startsWith("*.")) return dnsName(name.value) === hostname;
    const suffix = dnsName(name.value.slice(2));
    return Boolean(suffix?.includes(".") && hostname.slice(hostname.indexOf(".") + 1) === suffix &&
      hostname.includes("."));
  });
}

function validityFinding(cert: X509Certificate, now: number): Finding {
  const start = cert.notBefore.getTime();
  const end = cert.notAfter.getTime();
  let evidence: string;
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) {
    return { label: "Validity", status: "unknown", evidence: "Validity dates are unavailable or inconsistent." };
  }
  if (now < start) evidence = "Not yet valid.";
  else if (now >= end) evidence = "Expired.";
  else if (end - now <= 30 * 86_400_000) evidence = "Expires within 30 days.";
  else return { label: "Validity", status: "pass", evidence: "Within its validity dates." };
  return { label: "Validity", status: "review", evidence };
}

function keyFinding(cert: X509Certificate): Finding {
  const algorithm = cert.publicKey.algorithm as Algorithm & { modulusLength?: number; namedCurve?: string };
  const details = [algorithm.name, algorithm.modulusLength && algorithm.modulusLength + " bits", algorithm.namedCurve]
    .filter(Boolean).join(" · ");
  if (/rsa/i.test(algorithm.name)) {
    const bits = algorithm.modulusLength;
    if (typeof bits !== "number") return { label: "Public key", status: "unknown", evidence: details };
    return { label: "Public key", status: bits < 2048 ? "review" : "pass",
      evidence: details + (bits < 2048 ? ". RSA keys below 2048 bits are weak." : "") };
  }
  const curve = algorithm.namedCurve?.toUpperCase() ?? "";
  const weakCurve = /^(?:P-192|P-224|SECP192R1|SECP224R1)$/.test(curve);
  const supported = /^(?:P-256|P-384|P-521)$/.test(curve) || /^(?:ED25519|ED448)$/i.test(algorithm.name);
  return { label: "Public key", status: weakCurve ? "review" : supported ? "pass" : "unknown",
    evidence: details + (weakCurve ? ". This curve is below current TLS key-strength recommendations." : "") };
}

function signatureFinding(cert: X509Certificate): Finding {
  const algorithm = cert.signatureAlgorithm;
  const hash = algorithm.hash?.name ?? "";
  const label = [algorithm.name, hash].filter(Boolean).join(" · ");
  const weak = /(?:^|[^a-z0-9])(?:md[245]|sha-?1)(?:$|[^a-z0-9])/i.test(label);
  const supported = /^(?:SHA-(?:256|384|512)|SHA3-(?:256|384|512))$/i.test(hash) ||
    /^(?:ED25519|ED448)$/i.test(algorithm.name);
  return { label: "Signature algorithm", status: weak ? "review" : supported ? "pass" : "unknown",
    evidence: label + (weak ? ". The signature uses a deprecated digest." : "") };
}

function certificateNames(cert: X509Certificate): AltName[] | null {
  try {
    const extension = cert.getExtension(SubjectAlternativeNameExtension);
    const entries = extension?.names.items ?? [];
    return entries.flatMap(({ type, value }) => type === DNS || type === IP ? [{ type, value }] : []);
  } catch {
    return null;
  }
}

function singlePem(value: string): string {
  const pem = value.trim();
  const parts = pem.split(/\r?\n/);
  const payload = parts.slice(1, -1).join("");
  if (pem.length > MAX_CERTIFICATE_BYTES || parts[0] !== "-----BEGIN CERTIFICATE-----" ||
    parts.at(-1) !== "-----END CERTIFICATE-----" || !/^[A-Za-z0-9+/]+={0,2}$/.test(payload)) {
    throw new Error("Use one public certificate in PEM format.");
  }
  return pem;
}

async function certificateInput(paste: string, file: File | undefined): Promise<string | Uint8Array<ArrayBuffer>> {
  if (file && paste.trim()) throw new Error("Choose a file or paste a certificate.");
  if (!file) return singlePem(paste);
  if (file.size > MAX_CERTIFICATE_BYTES) throw new Error("Choose a certificate file under 32 KB.");
  const bytes = new Uint8Array(await file.arrayBuffer());
  return bytes[0] === 0x30 ? bytes : singlePem(new TextDecoder().decode(bytes));
}

function appendText<N extends keyof HTMLElementTagNameMap>(
  parent: HTMLElement, name: N, value: string,
): HTMLElementTagNameMap[N] {
  const element = document.createElement(name);
  element.textContent = value;
  parent.append(element);
  return element;
}

function showFinding(parent: HTMLElement, finding: Finding) {
  const item = document.createElement("li");
  const heading = document.createElement("div");
  heading.className = "check-head";
  appendText(heading, "strong", finding.label);
  const labels = { pass: "Pass", review: "Review", unknown: "Unknown" };
  appendText(heading, "span", labels[finding.status]).className = "status " + finding.status;
  item.append(heading);
  appendText(item, "p", finding.evidence || "Unavailable");
  parent.append(item);
}

const form = document.querySelector<HTMLFormElement>("#certificate-form");
const expected = document.querySelector<HTMLInputElement>("#certificate-name");
const file = document.querySelector<HTMLInputElement>("#certificate-file");
const paste = document.querySelector<HTMLTextAreaElement>("#certificate-pem");
const submit = document.querySelector<HTMLButtonElement>("#inspect-certificate");
const status = document.querySelector<HTMLElement>("#certificate-status");
const result = document.querySelector<HTMLElement>("#certificate-result");
const metadata = document.querySelector<HTMLElement>("#certificate-metadata");
const findings = document.querySelector<HTMLElement>("#certificate-findings");

function dateLabel(date: Date): string {
  return Number.isFinite(date.getTime()) ? date.toISOString().replace("T", " ").slice(0, 19) + " UTC" : "Unavailable";
}

if (form && expected && file && paste && submit && status && result && metadata && findings) {
  submit.disabled = false;
  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (submit.disabled) return;
    result.hidden = true;
    const name = expected.value.trim();
    if (name && !parseReconAddress(name) && !dnsName(name)) {
      status.textContent = "Enter an exact hostname or IP address.";
      return;
    }
    submit.disabled = true;
    status.textContent = "Inspecting certificate…";
    try {
      let input: string | Uint8Array<ArrayBuffer>;
      try {
        input = await certificateInput(paste.value, file.files?.[0]);
      } catch (error) {
        status.textContent = error instanceof Error ? error.message : "The certificate file could not be read.";
        return;
      }
      const cert = new X509Certificate(input);
      const names = certificateNames(cert);
      const fingerprint = Array.from(new Uint8Array(await cert.getThumbprint("SHA-256")),
        byte => byte.toString(16).padStart(2, "0")).join(":");
      metadata.replaceChildren();
      findings.replaceChildren();
      for (const [label, value] of [
        ["Subject", cert.subject.slice(0, 400)], ["Issuer", cert.issuer.slice(0, 400)],
        ["Valid from", dateLabel(cert.notBefore)], ["Expires", dateLabel(cert.notAfter)],
        ["SHA-256", fingerprint], ["DNS and IP names", names?.slice(0, 24).map(entry => entry.value.slice(0, 253)).join(", ") ?? "Unavailable"],
      ]) {
        appendText(metadata, "dt", label);
        appendText(metadata, "dd", value || "None");
      }
      for (const finding of [validityFinding(cert, Date.now()), keyFinding(cert), signatureFinding(cert)]) {
        showFinding(findings, finding);
      }
      if (name) {
        const matches = names && nameMatches(name, names);
        showFinding(findings, {
          label: "Expected name",
          status: matches === null ? "unknown" : matches ? "pass" : "review",
          evidence: matches === null ? "DNS and IP names could not be read."
            : name + (matches ? " matches a subject alternative name." : " has no matching subject alternative name."),
        });
      }
      result.hidden = false;
      status.textContent = "Certificate inspected in this browser.";
    } catch {
      status.textContent = "The file could not be read as an X.509 certificate.";
    } finally {
      submit.disabled = false;
    }
  });
}
