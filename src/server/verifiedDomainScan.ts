import { BodyLimitError, readBoundedText } from "./boundedBody";

const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
const BODY_LIMIT = 256 * 1024;
const TIMEOUT = 5000;
const REDIRECTS = new Set([301, 302, 303, 307, 308]);

export type ToolFinding = {
  check: string;
  status: "pass" | "review" | "unknown";
  evidence: string;
  remediation?: string;
};

export function scannerDomains(config?: string): string[] {
  return [...new Set((config ?? "").split(",").map((host) => host.trim().toLowerCase().replace(/\.$/, "")))]
    .filter((host) => DOMAIN.test(host) && !/\.(?:localhost|local|internal|test|invalid|example|onion|arpa)$/.test(host));
}

function request(url: string) {
  return fetch(url, {
    redirect: "manual",
    signal: AbortSignal.timeout(TIMEOUT),
    headers: { accept: "text/html, application/json;q=0.9" },
  });
}

async function certificate(domain: string): Promise<ToolFinding> {
  const check = "Certificate transparency expiry";
  try {
    const url = new URL("https://api.certspotter.com/v1/issuances");
    url.searchParams.set("domain", domain);
    url.searchParams.set("match_wildcards", "true");
    url.searchParams.append("expand", "dns_names");
    const response = await request(url.href);
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error("Certificate transparency source unavailable.");
    }
    const records = JSON.parse(await readBoundedText(response.body, BODY_LIMIT)) as {
      dns_names?: string[]; not_after?: string;
    }[];
    const parent = domain.slice(domain.indexOf(".") + 1);
    const dates = records.filter((record) => record.dns_names?.some((name) =>
      name.toLowerCase() === domain || name.toLowerCase() === "*." + parent
    )).map((record) => Date.parse(record.not_after ?? "")).filter(Number.isFinite);
    if (!dates.length) throw new Error();
    const expiry = Math.max(...dates);
    const nearExpiry = expiry - Date.now() < 30 * 86_400_000;
    return {
      check, status: nearExpiry ? "review" : "unknown",
      evidence: "Latest expiry among matching records returned by Cert Spotter: " +
        new Date(expiry).toISOString() + ". The certificate served by the endpoint was not identified.",
      remediation: "Confirm the served certificate's expiry with your TLS endpoint monitor and renew before expiry.",
    };
  } catch {
    return { check, status: "unknown", evidence: "No matching expiry was available from Cert Spotter.",
      remediation: "Check the certificate served by the endpoint using your TLS endpoint monitor." };
  }
}

async function redirect(domain: string): Promise<ToolFinding> {
  const check = "HTTP to HTTPS redirect";
  try {
    const origin = "http://" + domain;
    const response = await request(origin + "/");
    await response.body?.cancel();
    const location = response.headers.get("location");
    const target = location && new URL(location, origin);
    const redirects = REDIRECTS.has(response.status);
    const ok = Boolean(redirects && target && target.origin === "https://" + domain && !target.username && !target.password);
    const destination = redirects && target && target.origin !== "null" ? " redirects to " + target.origin : "";
    return { check, status: ok ? "pass" : "review",
      evidence: "HTTP " + response.status + destination + ".",
      remediation: ok ? undefined : "Redirect HTTP requests to HTTPS on the same verified hostname." };
  } catch {
    return { check, status: "unknown", evidence: "HTTP request or redirect parsing failed.",
      remediation: "Confirm that port 80 returns a redirect to the HTTPS site." };
  }
}

async function httpsChecks(domain: string): Promise<ToolFinding[]> {
  let response: Response;
  try {
    response = await request("https://" + domain + "/");
  } catch {
    return [{ check: "HTTPS response", status: "unknown", evidence: "HTTPS request failed or timed out.",
      remediation: "Check public DNS, HTTPS availability, and the endpoint certificate." }];
  }

  const findings: ToolFinding[] = [{
    check: "HTTPS response", status: response.ok ? "pass" : "review",
    evidence: "HTTPS returned HTTP " + response.status + ".",
    remediation: response.ok ? undefined : "Inspect the root response and scan the destination separately if it is verified.",
  }];
  const hsts = response.headers.get("strict-transport-security");
  const csp = response.headers.get("content-security-policy");
  const frame = response.headers.get("x-frame-options");
  const ancestors = /(?:^|;)\s*frame-ancestors\s+([^;]+)/i.exec(csp ?? "")?.[1].trim();
  const restrictsFraming = ancestors
    ? !/\*/.test(ancestors) && !ancestors.split(/\s+/).some((source) => /^[a-z][a-z0-9+.-]*:$/i.test(source))
    : /^(deny|sameorigin)$/i.test(frame?.trim() ?? "");
  const headers = [
    ["Strict-Transport-Security", hsts, Number(hsts?.match(/(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)/i)?.[1]) > 0,
      "Set Strict-Transport-Security with a positive max-age after confirming HTTPS coverage."],
    ["Content-Security-Policy", csp, Boolean(csp?.trim()),
      "Deploy an enforcing Content-Security-Policy appropriate for the application."],
    ["X-Content-Type-Options", response.headers.get("x-content-type-options"),
      response.headers.get("x-content-type-options")?.trim().toLowerCase() === "nosniff", "Set X-Content-Type-Options to nosniff."],
    ["Framing restrictions", ancestors ? "frame-ancestors " + ancestors : frame, restrictsFraming,
      "Set CSP frame-ancestors to the required origins, or use 'none' if embedding is unnecessary."],
    ["Referrer-Policy", response.headers.get("referrer-policy"), Boolean(response.headers.get("referrer-policy")?.trim()),
      "Set a suitable Referrer-Policy, such as strict-origin-when-cross-origin."],
  ] as const;
  for (const [check, value, ok, remediation] of headers) {
    findings.push({ check, status: ok ? "pass" : "review",
      evidence: value?.slice(0, 300) || "Header not observed.", remediation: ok ? undefined : remediation });
  }

  const cookies = response.headers.getSetCookie();
  if (!cookies.length) {
    findings.push({ check: "Cookie flags", status: "unknown", evidence: "Root response set no cookies. Authenticated flows were not inspected." });
  }
  for (const [index, cookie] of cookies.slice(0, 30).entries()) {
    const attributes = cookie.split(";").slice(1).map((part) => part.trim().toLowerCase());
    const missing = [
      attributes.includes("secure") ? "" : "Secure",
      attributes.includes("httponly") ? "" : "HttpOnly",
      attributes.some((part) => /^samesite\s*=\s*(strict|lax|none)$/.test(part)) ? "" : "SameSite",
    ].filter(Boolean);
    findings.push({ check: "Cookie " + (index + 1),
      status: missing.length ? "review" : "pass",
      evidence: missing.length ? "Missing flags: " + missing.join(", ") : "Secure, HttpOnly, and SameSite observed.",
      remediation: missing.length ? "Use Secure and HttpOnly for session cookies and choose a SameSite value that fits the workflow." : undefined });
  }
  if (cookies.length > 30) findings.push({ check: "Cookie coverage", status: "unknown", evidence: "Only the first 30 cookies were reviewed." });

  try {
    if (!response.ok || !/^text\/html(?:;|$)/i.test(response.headers.get("content-type") ?? "")) {
      await response.body?.cancel();
      throw new Error();
    }
    const html = await readBoundedText(response.body, BODY_LIMIT);
    const insecure = new Set<string>();
    const resources: string[] = [];
    let base = new URL("https://" + domain + "/");
    let baseSeen = false;
    const rewriter = new HTMLRewriter()
      .on("base[href]", { element(element) {
        if (baseSeen) return;
        baseSeen = true;
        try { base = new URL(element.getAttribute("href") ?? "", base); } catch { /* malformed base URL */ }
      } })
      .on("script[src], img[src], iframe[src], source[src], video[src], audio[src], embed[src], track[src]", {
        element(element) { resources.push(element.getAttribute("src") ?? ""); },
      })
      .on("video[poster]", { element(element) { resources.push(element.getAttribute("poster") ?? ""); } })
      .on("object[data]", { element(element) { resources.push(element.getAttribute("data") ?? ""); } })
      .on("img[srcset], source[srcset]", { element(element) {
        for (const candidate of (element.getAttribute("srcset") ?? "").split(",")) {
          resources.push(candidate.trim().split(/\s+/, 1)[0]);
        }
      } })
      .on("link[href]", { element(element) {
        if (/\b(stylesheet|preload|modulepreload|icon)\b/i.test(element.getAttribute("rel") ?? "")) {
          resources.push(element.getAttribute("href") ?? "");
        }
      } });
    await rewriter.transform(new Response(html, { headers: { "content-type": "text/html; charset=utf-8" } })).text();
    for (const resource of resources) {
      if (!resource.trim()) continue;
      try {
        const target = new URL(resource, base);
        if (target.protocol === "http:") insecure.add(target.origin);
      } catch { /* malformed resource URL */ }
    }
    findings.push({ check: "Mixed content", status: insecure.size ? "review" : "pass",
      evidence: insecure.size ? "HTTP resource origins: " + [...insecure].slice(0, 10).join(", ")
        : "No HTTP resource URLs in the inspected HTML attributes.",
      remediation: insecure.size ? "Serve those resources over HTTPS and replace the HTTP URLs." : undefined });
  } catch (error) {
    findings.push({ check: "Mixed content", status: "unknown",
      evidence: error instanceof BodyLimitError ? "The root HTML exceeded the 256 KiB inspection limit."
        : "The root response did not provide inspectable HTML." });
  }
  return findings;
}

export async function scanVerifiedDomain(domain: string) {
  const [tls, upgrade, https] = await Promise.all([certificate(domain), redirect(domain), httpsChecks(domain)]);
  return [upgrade, ...https, tls];
}
