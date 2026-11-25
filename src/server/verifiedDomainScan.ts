import { BodyLimitError, readBoundedText } from "./boundedBody";

const BODY_LIMIT = 256 * 1024;
const TIMEOUT = 5000;
const REDIRECTS = new Set([301, 302, 303, 307, 308]);

export type ToolFinding = {
  check: string;
  status: "pass" | "review" | "unknown";
  evidence: string;
  remediation?: string;
};

export type WebFinding = ToolFinding & { id: string };

function request(url: string) {
  return fetch(url, {
    redirect: "manual",
    cache: "no-store",
    signal: AbortSignal.timeout(TIMEOUT),
    headers: { accept: "text/html, application/json;q=0.9" },
  });
}

async function certificate(domain: string): Promise<WebFinding> {
  const check = "Certificate Transparency expiry";
  const id = "tls.ct-expiry";
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
      id, check, status: nearExpiry ? "review" : "unknown",
      evidence: "Latest published expiry in matching Certificate Transparency records from Cert Spotter: " +
        new Date(expiry).toISOString() + ".",
      remediation: "Verify the active certificate's expiry and renew it as needed.",
    };
  } catch {
    return { id, check, status: "unknown", evidence: "No matching expiry was available from Cert Spotter.",
      remediation: "Check the expiry of the certificate served by the endpoint." };
  }
}

async function redirect(domain: string): Promise<WebFinding> {
  const check = "HTTP to HTTPS redirect";
  const id = "http.redirect";
  try {
    const origin = "http://" + domain;
    const response = await request(origin + "/");
    await response.body?.cancel();
    const location = response.headers.get("location");
    const target = location && new URL(location, origin);
    const redirects = REDIRECTS.has(response.status);
    const ok = Boolean(redirects && target && target.origin === "https://" + domain && !target.username && !target.password);
    const destination = redirects && target && target.origin !== "null"
      ? " redirects to " + (target.origin + target.pathname).slice(0, 300) : "";
    return { id, check, status: ok ? "pass" : "review",
      evidence: "HTTP " + response.status + destination + ".",
      remediation: ok ? undefined : "Redirect HTTP requests to HTTPS on the same verified hostname." };
  } catch {
    return { id, check, status: "unknown", evidence: "HTTP request or redirect parsing failed.",
      remediation: "Confirm that port 80 returns a redirect to the HTTPS site." };
  }
}

async function httpsChecks(domain: string): Promise<WebFinding[]> {
  const check = "HTTPS response";
  const id = "https.response";
  const origin = "https://" + domain;
  let response: Response;
  try {
    response = await request(origin + "/");
  } catch {
    return [{ id, check, status: "unknown", evidence: "HTTPS request failed or timed out.",
      remediation: "Check public DNS, HTTPS availability, and the endpoint certificate." }];
  }

  let evidence = "HTTPS returned HTTP " + response.status + ".";
  const location = response.headers.get("location");
  if (REDIRECTS.has(response.status) && location) {
    try {
      const target = new URL(location, origin);
      if (target.origin !== "null") evidence += " Redirect to " + (target.origin + target.pathname).slice(0, 300) + ".";
    } catch { /* malformed Location header */ }
  }
  if (!response.ok) {
    await response.body?.cancel();
    return [{ id, check, status: response.status >= 500 ? "unknown" : "review", evidence,
      remediation: "Inspect the root response and verify that the destination is reachable." }];
  }
  const findings: WebFinding[] = [{ id, check, status: "pass", evidence }];
  const hsts = response.headers.get("strict-transport-security");
  const csp = response.headers.get("content-security-policy");
  const frame = response.headers.get("x-frame-options");
  const ancestors = /(?:^|;)\s*frame-ancestors\s+([^;]+)/i.exec(csp ?? "")?.[1].trim();
  const restrictsFraming = ancestors
    ? !/\*/.test(ancestors) && !ancestors.split(/\s+/).some((source) => /^[a-z][a-z0-9+.-]*:$/i.test(source))
    : /^(deny|sameorigin)$/i.test(frame?.trim() ?? "");
  const headers = [
    ["headers.hsts", "Strict-Transport-Security", hsts, Number(hsts?.match(/(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)/i)?.[1]) > 0,
      "Set Strict-Transport-Security with a positive max-age after confirming HTTPS coverage."],
    ["headers.csp", "Content-Security-Policy", csp, Boolean(csp?.trim()),
      "Deploy an enforcing Content-Security-Policy appropriate for the application."],
    ["headers.nosniff", "X-Content-Type-Options", response.headers.get("x-content-type-options"),
      response.headers.get("x-content-type-options")?.trim().toLowerCase() === "nosniff", "Set X-Content-Type-Options to nosniff."],
    ["headers.framing", "Framing restrictions", ancestors ? "frame-ancestors " + ancestors : frame, restrictsFraming,
      "Set CSP frame-ancestors to the required origins, or use 'none' if embedding is unnecessary."],
    ["headers.referrer", "Referrer-Policy", response.headers.get("referrer-policy"), Boolean(response.headers.get("referrer-policy")?.trim()),
      "Set a suitable Referrer-Policy, such as strict-origin-when-cross-origin."],
  ] as const;
  for (const [id, check, value, ok, remediation] of headers) {
    findings.push({ id, check, status: ok ? "pass" : "review",
      evidence: value?.slice(0, 300) || "Header not observed.", remediation: ok ? undefined : remediation });
  }

  const cookies = response.headers.getSetCookie();
  const cookieIssues: string[] = [];
  for (const cookie of cookies.slice(0, 30)) {
    const [assignment, ...flags] = cookie.split(";");
    const rawName = assignment.slice(0, Math.max(0, assignment.indexOf("="))).trim();
    const name = /^[a-z0-9_!#$%&'*+.^|-]{1,80}$/i.test(rawName) ? rawName : "A cookie";
    const attributes = flags.map((flag) => flag.trim().toLowerCase());
    const missing = ["secure", "httponly"].filter((flag) => !attributes.includes(flag));
    if (!attributes.some((flag) => /^samesite\s*=\s*(strict|lax|none)$/.test(flag))) missing.push("samesite");
    if (missing.length) cookieIssues.push(name + " is missing " + missing.join(", "));
  }
  findings.push({
    id: "cookies.flags", check: "Cookie flags",
    status: cookieIssues.length ? "review" : cookies.length === 0 || cookies.length > 30 ? "unknown" : "pass",
    evidence: cookieIssues.length ? cookieIssues.join(". ").slice(0, 2000) + "."
      : cookies.length === 0 ? "The root response set no cookies."
      : cookies.length > 30 ? "Only the first 30 cookies were reviewed."
      : "Secure, HttpOnly, and SameSite observed on " + cookies.length + " cookie(s).",
    remediation: cookieIssues.length ? "Use Secure and HttpOnly for session cookies and set an appropriate SameSite value." : undefined,
  });

  try {
    if (!/^text\/html(?:;|$)/i.test(response.headers.get("content-type") ?? "")) {
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
    findings.push({ id: "html.mixed-content", check: "Mixed content", status: insecure.size ? "review" : "pass",
      evidence: insecure.size ? "HTTP resource origins: " + [...insecure].slice(0, 10).join(", ")
        : "No HTTP resource URLs in the inspected HTML attributes.",
      remediation: insecure.size ? "Serve those resources over HTTPS and replace the HTTP URLs." : undefined });
  } catch (error) {
    findings.push({ id: "html.mixed-content", check: "Mixed content", status: "unknown",
      evidence: error instanceof BodyLimitError ? "The root HTML exceeded the 256 KiB inspection limit."
        : "The root response did not provide inspectable HTML." });
  }
  return findings;
}

export async function scanVerifiedDomain(domain: string) {
  const [tls, upgrade, https] = await Promise.all([certificate(domain), redirect(domain), httpsChecks(domain)]);
  return [upgrade, ...https, tls];
}
