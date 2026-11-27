import type { ToolFinding } from "./purpleTeamTools";

function cookieAttributes(cookie: string): string[] {
  return cookie.split(";").slice(1).map(flag => flag.trim().toLowerCase());
}

export function globeHeaderFindings(headers: Headers, sessionCookieExample: string): ToolFinding[] {
  const hsts = headers.get("strict-transport-security") ?? "";
  const csp = headers.get("content-security-policy") ?? "";
  const maxAge = Number(hsts.match(/\bmax-age\s*=\s*(\d+)/i)?.[1]);
  const checks = [
    ["Content-Security-Policy", Boolean(csp.trim())],
    ["Strict-Transport-Security", Number.isFinite(maxAge) && maxAge > 0],
    ["X-Frame-Options", /^(deny|sameorigin)$/i.test(headers.get("x-frame-options")?.trim() ?? "")],
    ["X-Content-Type-Options", headers.get("x-content-type-options")?.trim().toLowerCase() === "nosniff"],
    ["Referrer-Policy", Boolean(headers.get("referrer-policy")?.trim())],
    ["Permissions-Policy", Boolean(headers.get("permissions-policy")?.trim())],
  ] as const;
  const missing = checks.filter(([, present]) => !present).map(([name]) => name);
  const grade = ["A", "B", "C", "D", "F"][Math.min(missing.length, 4)];
  const cookies = headers.getSetCookie();
  const flags = cookies.map(cookieAttributes);
  const withFlag = (test: (flag: string) => boolean) => flags.filter(cookie => cookie.some(test)).length;
  const secure = withFlag(flag => flag === "secure");
  const httpOnly = withFlag(flag => flag === "httponly");
  const sameSite = withFlag(flag => /^samesite\s*=\s*(lax|strict|none)$/.test(flag));
  const directives = hsts.split(";").map(directive => directive.trim().toLowerCase());
  const sessionFlags = cookieAttributes(sessionCookieExample);
  const sessionPolicy = [
    ["Secure", sessionFlags.includes("secure")],
    ["HttpOnly", sessionFlags.includes("httponly")],
    ["SameSite=Lax or Strict", sessionFlags.some(flag => /^samesite\s*=\s*(lax|strict)$/.test(flag))],
    ["Host-only", !sessionFlags.some(flag => /^domain\s*=/.test(flag))],
  ] as const;
  return [
    {
      check: "Globe security headers",
      status: missing.length ? "review" : "pass",
      evidence: "Coverage grade " + grade + " · " + (checks.length - missing.length) + "/" + checks.length + " checks on HEAD /." +
        (missing.length ? " Missing or invalid: " + missing.join(", ") + "." : ""),
    },
    {
      check: "Globe HSTS",
      status: Number.isFinite(maxAge) && maxAge > 0 ? "pass" : "review",
      evidence: hsts ? "max-age " + (Number.isFinite(maxAge) ? maxAge + " seconds" : "unavailable") +
        " · includeSubDomains " + (directives.includes("includesubdomains") ? "set" : "absent") +
        " · preload directive " + (directives.includes("preload") ? "set" : "absent") + "." : "Header absent.",
    },
    {
      check: "Globe root cookie flags",
      status: !cookies.length ? "unknown" : [secure, httpOnly, sameSite].every(count => count === cookies.length) ? "pass" : "review",
      evidence: cookies.length ? "HEAD / returned " + cookies.length + " cookies. Secure " + secure +
        " · HttpOnly " + httpOnly + " · SameSite " + sameSite + "." : "HEAD / returned zero Set-Cookie headers.",
    },
    {
      check: "Globe session cookie policy",
      status: sessionPolicy.every(([, present]) => present) ? "pass" : "review",
      evidence: "Generated from Globe's sign-in cookie builder · " +
        sessionPolicy.map(([label, present]) => label + " " + (present ? "set" : "absent")).join(" · ") + ".",
    },
  ];
}
