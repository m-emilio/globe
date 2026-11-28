// Offline self-test for Red Team Recon scoring (no network). Run with: npm run test:red
import { build } from "esbuild";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const dir = mkdtempSync(join(tmpdir(), "red-selftest-"));
try {
  const outfile = join(dir, "red.mjs");
  await build({ entryPoints: ["src/server/redTeamRecon.ts"], bundle: true, format: "esm", platform: "node", outfile, logLevel: "silent" });
  const red = await import(pathToFileURL(outfile).href);

  const group = (label, values) => ({ label, values, limited: false });
  const dns = (spf, dmarc, extra = []) => [group("SPF", spf), group("DMARC", dmarc), group("A", ["93.184.216.34"]), ...extra];
  const sev = (assessment, id) => assessment.findings.find(item => item.id === id)?.severity;
  const run = (results, extras = {}) => red.assessRed("example.com", results, extras, "2026-11-28T00:00:00Z");

  // Email spoofing scoring
  assert.equal(sev(run({ dns: dns([], []), certificates: null }), "email-spoofing"), "critical");
  assert.equal(sev(run({ dns: dns(['"v=spf1 -all"'], []), certificates: null }), "email-spoofing"), "high");
  assert.equal(sev(run({ dns: dns(['"v=spf1 +all"'], ['"v=DMARC1; p=reject"']), certificates: null }), "email-spoofing"), "critical");
  assert.equal(sev(run({ dns: dns(['"v=spf1 -all"'], ['"v=DMARC1; p=none"']), certificates: null }), "email-spoofing"), "medium");
  assert.equal(sev(run({ dns: dns(['"v=spf1 ~all"'], ['"v=DMARC1; p=quarantine"']), certificates: null }), "email-spoofing"), "low");
  assert.equal(sev(run({ dns: dns(['"v=spf1 -all"'], ['"v=DMARC1; p=reject"']), certificates: null }), "email-spoofing"), "info");
  assert.equal(sev(run({ dns: dns(['"v=spf1 -all"'], ['"v=DMARC1; p=reject; sp=none"']), certificates: null }), "email-spoofing"), "medium");
  assert.equal(sev(run({ dns: dns(['"v=spf1 -all"'], ['"v=DMARC1; p=reject; pct=50"']), certificates: null }), "email-spoofing"), "low");
  assert.equal(sev(run({ dns: [group("SPF", null), group("DMARC", null)], certificates: null }), "email-spoofing"), undefined);

  // Certificate-log findings
  const certificates = {
    records: [{ names: ["a.example.com"], issuer: "CA", issued: "2025-01-01", expires: "2026-01-01", revoked: false }],
    recordCount: 1, nameCount: 4,
    names: ["admin.example.com", "dev.example.com", "example.com", "www.example.com"],
  };
  const certAssessment = run({ dns: dns(['"v=spf1 -all"'], ['"v=DMARC1; p=reject"']), certificates });
  assert.equal(sev(certAssessment, "interesting-hosts"), "medium");
  assert.equal(sev(certAssessment, "cert-expired"), "medium");
  assert.equal(certAssessment.summary.subdomains, 4);

  // Exposure, takeover, headers
  const extras = {
    exposure: [
      { address: "203.0.113.10", status: "ok", ports: [22, 80, 3389], vulns: ["CVE-2021-44228"], hostnames: [], tags: [] },
      { address: "203.0.113.11", status: "ok", ports: [80, 443], vulns: [], hostnames: [], tags: ["cdn"] },
      { address: "203.0.113.12", status: "unavailable", ports: [], vulns: [], hostnames: [], tags: [] },
    ],
    takeover: { checked: 3, hints: [
      { name: "old.example.com", target: "x.github.io", service: "GitHub Pages", state: "dangling" },
      { name: "gone.example.com", target: "nowhere.example.net", service: null, state: "dangling" },
      { name: "docs.example.com", target: "y.readme.io", service: "Readme", state: "delegated" },
    ] },
    headers: { status: "ok", httpStatus: 200, missing: ["Strict-Transport-Security"], weak: [], disclosure: ["server: nginx/1.18.0"], downgrade: true },
  };
  const full = run({ dns: dns(['"v=spf1 -all"'], ['"v=DMARC1; p=reject"']), certificates: null }, extras);
  assert.equal(sev(full, "ports-203.0.113.10"), "high");
  assert.equal(sev(full, "cves-203.0.113.10"), "high");
  assert.equal(sev(full, "ports-203.0.113.11"), "info");
  assert.equal(sev(full, "takeover-old.example.com"), "high");
  assert.equal(sev(full, "takeover-gone.example.com"), "medium");
  assert.equal(sev(full, "takeover-delegated"), "info");
  assert.equal(sev(full, "headers-missing"), "medium");
  assert.equal(sev(full, "headers-downgrade"), "medium");
  assert.equal(sev(full, "headers-disclosure"), "low");
  assert.equal(full.summary.openPorts, 5);
  assert.equal(full.summary.cves, 1);
  assert.equal(full.summary.takeoverCandidates, 2);
  assert.equal(full.summary.worst, "high");
  assert.ok(full.entryPoints.every(item => item.severity !== "info"));
  assert.deepEqual(full.findings.map(item => item.severity), [...full.findings.map(item => item.severity)].sort((a, b) => red.SEVERITIES.indexOf(a) - red.SEVERITIES.indexOf(b)));
  assert.equal(run({ dns: dns(['"v=spf1 -all"'], ['"v=DMARC1; p=reject"']), certificates: null }, { headers: { status: "unreachable" } }).findings.some(item => item.id === "headers-unreachable"), true);

  // Exposure targets keep public addresses only, capped at three
  assert.deepEqual(red.exposureTargets([group("A", ["93.184.216.34", "10.0.0.1", "93.184.216.35", "93.184.216.36", "93.184.216.37"])]).length, 3);
  assert.deepEqual(red.exposureTargets([group("A", ["10.0.0.1", "192.168.1.5"])]), []);

  // Reports
  const md = red.redReportMarkdown("example.com", full, undefined, extras, "2026-11-28T00:00:00Z");
  assert.match(md, /^# Red Team Recon report: example.com/);
  assert.match(md, /Dangling CNAME on old.example.com/);
  const json = JSON.parse(red.redReportJson("example.com", full, undefined, extras, "2026-11-28T00:00:00Z"));
  assert.equal(json.summary.cves, 1);
  assert.equal(json.findings.length, full.findings.length);
  const hostile = run({ dns: dns(['"v=spf1 -all"'], ['"v=DMARC1; p=none"']), certificates: null });
  hostile.findings[0].evidence = "a|b\n<script>";
  assert.ok(!red.redReportMarkdown("x.com", hostile, undefined, {}, "t").includes("<script>"));
  console.log("red-team self-test passed");
} finally {
  rmSync(dir, { recursive: true, force: true });
}
