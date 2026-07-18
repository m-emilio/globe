/**
 * Push local .dev.vars into Cloudflare Worker secrets (never commits values).
 *
 * Usage:
 *   npx wrangler login
 *   node scripts/push-secrets-to-cf.mjs              # default worker: globe-security-test
 *   node scripts/push-secrets-to-cf.mjs globe        # explicit worker name
 *
 * Skips placeholders (whsec_..., sk_test_..., empty). Never prints secret values.
 */
import { readFileSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const workerName = process.argv[2] || "globe-security-test";
const varsPath = resolve(process.cwd(), ".dev.vars");

if (!existsSync(varsPath)) {
  console.error("Missing .dev.vars — copy from .dev.vars.example and fill real values.");
  process.exit(1);
}

function parseDevVars(text) {
  const out = {};
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const i = t.indexOf("=");
    if (i < 1) continue;
    const k = t.slice(0, i).trim();
    let v = t.slice(i + 1).trim();
    if (
      (v.startsWith('"') && v.endsWith('"')) ||
      (v.startsWith("'") && v.endsWith("'"))
    ) {
      v = v.slice(1, -1);
    }
    if (k) out[k] = v;
  }
  return out;
}

function isPlaceholder(name, value) {
  const v = (value || "").trim();
  if (!v) return true;
  if (/\.\.\.|your_|change-me|placeholder|whsec_\.\.\./i.test(v)) return true;
  // Incomplete webhook secrets often look like "whsec_... # comment"
  if (name === "STRIPE_WEBHOOK_SECRET" && !/^whsec_[A-Za-z0-9]+$/.test(v)) {
    return true;
  }
  return false;
}

// Secrets / env that the Worker runtime reads
const KEYS = [
  "TRANSIT_PUBLICAPI_V4",
  "TRANSIT_REQUIRE_PAYMENT",
  "STRIPE_SECRET_KEY",
  "STRIPE_WEBHOOK_SECRET",
  "STRIPE_PUBLISHABLE_KEY",
  "STRIPE_PAYMENT_LINK_URL",
  "STRIPE_MIN_AMOUNT_CENTS",
  "STRIPE_SUCCESS_URL",
  "STRIPE_CANCEL_URL",
  "ADMIN_ACTION_SECRET",
  "ADMIN_FINGERPRINTS",
  "ADMIN_USER_IDS",
];

const vars = parseDevVars(readFileSync(varsPath, "utf8"));
if (!vars.STRIPE_MIN_AMOUNT_CENTS) vars.STRIPE_MIN_AMOUNT_CENTS = "2000";
if (!vars.TRANSIT_REQUIRE_PAYMENT) vars.TRANSIT_REQUIRE_PAYMENT = "1";

console.log(`Target Worker: ${workerName}`);
console.log("Putting secrets via wrangler (values never logged)...\n");

let ok = 0;
let skipped = 0;
let failed = 0;

for (const key of KEYS) {
  const value = vars[key];
  if (value == null || isPlaceholder(key, value)) {
    console.log(`  skip  ${key} (missing or placeholder)`);
    skipped += 1;
    continue;
  }
  const r = spawnSync(
    "npx",
    ["wrangler", "secret", "put", key, "--name", workerName],
    {
      input: value,
      encoding: "utf8",
      shell: true,
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  if (r.status === 0) {
    console.log(`  ok    ${key} (len=${String(value).length})`);
    ok += 1;
  } else {
    console.log(`  FAIL  ${key}: ${(r.stderr || r.stdout || "").trim().slice(0, 200)}`);
    failed += 1;
  }
}

console.log(`\nDone. ok=${ok} skipped=${skipped} failed=${failed}`);
if (failed > 0) process.exit(1);
if (ok === 0) {
  console.error("No secrets uploaded. Run: npx wrangler login");
  process.exit(1);
}
