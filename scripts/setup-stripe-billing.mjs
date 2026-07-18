/**
 * Automate Stripe Payment Link success redirect + optional webhook registration.
 * Does NOT require the Stripe CLI.
 *
 * Usage:
 *   node scripts/setup-stripe-billing.mjs
 *   node scripts/setup-stripe-billing.mjs --app-url http://127.0.0.1:8787
 *   node scripts/setup-stripe-billing.mjs --app-url https://your-worker.workers.dev --webhook
 *
 * Reads STRIPE_SECRET_KEY + STRIPE_PAYMENT_LINK_URL from .dev.vars
 * Writes STRIPE_WEBHOOK_SECRET when a new endpoint is created (--webhook + public URL).
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Stripe from "stripe";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const devVarsPath = path.join(root, ".dev.vars");

function parseArgs(argv) {
  const out = {
    appUrl: "http://127.0.0.1:8787",
    webhook: false,
    webhookUrl: null,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--app-url" && argv[i + 1]) {
      out.appUrl = argv[++i].replace(/\/$/, "");
    } else if (a === "--webhook") {
      out.webhook = true;
    } else if (a === "--webhook-url" && argv[i + 1]) {
      out.webhookUrl = argv[++i].replace(/\/$/, "");
      out.webhook = true;
    }
  }
  return out;
}

function parseDevVars(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`.dev.vars not found at ${filePath}`);
  }
  const map = {};
  for (const line of fs.readFileSync(filePath, "utf8").split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const i = t.indexOf("=");
    if (i <= 0) continue;
    map[t.slice(0, i).trim()] = t.slice(i + 1).trim();
  }
  return map;
}

function upsertDevVar(filePath, key, value) {
  let text = fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : "";
  const re = new RegExp(`^${key}=.*$`, "m");
  if (re.test(text)) {
    text = text.replace(re, `${key}=${value}`);
  } else {
    text = `${text.replace(/\s*$/, "")}\n${key}=${value}\n`;
  }
  fs.writeFileSync(filePath, text, "utf8");
}

function mask(s) {
  if (!s || s.length < 12) return "(set)";
  return `${s.slice(0, 7)}…${s.slice(-4)}`;
}

async function findPaymentLink(stripe, paymentLinkUrl) {
  const target = (paymentLinkUrl || "").trim();
  if (!target) return null;

  // Direct plink_ id
  const plMatch = target.match(/plink_[a-zA-Z0-9]+/);
  if (plMatch) {
    return stripe.paymentLinks.retrieve(plMatch[0]);
  }

  // Match buy.stripe.com/... short URL against listed links
  let startingAfter;
  for (let page = 0; page < 10; page += 1) {
    const list = await stripe.paymentLinks.list({
      limit: 100,
      starting_after: startingAfter,
    });
    for (const link of list.data) {
      if (link.url === target || target.endsWith(link.url.split("/").pop())) {
        return link;
      }
      // some accounts expose url that matches buy.stripe.com path segment
      if (link.url && target.includes(link.url.replace("https://", ""))) {
        return link;
      }
    }
    if (!list.has_more || list.data.length === 0) break;
    startingAfter = list.data[list.data.length - 1].id;
  }

  // Fallback: active link with matching amount if only one active
  const active = await stripe.paymentLinks.list({ limit: 20, active: true });
  if (active.data.length === 1) return active.data[0];
  return null;
}

async function ensureWebhook(stripe, webhookUrl) {
  const full = `${webhookUrl.replace(/\/$/, "")}/api/billing/webhook`;
  const events = [
    "checkout.session.completed",
    "checkout.session.async_payment_succeeded",
  ];

  const existing = await stripe.webhookEndpoints.list({ limit: 100 });
  const found = existing.data.find((e) => e.url === full && e.status === "enabled");
  if (found) {
    return {
      id: found.id,
      url: found.url,
      secret: null, // secret only returned on create
      created: false,
    };
  }

  const created = await stripe.webhookEndpoints.create({
    url: full,
    enabled_events: events,
    description: "Globe Transit billing unlock",
  });

  return {
    id: created.id,
    url: created.url,
    secret: created.secret || null,
    created: true,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const vars = parseDevVars(devVarsPath);
  const secret = vars.STRIPE_SECRET_KEY?.trim();
  if (!secret) {
    throw new Error("STRIPE_SECRET_KEY missing in .dev.vars");
  }

  const stripe = new Stripe(secret, {
    apiVersion: "2025-02-24.acacia",
  });

  const appUrl = args.appUrl;
  const successUrl = `${appUrl}/?billing=success&session_id={CHECKOUT_SESSION_ID}`;
  const cancelUrl = `${appUrl}/?billing=cancel`;

  console.log("Stripe billing setup (no CLI required)");
  console.log(`  App URL:     ${appUrl}`);
  console.log(`  Success URL: ${successUrl}`);
  console.log(`  Cancel URL:  ${cancelUrl}`);
  console.log(`  Secret key:  ${mask(secret)}`);

  // 1) Payment Link after_completion → unlock via claim-session (works without webhook)
  const linkUrl = vars.STRIPE_PAYMENT_LINK_URL?.trim();
  const paymentLink = await findPaymentLink(stripe, linkUrl);
  if (!paymentLink) {
    console.warn(
      "Could not find Payment Link from STRIPE_PAYMENT_LINK_URL. Set after-payment redirect manually in Stripe Dashboard:",
    );
    console.warn(`  ${successUrl}`);
  } else {
    const updated = await stripe.paymentLinks.update(paymentLink.id, {
      after_completion: {
        type: "redirect",
        redirect: { url: successUrl },
      },
    });
    console.log(`  Payment Link: ${updated.id} → success redirect configured`);
    if (updated.url) {
      upsertDevVar(devVarsPath, "STRIPE_PAYMENT_LINK_URL", updated.url);
      console.log(`  Updated STRIPE_PAYMENT_LINK_URL in .dev.vars`);
    }
  }

  // Optional cancel is Payment Link hosted; Dashboard also has "Don't show confirmation" path.
  // Store cancel URL for docs
  upsertDevVar(devVarsPath, "STRIPE_CANCEL_URL", cancelUrl);
  upsertDevVar(devVarsPath, "STRIPE_SUCCESS_URL", successUrl);

  // 2) Webhook only for publicly reachable HTTPS hosts (Stripe cannot reach localhost)
  const isLocal =
    /localhost|127\.0\.0\.1/i.test(appUrl) || appUrl.startsWith("http://");
  const wantWebhook = args.webhook || Boolean(args.webhookUrl);
  const webhookBase = args.webhookUrl || appUrl;

  if (wantWebhook) {
    if (isLocal && !args.webhookUrl) {
      console.log("");
      console.log(
        "Skipping Stripe Dashboard webhook for localhost (Stripe cannot POST to 127.0.0.1).",
      );
      console.log(
        "Unlock path for local: Payment Link success redirect → claim-session (configured above).",
      );
      console.log(
        "For a real webhook later: deploy, then re-run with --app-url https://your-host --webhook",
      );
    } else if (!/^https:\/\//i.test(webhookBase)) {
      console.warn(
        "Webhook URL must be https:// for Stripe Dashboard endpoints. Skipping webhook create.",
      );
    } else {
      const wh = await ensureWebhook(stripe, webhookBase);
      console.log(
        `  Webhook: ${wh.id} ${wh.created ? "(created)" : "(already exists)"}`,
      );
      console.log(`  Webhook URL: ${wh.url}`);
      if (wh.secret) {
        upsertDevVar(devVarsPath, "STRIPE_WEBHOOK_SECRET", wh.secret);
        console.log(
          `  Wrote STRIPE_WEBHOOK_SECRET to .dev.vars (${mask(wh.secret)})`,
        );
      } else {
        console.log(
          "  Endpoint already existed — secret is only shown once at create time.",
        );
        console.log(
          "  Keep your existing STRIPE_WEBHOOK_SECRET, or delete the endpoint in Dashboard and re-run.",
        );
      }
    }
  } else {
    console.log("");
    console.log(
      "Webhook not requested. Local unlock uses success redirect + claim-session.",
    );
    console.log(
      "When you deploy publicly: node scripts/setup-stripe-billing.mjs --app-url https://YOUR_HOST --webhook",
    );
  }

  console.log("");
  console.log("Done. Restart wrangler if .dev.vars changed: npm run dev");
  console.log(
    "Test: sign in → Buy Transit access → complete checkout → return should unlock.",
  );
}

main().catch((err) => {
  console.error("setup-stripe-billing failed:", err.message || err);
  process.exit(1);
});
