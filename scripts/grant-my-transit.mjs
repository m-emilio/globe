/**
 * One-shot: list local users is not available remotely.
 * Use Admin UI after setting ADMIN_FINGERPRINTS.
 *
 * This script prints the paid Stripe session you can paste into Admin → Claim session.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Stripe from "stripe";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const vars = Object.fromEntries(
  fs
    .readFileSync(path.join(root, ".dev.vars"), "utf8")
    .split(/\r?\n/)
    .filter((l) => l && !l.trim().startsWith("#") && l.includes("="))
    .map((l) => {
      const i = l.indexOf("=");
      return [l.slice(0, i).trim(), l.slice(i + 1).trim()];
    }),
);

const stripe = new Stripe(vars.STRIPE_SECRET_KEY);
const sessions = await stripe.checkout.sessions.list({ limit: 25 });
const paid = sessions.data.filter((s) => s.payment_status === "paid");

console.log("Paid Checkout sessions (paste session id into Admin → Claim):");
for (const s of paid) {
  console.log(
    `  ${s.id}  amount=${s.amount_total}  ref=${s.client_reference_id || "(none)"}  ${new Date(s.created * 1000).toISOString()}`,
  );
}
if (paid[0]) {
  console.log("\nLatest paid session id:");
  console.log(paid[0].id);
  if (!paid[0].client_reference_id) {
    console.log(
      "\nNote: this payment has no client_reference_id (bought before binding).",
    );
    console.log(
      "In Admin: Lookup your fingerprint, then Claim session with that user selected.",
    );
  }
}
