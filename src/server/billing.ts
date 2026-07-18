/**
 * Stripe Payment Link + webhook entitlement (optional, for later).
 *
 * Default product path uses Cloudflare login (auth.ts). Payment enforcement
 * is off unless TRANSIT_REQUIRE_PAYMENT=1. When Stripe is enabled later:
 * 1. Logged-in user opens Payment Link with client_reference_id=<userId>
 * 2. Webhook verifies signature and sets user.transitPaid
 * 3. claim-session only grants if client_reference_id === session user id
 */

import Stripe from "stripe";
import {
  getSessionUser,
  rateLimitOrNull,
  setUserTransitPaid,
  clientIp,
  type AuthEnv,
} from "./auth";

const DEFAULT_PAYMENT_LINK_URL =
  "https://buy.stripe.com/fZubJ2aGpgzr0sX0gW0oM00";
const PAYMENT_LINK_KV_KEY = "stripe:payment_link_url";
const CATALOG_KV_KEY = "stripe:catalog";
const CLAIMED_SESSION_PREFIX = "payment:claimed:";

export type BillingEnv = AuthEnv & {
  STRIPE_SECRET_KEY?: string;
  STRIPE_WEBHOOK_SECRET?: string;
  STRIPE_PRICE_ID?: string;
  STRIPE_PAYMENT_LINK_URL?: string;
  STRIPE_PUBLISHABLE_KEY?: string;
  /** Minimum paid amount in cents (default 2000 = $20). */
  STRIPE_MIN_AMOUNT_CENTS?: string;
  /** When "1", allow payment_status=no_payment_required to grant access. */
  STRIPE_ALLOW_FREE?: string;
};

/** Default $20 unlock price in cents. */
const DEFAULT_MIN_AMOUNT_CENTS = 2000;

function minAmountCents(env: BillingEnv): number {
  const n = Number(env.STRIPE_MIN_AMOUNT_CENTS);
  return Number.isFinite(n) && n >= 0 ? Math.round(n) : DEFAULT_MIN_AMOUNT_CENTS;
}

function allowFreeCheckout(env: BillingEnv): boolean {
  const v = env.STRIPE_ALLOW_FREE?.trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes";
}

function paymentQualifies(
  env: BillingEnv,
  paymentStatus: string,
  amountTotal: number | null,
): { ok: true } | { ok: false; reason: string } {
  if (paymentStatus === "no_payment_required") {
    if (!allowFreeCheckout(env)) {
      return {
        ok: false,
        reason: "free_checkout_disabled",
      };
    }
    return { ok: true };
  }
  if (paymentStatus !== "paid") {
    return { ok: false, reason: "payment_not_complete" };
  }
  const min = minAmountCents(env);
  if (min > 0) {
    if (amountTotal == null || !Number.isFinite(amountTotal)) {
      return { ok: false, reason: "amount_missing" };
    }
    if (amountTotal < min) {
      return { ok: false, reason: "amount_too_low" };
    }
  }
  return { ok: true };
}

export type EntitlementRecord = {
  status: "active" | "inactive";
  userId: string;
  sessionId: string | null;
  customerId: string | null;
  customerEmail: string | null;
  paymentStatus: string;
  amountTotal: number | null;
  currency: string | null;
  grantedAt: string;
  source: "webhook" | "claim";
};

type BillingCatalog = {
  paymentLinkUrl: string;
  label: string;
  amountLabel: string;
  updatedAt: string;
};

type SecurityHeadersFn = (headers: Headers) => void;

function json(
  data: unknown,
  init?: ResponseInit,
  applySecurityHeaders?: SecurityHeadersFn,
) {
  const headers = new Headers(init?.headers);
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  applySecurityHeaders?.(headers);
  return new Response(JSON.stringify(data), { ...init, headers });
}

function createStripeClient(secretKey: string) {
  return new Stripe(secretKey, {
    httpClient: Stripe.createFetchHttpClient(),
  } as ConstructorParameters<typeof Stripe>[1]);
}

function resolvePaymentLinkUrl(env: BillingEnv): string {
  return env.STRIPE_PAYMENT_LINK_URL?.trim() || DEFAULT_PAYMENT_LINK_URL;
}

function entitlementUserKey(userId: string) {
  return `entitlement:user:${userId}`;
}

function paymentSessionKey(sessionId: string) {
  return `payment:session:${sessionId}`;
}

function claimedSessionKey(sessionId: string) {
  return `${CLAIMED_SESSION_PREFIX}${sessionId}`;
}

/**
 * Return Payment Link URL for the *authenticated* user only.
 * client_reference_id is always the server-side user id (not client-supplied).
 */
export async function getPaymentLink(
  request: Request,
  env: BillingEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const limited = rateLimitOrNull(
    `billing:link:${clientIp(request)}`,
    20,
    60_000,
    applySecurityHeaders,
  );
  if (limited) return limited;

  const session = await getSessionUser(request, env);
  if (!session) {
    return json(
      {
        error: "login_required",
        message: "Log in before starting checkout.",
      },
      { status: 401 },
      applySecurityHeaders,
    );
  }

  if (session.user.transitPaid) {
    return json(
      {
        error: "already_paid",
        message:
          "Stripe access is already unlocked on this account (Transit + Live Feed).",
        url: null,
      },
      { status: 409 },
      applySecurityHeaders,
    );
  }

  let paymentLinkUrl =
    (env.BILLING_KV && (await env.BILLING_KV.get(PAYMENT_LINK_KV_KEY))) ||
    resolvePaymentLinkUrl(env);

  // Always bind checkout to the authenticated user id (never client-supplied).
  try {
    const link = new URL(paymentLinkUrl);
    link.searchParams.set("client_reference_id", session.user.id);
    // Strip any client-tampered params that might have been stored in KV.
    paymentLinkUrl = link.toString();
  } catch {
    return json(
      {
        error: "payment_link_invalid",
        message: "Payment link is misconfigured.",
      },
      { status: 503 },
      applySecurityHeaders,
    );
  }

  return json(
    {
      url: paymentLinkUrl,
      label: "Transit + Live Feed",
      amountLabel: "$20",
    },
    { status: 200 },
    applySecurityHeaders,
  );
}

/**
 * Minimal access status for the logged-in user (no setup recon, no PII dump).
 */
export async function getAccessStatus(
  request: Request,
  env: BillingEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const session = await getSessionUser(request, env);
  if (!session) {
    return json(
      {
        authenticated: false,
        hasAccess: false,
      },
      { status: 200 },
      applySecurityHeaders,
    );
  }

  return json(
    {
      authenticated: true,
      hasAccess: Boolean(session.user.transitPaid),
      fingerprint: session.user.fingerprint,
    },
    { status: 200 },
    applySecurityHeaders,
  );
}

/**
 * Grant paid entitlement with claim-first race reduction and amount checks.
 * Exported for admin claim path.
 */
export async function grantPaidToUser(
  env: BillingEnv,
  input: {
    userId: string;
    sessionId: string | null;
    customerId: string | null;
    customerEmail: string | null;
    paymentStatus: string;
    amountTotal: number | null;
    currency: string | null;
    source: EntitlementRecord["source"];
    /** Admin recovery may rebind when true and secret path already gated */
    forceRebind?: boolean;
  },
): Promise<EntitlementRecord | null> {
  if (!env.BILLING_KV) return null;
  if (!/^[a-f0-9]{16,64}$/i.test(input.userId)) {
    return null;
  }

  const qual = paymentQualifies(env, input.paymentStatus, input.amountTotal);
  if (!qual.ok) {
    return null;
  }

  // Claim-first: write claimed key before unlocking (reduces dual-grant race)
  if (input.sessionId) {
    const claimKey = claimedSessionKey(input.sessionId);
    const existing = await env.BILLING_KV.get(claimKey);
    if (existing && existing !== input.userId && !input.forceRebind) {
      return null;
    }
    // Reserve claim for this user before grant
    await env.BILLING_KV.put(claimKey, input.userId, {
      expirationTtl: 60 * 60 * 24 * 365,
    });
    // Re-read winner
    const winner = await env.BILLING_KV.get(claimKey);
    if (winner !== input.userId && !input.forceRebind) {
      return null;
    }
  }

  const user = await setUserTransitPaid(env, input.userId, true);
  if (!user) return null;

  const record: EntitlementRecord = {
    status: "active",
    userId: input.userId,
    sessionId: input.sessionId,
    customerId: input.customerId,
    customerEmail: input.customerEmail,
    paymentStatus: input.paymentStatus,
    amountTotal: input.amountTotal,
    currency: input.currency,
    grantedAt: new Date().toISOString(),
    source: input.source,
  };

  await env.BILLING_KV.put(
    entitlementUserKey(input.userId),
    JSON.stringify(record),
  );
  if (input.sessionId) {
    await env.BILLING_KV.put(
      paymentSessionKey(input.sessionId),
      JSON.stringify({ userId: input.userId, grantedAt: record.grantedAt }),
    );
  }

  return record;
}

/**
 * Secure claim: caller must be logged in; Stripe session.client_reference_id
 * must equal the logged-in user id. No free rebinding of paid sessions.
 */
export async function claimCheckoutSession(
  request: Request,
  env: BillingEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const limited = rateLimitOrNull(
    `billing:claim:${clientIp(request)}`,
    10,
    60_000,
    applySecurityHeaders,
  );
  if (limited) return limited;

  if (!env.BILLING_KV) {
    return json(
      { error: "kv_missing", message: "BILLING_KV is required." },
      { status: 503 },
      applySecurityHeaders,
    );
  }

  const auth = await getSessionUser(request, env);
  if (!auth) {
    return json(
      { error: "login_required", message: "Log in before claiming a purchase." },
      { status: 401 },
      applySecurityHeaders,
    );
  }

  const secret = env.STRIPE_SECRET_KEY?.trim();
  if (!secret) {
    return json(
      {
        error: "stripe_not_configured",
        message: "Stripe is not configured on this deployment.",
      },
      { status: 503 },
      applySecurityHeaders,
    );
  }

  let body: { session_id?: string } = {};
  try {
    body = (await request.json()) as typeof body;
  } catch {
    body = {};
  }

  const url = new URL(request.url);
  const sessionId =
    body.session_id?.trim() || url.searchParams.get("session_id")?.trim();

  if (!sessionId || !/^cs_[a-zA-Z0-9_]+$/.test(sessionId)) {
    return json(
      { error: "session_id_required" },
      { status: 400 },
      applySecurityHeaders,
    );
  }

  try {
    const stripe = createStripeClient(secret);
    const checkout = await stripe.checkout.sessions.retrieve(sessionId);

    const ref =
      typeof checkout.client_reference_id === "string"
        ? checkout.client_reference_id.trim()
        : "";

    // Critical: paid session may only unlock the user named in client_reference_id
    if (!ref || ref !== auth.user.id) {
      return json(
        {
          error: "session_user_mismatch",
          message:
            "This checkout session is not linked to your account. Open checkout while logged in.",
        },
        { status: 403 },
        applySecurityHeaders,
      );
    }

    const record = await grantPaidToUser(env, {
      userId: auth.user.id,
      sessionId: checkout.id,
      customerId:
        typeof checkout.customer === "string"
          ? checkout.customer
          : checkout.customer?.id ?? null,
      customerEmail:
        checkout.customer_details?.email ?? checkout.customer_email ?? null,
      paymentStatus: checkout.payment_status,
      amountTotal: checkout.amount_total,
      currency: checkout.currency,
      source: "claim",
    });

    if (!record) {
      const qual = paymentQualifies(
        env,
        checkout.payment_status,
        checkout.amount_total,
      );
      return json(
        {
          error: qual.ok ? "claim_unavailable" : "payment_not_complete",
          message: qual.ok
            ? "Session was already claimed by another account."
            : "Payment is incomplete or does not meet the minimum amount.",
          code: qual.ok ? "claim_unavailable" : qual.reason,
        },
        { status: 402 },
        applySecurityHeaders,
      );
    }

    return json(
      { hasAccess: true, authenticated: true },
      { status: 200 },
      applySecurityHeaders,
    );
  } catch {
    return json(
      {
        error: "claim_failed",
        message: "Could not claim checkout session. Try again shortly.",
      },
      { status: 502 },
      applySecurityHeaders,
    );
  }
}

/**
 * Stripe webhook: unlock transit for user id in client_reference_id.
 */
export async function handleStripeWebhook(
  request: Request,
  env: BillingEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const webhookSecret = env.STRIPE_WEBHOOK_SECRET?.trim();
  const secretKey = env.STRIPE_SECRET_KEY?.trim();

  if (!webhookSecret || !secretKey) {
    return json(
      {
        error: "stripe_not_configured",
        message: "Webhook secret and secret key must be set.",
      },
      { status: 503 },
      applySecurityHeaders,
    );
  }

  if (!env.BILLING_KV) {
    return json(
      { error: "kv_missing" },
      { status: 503 },
      applySecurityHeaders,
    );
  }

  const signature = request.headers.get("stripe-signature");
  if (!signature) {
    return json(
      { error: "stripe_signature_missing" },
      { status: 400 },
      applySecurityHeaders,
    );
  }

  const stripe = createStripeClient(secretKey);
  const payload = await request.text();

  let event: Stripe.Event;
  try {
    event = await stripe.webhooks.constructEventAsync(
      payload,
      signature,
      webhookSecret,
    );
  } catch {
    return json(
      {
        error: "stripe_signature_invalid",
        message: "Invalid Stripe webhook signature.",
      },
      { status: 400 },
      applySecurityHeaders,
    );
  }

  if (
    event.type === "checkout.session.completed" ||
    event.type === "checkout.session.async_payment_succeeded"
  ) {
    const checkout = event.data.object as Stripe.Checkout.Session;
    const userId =
      typeof checkout.client_reference_id === "string"
        ? checkout.client_reference_id.trim()
        : "";

    if (userId) {
      await grantPaidToUser(env, {
        userId,
        sessionId: checkout.id,
        customerId:
          typeof checkout.customer === "string"
            ? checkout.customer
            : checkout.customer?.id ?? null,
        customerEmail:
          checkout.customer_details?.email ?? checkout.customer_email ?? null,
        paymentStatus: checkout.payment_status,
        amountTotal: checkout.amount_total,
        currency: checkout.currency,
        source: "webhook",
      });
    }
  }

  return json({ received: true }, { status: 200 }, applySecurityHeaders);
}

/**
 * Seed catalog — login required; never returns secrets or raw payment URLs.
 */
export async function ensureBillingCatalog(
  request: Request,
  env: BillingEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const limited = rateLimitOrNull(
    `billing:catalog:${clientIp(request)}`,
    20,
    60_000,
    applySecurityHeaders,
  );
  if (limited) return limited;

  const session = await getSessionUser(request, env);
  if (!session) {
    return json(
      {
        error: "login_required",
        message: "Log in before starting checkout.",
      },
      { status: 401 },
      applySecurityHeaders,
    );
  }

  const paymentLinkUrl = resolvePaymentLinkUrl(env);
  const catalog: BillingCatalog = {
    paymentLinkUrl,
    label: "Transit + Live Feed",
    amountLabel: "$20",
    updatedAt: new Date().toISOString(),
  };

  if (env.BILLING_KV) {
    await env.BILLING_KV.put(PAYMENT_LINK_KV_KEY, paymentLinkUrl);
    await env.BILLING_KV.put(CATALOG_KV_KEY, JSON.stringify(catalog));
  }

  return json(
    {
      label: catalog.label,
      amountLabel: catalog.amountLabel,
    },
    { status: 200 },
    applySecurityHeaders,
  );
}

/**
 * Read-only payment status — never claims / never rebinds.
 */
export async function getPaymentStatus(
  request: Request,
  env: BillingEnv,
  applySecurityHeaders?: SecurityHeadersFn,
): Promise<Response> {
  const limited = rateLimitOrNull(
    `billing:status:${clientIp(request)}`,
    20,
    60_000,
    applySecurityHeaders,
  );
  if (limited) return limited;

  const auth = await getSessionUser(request, env);
  if (!auth) {
    return json(
      { error: "login_required" },
      { status: 401 },
      applySecurityHeaders,
    );
  }

  const url = new URL(request.url);
  const sessionId = url.searchParams.get("session_id")?.trim();
  if (!sessionId || !/^cs_[a-zA-Z0-9_]+$/.test(sessionId)) {
    return json(
      { error: "session_id_required" },
      { status: 400 },
      applySecurityHeaders,
    );
  }

  if (env.BILLING_KV) {
    const claimed = await env.BILLING_KV.get(claimedSessionKey(sessionId));
    if (claimed) {
      return json(
        {
          claimed: true,
          belongsToYou: claimed === auth.user.id,
          hasAccess: Boolean(auth.user.transitPaid),
        },
        { status: 200 },
        applySecurityHeaders,
      );
    }
  }

  return json(
    {
      claimed: false,
      hasAccess: Boolean(auth.user.transitPaid),
    },
    { status: 200 },
    applySecurityHeaders,
  );
}

// Re-export transit gate from auth (single source of truth)
export { requireTransitAccess } from "./auth";
