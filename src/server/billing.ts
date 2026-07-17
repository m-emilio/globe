import Stripe from "stripe";

const PRODUCT_NAME = "Example Product";
const PRODUCT_AMOUNT_CENTS = 2000;
const PRODUCT_CURRENCY = "usd";
const PRICE_KV_KEY = "stripe:example-product:price_id";
const PRODUCT_KV_KEY = "stripe:example-product:product_id";

export type BillingEnv = {
  STRIPE_SECRET_KEY?: string;
  STRIPE_WEBHOOK_SECRET?: string;
  STRIPE_PRICE_ID?: string;
  BILLING_KV?: KVNamespace;
};

type PaymentRecord = {
  sessionId: string;
  paymentStatus: string;
  customerId: string | null;
  customerEmail: string | null;
  amountTotal: number | null;
  currency: string | null;
  priceId: string | null;
  completedAt: string;
};

function json(
  data: unknown,
  init?: ResponseInit,
  applySecurityHeaders?: (headers: Headers) => void,
) {
  const headers = new Headers(init?.headers);
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  applySecurityHeaders?.(headers);
  return new Response(JSON.stringify(data), { ...init, headers });
}

function createStripeClient(secretKey: string) {
  // API version intentionally left unset (use account default / SDK default)
  return new Stripe(secretKey, {
    httpClient: Stripe.createFetchHttpClient(),
  } as ConstructorParameters<typeof Stripe>[1]);
}

function requireStripeSecret(env: BillingEnv): string | Response {
  const key = env.STRIPE_SECRET_KEY?.trim();
  if (!key) {
    return json(
      {
        error: "stripe_secret_missing",
        message:
          "Set STRIPE_SECRET_KEY in .dev.vars (local) or as a Cloudflare/GitHub secret. Get keys from the Stripe Dashboard.",
      },
      { status: 503 },
    );
  }
  return key;
}

async function readStoredPriceId(env: BillingEnv): Promise<string | null> {
  if (env.STRIPE_PRICE_ID?.trim()) {
    return env.STRIPE_PRICE_ID.trim();
  }
  if (!env.BILLING_KV) {
    return null;
  }
  return env.BILLING_KV.get(PRICE_KV_KEY);
}

/**
 * Ensure the one-time Example Product + default price exist.
 * Reuses env STRIPE_PRICE_ID or KV-stored price when present.
 */
export async function ensureBillingProduct(
  env: BillingEnv,
  applySecurityHeaders?: (headers: Headers) => void,
): Promise<Response> {
  const secretOrError = requireStripeSecret(env);
  if (secretOrError instanceof Response) {
    return secretOrError;
  }

  const existingPriceId = await readStoredPriceId(env);
  if (existingPriceId) {
    return json(
      {
        productId: env.BILLING_KV
          ? await env.BILLING_KV.get(PRODUCT_KV_KEY)
          : null,
        priceId: existingPriceId,
        reused: true,
      },
      { status: 200 },
      applySecurityHeaders,
    );
  }

  const stripe = createStripeClient(secretOrError);

  try {
    const product = await stripe.products.create({
      name: PRODUCT_NAME,
      default_price_data: {
        currency: PRODUCT_CURRENCY,
        unit_amount: PRODUCT_AMOUNT_CENTS,
      },
    });

    const priceId =
      typeof product.default_price === "string"
        ? product.default_price
        : product.default_price?.id;

    if (!priceId) {
      return json(
        {
          error: "stripe_price_missing",
          message: "Product created without a default price id",
        },
        { status: 502 },
        applySecurityHeaders,
      );
    }

    if (env.BILLING_KV) {
      await env.BILLING_KV.put(PRICE_KV_KEY, priceId);
      await env.BILLING_KV.put(PRODUCT_KV_KEY, product.id);
    }

    return json(
      {
        productId: product.id,
        priceId,
        reused: false,
      },
      { status: 200 },
      applySecurityHeaders,
    );
  } catch (error) {
    return json(
      {
        error: "stripe_product_create_failed",
        message: error instanceof Error ? error.message : "unknown_error",
      },
      { status: 502 },
      applySecurityHeaders,
    );
  }
}

/**
 * Create a Checkout Session for a one-time payment (mode=payment).
 */
export async function createCheckoutSession(
  request: Request,
  env: BillingEnv,
  applySecurityHeaders?: (headers: Headers) => void,
): Promise<Response> {
  const secretOrError = requireStripeSecret(env);
  if (secretOrError instanceof Response) {
    return secretOrError;
  }

  const stripe = createStripeClient(secretOrError);

  let priceId = await readStoredPriceId(env);
  if (!priceId) {
    const ensured = await ensureBillingProduct(env, applySecurityHeaders);
    if (!ensured.ok) {
      return ensured;
    }
    const body = (await ensured.json()) as { priceId?: string };
    priceId = body.priceId ?? null;
  }

  if (!priceId) {
    return json(
      {
        error: "stripe_price_unavailable",
        message: "Could not resolve a Stripe price for checkout",
      },
      { status: 502 },
      applySecurityHeaders,
    );
  }

  const origin = new URL(request.url).origin;
  const successUrl = `${origin}/?billing=success&session_id={CHECKOUT_SESSION_ID}`;
  const cancelUrl = `${origin}/?billing=cancel`;

  try {
    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      line_items: [
        {
          price: priceId,
          quantity: 1,
        },
      ],
      success_url: successUrl,
      cancel_url: cancelUrl,
      // Persist linkage for later webhook / status lookups
      metadata: {
        product_name: PRODUCT_NAME,
        price_id: priceId,
      },
    });

    if (env.BILLING_KV && session.id) {
      await env.BILLING_KV.put(
        `checkout:session:${session.id}`,
        JSON.stringify({
          sessionId: session.id,
          status: session.status,
          paymentStatus: session.payment_status,
          priceId,
          createdAt: new Date().toISOString(),
        }),
      );
    }

    return json(
      {
        sessionId: session.id,
        url: session.url,
      },
      { status: 200 },
      applySecurityHeaders,
    );
  } catch (error) {
    return json(
      {
        error: "stripe_checkout_create_failed",
        message: error instanceof Error ? error.message : "unknown_error",
      },
      { status: 502 },
      applySecurityHeaders,
    );
  }
}

/**
 * Handle Stripe webhooks. Confirms one-time payment via checkout.session.completed.
 */
export async function handleStripeWebhook(
  request: Request,
  env: BillingEnv,
  applySecurityHeaders?: (headers: Headers) => void,
): Promise<Response> {
  const secretOrError = requireStripeSecret(env);
  if (secretOrError instanceof Response) {
    return secretOrError;
  }

  const webhookSecret = env.STRIPE_WEBHOOK_SECRET?.trim();
  if (!webhookSecret) {
    return json(
      {
        error: "stripe_webhook_secret_missing",
        message:
          "Set STRIPE_WEBHOOK_SECRET from the Stripe Dashboard webhook signing secret.",
      },
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

  const stripe = createStripeClient(secretOrError);
  const payload = await request.text();

  let event: Stripe.Event;
  try {
    event = await stripe.webhooks.constructEventAsync(
      payload,
      signature,
      webhookSecret,
    );
  } catch (error) {
    return json(
      {
        error: "stripe_signature_invalid",
        message: error instanceof Error ? error.message : "invalid_signature",
      },
      { status: 400 },
      applySecurityHeaders,
    );
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object as Stripe.Checkout.Session;

    const record: PaymentRecord = {
      sessionId: session.id,
      paymentStatus: session.payment_status,
      customerId:
        typeof session.customer === "string"
          ? session.customer
          : session.customer?.id ?? null,
      customerEmail:
        session.customer_details?.email ??
        session.customer_email ??
        null,
      amountTotal: session.amount_total,
      currency: session.currency,
      priceId: session.metadata?.price_id ?? null,
      completedAt: new Date().toISOString(),
    };

    if (env.BILLING_KV) {
      await env.BILLING_KV.put(
        `payment:session:${session.id}`,
        JSON.stringify(record),
      );
      if (record.customerId) {
        await env.BILLING_KV.put(
          `payment:customer:${record.customerId}:latest`,
          session.id,
        );
      }
      if (record.customerEmail) {
        await env.BILLING_KV.put(
          `payment:email:${record.customerEmail.toLowerCase()}:latest`,
          session.id,
        );
      }
      // Mark session as completed for status polling
      await env.BILLING_KV.put(
        `checkout:session:${session.id}`,
        JSON.stringify({
          sessionId: session.id,
          status: "complete",
          paymentStatus: session.payment_status,
          priceId: record.priceId,
          completedAt: record.completedAt,
        }),
      );
    }
  }

  return json({ received: true }, { status: 200 }, applySecurityHeaders);
}

/**
 * Look up payment completion status for a Checkout Session id.
 */
export async function getPaymentStatus(
  request: Request,
  env: BillingEnv,
  applySecurityHeaders?: (headers: Headers) => void,
): Promise<Response> {
  const url = new URL(request.url);
  const sessionId = url.searchParams.get("session_id")?.trim();
  if (!sessionId) {
    return json(
      { error: "session_id_required" },
      { status: 400 },
      applySecurityHeaders,
    );
  }

  // Prefer persisted webhook/checkout records
  if (env.BILLING_KV) {
    const paymentRaw = await env.BILLING_KV.get(`payment:session:${sessionId}`);
    if (paymentRaw) {
      return json(
        { source: "webhook", ...JSON.parse(paymentRaw) },
        { status: 200 },
        applySecurityHeaders,
      );
    }
    const sessionRaw = await env.BILLING_KV.get(
      `checkout:session:${sessionId}`,
    );
    if (sessionRaw) {
      return json(
        { source: "session", ...JSON.parse(sessionRaw) },
        { status: 200 },
        applySecurityHeaders,
      );
    }
  }

  const secretOrError = requireStripeSecret(env);
  if (secretOrError instanceof Response) {
    return secretOrError;
  }

  try {
    const stripe = createStripeClient(secretOrError);
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    return json(
      {
        source: "stripe",
        sessionId: session.id,
        status: session.status,
        paymentStatus: session.payment_status,
        customerId:
          typeof session.customer === "string"
            ? session.customer
            : session.customer?.id ?? null,
        amountTotal: session.amount_total,
        currency: session.currency,
      },
      { status: 200 },
      applySecurityHeaders,
    );
  } catch (error) {
    return json(
      {
        error: "stripe_session_lookup_failed",
        message: error instanceof Error ? error.message : "unknown_error",
      },
      { status: 404 },
      applySecurityHeaders,
    );
  }
}
