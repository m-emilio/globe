/** Fixed FederalKey market catalog. Prices are USD cents and never come from the browser. */
export const MARKET_ITEMS = {
  auditing: {
    name: "Auditing",
    summary: "Dev/Test PKI auditing for internal and external environments.",
    amountCents: 250_000,
  },
  consulting: {
    name: "Consulting",
    summary:
      "Advisory on cryptographic protocols, smart cards, end user devices, back-end servers, and HSMs.",
    amountCents: 320_000,
  },
} as const;

export type MarketSku = keyof typeof MARKET_ITEMS;

const SKUS = Object.keys(MARKET_ITEMS) as MarketSku[];

export function isMarketSku(value: string): value is MarketSku {
  return Object.prototype.hasOwnProperty.call(MARKET_ITEMS, value);
}

/** Accept only known ids, once each, in catalog order. */
export function parseMarketSkus(input: unknown): MarketSku[] | null {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  const raw = (input as { items?: unknown }).items;
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > SKUS.length) return null;
  const chosen = new Set<MarketSku>();
  for (let i = 0; i < raw.length; i += 1) {
    const item = raw[i];
    if (typeof item !== "string" || !isMarketSku(item) || chosen.has(item)) return null;
    chosen.add(item);
  }
  return SKUS.filter((sku) => chosen.has(sku));
}

export function marketSkusFromMetadata(skus: string | undefined): MarketSku[] {
  if (!skus) return [];
  const chosen = new Set<MarketSku>();
  for (const part of skus.split(",")) {
    if (isMarketSku(part)) chosen.add(part);
  }
  return SKUS.filter((sku) => chosen.has(sku));
}

export function isMarketMetadata(metadata: { globe_product?: string } | null | undefined): boolean {
  return metadata?.globe_product === "market";
}

/** Production checkout may return only to the Globe host. Local wrangler may use loopback. */
export function marketOrigin(request: Request): string | null {
  const url = new URL(request.url);
  const host = url.hostname.toLowerCase();
  if (host === "globe.federalkey.workers.dev") return "https://globe.federalkey.workers.dev";
  if (host === "localhost" || host === "127.0.0.1") return url.origin;
  return null;
}

export function marketCatalog() {
  return SKUS.map((id) => {
    const item = MARKET_ITEMS[id];
    return {
      id,
      name: item.name,
      summary: item.summary,
      amountCents: item.amountCents,
    };
  });
}

export function integrationIdentifier(): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz";
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  let suffix = "";
  for (let i = 0; i < bytes.length; i += 1) suffix += alphabet[bytes[i]! % alphabet.length];
  return `globe_market_${suffix}`;
}
