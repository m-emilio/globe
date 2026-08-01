/**
 * Safe external / preview URL helpers — block javascript:, data:, and other
 * non-https schemes that can turn dynamic href={serverField} into XSS.
 */

const MAX_URL_LEN = 2048;

/**
 * Allow only https URLs without credentials. Optional host allow-list
 * (exact host or subdomain of an entry).
 */
export function safeHttpsUrl(
  raw: string | null | undefined,
  options?: { hosts?: readonly string[] },
): string | undefined {
  if (raw == null || typeof raw !== "string") return undefined;
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > MAX_URL_LEN) return undefined;
  // Reject common XSS schemes before URL parser quirks
  if (/^(javascript|data|vbscript|file|blob):/i.test(trimmed)) {
    return undefined;
  }

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return undefined;
  }

  if (url.protocol !== "https:") return undefined;
  if (url.username || url.password) return undefined;
  // Block empty / weird hosts
  if (!url.hostname || url.hostname.includes(" ")) return undefined;

  if (options?.hosts?.length) {
    const host = url.hostname.toLowerCase();
    const ok = options.hosts.some((allowed) => {
      const a = allowed.toLowerCase();
      return host === a || host.endsWith(`.${a}`);
    });
    if (!ok) return undefined;
  }

  return url.toString();
}

/**
 * Dynamic panel links: https only, no credentials.
 * Blocks javascript:/data: XSS via href={serverField}. Host allow-list is
 * optional (use for payment redirects); general docs links may add hosts.
 */
export function safeGlobeHref(
  raw: string | null | undefined,
): string | undefined {
  return safeHttpsUrl(raw);
}

/**
 * Preview fetch keys must be same-origin relative /api/ paths only
 * (prevents open cache poisoning / accidental cross-origin credentials fetch).
 */
export function assertSameOriginApiPath(url: string): string {
  const trimmed = url.trim();
  if (
    !trimmed.startsWith("/api/") ||
    trimmed.includes("//") ||
    trimmed.includes("\\") ||
    trimmed.includes("\0") ||
    trimmed.length > 512
  ) {
    throw new Error("Invalid preview API path");
  }
  return trimmed;
}

/** href-safe value: https allow-listed URL or undefined (omit the <a>). */
export function externalHref(
  raw: string | null | undefined,
): string | undefined {
  return safeGlobeHref(raw);
}
