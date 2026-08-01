/**
 * Client-side memory + sessionStorage cache for public globe preview APIs.
 * Stops repeat panel opens from re-downloading large JSON (main-thread lag).
 */

import { assertSameOriginApiPath } from "./safeUrl";

type CacheEntry = {
  at: number;
  data: unknown;
};

const memory = new Map<string, CacheEntry>();

/** Fresh enough to skip network entirely. */
const FRESH_MS = 30 * 60 * 1000;
/** Still usable while a background revalidate runs. */
const STALE_MS = 6 * 60 * 60 * 1000;

const STORAGE_PREFIX = "globe:preview:v3:";

function storageKey(url: string) {
  return `${STORAGE_PREFIX}${assertSameOriginApiPath(url)}`;
}

/** Drop a cached preview so the next fetch hits the network. */
export function clearPreviewCache(url: string) {
  try {
    const key = assertSameOriginApiPath(url);
    memory.delete(key);
    sessionStorage.removeItem(storageKey(key));
  } catch {
    // ignore invalid keys
  }
}

function readSession(url: string): CacheEntry | null {
  try {
    const raw = sessionStorage.getItem(storageKey(url));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as CacheEntry;
    if (
      !parsed ||
      typeof parsed.at !== "number" ||
      parsed.data === undefined
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function writeSession(url: string, entry: CacheEntry) {
  try {
    sessionStorage.setItem(storageKey(url), JSON.stringify(entry));
  } catch {
    // quota / private mode — memory still works
  }
}

export function getPreviewCache<T>(url: string): {
  data: T;
  ageMs: number;
  fresh: boolean;
  stale: boolean;
} | null {
  let key: string;
  try {
    key = assertSameOriginApiPath(url);
  } catch {
    return null;
  }
  const now = Date.now();
  const entry = memory.get(key) ?? readSession(key);
  if (!entry) return null;
  if (!memory.has(key)) {
    memory.set(key, entry);
  }
  const ageMs = now - entry.at;
  if (ageMs > STALE_MS) return null;
  return {
    data: entry.data as T,
    ageMs,
    fresh: ageMs <= FRESH_MS,
    stale: ageMs > FRESH_MS && ageMs <= STALE_MS,
  };
}

export function setPreviewCache(url: string, data: unknown) {
  const key = assertSameOriginApiPath(url);
  const entry: CacheEntry = { at: Date.now(), data };
  memory.set(key, entry);
  writeSession(key, entry);
}

/**
 * Fetch JSON with memory/session cache + HTTP cache.
 * - Fresh hit: no network
 * - Stale hit: return immediately, revalidate in background
 * - Miss: network (force-cache so CDN/browser headers apply)
 */
export async function fetchPreviewJson<T>(
  url: string,
  options?: {
    validate?: (data: unknown) => data is T;
    /** When true, ignore fresh memory and revalidate (still uses HTTP cache). */
    forceNetwork?: boolean;
  },
): Promise<T> {
  const key = assertSameOriginApiPath(url);
  const validate =
    options?.validate ??
    ((data: unknown): data is T => data != null && typeof data === "object");

  if (!options?.forceNetwork) {
    const hit = getPreviewCache<T>(key);
    if (hit?.fresh && validate(hit.data)) {
      return hit.data;
    }
    if (hit?.stale && validate(hit.data)) {
      void revalidate(key, validate);
      return hit.data;
    }
  }

  const response = await fetch(key, {
    headers: { accept: "application/json" },
    // forceNetwork must bypass browser HTTP cache (stale 7/12 UNODC payloads).
    cache: options?.forceNetwork ? "reload" : "force-cache",
    credentials: "same-origin",
  }).catch(() =>
    fetch(key, {
      headers: { accept: "application/json" },
      cache: options?.forceNetwork ? "no-store" : "default",
      credentials: "same-origin",
    }),
  );

  if (!response.ok) {
    // Last resort: serve stale on network error
    const stale = getPreviewCache<T>(key);
    if (stale && validate(stale.data)) return stale.data;
    throw new Error(`Preview request failed (${response.status})`);
  }

  const data = (await response.json()) as unknown;
  if (!validate(data)) {
    throw new Error("Preview response incomplete");
  }
  setPreviewCache(key, data);
  return data;
}

async function revalidate<T>(
  url: string,
  validate: (data: unknown) => data is T,
) {
  try {
    const key = assertSameOriginApiPath(url);
    const response = await fetch(key, {
      headers: { accept: "application/json" },
      cache: "default",
      credentials: "same-origin",
    });
    if (!response.ok) return;
    const data = (await response.json()) as unknown;
    if (validate(data)) {
      setPreviewCache(key, data);
    }
  } catch {
    // ignore background revalidate errors
  }
}

/** Warm browser/edge caches without updating React state. */
export function warmPreviewUrl(url: string) {
  let key: string;
  try {
    key = assertSameOriginApiPath(url);
  } catch {
    return;
  }
  void fetch(key, {
    headers: { accept: "application/json" },
    cache: "force-cache",
    credentials: "same-origin",
  })
    .then(async (response) => {
      if (!response.ok) return;
      try {
        const data = await response.json();
        if (data && typeof data === "object") {
          setPreviewCache(key, data);
        }
      } catch {
        // ignore
      }
    })
    .catch(() => {});
}
