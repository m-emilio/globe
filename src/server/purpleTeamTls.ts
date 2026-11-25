import { readBoundedText } from "./boundedBody";
import type { WebFinding } from "./verifiedDomainScan";

export interface TlsObserverEnv {
  TLS_OBSERVER_URL?: string;
  TLS_OBSERVER_KEY?: string;
  TLS_OBSERVER_ACCESS_ID?: string;
  TLS_OBSERVER_ACCESS_SECRET?: string;
}

export type TlsObservation = {
  observedAt: string;
  expiresAt: string | null;
  hostnameMatches: boolean | null;
  chainValid: boolean | null;
  reason?: "dns" | "address_rejected" | "certificate_invalid" | "hostname_mismatch" | "handshake_unavailable";
};

const encoder = new TextEncoder();
const check = "Served TLS certificate";
const id = "tls.served-certificate";

function statusLabel(status: boolean | null): string {
  if (status === null) return "unknown";
  return status ? "valid" : "invalid";
}

function dateLabel(value: unknown): string | null {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) return null;
  return new Date(value).toISOString();
}

export async function observeTls(hostname: string, env: TlsObserverEnv): Promise<WebFinding> {
  const secret = env.TLS_OBSERVER_KEY;
  if (!env.TLS_OBSERVER_URL || !secret || secret.length < 32) {
    return { id, check, status: "unknown", evidence: "The private certificate observer is unavailable." };
  }

  try {
    const url = new URL(env.TLS_OBSERVER_URL);
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/observe") {
      throw new Error("Invalid observer URL");
    }

    const expires = Math.floor(Date.now() / 1000) + 30;
    const nonce = crypto.randomUUID();
    const key = await crypto.subtle.importKey("raw", encoder.encode(secret), {
      name: "HMAC", hash: "SHA-256",
    }, false, ["sign"]);
    const signed = await crypto.subtle.sign("HMAC", key, encoder.encode("globe-tls-observer:v1\n" + hostname + "\n" + expires + "\n" + nonce));
    const proof = Array.from(new Uint8Array(signed), (byte) => byte.toString(16).padStart(2, "0")).join("");
    const headers = new Headers({ "content-type": "application/json", authorization: "HMAC " + proof });
    if (env.TLS_OBSERVER_ACCESS_ID && env.TLS_OBSERVER_ACCESS_SECRET) {
      headers.set("CF-Access-Client-Id", env.TLS_OBSERVER_ACCESS_ID);
      headers.set("CF-Access-Client-Secret", env.TLS_OBSERVER_ACCESS_SECRET);
    }
    const response = await fetch(url, {
      method: "POST", headers, redirect: "manual", signal: AbortSignal.timeout(9000),
      body: JSON.stringify({ hostname, expires, nonce }),
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error("Observer unavailable");
    }
    const result = JSON.parse(await readBoundedText(response.body, 4096)) as TlsObservation;
    const observedAt = dateLabel(result.observedAt);
    const expiresAt = dateLabel(result.expiresAt);
    if (!observedAt || ![true, false, null].includes(result.hostnameMatches) ||
        ![true, false, null].includes(result.chainValid)) throw new Error("Invalid observer result");

    const invalid = result.chainValid === false || result.hostnameMatches === false;
    const soon = expiresAt !== null && Date.parse(expiresAt) - Date.now() < 30 * 86_400_000;
    const complete = result.chainValid === true && result.hostnameMatches === true && expiresAt !== null;
    const context = {
      dns: "Public DNS did not return a usable address.",
      address_rejected: "DNS returned a private or reserved address.",
      certificate_invalid: "The certificate chain did not validate.",
      hostname_mismatch: "The certificate does not match the hostname.",
      handshake_unavailable: "The TLS handshake was incomplete.",
    };
    const reason = result.reason && Object.hasOwn(context, result.reason) ? context[result.reason] : "";
    return {
      id, check, status: invalid || soon ? "review" : complete ? "pass" : "unknown",
      evidence: "Observed " + observedAt + " · Expiry " + (expiresAt ?? "unknown") +
        " · Hostname " + statusLabel(result.hostnameMatches) + " · Chain " + statusLabel(result.chainValid) +
        (reason ? ". " + reason : "."),
      remediation: invalid || soon ? "Renew or replace the served certificate and verify the hostname and chain." : undefined,
    };
  } catch {
    return { id, check, status: "unknown", evidence: "The certificate observer timed out or did not return a usable result." };
  }
}
