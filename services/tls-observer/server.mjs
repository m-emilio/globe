import { createHmac, timingSafeEqual } from "node:crypto";
import { Resolver } from "node:dns/promises";
import { createServer } from "node:http";
import { BlockList, isIP } from "node:net";
import { pathToFileURL } from "node:url";
import { checkServerIdentity, connect } from "node:tls";

const HOSTNAME = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
const RESERVED_SUFFIX = /(?:\.(?:localhost|local|internal|test|invalid|example|onion|arpa)|(?:^|\.)example\.(?:com|org|net))$/;
const nonPublic = new BlockList();
for (const [address, bits] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 3],
]) nonPublic.addSubnet(address, bits, "ipv4");
const globalV6 = new BlockList();
globalV6.addSubnet("2000::", 3, "ipv6");
for (const [address, bits] of [
  ["2001::", 23], ["2001:db8::", 32], ["2002::", 16], ["3fff::", 20],
]) nonPublic.addSubnet(address, bits, "ipv6");

export function isPublicAddress(address) {
  const family = isIP(address);
  if (family === 4) return !nonPublic.check(address, "ipv4");
  return family === 6 && !address.includes("%") && globalV6.check(address, "ipv6") && !nonPublic.check(address, "ipv6");
}

const resolver = new Resolver({ timeout: 1700, tries: 1 });
export async function resolvePublicAddress(hostname, dns = resolver) {
  const responses = await Promise.allSettled([dns.resolve4(hostname), dns.resolve6(hostname)]);
  if (responses.some((result) => result.status === "rejected" && result.reason?.code !== "ENODATA")) {
    return { reason: "dns" };
  }
  const addresses = responses.flatMap((result) => result.status === "fulfilled" ? result.value : []);
  if (!addresses.length) return { reason: "dns" };
  if (!addresses.every(isPublicAddress)) return { reason: "address_rejected" };
  return { address: addresses[0] };
}

const CHAIN_ERRORS = new Set([
  "CERT_NOT_YET_VALID", "CERT_HAS_EXPIRED", "CERT_REVOKED", "CERT_SIGNATURE_FAILURE",
  "DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN", "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "INVALID_CA",
  "CERT_UNTRUSTED", "INVALID_PURPOSE", "PATH_LENGTH_EXCEEDED",
]);

function observation(fields = {}) {
  return { observedAt: new Date().toISOString(), expiresAt: null, hostnameMatches: null, chainValid: null, ...fields };
}

export async function observeCertificate(hostname, resolve = resolvePublicAddress, connectTls = connect) {
  const target = await resolve(hostname);
  if (!target.address) return observation({ reason: target.reason });
  if (!isPublicAddress(target.address)) return observation({ reason: "address_rejected" });

  return new Promise((resolveObservation) => {
    const socket = connectTls({
      host: target.address,
      port: 443,
      family: isIP(target.address),
      servername: hostname,
      rejectUnauthorized: true,
      checkServerIdentity: (_ignored, certificate) => checkServerIdentity(hostname, certificate),
    });
    const timer = setTimeout(() => settle({ reason: "handshake_unavailable" }), 4500);
    let finished = false;
    function settle(fields) {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      resolveObservation(observation(fields));
      socket.destroy();
    }
    socket.once("secureConnect", () => {
      const leaf = socket.getPeerCertificate();
      const expires = Date.parse(leaf?.valid_to ?? "");
      settle({
        expiresAt: Number.isFinite(expires) ? new Date(expires).toISOString() : null,
        chainValid: socket.authorized ? true : null,
        hostnameMatches: socket.authorized ? true : null,
      });
    });
    socket.once("error", (error) => {
      if (error.code === "ERR_TLS_CERT_ALTNAME_INVALID") {
        settle({ chainValid: true, hostnameMatches: false, reason: "hostname_mismatch" });
      } else if (CHAIN_ERRORS.has(error.code)) {
        settle({ chainValid: false, reason: "certificate_invalid" });
      } else {
        settle({ reason: "handshake_unavailable" });
      }
    });
    socket.once("close", () => settle({ reason: "handshake_unavailable" }));
  });
}

function validGrant(hostname, expires, nonce, authentication, secret) {
  const now = Math.floor(Date.now() / 1000);
  if (typeof hostname !== "string" || hostname.length > 253 || !HOSTNAME.test(hostname) || RESERVED_SUFFIX.test(hostname) ||
      !Number.isSafeInteger(expires) || expires < now || expires > now + 35 ||
      typeof nonce !== "string" || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(nonce) ||
      typeof authentication !== "string" || !/^HMAC [0-9a-f]{64}$/.test(authentication)) return false;

  const expected = createHmac("sha256", secret)
    .update("globe-tls-observer:v1\n" + hostname + "\n" + expires + "\n" + nonce)
    .digest();
  return timingSafeEqual(expected, Buffer.from(authentication.slice(5), "hex"));
}

async function readJson(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 2048) throw new Error("Request too large");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

export function createObserverServer(secret, observe = observeCertificate) {
  if (typeof secret !== "string" || secret.length < 32) throw new Error("Set TLS_OBSERVER_KEY to a strong shared secret.");
  let active = 0;
  const usedGrants = new Map();
  const server = createServer({ requestTimeout: 4000, headersTimeout: 3000, keepAliveTimeout: 4000 }, async (request, response) => {
    const reply = (status, body) => {
      response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
      response.end(JSON.stringify(body));
    };

    if (request.method !== "POST" || request.url !== "/observe") return reply(404, { error: "not_found" });
    if (!/^HMAC [0-9a-f]{64}$/.test(request.headers.authorization ?? "")) {
      return reply(403, { error: "invalid_grant" });
    }
    if (active >= 8) return reply(429, { error: "observer_busy" });
    active++;
    // The bound covers body delivery as well as the maximum parsed bytes.
    const bodyTimer = setTimeout(() => request.destroy(), 3000);
    try {
      const data = await readJson(request);
      clearTimeout(bodyTimer);
      const { hostname, expires, nonce } = data ?? {};
      if (!validGrant(hostname, expires, nonce, request.headers.authorization, secret)) {
        return reply(403, { error: "invalid_grant" });
      }
      const now = Math.floor(Date.now() / 1000);
      for (const [id, expiry] of usedGrants) {
        if (expiry < now) usedGrants.delete(id);
      }
      if (usedGrants.has(nonce)) return reply(403, { error: "invalid_grant" });
      usedGrants.set(nonce, expires);
      return reply(200, await observe(hostname));
    } catch {
      if (!response.destroyed && !response.headersSent) return reply(400, { error: "request_unavailable" });
    } finally {
      clearTimeout(bodyTimer);
      active--;
    }
  });
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const server = createObserverServer(process.env.TLS_OBSERVER_KEY);
  const port = Number(process.env.TLS_OBSERVER_PORT ?? "8080");
  server.listen(port, process.env.TLS_OBSERVER_BIND ?? "127.0.0.1");
}
