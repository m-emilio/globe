import assert from "node:assert/strict";
import { createHmac, randomUUID } from "node:crypto";
import { EventEmitter, once } from "node:events";
import test from "node:test";
import { createObserverServer, isPublicAddress, observeCertificate, resolvePublicAddress } from "./server.mjs";

const host = "verified.globe-fixture.net";
const noRecords = () => Promise.reject(Object.assign(new Error("No records"), { code: "ENODATA" }));

test("rejects nonpublic and translated addresses", () => {
  for (const address of [
    "0.1.2.3", "10.1.2.3", "100.64.0.1", "127.0.0.1", "169.254.169.254",
    "172.16.0.1", "192.0.0.1", "192.168.0.1", "198.18.0.1", "203.0.113.1",
    "224.1.1.1", "255.255.255.255", "::", "::1", "::ffff:127.0.0.1", "fe80::1",
    "fc00::1", "2001:db8::1", "2002::1", "3fff::1",
  ]) assert.equal(isPublicAddress(address), false, address);
  assert.equal(isPublicAddress("1.1.1.1"), true);
  assert.equal(isPublicAddress("2606:4700:4700::1111"), true);
});

test("requires every DNS address to be public", async () => {
  assert.deepEqual(await resolvePublicAddress(host, {
    resolve4: async () => ["1.1.1.1"], resolve6: noRecords,
  }), { address: "1.1.1.1" });
  assert.deepEqual(await resolvePublicAddress(host, {
    resolve4: async () => ["1.1.1.1"], resolve6: async () => ["fd00::1"],
  }), { reason: "address_rejected" });
});

test("connects to the validated address with SNI and certificate validation", async () => {
  let configured;
  const result = await observeCertificate(host, async () => ({ address: "1.1.1.1" }), (options) => {
    configured = options;
    const socket = new EventEmitter();
    socket.authorized = true;
    socket.getPeerCertificate = () => ({ valid_to: "2035-01-01T00:00:00Z" });
    socket.destroy = () => {};
    queueMicrotask(() => socket.emit("secureConnect"));
    return socket;
  });
  assert.equal(configured.host, "1.1.1.1");
  assert.equal(configured.port, 443);
  assert.equal(configured.servername, host);
  assert.equal(configured.rejectUnauthorized, true);
  assert.equal(configured.checkServerIdentity(host, { subjectaltname: "DNS:wrong.globe-fixture.net" }).code,
    "ERR_TLS_CERT_ALTNAME_INVALID");
  assert.equal(result.expiresAt, "2035-01-01T00:00:00.000Z");
  assert.equal(result.hostnameMatches, true);
  assert.equal(result.chainValid, true);
});

test("requires a fresh grant for the exact requested hostname", async (t) => {
  const secret = "fixture secret for testing only and never configured";
  const observed = [];
  const server = createObserverServer(secret, async (hostname) => {
    observed.push(hostname);
    return { observedAt: new Date().toISOString(), expiresAt: null, hostnameMatches: null, chainValid: null };
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise((done) => server.close(done)));

  const now = Math.floor(Date.now() / 1000);
  const endpoint = "http://127.0.0.1:" + server.address().port + "/observe";
  const send = (hostname, expires, signedFor = hostname, nonce = randomUUID()) => {
    const signature = createHmac("sha256", secret)
      .update("globe-tls-observer:v1\n" + signedFor + "\n" + expires + "\n" + nonce)
      .digest("hex");
    return fetch(endpoint, {
      method: "POST", headers: { authorization: "HMAC " + signature, "content-type": "application/json" },
      body: JSON.stringify({ hostname, expires, nonce }),
    });
  };
  assert.equal((await send(host, now - 1)).status, 403);
  assert.equal((await send(host, now + 30, "other.globe-fixture.net")).status, 403);
  assert.equal((await send("127.0.0.1", now + 30)).status, 403);
  const nonce = randomUUID();
  assert.equal((await send(host, now + 30, host, nonce)).status, 200);
  assert.equal((await send(host, now + 30, host, nonce)).status, 403);
  assert.deepEqual(observed, [host]);
});
