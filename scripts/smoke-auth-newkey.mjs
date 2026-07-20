import * as openpgp from "openpgp";

const BASE = process.env.SMOKE_BASE || "https://globe.federalkey.workers.dev";
const jar = new Map();
let pass = 0, fail = 0;

function parseSetCookie(res) {
  const list = typeof res.headers.getSetCookie === "function"
    ? res.headers.getSetCookie()
    : (res.headers.get("set-cookie") ? [res.headers.get("set-cookie")] : []);
  for (const raw of list) {
    const part = String(raw).split(";")[0];
    const eq = part.indexOf("=");
    if (eq > 0) jar.set(part.slice(0, eq).trim(), part.slice(eq + 1).trim());
  }
}
function cookieHeader() {
  return jar.size ? [...jar.entries()].map(([k,v]) => `${k}=${v}`).join("; ") : undefined;
}
async function api(path, init = {}) {
  const headers = new Headers(init.headers || {});
  if (init.body && !headers.has("content-type")) headers.set("content-type", "application/json");
  const c = cookieHeader();
  if (c) headers.set("cookie", c);
  const res = await fetch(BASE + path, { ...init, headers });
  parseSetCookie(res);
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { json = { _raw: text.slice(0, 200) }; }
  return { status: res.status, json };
}
function ok(cond, msg) {
  if (!cond) throw new Error(msg);
  console.log("  OK  " + msg);
  pass++;
}
async function step(name, fn) {
  console.log("\n[" + name + "]");
  try { await fn(); }
  catch (e) { fail++; console.error("  FAIL " + (e.message || e)); }
}

async function genClientStyle(profile = "curve25519") {
  const common = {
    userIDs: [{ name: "Smoke Test", email: "smoke-test@localhost" }],
    format: "armored",
  };
  let r;
  if (profile === "curve25519") r = await openpgp.generateKey({ ...common, type: "curve25519" });
  else if (profile === "nistP256") r = await openpgp.generateKey({ ...common, type: "ecc", curve: "nistP256" });
  else if (profile === "rsa2048") r = await openpgp.generateKey({ ...common, type: "rsa", rsaBits: 2048 });
  else throw new Error("unknown profile");
  const key = await openpgp.readKey({ armoredKey: r.publicKey });
  const fingerprint = key.getFingerprint().toLowerCase().replace(/[\s:]/g, "");
  return { privateKey: r.privateKey, publicKey: r.publicKey, fingerprint, algo: key.getAlgorithmInfo() };
}

async function loginWithKey(fingerprint, privateKeyArmored) {
  jar.clear();
  const chal = await api("/api/auth/challenge", {
    method: "POST",
    body: JSON.stringify({ fingerprint }),
  });
  if (chal.status !== 200 || !chal.json?.challengeId) {
    throw new Error("challenge failed " + chal.status + " " + JSON.stringify(chal.json));
  }
  const priv = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });
  const message = await openpgp.createMessage({ text: chal.json.message });
  const signatureArmored = await openpgp.sign({
    message, signingKeys: priv, detached: true, format: "armored",
  });
  const login = await api("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({
      fingerprint,
      challengeId: chal.json.challengeId,
      signatureArmored,
    }),
  });
  return login;
}

console.log("Smoke base:", BASE);

await step("me unauth", async () => {
  const r = await api("/api/auth/me");
  ok(r.status === 200 && r.json.authenticated === false, "unauthenticated");
});

await step("anti-enumeration", async () => {
  const u = await api("/api/auth/challenge", { method: "POST", body: JSON.stringify({ fingerprint: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" }) });
  const k = await api("/api/auth/challenge", { method: "POST", body: JSON.stringify({ fingerprint: "a7a4ff41149c42ca8d3cc6ef5ec82c2ece415f48" }) });
  ok(u.status === 200 && u.json.challengeId, "unknown → 200 + challenge");
  ok(k.status === 200 && k.json.challengeId, "known → 200 + challenge");
  ok(!String(u.json.error || "").includes("unknown_identity"), "no unknown_identity");
});

for (const profile of ["curve25519", "nistP256"]) {
  await step(`full flow: ${profile}`, async () => {
    jar.clear();
    const g = await genClientStyle(profile);
    console.log("  ..  algo", JSON.stringify(g.algo), "fp", g.fingerprint.slice(0, 12) + "…");
    const reg = await api("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ publicKeyArmored: g.publicKey }),
    });
    ok(reg.status === 201 || reg.status === 200, "register " + reg.status + " " + (reg.json?.error || ""));
    ok(reg.json?.user?.fingerprint, "user returned");
    ok(jar.has("globe_session"), "session cookie set");

    const me1 = await api("/api/auth/me");
    ok(me1.json?.authenticated === true, "me after register");

    await api("/api/auth/logout", { method: "POST", body: "{}" });
    jar.clear();

    const login = await loginWithKey(g.fingerprint, g.privateKey);
    ok(login.status === 200, "login " + login.status + " " + (login.json?.error || login.json?.message || ""));
    ok(login.json?.user?.id, "login user");
    ok(jar.has("globe_session"), "login cookie");

    const me2 = await api("/api/auth/me");
    ok(me2.json?.authenticated === true, "me after login");
  });
}

await step("unregistered key login rejected", async () => {
  const g = await genClientStyle("curve25519");
  const login = await loginWithKey(g.fingerprint, g.privateKey);
  ok(login.status === 401, "401 unregistered");
  ok(login.json?.error === "auth_failed", "auth_failed generic");
});

await step("private key on register rejected", async () => {
  const g = await genClientStyle("curve25519");
  const r = await api("/api/auth/register", {
    method: "POST",
    body: JSON.stringify({ publicKeyArmored: g.privateKey }),
  });
  ok(r.status === 400 && r.json?.error === "private_key_rejected", "private_key_rejected");
});

await step("admin users requires auth", async () => {
  jar.clear();
  const r = await api("/api/admin/users");
  ok(r.status === 401, "401");
});

console.log("\n========");
console.log("assertions OK:", pass, " steps FAIL:", fail);
process.exit(fail > 0 ? 1 : 0);
