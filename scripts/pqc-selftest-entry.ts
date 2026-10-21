import { acceptLabPaste, acceptLoginPaste } from "../src/client/keyMaterial.ts";
import { mlDsaLoginSelfTest, slhDsaLoginSelfTest } from "../src/client/mlDsa.ts";
import { pqcSelfTest } from "../src/client/pqc.ts";
import { ipKeyDecision, MAX_KEYS_PER_IP, stripeAccessKind } from "../src/server/auth.ts";
import { labLoginSelfTest } from "../src/server/labAuth.ts";
import { decodeMldsa87PrivateAsc, encodeMldsa87PrivateAsc } from "../src/server/mldsaAsc.ts";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { pqcLoginContext, verifyPqcSignature } from "../src/server/pqcVerify.ts";

const result = await pqcSelfTest();
if (!result.ok || result.kemSuites !== 6) {
  console.error("pqc self-test failed");
  process.exit(1);
}
const dsa = await mlDsaLoginSelfTest();
if (!dsa.ok || dsa.suites !== 3) {
  console.error("ml-dsa self-test failed");
  process.exit(1);
}
const slh = await slhDsaLoginSelfTest();
if (!slh.ok || slh.suites !== 12 || slh.signed !== "slh-dsa-sha2-128f") {
  console.error("slh-dsa self-test failed");
  process.exit(1);
}
const lab = await labLoginSelfTest();
if (!lab.ok || lab.ecdhe !== "P-256" || lab.kem !== "ml-kem512") {
  console.error("lab login self-test failed");
  process.exit(1);
}
const sample = "ab".repeat(32);
const held = ["11".repeat(32), "22".repeat(32), "33".repeat(32)];
if (
  MAX_KEYS_PER_IP !== 3 ||
  held.length !== MAX_KEYS_PER_IP ||
  ipKeyDecision([], sample) !== "allow" ||
  ipKeyDecision([sample], sample) !== "known" ||
  ipKeyDecision(held, sample) !== "block" ||
  ipKeyDecision(held, sample, MAX_KEYS_PER_IP, true) !== "allow" ||
  stripeAccessKind(2000, "paid", 1999) !== "unlimited_keys" ||
  stripeAccessKind(2000, "paid", 2000) !== "transit" ||
  stripeAccessKind(2000, "paid", 0) !== "none" ||
  stripeAccessKind(2000, "unpaid", 500) !== "none"
) {
  console.error("ip key limit self-test failed");
  process.exit(1);
}
const armorPair = ml_dsa87.keygen();
const armor = encodeMldsa87PrivateAsc(armorPair.publicKey, armorPair.secretKey);
const decoded = decodeMldsa87PrivateAsc(armor);
const flipped = armor.replace("Comment: globe-ml-dsa:v1:ml-dsa87", "Comment: globe-ml-dsa:v1:ml-dsa65");
const plainPgp = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nAA==\n-----END PGP PRIVATE KEY BLOCK-----\n";
if (
  !decoded ||
  decoded.publicKey.length !== armorPair.publicKey.length ||
  decoded.secretKey.length !== armorPair.secretKey.length ||
  decoded.publicKey.some((byte, index) => byte !== armorPair.publicKey[index]) ||
  decoded.secretKey.some((byte, index) => byte !== armorPair.secretKey[index]) ||
  decodeMldsa87PrivateAsc(flipped) ||
  acceptLoginPaste(armor).kind !== "mldsa87-private" ||
  acceptLoginPaste(plainPgp).kind !== "openpgp-private" ||
  acceptLabPaste(armor).kind !== "rejected"
) {
  console.error("ml-dsa87 armor self-test failed");
  process.exit(1);
}
const proof = "globe-ml-dsa87-armor:v1";
const proofSig = ml_dsa87.sign(new TextEncoder().encode(proof), decoded.secretKey, {
  context: pqcLoginContext(),
});
if (!verifyPqcSignature("ml-dsa87", proofSig, proof, decoded.publicKey)) {
  console.error("ml-dsa87 armor proof failed");
  process.exit(1);
}
armorPair.secretKey.fill(0);
armorPair.publicKey.fill(0);
decoded.secretKey.fill(0);
decoded.publicKey.fill(0);
proofSig.fill(0);
console.log(
  `pqc self-test ok suite=${result.suite} public=${result.publicKeyBytes} secret=${result.secretKeyBytes} ciphertext=${result.cipherTextBytes} shared=${result.sharedSecretBytes} fingerprint-hex=${result.sharedSecretSha256Hex.length} kems=${result.kemSuites} dsa=${dsa.suites} slh=${slh.suites} slh-signed=${slh.signed} lab=${lab.ecdhe}/${lab.kem} keys-per-ip=${MAX_KEYS_PER_IP} stripe-under-20=unlimited mldsa87-asc=same-account`,
);
