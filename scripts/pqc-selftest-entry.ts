import { mlDsaLoginSelfTest, slhDsaLoginSelfTest } from "../src/client/mlDsa.ts";
import { pqcSelfTest } from "../src/client/pqc.ts";

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
console.log(
  `pqc self-test ok suite=${result.suite} public=${result.publicKeyBytes} secret=${result.secretKeyBytes} ciphertext=${result.cipherTextBytes} shared=${result.sharedSecretBytes} fingerprint-hex=${result.sharedSecretSha256Hex.length} kems=${result.kemSuites} dsa=${dsa.suites} slh=${slh.suites} slh-signed=${slh.signed}`,
);
