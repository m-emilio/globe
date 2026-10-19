import { pqcSelfTest } from "../src/client/pqc.ts";

const result = await pqcSelfTest();
if (!result.ok) {
  console.error("pqc self-test failed");
  process.exit(1);
}
console.log(
  `pqc self-test ok suite=${result.suite} public=${result.publicKeyBytes} secret=${result.secretKeyBytes} ciphertext=${result.cipherTextBytes} shared=${result.sharedSecretBytes} fingerprint-hex=${result.sharedSecretSha256Hex.length}`,
);
