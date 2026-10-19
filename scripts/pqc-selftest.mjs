/**
 * Bundle the browser PQC module with esbuild and run the X-Wing self-test on Node.
 * CI calls this before `wrangler deploy` so a broken hybrid never ships.
 */
import * as esbuild from "esbuild";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [major, minor] = process.versions.node.split(".").map((n) => Number(n));
if (major < 20 || (major === 20 && minor < 19)) {
  console.error(
    `Node ${process.versions.node} is too old for @noble/post-quantum (need >= 20.19).`,
  );
  process.exit(1);
}

const dir = await mkdtemp(join(tmpdir(), "globe-pqc-"));
const outfile = join(dir, "selftest.mjs");
try {
  await esbuild.build({
    entryPoints: [
      new URL("./pqc-selftest-entry.ts", import.meta.url).pathname,
    ],
    bundle: true,
    platform: "node",
    format: "esm",
    outfile,
    logLevel: "warning",
  });
  await import(pathToFileURL(outfile).href);
} finally {
  await rm(dir, { recursive: true, force: true });
}
