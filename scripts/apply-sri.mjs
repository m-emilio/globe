/**
 * Post-build Subresource Integrity for first-party static assets.
 *
 * - Hashes files referenced by public/index.html
 * - Injects integrity + crossorigin on <script> / <link>
 * - Fails if any third-party script/style URL is present (keep third-party JS out forever)
 * - Writes public/dist/sri-manifest.json for ops verification
 *
 * Note: Dynamic ESM chunks (if any) still rely on CSP script-src 'self'.
 * Prefer a single entry bundle so the HTML integrity covers the main graph.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const publicDir = join(root, "public");
const htmlPath = join(publicDir, "index.html");
const distDir = join(publicDir, "dist");

function sha384Integrity(filePath) {
  const buf = readFileSync(filePath);
  const hash = createHash("sha384").update(buf).digest("base64");
  return `sha384-${hash}`;
}

function resolvePublicPath(urlPath) {
  const clean = urlPath.split("?")[0].split("#")[0];
  if (!clean.startsWith("/")) {
    throw new Error(`Expected absolute path for static asset: ${urlPath}`);
  }
  return join(publicDir, clean.slice(1));
}

function assertFirstPartyOnly(html) {
  const bad = [];
  const tagRe =
    /<(?:script|link)\b[^>]*(?:src|href)\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let m;
  while ((m = tagRe.exec(html)) !== null) {
    const url = m[1];
    if (/^https?:\/\//i.test(url) || url.startsWith("//")) {
      bad.push(url);
    }
  }
  if (bad.length) {
    throw new Error(
      `Third-party script/style URLs are forbidden (CSP + supply-chain policy):\n  ${bad.join("\n  ")}`,
    );
  }
}

function injectIntegrity(html, attr, urlPath, integrity) {
  // Match tags with this src/href and inject/replace integrity + crossorigin.
  // Scripts may be written as <script …></script>; consume the closer to avoid duplicates.
  const esc = urlPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(
    `<(script|link)\\b([^>]*\\b${attr}\\s*=\\s*["']${esc}["'][^>]*)\\s*/?>` +
      `(?:\\s*</script>)?`,
    "i",
  );
  if (!re.test(html)) {
    throw new Error(`Could not find <… ${attr}="${urlPath}"> in index.html`);
  }
  return html.replace(re, (_full, tag, mid) => {
    const isScript = tag.toLowerCase() === "script";
    let attrs = mid
      .replace(/\s+integrity\s*=\s*["'][^"']*["']/gi, "")
      .replace(/\s+crossorigin\s*=\s*["'][^"']*["']/gi, "")
      .replace(/\s*\/\s*$/, "")
      .trimEnd();
    attrs = `${attrs} integrity="${integrity}" crossorigin="anonymous"`;
    if (isScript) {
      return `<script${attrs}></script>`;
    }
    return `<link${attrs} />`;
  });
}

function main() {
  if (!existsSync(htmlPath)) {
    throw new Error(`Missing ${htmlPath}`);
  }
  let html = readFileSync(htmlPath, "utf8");
  assertFirstPartyOnly(html);

  // Assets we ship and pin with SRI
  const assets = [
    { attr: "href", path: "/normalize.css" },
    { attr: "href", path: "/dist/index.css" },
    { attr: "src", path: "/dist/index.js" },
  ];

  const manifest = {
    generatedAt: new Date().toISOString(),
    algorithm: "sha384",
    policy: "first-party-only; no third-party scripts",
    files: {},
  };

  for (const asset of assets) {
    const abs = resolvePublicPath(asset.path);
    if (!existsSync(abs)) {
      throw new Error(
        `Missing build output ${asset.path} (${abs}). Run esbuild first.`,
      );
    }
    const integrity = sha384Integrity(abs);
    html = injectIntegrity(html, asset.attr, asset.path, integrity);
    manifest.files[asset.path] = {
      integrity,
      bytes: readFileSync(abs).length,
    };
  }

  // Record other dist JS for operators (dynamic chunks still CSP-gated to 'self')
  if (existsSync(distDir)) {
    for (const name of readdirSync(distDir)) {
      if (!name.endsWith(".js") || name.endsWith(".map.js")) continue;
      const rel = `/dist/${name}`;
      if (manifest.files[rel]) continue;
      const abs = join(distDir, name);
      manifest.files[rel] = {
        integrity: sha384Integrity(abs),
        bytes: readFileSync(abs).length,
        note: "Not HTML-pinned; protected by CSP script-src 'self' only",
      };
    }
  }

  writeFileSync(htmlPath, html, "utf8");
  writeFileSync(
    join(distDir, "sri-manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
    "utf8",
  );

  console.log("SRI applied:");
  for (const [path, meta] of Object.entries(manifest.files)) {
    if (!meta.note) console.log(`  ${path}  ${meta.integrity}`);
  }
}

main();
