#!/usr/bin/env node
// Build the static site in web/ (GitHub Pages):
//   web/playground.js         page controller   (harness/src/browser/page.ts)
//   web/playground-worker.js  engine in a Worker (harness/src/browser/worker.ts)
//   web/wasm/*.wasm + manifest.json   the committed guard builds from artifacts/
//   web/corpus.json           the prompt corpus from corpus/prompt/
//   web/index.html            re-rendered from web/scorecard.json (no re-run, no anchoring)
//
//   node scripts/build-web.mjs          (make web)
//
// Browser bundles swap harness/src/platform/crypto.node.ts for crypto.browser.ts (@noble), and
// must not contain node: modules or the OpenAI SDK; the build fails if they do.
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HARNESS = join(ROOT, "harness");
const WEB = join(ROOT, "web");
const require = createRequire(join(HARNESS, "package.json"));

/** esbuild plugin: resolve platform/crypto.node.js to platform/crypto.browser.ts. */
export const browserCryptoPlugin = {
  name: "agentfuzz-browser-crypto",
  setup(b) {
    b.onResolve({ filter: /crypto\.node\.js$/ }, (a) => ({ path: join(a.resolveDir, "crypto.browser.ts") }));
  },
};

/** Shared esbuild options for every browser bundle (also used by harness/test/browser.test.ts). */
export function browserBundleOptions(entry, extra = {}) {
  return {
    entryPoints: [entry],
    bundle: true,
    platform: "browser",
    target: "es2022",
    plugins: [browserCryptoPlugin],
    metafile: true,
    logLevel: "warning",
    ...extra,
  };
}

/** Fail if a bundle pulled in Node-only code. */
export function assertBrowserSafe(result, label) {
  const bad = Object.keys(result.metafile.inputs).filter((i) => /^node:|[\\/]node_modules[\\/]openai[\\/]|crypto\.node\.ts$/.test(i));
  if (bad.length) throw new Error(`${label} pulls in Node-only code: ${bad.join(", ")}`);
}

async function main() {
  const { build } = require("esbuild");
  mkdirSync(WEB, { recursive: true });

  for (const [entry, out] of [
    ["page.ts", "playground.js"],
    ["worker.ts", "playground-worker.js"],
  ]) {
    const r = await build(browserBundleOptions(join(HARNESS, "src", "browser", entry), { format: "iife", minify: true, outfile: join(WEB, out) }));
    assertBrowserSafe(r, out);
    console.log(`  wrote web/${out} (${(r.metafile.outputs[Object.keys(r.metafile.outputs)[0]].bytes / 1024).toFixed(0)} KiB)`);
  }

  const wasmDir = join(WEB, "wasm");
  rmSync(wasmDir, { recursive: true, force: true });
  mkdirSync(wasmDir, { recursive: true });
  const artifacts = join(ROOT, "artifacts");
  const files = readdirSync(artifacts).filter((f) => f.endsWith(".wasm") || f === "manifest.json");
  for (const f of files) copyFileSync(join(artifacts, f), join(wasmDir, f));
  console.log(`  copied ${files.length} files from artifacts/ to web/wasm/`);

  // Same order and content as loadCorpus() in harness/src/prompt-runner.ts.
  const corpusDir = join(ROOT, "corpus", "prompt");
  const scenarios = readdirSync(corpusDir)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .flatMap((f) => JSON.parse(readFileSync(join(corpusDir, f), "utf8")).scenarios);
  writeFileSync(join(WEB, "corpus.json"), JSON.stringify(scenarios));
  console.log(`  wrote web/corpus.json (${scenarios.length} scenarios)`);

  execFileSync(process.execPath, ["bin/agentfuzz.mjs", "render-web", "--no-env"], { cwd: HARNESS, stdio: "inherit" });
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((e) => {
    console.error(e);
    process.exitCode = 1;
  });
}
