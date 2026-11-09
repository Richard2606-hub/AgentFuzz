#!/usr/bin/env node
// Build every contract to wasm and copy the results into artifacts/ with a manifest.
//
//   node scripts/build-contracts.mjs            # all contracts + every single-bug naive variant
//   node scripts/build-contracts.mjs --check    # rebuild and fail if artifacts/ would change
//
// The committed artifacts let `make demo-offline` run from a clean clone without Rust.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "artifacts");
const wasmDir = join(root, "target", "wasm32-unknown-unknown", "release");
const check = process.argv.includes("--check");

const BUGS = [
  "bug-window-lag",
  "bug-prefix-allowlist",
  "bug-rotate-full-key",
  "bug-deferred-accounting",
  "bug-ignore-promise-result",
  "bug-withdraw-underflow",
  "bug-no-rekey",
];

const builds = [
  { pkg: "guard-reference", file: "guard_reference.wasm", name: "guard_reference.wasm" },
  { pkg: "scoreboard", file: "scoreboard.wasm", name: "scoreboard.wasm" },
  { pkg: "guard-naive", file: "guard_naive.wasm", name: "guard_naive.wasm" },
  ...BUGS.map((bug) => ({
    pkg: "guard-naive",
    file: "guard_naive.wasm",
    name: `guard_naive__${bug}.wasm`,
    features: [bug],
  })),
  // Every planted bug switched off: must behave like a correct guard.
  { pkg: "guard-naive", file: "guard_naive.wasm", name: "guard_naive__fixed.wasm", features: [] },
];

function cargo(args) {
  execFileSync("cargo", args, { cwd: root, stdio: ["ignore", "inherit", "inherit"] });
}

const sha = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");

mkdirSync(out, { recursive: true });
const manifestPath = join(out, "manifest.json");
const previous = existsSync(manifestPath) ? JSON.parse(readFileSync(manifestPath, "utf8")) : { artifacts: {} };
const rustc = execFileSync("rustc", ["--version"], { cwd: root }).toString().trim();
const manifest = { toolchain: rustc, nearSdk: "5.30.1", artifacts: {} };

for (const b of builds) {
  const args = ["build", "--release", "--target", "wasm32-unknown-unknown", "-p", b.pkg];
  if (b.features) {
    args.push("--no-default-features");
    if (b.features.length) args.push("--features", b.features.join(","));
  }
  console.log(`\n==> ${b.name}`);
  cargo(args);
  const src = join(wasmDir, b.file);
  const dst = join(out, b.name);
  const hash = sha(src);
  manifest.artifacts[b.name] = { package: b.pkg, features: b.features ?? "default", sha256: hash, bytes: readFileSync(src).length };
  if (!check) copyFileSync(src, dst);
}

if (check) {
  const drift = Object.entries(manifest.artifacts).filter(([n, a]) => previous.artifacts?.[n]?.sha256 !== a.sha256);
  if (drift.length) {
    console.error(`\nartifacts/ is stale for: ${drift.map(([n]) => n).join(", ")}\nRun: node scripts/build-contracts.mjs`);
    process.exit(1);
  }
  console.log("\nartifacts/ matches a fresh build");
} else {
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
  console.log(`\nwrote ${Object.keys(manifest.artifacts).length} artifacts to artifacts/`);
}
