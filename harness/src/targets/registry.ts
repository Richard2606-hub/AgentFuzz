/**
 * Target registry: which guard wasm to attack, through which adapter, and (for the planted-bug
 * matrix) which invariants each target is expected to break.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { sha256Hex } from "../near/keys.js";
import { guardV1, guardV1WithRotate, type GuardAdapter } from "./adapter.js";
import type { InvariantId } from "../invariants/types.js";

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const ARTIFACTS = join(REPO_ROOT, "artifacts");

export interface TargetSpec {
  name: string;
  description: string;
  wasmPath: string;
  adapter: GuardAdapter;
  /** Planted-bug matrix: invariants this target must break (CI fails if one is missed). */
  expectBroken?: InvariantId[];
  /** Where the code came from (repo + commit for third-party targets). */
  source: string;
}

export interface LoadedTarget extends TargetSpec {
  wasm: Uint8Array;
  wasmSha256: string;
}

export const PLANTED_BUGS: { feature: string; breaks: InvariantId; attack: string; summary: string }[] = [
  { feature: "bug-window-lag", breaks: "INV-1", attack: "A4", summary: "window_start += W lags after idle time; every pay resets the cap" },
  { feature: "bug-prefix-allowlist", breaks: "INV-2", attack: "A5", summary: "allowlist matched with starts_with; look-alike receivers pass" },
  { feature: "bug-rotate-full-key", breaks: "INV-3", attack: "A7", summary: "agent-callable rotate_key installs a FULL-access key" },
  { feature: "bug-deferred-accounting", breaks: "INV-1", attack: "A6", summary: "spend recorded in the callback; same-block pays bypass the cap" },
  { feature: "bug-ignore-promise-result", breaks: "INV-5", attack: "A6", summary: "callback ignores transfer failure; recorded spend drifts from reality" },
  { feature: "bug-withdraw-underflow", breaks: "INV-4", attack: "A3", summary: "withdraw reserves one cap with unchecked subtraction; owner funds locked" },
  { feature: "bug-no-rekey", breaks: "INV-6", attack: "A7", summary: "no owner re-key path; allowance exhaustion locks the agent out for good" },
  // Opt-in: not compiled into the default guard_naive.wasm (see contracts/guard-naive/Cargo.toml).
  { feature: "bug-reset-on-failure", breaks: "INV-1", attack: "A6", summary: "a failed transfer resets the window spend to 0; one failure re-opens the full cap" },
];

const builtins: TargetSpec[] = [
  {
    name: "reference",
    description: "guard-reference: the well-built baseline. Expected to hold every invariant.",
    wasmPath: join(ARTIFACTS, "guard_reference.wasm"),
    adapter: guardV1,
    expectBroken: [],
    source: "contracts/guard-reference",
  },
  {
    name: "naive",
    description: "guard-naive with all planted bugs (see contracts/guard-naive/BUGS.md).",
    wasmPath: join(ARTIFACTS, "guard_naive.wasm"),
    adapter: guardV1WithRotate,
    expectBroken: [...new Set(PLANTED_BUGS.map((b) => b.breaks))],
    source: "contracts/guard-naive (default features)",
  },
  {
    name: "naive-fixed",
    description: "guard-naive with every planted bug disabled. Control: expected to hold every invariant.",
    wasmPath: join(ARTIFACTS, "guard_naive__fixed.wasm"),
    adapter: guardV1WithRotate,
    expectBroken: [],
    source: "contracts/guard-naive --no-default-features",
  },
  ...PLANTED_BUGS.map((b) => ({
    name: `naive:${b.feature}`,
    description: `guard-naive with only ${b.feature}: ${b.summary}`,
    wasmPath: join(ARTIFACTS, `guard_naive__${b.feature}.wasm`),
    adapter: guardV1WithRotate,
    expectBroken: [b.breaks],
    source: `contracts/guard-naive --features ${b.feature}`,
  })),
];

const registry = new Map<string, TargetSpec>(builtins.map((t) => [t.name, t]));

export function registerTarget(t: TargetSpec) {
  registry.set(t.name, t);
}

export function listTargets(): TargetSpec[] {
  return [...registry.values()];
}

export function loadTarget(nameOrPath: string, adapter?: GuardAdapter): LoadedTarget {
  let spec = registry.get(nameOrPath);
  if (!spec && nameOrPath.endsWith(".wasm")) {
    const p = isAbsolute(nameOrPath) ? nameOrPath : resolve(process.cwd(), nameOrPath);
    spec = { name: nameOrPath, description: `custom wasm ${p}`, wasmPath: p, adapter: adapter ?? guardV1, source: p };
  }
  if (!spec) throw new Error(`unknown target '${nameOrPath}'. Known: ${[...registry.keys()].join(", ")}`);
  if (!existsSync(spec.wasmPath))
    throw new Error(`wasm not found for target '${spec.name}': ${spec.wasmPath}\nRun: node scripts/build-contracts.mjs`);
  const wasm = new Uint8Array(readFileSync(spec.wasmPath));
  return { ...spec, wasm, wasmSha256: sha256Hex(wasm) };
}

export const THIRD_PARTY_DIR = join(REPO_ROOT, "targets", "third-party");

export interface ThirdPartyManifest {
  name: string;
  description: string;
  repo: string;
  commit: string;
  license: string;
  /** Path to the compiled wasm, relative to the manifest. */
  wasm: string;
  /** "agentfuzz-guard-v1" or a path (relative to the manifest) to an ESM module exporting a GuardAdapter. */
  adapter: string;
  /** Author consent to appear in the public scorecard. Default false. */
  publish?: boolean;
  expectBroken?: InvariantId[];
}

/** Register every targets/third-party/<dir>/target.json. Returns the registered names. */
export async function loadThirdPartyTargets(dir = THIRD_PARTY_DIR): Promise<string[]> {
  if (!existsSync(dir)) return [];
  const names: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name.startsWith("_")) continue;
    const base = join(dir, entry.name);
    const manifestPath = join(base, "target.json");
    if (!existsSync(manifestPath)) continue;
    const m = JSON.parse(readFileSync(manifestPath, "utf8")) as ThirdPartyManifest;
    let adapter: GuardAdapter = guardV1;
    if (m.adapter !== "agentfuzz-guard-v1") {
      const mod = await import(pathToFileURL(resolve(base, m.adapter)).href);
      adapter = (mod.default ?? mod.adapter) as GuardAdapter;
      if (!adapter?.pay || !adapter?.initCall) throw new Error(`${manifestPath}: adapter module must export a GuardAdapter`);
    }
    registerTarget({
      name: m.name,
      description: `${m.description} (${m.repo} @ ${m.commit}, ${m.license})`,
      wasmPath: resolve(base, m.wasm),
      adapter,
      expectBroken: m.expectBroken,
      source: `${m.repo}@${m.commit}`,
    });
    names.push(m.name);
  }
  return names;
}
