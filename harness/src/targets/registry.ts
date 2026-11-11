/**
 * Target registry (Node): resolves built-in targets to files in artifacts/, loads custom wasm
 * from disk, and registers third-party targets. The target table itself is in specs.ts.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { guardV1, type GuardAdapter } from "./adapter.js";
import type { InvariantId } from "../invariants/types.js";
import { BUILTIN_TARGETS, targetFromBytes, type LoadedTarget } from "./specs.js";

export { BUILTIN_TARGETS, PLANTED_BUGS, targetFromBytes, type BuiltinTarget, type LoadedTarget } from "./specs.js";

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

const builtins: TargetSpec[] = BUILTIN_TARGETS.map(({ artifact, ...t }) => ({ ...t, wasmPath: join(ARTIFACTS, artifact) }));

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
  return targetFromBytes(spec, new Uint8Array(readFileSync(spec.wasmPath)));
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
