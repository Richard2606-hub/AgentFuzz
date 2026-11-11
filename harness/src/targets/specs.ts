/**
 * Built-in guard targets, without touching the filesystem: names, adapters, which artifact file
 * holds each wasm, and (for the planted-bug matrix) which invariants each must break. Shared by
 * the Node loader (registry.ts) and the browser playground, which fetches the same artifacts.
 */
import { sha256Hex } from "../near/keys.js";
import { guardV1, guardV1WithRotate, type GuardAdapter } from "./adapter.js";
import type { InvariantId } from "../invariants/types.js";

export interface BuiltinTarget {
  name: string;
  description: string;
  /** File name in artifacts/ (and web/wasm/ for the playground). */
  artifact: string;
  adapter: GuardAdapter;
  /** Planted-bug matrix: invariants this target must break (CI fails if one is missed). */
  expectBroken?: InvariantId[];
  /** Where the code came from (repo + commit for third-party targets). */
  source: string;
}

export interface LoadedTarget {
  name: string;
  description: string;
  adapter: GuardAdapter;
  expectBroken?: InvariantId[];
  source: string;
  wasm: Uint8Array;
  wasmSha256: string;
  /** Where the wasm was read from, when it came from disk. */
  wasmPath?: string;
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

export const BUILTIN_TARGETS: BuiltinTarget[] = [
  {
    name: "reference",
    description: "guard-reference: the well-built baseline. Expected to hold every invariant.",
    artifact: "guard_reference.wasm",
    adapter: guardV1,
    expectBroken: [],
    source: "contracts/guard-reference",
  },
  {
    name: "naive",
    description: "guard-naive with all planted bugs (see contracts/guard-naive/BUGS.md).",
    artifact: "guard_naive.wasm",
    adapter: guardV1WithRotate,
    expectBroken: [...new Set(PLANTED_BUGS.map((b) => b.breaks))],
    source: "contracts/guard-naive (default features)",
  },
  {
    name: "naive-fixed",
    description: "guard-naive with every planted bug disabled. Control: expected to hold every invariant.",
    artifact: "guard_naive__fixed.wasm",
    adapter: guardV1WithRotate,
    expectBroken: [],
    source: "contracts/guard-naive --no-default-features",
  },
  ...PLANTED_BUGS.map((b) => ({
    name: `naive:${b.feature}`,
    description: `guard-naive with only ${b.feature}: ${b.summary}`,
    artifact: `guard_naive__${b.feature}.wasm`,
    adapter: guardV1WithRotate,
    expectBroken: [b.breaks],
    source: `contracts/guard-naive --features ${b.feature}`,
  })),
];

/** A loaded target from wasm bytes; `adapter` defaults to agentfuzz-guard-v1 (custom uploads). */
export function targetFromBytes(
  spec: Omit<LoadedTarget, "wasm" | "wasmSha256" | "adapter"> & { adapter?: GuardAdapter },
  wasm: Uint8Array,
): LoadedTarget {
  return { ...spec, adapter: spec.adapter ?? guardV1, wasm, wasmSha256: sha256Hex(wasm) };
}
