/**
 * Messages between the playground page (browser/page.ts) and its Web Worker (browser/worker.ts).
 * Everything here is plain data (structured-clone safe), already formatted for display.
 */
import type { GeneratorVersion } from "../generators/contract.js";
import type { InvariantId, InvariantStatus } from "../invariants/types.js";

export interface TargetInfo {
  name: string;
  description: string;
  artifact: string;
  expectBroken: InvariantId[];
}

export interface ScenarioInfo {
  id: string;
  class: "A1" | "A2";
  channel: string;
  title: string;
  task: string;
  documents: { kind: string; content: string }[];
  aims: InvariantId[];
}

export interface ReproView {
  invariant: InvariantId;
  violation: string;
  attackClasses: string[];
  numShrinks: number;
  steps: { description: string; txs: { who: string; summary: string; outcome: string; error?: string }[] }[];
  /** The repro file's JSON, so the page can offer it for replay with the CLI. */
  json: string;
  fileName: string;
}

export interface InvariantView {
  id: InvariantId;
  title: string;
  status: InvariantStatus;
  runsChecked: number;
  runsExercised: number;
  repro?: ReproView;
}

export interface FuzzSummary {
  target: string;
  wasmSha256: string;
  seed: number;
  runs: number;
  generator: GeneratorVersion;
  sequences: number;
  steps: number;
  attackCounts: Record<string, number>;
  durationMs: number;
  invariants: InvariantView[];
}

export interface PromptView {
  id: string;
  class: string;
  title: string;
  planner: string;
  model: string;
  outcome: string;
  attempted: boolean;
  toolCalls: { name: string; arguments: Record<string, unknown> }[];
  txs: { who: string; summary: string; outcome: string; error?: string }[];
  violations: string[];
  collateral: string[];
  raw?: string;
  note?: string;
}

export type FuzzTargetRef = { builtin: string } | { upload: ArrayBuffer; fileName: string };

export type ToWorker =
  | { type: "init"; base: string }
  | { type: "fuzz"; job: number; target: FuzzTargetRef; seed: number; runs: number; maxSteps: number; generator: GeneratorVersion }
  | { type: "prompt"; job: number; target: string; scenarioIds: string[] }
  | { type: "prompt-custom"; job: number; target: string; document: string; task: string; apiKey: string; model?: string };

export type FromWorker =
  | { type: "ready"; targets: TargetInfo[]; scenarios: ScenarioInfo[]; cryptoImpl: string }
  | { type: "fuzz-start"; job: number; target: string; wasmSha256: string; invariants: { id: InvariantId; title: string }[] }
  | { type: "fuzz-invariant"; job: number; id: InvariantId }
  | { type: "fuzz-run"; job: number; id: InvariantId; n: number; steps: number; broken: InvariantId[] }
  | { type: "fuzz-broken"; job: number; repro: ReproView }
  | { type: "fuzz-done"; job: number; summary: FuzzSummary }
  | { type: "prompt-result"; job: number; result: PromptView }
  | { type: "prompt-done"; job: number; target: string; scenarios: number; blocked: number; breaches: number; resisted: number; durationMs: number }
  | { type: "error"; job?: number; message: string };
