/**
 * Runner: deploy -> attack -> check -> minimise -> report.
 *
 * For each invariant, fast-check searches attack sequences for a counterexample and shrinks it.
 * All per-invariant searches use the same seed, so they walk the same sequence stream; a memo
 * cache makes every distinct sequence execute once. Every run uses a fresh world.
 */
import fc from "fast-check";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { executeSequence, stepClass, type AttackClass, type Step, type StepRecord, type Trace } from "./attacks/steps.js";
import { sequenceArb } from "./generators/contract.js";
import { checkRun } from "./invariants/check.js";
import { INVARIANT_IDS, brokenIn, type InvariantId, type InvariantStatus, type RunVerdict, type Violation } from "./invariants/types.js";
import type { Backend } from "./near/backend.js";
import { sha256Hex } from "./near/keys.js";
import { SimBackend } from "./sim/backend.js";
import { loadTarget, type LoadedTarget } from "./targets/registry.js";
import { prettyJSON, toJSONSafe } from "./util/json.js";
import { createWorld, defaultConfig, type WorldConfig } from "./world.js";

export type BackendFactory = (chainSeed: string) => Backend;
export const simBackendFactory: BackendFactory = (seed) => new SimBackend({ seed });

export interface RunOutcome {
  verdict: RunVerdict;
  trace: Trace;
  steps: Step[];
}

/** Execute one attack sequence in a brand-new world and check every invariant. */
export async function evaluate(target: LoadedTarget, cfg: WorldConfig, steps: Step[], backendFactory: BackendFactory = simBackendFactory): Promise<RunOutcome> {
  const backend = backendFactory(cfg.seed);
  const world = await createWorld(backend, target, { ...cfg, blockTimeNs: backend.blockTimeNs });
  const trace = await executeSequence(world, steps);
  const verdict = await checkRun(world, trace);
  return { verdict, trace, steps };
}

export interface Repro {
  format: "agentfuzz-repro/1";
  target: string;
  wasmSha256: string;
  invariant: InvariantId;
  violation: Violation;
  seed: number;
  fcPath?: string;
  numShrinks: number;
  backend: string;
  config: WorldConfig;
  steps: Step[];
  attackClasses: AttackClass[];
  trace: StepRecord[];
}

export interface InvariantOutcome {
  id: InvariantId;
  status: InvariantStatus;
  runsChecked: number;
  runsExercised: number;
  violation?: Violation;
  repro?: Repro;
  reproFile?: string;
}

export interface CampaignResult {
  target: string;
  wasmSha256: string;
  source: string;
  seed: number;
  runsPerInvariant: number;
  distinctSequences: number;
  stepsExecuted: number;
  attackCounts: Record<string, number>;
  durationMs: number;
  backend: string;
  invariants: InvariantOutcome[];
  config: WorldConfig;
}

export interface CampaignOptions {
  target: LoadedTarget;
  seed: number;
  runs: number;
  maxSteps?: number;
  invariants?: InvariantId[];
  cfg?: Partial<WorldConfig>;
  backendFactory?: BackendFactory;
  outDir?: string;
  onEvent?: (e: CampaignEvent) => void;
}

export type CampaignEvent =
  | { type: "invariant-start"; id: InvariantId }
  | { type: "run"; id: InvariantId; n: number; steps: number; broken: InvariantId[] }
  | { type: "broken"; id: InvariantId; repro: Repro; file?: string }
  | { type: "held"; id: InvariantId; status: InvariantStatus };

export async function runCampaign(opts: CampaignOptions): Promise<CampaignResult> {
  const started = Date.now();
  const { target, seed, runs } = opts;
  const maxSteps = opts.maxSteps ?? 20;
  const backendFactory = opts.backendFactory ?? simBackendFactory;
  const probe = backendFactory("probe");
  const cfg: WorldConfig = { ...defaultConfig(`agentfuzz/${seed}`, probe.blockTimeNs), ...opts.cfg };
  const ids = opts.invariants ?? INVARIANT_IDS;

  const cache = new Map<string, RunOutcome>();
  const attackCounts: Record<string, number> = {};
  let stepsExecuted = 0;
  const checkedRuns = new Map<InvariantId, number>();
  const exercisedRuns = new Map<InvariantId, number>();

  const run = async (steps: Step[]): Promise<RunOutcome> => {
    const key = JSON.stringify(steps);
    let r = cache.get(key);
    if (!r) {
      r = await evaluate(target, cfg, steps, backendFactory);
      cache.set(key, r);
      stepsExecuted += steps.length;
      for (const s of steps) attackCounts[stepClass(s)] = (attackCounts[stepClass(s)] ?? 0) + 1;
      for (const id of r.verdict.checked) checkedRuns.set(id, (checkedRuns.get(id) ?? 0) + 1);
      for (const id of r.verdict.exercised) exercisedRuns.set(id, (exercisedRuns.get(id) ?? 0) + 1);
    }
    return r;
  };

  const outcomes: InvariantOutcome[] = [];
  for (const id of ids) {
    opts.onEvent?.({ type: "invariant-start", id });
    let n = 0;
    const details = await fc.check(
      fc.asyncProperty(sequenceArb(maxSteps), async (steps) => {
        const r = await run(steps);
        const broken = [...brokenIn(r.verdict)];
        opts.onEvent?.({ type: "run", id, n: ++n, steps: steps.length, broken });
        return !broken.includes(id);
      }),
      { seed, numRuns: runs },
    );

    if (details.failed && details.counterexample) {
      const steps = details.counterexample[0] as Step[];
      const r = await run(steps);
      const violation = r.verdict.violations.find((v) => v.invariant === id)!;
      const repro: Repro = {
        format: "agentfuzz-repro/1",
        target: target.name,
        wasmSha256: target.wasmSha256,
        invariant: id,
        violation,
        seed,
        fcPath: details.counterexamplePath ?? undefined,
        numShrinks: details.numShrinks,
        backend: backendFactory("probe").name,
        config: cfg,
        steps,
        attackClasses: [...new Set(steps.map(stepClass).filter((c): c is AttackClass => c !== "owner"))].sort(),
        trace: r.trace.steps,
      };
      const file = opts.outDir ? saveRepro(opts.outDir, repro) : undefined;
      outcomes.push({ id, status: "broken", runsChecked: 0, runsExercised: 0, violation, repro, reproFile: file });
      opts.onEvent?.({ type: "broken", id, repro, file });
    } else if (details.failed) {
      throw new Error(`fuzzing ${id} errored: ${details.errorInstance ?? "unknown error"}`);
    } else {
      outcomes.push({ id, status: "held", runsChecked: 0, runsExercised: 0 });
    }
  }

  for (const o of outcomes) {
    o.runsChecked = checkedRuns.get(o.id) ?? 0;
    o.runsExercised = exercisedRuns.get(o.id) ?? 0;
    if (o.status === "held") {
      if (o.runsChecked === 0) o.status = "n/a";
      else if (o.runsExercised === 0) o.status = "not-exercised";
      opts.onEvent?.({ type: "held", id: o.id, status: o.status });
    }
  }

  return {
    target: target.name,
    wasmSha256: target.wasmSha256,
    source: target.source,
    seed,
    runsPerInvariant: runs,
    distinctSequences: cache.size,
    stepsExecuted,
    attackCounts,
    durationMs: Date.now() - started,
    backend: probe.name,
    invariants: outcomes,
    config: cfg,
  };
}

export function saveRepro(outDir: string, repro: Repro): string {
  mkdirSync(outDir, { recursive: true });
  const body = prettyJSON(repro);
  const tag = repro.target.replace(/[^a-z0-9-]+/gi, "_");
  const file = join(outDir, `repro-${tag}-${repro.invariant}-${sha256Hex(body).slice(0, 8)}.json`);
  writeFileSync(file, body);
  return file;
}

export function loadRepro(file: string): Repro {
  const raw = JSON.parse(readFileSync(file, "utf8"));
  if (raw.format !== "agentfuzz-repro/1") throw new Error(`${file} is not an agentfuzz repro`);
  const c = raw.config;
  raw.config = {
    ...c,
    guardBalance: BigInt(c.guardBalance),
    cap: BigInt(c.cap),
    agentAllowance: BigInt(c.agentAllowance),
    blockTimeNs: BigInt(c.blockTimeNs),
    withdrawMargin: BigInt(c.withdrawMargin),
  };
  return raw as Repro;
}

export interface ReplayResult {
  reproduced: boolean;
  wasmMatches: boolean;
  outcome: RunOutcome;
}

/** Re-execute a repro's steps in a fresh world and confirm the invariant still breaks. */
export async function replay(repro: Repro, backendFactory: BackendFactory = simBackendFactory, targetOverride?: LoadedTarget): Promise<ReplayResult> {
  const target = targetOverride ?? loadTarget(repro.target);
  const outcome = await evaluate(target, repro.config, repro.steps, backendFactory);
  return {
    reproduced: brokenIn(outcome.verdict).has(repro.invariant),
    wasmMatches: target.wasmSha256 === repro.wasmSha256,
    outcome,
  };
}

export { toJSONSafe };
