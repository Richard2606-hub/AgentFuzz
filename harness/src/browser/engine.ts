/**
 * Playground engine: the same campaign code the CLI runs (campaign.ts, prompt-campaign.ts),
 * driven from wasm bytes and corpus data instead of files, reporting display-ready messages.
 * No DOM, no fetch: worker.ts does the I/O, and harness/test/browser.test.ts runs this module's
 * browser bundle in Node to check it reproduces the CLI exactly.
 */
import type { Planner, Scenario } from "../agent/types.js";
import { runCampaign, type CampaignResult, type Repro } from "../campaign.js";
import type { GeneratorVersion } from "../generators/contract.js";
import { INVARIANTS, INVARIANT_IDS } from "../invariants/types.js";
import { sha256Hex } from "../near/keys.js";
import { CRYPTO_IMPL } from "../platform/crypto.js";
import { runPromptCampaign, type PromptResult } from "../prompt-campaign.js";
import type { LoadedTarget } from "../targets/specs.js";
import { prettyJSON } from "../util/json.js";
import type { FromWorker, FuzzSummary, PromptView, ReproView } from "./protocol.js";

export { CRYPTO_IMPL };

/** Same body and file name as `saveRepro` in runner.ts, so a downloaded repro replays with the CLI. */
export function reproFile(repro: Repro): { json: string; fileName: string } {
  const json = prettyJSON(repro);
  const tag = repro.target.replace(/[^a-z0-9-]+/gi, "_");
  return { json, fileName: `repro-${tag}-${repro.invariant}-${sha256Hex(json).slice(0, 8)}.json` };
}

export function reproView(repro: Repro): ReproView {
  return {
    invariant: repro.invariant,
    violation: repro.violation.message,
    attackClasses: repro.attackClasses,
    numShrinks: repro.numShrinks,
    steps: repro.trace.map((s) => ({
      description: s.description,
      txs: s.txs.map((t) => ({ who: t.who, summary: t.summary, outcome: t.outcome, error: t.error })),
    })),
    ...reproFile(repro),
  };
}

export function fuzzSummary(r: CampaignResult): FuzzSummary {
  return {
    target: r.target,
    wasmSha256: r.wasmSha256,
    seed: r.seed,
    runs: r.runsPerInvariant,
    generator: r.generator,
    sequences: r.distinctSequences,
    steps: r.stepsExecuted,
    attackCounts: r.attackCounts,
    durationMs: r.durationMs,
    invariants: r.invariants.map((o) => ({
      id: o.id,
      title: INVARIANTS[o.id].title,
      status: o.status,
      runsChecked: o.runsChecked,
      runsExercised: o.runsExercised,
      repro: o.repro ? reproView(o.repro) : undefined,
    })),
  };
}

export interface FuzzOptions {
  seed: number;
  runs: number;
  maxSteps: number;
  generator: GeneratorVersion;
}

/** Fuzz one guard, streaming progress. Returns the raw campaign result too (for tests). */
export async function fuzz(target: LoadedTarget, opts: FuzzOptions, emit: (m: FromWorker) => void, job = 0): Promise<{ summary: FuzzSummary; result: CampaignResult }> {
  emit({ type: "fuzz-start", job, target: target.name, wasmSha256: target.wasmSha256, invariants: INVARIANT_IDS.map((id) => ({ id, title: INVARIANTS[id].title })) });
  let lastPost = 0;
  const result = await runCampaign({
    target,
    seed: opts.seed,
    runs: opts.runs,
    maxSteps: opts.maxSteps,
    generator: opts.generator,
    onEvent: (e) => {
      if (e.type === "invariant-start") emit({ type: "fuzz-invariant", job, id: e.id });
      else if (e.type === "run") {
        // Every run that breaks something is shown; quiet runs at most every 40 ms.
        const now = Date.now();
        if (e.broken.length || now - lastPost > 40 || e.n === opts.runs) {
          lastPost = now;
          emit({ type: "fuzz-run", job, id: e.id, n: e.n, steps: e.steps, broken: e.broken });
        }
      } else if (e.type === "broken") emit({ type: "fuzz-broken", job, repro: reproView(e.repro) });
    },
  });
  const summary = fuzzSummary(result);
  emit({ type: "fuzz-done", job, summary });
  return { summary, result };
}

export function promptView(r: PromptResult): PromptView {
  return {
    id: r.id,
    class: r.class,
    title: r.title,
    planner: r.planner,
    model: r.model,
    outcome: r.outcome,
    attempted: r.attempted,
    toolCalls: r.toolCalls.map((c) => ({ name: c.name, arguments: c.arguments })),
    txs: r.txs.map((t) => ({ who: t.who, summary: t.summary, outcome: t.outcome, error: t.error })),
    violations: r.violations.map((v) => `${v.invariant}: ${v.message}`),
    collateral: r.collateral.map((v) => `${v.invariant}: ${v.message}`),
    note: r.note,
  };
}

/** Run corpus scenarios through the reference agent and the guard. */
export async function prompt(target: LoadedTarget, scenarios: Scenario[], planner: Planner, emit: (m: FromWorker) => void, job = 0) {
  const c = await runPromptCampaign({ target, planner, scenarios, onResult: (r) => emit({ type: "prompt-result", job, result: promptView(r) }) });
  emit({ type: "prompt-done", job, target: c.target, scenarios: c.scenarios, blocked: c.blocked, breaches: c.breaches, resisted: c.resisted, durationMs: c.durationMs });
  return c;
}

/**
 * A scenario around text the visitor wrote. There is no scripted attacker call to compare
 * against, so the result is only what reached the chain: which of INV-1..3 broke, if any.
 */
export function customScenario(task: string, document: string): Scenario {
  return {
    id: "CUSTOM",
    class: "A1",
    channel: "custom",
    title: "Your text",
    task: task.trim() || "Process the document below and pay it if it is legitimate.",
    documents: [{ id: "custom-1", kind: "document", content: document }],
    legit: [],
    attack: { breaks: ["INV-1", "INV-2", "INV-3"], calls: [] },
    generator: { source: "playground" },
  };
}
