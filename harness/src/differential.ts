/**
 * Differential test: run the same attack sequences on nearsim and on a real nearcore sandbox and
 * compare which invariants break. Agreement is evidence that nearsim's verdicts are faithful;
 * any disagreement is printed with the sequence so it can be investigated.
 */
import fc from "fast-check";
import { describeStep, type Step } from "./attacks/steps.js";
import { sequenceArb } from "./generators/contract.js";
import { brokenIn, type InvariantId } from "./invariants/types.js";
import { evaluate, simBackendFactory, type BackendFactory } from "./runner.js";
import { SandboxBackend } from "./sandbox/backend.js";
import type { LoadedTarget } from "./targets/registry.js";
import { defaultConfig } from "./world.js";

export const sandboxBackendFactory: BackendFactory = { name: "sandbox", create: () => SandboxBackend.start() };

export interface DiffRow {
  index: number;
  steps: Step[];
  nearsim: InvariantId[];
  sandbox: InvariantId[];
  agree: boolean;
}

export async function differential(opts: {
  target: LoadedTarget;
  seed: number;
  runs: number;
  maxSteps: number;
  include?: Step[][];
  onRow?: (r: DiffRow) => void;
}): Promise<DiffRow[]> {
  const cfg = defaultConfig(`agentfuzz/diff/${opts.seed}`);
  const sampled = fc.sample(sequenceArb(opts.maxSteps), { seed: opts.seed, numRuns: opts.runs });
  const sequences = [...(opts.include ?? []), ...sampled];
  const rows: DiffRow[] = [];
  for (const [index, steps] of sequences.entries()) {
    const a = await evaluate(opts.target, cfg, steps, simBackendFactory);
    const b = await evaluate(opts.target, cfg, steps, sandboxBackendFactory);
    const nearsim = [...brokenIn(a.verdict)].sort();
    const sandbox = [...brokenIn(b.verdict)].sort();
    const row = { index, steps, nearsim, sandbox, agree: nearsim.join() === sandbox.join() };
    rows.push(row);
    opts.onRow?.(row);
  }
  return rows;
}

export { describeStep };
