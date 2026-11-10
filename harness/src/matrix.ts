/**
 * Planted-bug matrix: AgentFuzz's own end-to-end test (proposal: "the planted bugs in
 * guard-naive must all be found within the CI seed budget; if any is missed, the build fails").
 *
 * Each single-bug variant of guard-naive must break its expected invariant, and the controls
 * (guard-reference, guard-naive with every bug disabled) must break nothing.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { DEFAULT_GENERATOR, type GeneratorVersion } from "./generators/contract.js";
import { runCampaign, type CampaignResult } from "./runner.js";
import { listTargets, loadTarget } from "./targets/registry.js";
import { prettyJSON } from "./util/json.js";
import { c } from "./util/term.js";

export interface MatrixRow {
  target: string;
  expected: string[];
  broken: string[];
  missed: string[];
  falsePositives: string[];
  ok: boolean;
  durationMs: number;
}

export async function computeMatrix(
  seed: number,
  runs: number,
  filter?: (name: string) => boolean,
  generator: GeneratorVersion = DEFAULT_GENERATOR,
): Promise<{ rows: MatrixRow[]; results: CampaignResult[] }> {
  const rows: MatrixRow[] = [];
  const results: CampaignResult[] = [];
  const targets = listTargets().filter((t) => t.expectBroken !== undefined && t.name !== "naive" && !t.name.startsWith("tp:") && (!filter || filter(t.name)));
  for (const spec of targets) {
    const target = loadTarget(spec.name);
    const expected = spec.expectBroken ?? [];
    // Bug variants only need to show their expected break; controls are searched on every invariant.
    const r = await runCampaign({ target, seed, runs, generator, invariants: expected.length ? expected : undefined });
    results.push(r);
    const broken = r.invariants.filter((o) => o.status === "broken").map((o) => o.id);
    const missed = expected.filter((e) => !broken.includes(e));
    const falsePositives = expected.length ? [] : broken;
    rows.push({ target: spec.name, expected, broken, missed, falsePositives, ok: !missed.length && !falsePositives.length, durationMs: r.durationMs });
  }
  return { rows, results };
}

export async function runMatrix(opts: { seed: number; runs: number; out: string; generator?: GeneratorVersion }): Promise<number> {
  const generator = opts.generator ?? DEFAULT_GENERATOR;
  console.log(`${c.bold("AgentFuzz planted-bug matrix")} ${c.dim("·")} seed ${opts.seed} ${c.dim("·")} ${opts.runs} runs/invariant ${c.dim("·")} generator v${generator}`);
  const { rows, results } = await computeMatrix(opts.seed, opts.runs, undefined, generator);
  for (const r of rows) {
    const mark = r.ok ? c.green("✓") : c.red("✗");
    const what = r.expected.length ? `expects ${r.expected.join(",")} → broke ${r.broken.join(",") || "nothing"}` : `control → broke ${r.broken.join(",") || "nothing"}`;
    console.log(`  ${mark} ${r.target.padEnd(34)} ${what} ${c.dim(`(${(r.durationMs / 1000).toFixed(1)}s)`)}`);
  }
  mkdirSync(opts.out, { recursive: true });
  writeFileSync(join(opts.out, `matrix-${opts.seed}.json`), prettyJSON({ seed: opts.seed, runs: opts.runs, generator, rows, results }));
  const failed = rows.filter((r) => !r.ok);
  if (failed.length) {
    console.log(c.red(`\n  ${failed.length} matrix row(s) failed: ${failed.map((f) => f.target).join(", ")}`));
    return 1;
  }
  console.log(c.green(`\n  all ${rows.length} rows passed: every planted bug caught, controls clean`));
  return 0;
}
