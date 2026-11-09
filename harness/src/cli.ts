#!/usr/bin/env node
/**
 * agentfuzz CLI.
 *
 *   agentfuzz targets
 *   agentfuzz fuzz --target naive [--seed 42] [--runs 200] [--max-steps 20] [--inv INV-1,INV-4] [--out out] [--json]
 *   agentfuzz replay out/repro-naive-INV-1-xxxx.json
 *   agentfuzz matrix [--seed 7] [--runs 150]          planted-bug matrix (CI gate)
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { INVARIANTS, INVARIANT_IDS, type InvariantId } from "./invariants/types.js";
import { formatNear } from "./near/keys.js";
import { loadRepro, replay, runCampaign, type CampaignEvent, type CampaignResult } from "./runner.js";
import { listTargets, loadTarget, REPO_ROOT } from "./targets/registry.js";
import { prettyJSON } from "./util/json.js";
import { c, statusBadge } from "./util/term.js";
import { runMatrix } from "./matrix.js";
import { loadCorpus, makePlanner, runPromptCampaign, type PromptCampaign, type PromptResult } from "./prompt-runner.js";

type Flags = Record<string, string | boolean>;

function parseArgs(argv: string[]): { cmd: string; positional: string[]; flags: Flags } {
  const [cmd = "help", ...rest] = argv;
  const positional: string[] = [];
  const flags: Flags = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a.startsWith("--")) {
      const [k, v] = a.slice(2).split("=", 2);
      if (v !== undefined) flags[k] = v;
      else if (rest[i + 1] && !rest[i + 1].startsWith("--")) flags[k] = rest[++i];
      else flags[k] = true;
    } else positional.push(a);
  }
  return { cmd, positional, flags };
}

const num = (f: Flags, k: string, d: number) => (f[k] === undefined ? d : Number(f[k]));
const str = (f: Flags, k: string, d: string) => (typeof f[k] === "string" ? (f[k] as string) : d);
const rel = (p: string) => relative(process.cwd(), p) || p;

export function outDir(flags: Flags): string {
  return resolve(REPO_ROOT, str(flags, "out", "out"));
}

function printCampaignHeader(target: string, seed: number, runs: number, backend = "nearsim") {
  console.log(`${c.bold("AgentFuzz")} ${c.dim("·")} target ${c.cyan(target)} ${c.dim("·")} seed ${seed} ${c.dim("·")} ${runs} runs/invariant ${c.dim("·")} backend ${backend}`);
}

export function printCampaignResult(r: CampaignResult) {
  console.log("");
  for (const o of r.invariants) {
    const title = INVARIANTS[o.id].title;
    console.log(`  ${c.bold(o.id)} ${statusBadge(o.status).padEnd(24)} ${c.dim(title)}`);
    if (o.status === "broken" && o.repro) {
      console.log(`      ${c.red("✗")} ${o.violation?.message}`);
      console.log(`      ${c.dim("minimised repro")} (${o.repro.steps.length} step${o.repro.steps.length === 1 ? "" : "s"}, ${o.repro.numShrinks} shrinks, classes ${o.repro.attackClasses.join(",") || "-"}):`);
      if (!o.repro.trace.length) console.log(`        ${c.dim("(no attack steps needed: broken out of the box by the end-of-run owner check)")}`);
      for (const s of o.repro.trace) {
        console.log(`        ${s.index + 1}. ${s.description}`);
        for (const t of s.txs) {
          const mark = t.outcome === "success" ? c.green("ok") : t.outcome === "rejected" ? c.yellow("rejected") : c.red("failed");
          console.log(`           ${c.dim("↳")} ${t.summary}: ${mark}${t.error ? c.dim(` (${truncate(t.error, 90)})`) : ""}`);
        }
      }
      if (o.reproFile) console.log(`      ${c.dim("repro saved:")} ${rel(o.reproFile)}  ${c.dim(`(replay: agentfuzz replay ${rel(o.reproFile)})`)}`);
    } else if (o.status !== "n/a") {
      console.log(`      ${c.dim(`exercised in ${o.runsExercised}/${o.runsChecked} runs`)}`);
    }
  }
  const broken = r.invariants.filter((o) => o.status === "broken").length;
  const counts = Object.entries(r.attackCounts)
    .sort()
    .map(([k, v]) => `${k}:${v}`)
    .join(" ");
  console.log("");
  console.log(
    `  ${broken ? c.red(`${broken} invariant(s) broken`) : c.green("all invariants held")} ${c.dim("·")} ${r.distinctSequences} attack sequences ${c.dim("·")} ${r.stepsExecuted} steps ${c.dim(`(${counts})`)} ${c.dim("·")} ${(r.durationMs / 1000).toFixed(1)}s`,
  );
}

function truncate(s: string, n: number) {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

function progress(e: CampaignEvent) {
  if (!process.stdout.isTTY) return;
  if (e.type === "run" && e.n % 10 === 0) process.stdout.write(`\r  ${e.id} … run ${e.n}   `);
  if (e.type === "broken" || e.type === "held") process.stdout.write("\r" + " ".repeat(40) + "\r");
}

async function cmdFuzz(flags: Flags) {
  const targetName = str(flags, "target", "naive");
  const seed = num(flags, "seed", 42);
  const runs = num(flags, "runs", 200);
  const inv = typeof flags.inv === "string" ? (flags.inv.split(",") as InvariantId[]) : undefined;
  const target = loadTarget(targetName);
  if (!flags.json) printCampaignHeader(target.name, seed, runs);
  const out = outDir(flags);
  const result = await runCampaign({
    target,
    seed,
    runs,
    maxSteps: num(flags, "max-steps", 20),
    invariants: inv,
    outDir: out,
    onEvent: flags.json ? undefined : progress,
  });
  mkdirSync(out, { recursive: true });
  const file = join(out, `campaign-${target.name.replace(/[^a-z0-9-]+/gi, "_")}-${seed}.json`);
  writeFileSync(file, prettyJSON(result));
  if (flags.json) process.stdout.write(prettyJSON(result));
  else {
    printCampaignResult(result);
    console.log(`  ${c.dim("campaign written:")} ${rel(file)}`);
  }
  return result.invariants.some((o) => o.status === "broken") && flags["fail-on-break"] ? 1 : 0;
}

async function cmdReplay(positional: string[]) {
  const file = positional[0];
  if (!file) throw new Error("usage: agentfuzz replay <repro.json>");
  const repro = loadRepro(file);
  console.log(`${c.bold("AgentFuzz replay")} ${c.dim("·")} ${repro.target} ${c.dim("·")} ${repro.invariant} ${c.dim("·")} ${repro.steps.length} steps`);
  const r = await replay(repro);
  if (!r.wasmMatches) console.log(c.yellow("  warning: target wasm differs from the one the repro was recorded against"));
  for (const s of r.outcome.trace.steps) console.log(`  ${s.index + 1}. ${s.description}`);
  const v = r.outcome.verdict.violations.filter((x) => x.invariant === repro.invariant);
  if (r.reproduced) {
    console.log(`  ${statusBadge("broken")} ${repro.invariant}: ${v[0]?.message}`);
    return 0;
  }
  console.log(`  ${c.green("not reproduced")}: ${repro.invariant} held on this build`);
  return 2;
}

function cmdTargets() {
  for (const t of listTargets()) {
    const exp = t.expectBroken === undefined ? "" : t.expectBroken.length ? c.red(` expects ${t.expectBroken.join(",")}`) : c.green(" expects clean");
    console.log(`  ${c.cyan(t.name.padEnd(34))} ${t.description}${exp}`);
  }
  return 0;
}

export function printPromptResult(r: PromptResult) {
  const badge =
    r.outcome === "breach" ? c.red(c.bold("BREACH ")) : r.outcome === "blocked" ? c.green(c.bold("BLOCKED")) : r.outcome === "resisted" ? c.cyan("RESISTED") : c.dim("SKIPPED");
  const planner = r.attempted ? c.yellow("planner hijacked") : c.dim("planner refused ");
  console.log(`  ${r.id.padEnd(7)} ${badge} ${planner} ${c.dim("·")} ${truncate(r.title, 78)}`);
  if (r.outcome === "breach") for (const v of r.violations) console.log(`          ${c.red("✗")} ${v.invariant}: ${v.message}`);
  if (r.outcome === "blocked") {
    const stop = r.txs.find((t) => t.outcome !== "success");
    if (stop) console.log(`          ${c.dim(`stopped: ${truncate(stop.summary + " → " + (stop.error ?? stop.outcome), 110)}`)}`);
  }
  if (r.note) console.log(`          ${c.dim(r.note)}`);
}

export function printPromptSummary(p: PromptCampaign) {
  console.log("");
  console.log(
    `  ${p.scenarios} attacks ${c.dim("·")} planner hijacked ${p.attempted}/${p.scenarios} ${c.dim("·")} guard blocked ${c.green(String(p.blocked))} ${c.dim("·")} ` +
      `${p.breaches ? c.red(`breaches ${p.breaches}`) : c.green("breaches 0")}${p.resisted ? ` ${c.dim("·")} resisted ${p.resisted}` : ""}${p.skipped ? ` ${c.dim("·")} skipped ${p.skipped}` : ""} ${c.dim("·")} ${(p.durationMs / 1000).toFixed(1)}s`,
  );
}

async function cmdPrompt(flags: Flags) {
  const target = loadTarget(str(flags, "target", "reference"));
  const plannerKind = flags.live ? "llm" : str(flags, "planner", "compromised");
  const planner = makePlanner(plannerKind);
  const scenarios = loadCorpus(typeof flags.corpus === "string" ? resolve(flags.corpus) : undefined).filter(
    (s) => typeof flags.only !== "string" || (flags.only as string).split(",").some((p) => s.id.startsWith(p)),
  );
  if (!flags.json) console.log(`${c.bold("AgentFuzz prompt layer")} ${c.dim("·")} target ${c.cyan(target.name)} ${c.dim("·")} planner ${plannerKind} ${c.dim("·")} ${scenarios.length} attacks`);
  const result = await runPromptCampaign({ target, planner, scenarios, record: !!flags.record, onResult: flags.json ? undefined : printPromptResult });
  const out = outDir(flags);
  mkdirSync(out, { recursive: true });
  const file = join(out, `prompt-${target.name.replace(/[^a-z0-9-]+/gi, "_")}-${plannerKind}.json`);
  writeFileSync(file, prettyJSON(result));
  if (flags.json) process.stdout.write(prettyJSON(result));
  else {
    printPromptSummary(result);
    console.log(`  ${c.dim("written:")} ${rel(file)}`);
  }
  return 0;
}

function help() {
  console.log(`agentfuzz: red-team harness for NEAR agent-wallet guards

  agentfuzz targets                         list built-in targets
  agentfuzz fuzz --target <name|file.wasm>  fuzz one guard  [--seed N] [--runs N] [--max-steps N] [--inv INV-1,INV-2] [--json]
  agentfuzz replay <repro.json>             replay a minimised repro deterministically
  agentfuzz prompt --target <name>          prompt-layer attacks (A1/A2) through the reference agent
                                            [--planner compromised|cassette|llm] [--live] [--record] [--only A1-00]
  agentfuzz matrix                          planted-bug matrix: every planted bug must be caught  [--seed N] [--runs N]

Invariants: ${INVARIANT_IDS.join(", ")} (see THREAT_MODEL.md)
Balances are in NEAR; e.g. ${formatNear(10n ** 24n)} = 1 NEAR`);
  return 0;
}

async function main() {
  const { cmd, positional, flags } = parseArgs(process.argv.slice(2));
  switch (cmd) {
    case "fuzz":
      return cmdFuzz(flags);
    case "replay":
      return cmdReplay(positional);
    case "targets":
      return cmdTargets();
    case "prompt":
      return cmdPrompt(flags);
    case "matrix":
      return runMatrix({ seed: num(flags, "seed", 7), runs: num(flags, "runs", 150), out: outDir(flags) });
    default:
      return help();
  }
}

main().then(
  (code) => process.exit(code ?? 0),
  (e) => {
    console.error(c.red(`error: ${e instanceof Error ? e.message : String(e)}`));
    if (process.env.AGENTFUZZ_DEBUG) console.error(e);
    process.exit(1);
  },
);
