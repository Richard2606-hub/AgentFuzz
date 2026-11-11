/**
 * Report-related CLI commands: report, verify, check, render-web, anchor, scoreboard-deploy, demo-offline.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { anchorNearsim, anchorTestnet, deployDemoGuardsTestnet, deployScoreboardTestnet, testnetConfigFromEnv } from "./anchor/anchor.js";
import { loadCorpus, makePlanner, runPromptCampaign } from "./prompt-runner.js";
import { parseGenerator } from "./generators/contract.js";
import { buildScorecard, targetScore } from "./report/scorecard.js";
import { corpusSha256, generateReport, makeSettings, loadScorecard, verifyScorecard, writeScorecard, type AnchorMode } from "./report.js";
import { runCampaign } from "./runner.js";
import { loadTarget, REPO_ROOT } from "./targets/registry.js";
import { renderScorecardHtml } from "./report/html.js";
import { checkGuard, PUBLISHED_SCOREBOARD, TESTNET_RPC, type CheckResult } from "./anchor/audit-lookup.js";
import { sha256Hex } from "./near/keys.js";
import { c } from "./util/term.js";

type Flags = Record<string, string | boolean>;
const rel = (p: string) => relative(process.cwd(), p) || p;
const num = (f: Flags, k: string, d: number) => (f[k] === undefined ? d : Number(f[k]));
const str = (f: Flags, k: string, d: string) => (typeof f[k] === "string" ? (f[k] as string) : d);

export async function cmdReport(flags: Flags, outDir: string): Promise<number> {
  const targets = str(flags, "targets", "reference,naive").split(",");
  console.log(`${c.bold("AgentFuzz report")} ${c.dim("·")} targets ${targets.join(", ")}`);
  const { scorecard, files } = await generateReport({
    targets,
    seed: num(flags, "seed", 42),
    runs: num(flags, "runs", 200),
    maxSteps: num(flags, "max-steps", 20),
    generator: parseGenerator(flags.generator),
    planner: str(flags, "planner", "compromised"),
    anchor: str(flags, "anchor", "auto") as AnchorMode,
    outDir,
    web: !flags["no-web"],
    log: (s) => console.log(`  ${c.dim(s)}`),
  });
  printScorecardSummary(scorecard, files);
  return 0;
}

function printScorecardSummary(sc: ReturnType<typeof buildScorecard>, files: string[]) {
  console.log("");
  for (const t of sc.body.targets) {
    const s = t.summary;
    const verdict = s.broken ? c.red(`${s.broken}/${s.total} invariants BROKEN`) : c.green(`${s.held}/${s.total} invariants held`);
    const prompt = t.prompt ? ` ${c.dim("·")} prompt layer: ${t.prompt.breaches ? c.red(`${t.prompt.breaches} breaches`) : c.green(`${t.prompt.blocked}/${t.prompt.scenarios} blocked`)}` : "";
    console.log(`  ${c.cyan(t.name.padEnd(12))} ${verdict}${prompt}`);
  }
  console.log("");
  console.log(`  run id   ${c.bold(sc.runId)}`);
  console.log(`  sha256   ${sc.sha256}`);
  for (const a of sc.anchors)
    console.log(`  anchor   ${a.network}${a.contractId ? ` ${a.contractId}` : ""}${a.txHash ? ` tx ${a.txHash}` : ""}${a.explorerUrl ? `\n           ${a.explorerUrl}` : ""}`);
  for (const f of files) console.log(`  ${c.dim("wrote")}    ${rel(f)}`);
}

/** Exit codes of `agentfuzz check`, so an agent or CI step can refuse to trust a guard. */
export const CHECK_EXIT: Record<CheckResult["verdict"], number> = { clean: 0, broken: 2, "not-audited": 3, "no-contract": 4, incomplete: 5 };

/**
 * agentfuzz check <account.testnet | code-hash-hex | guard.wasm>
 * Is this guard build audited on the scoreboard, and did it hold? Reads testnet; signs nothing.
 */
export async function cmdCheck(positional: string[], flags: Flags): Promise<number> {
  const ref = positional[0];
  if (!ref) throw new Error("usage: agentfuzz check <account-id | code-hash | guard.wasm> [--scoreboard id] [--trust a.testnet,b.testnet] [--json]");
  const scoreboard = str(flags, "scoreboard", process.env.SCOREBOARD_CONTRACT_ID ?? PUBLISHED_SCOREBOARD);
  const rpcUrl = str(flags, "rpc", process.env.NEAR_RPC_URL ?? TESTNET_RPC);
  const trustedSubmitters = typeof flags.trust === "string" ? flags.trust.split(",").map((s) => s.trim()).filter(Boolean) : undefined;
  const target = /^[0-9a-f]{64}$/.test(ref)
    ? { codeHash: ref }
    : ref.endsWith(".wasm")
      ? { codeHash: sha256Hex(new Uint8Array(readFileSync(ref))) }
      : { accountId: ref };
  const r = await checkGuard(target, { scoreboard, rpcUrl, trustedSubmitters });
  if (flags.json) {
    process.stdout.write(JSON.stringify(r, null, 2) + "\n");
    return CHECK_EXIT[r.verdict];
  }
  console.log(`${c.bold("AgentFuzz check")} ${c.dim("·")} ${ref} ${c.dim(`· scoreboard ${scoreboard}`)}`);
  console.log(`  code hash  ${r.codeHash}  ${c.dim("(SHA-256 of the guard wasm)")}`);
  const a = r.latest;
  if (r.verdict === "no-contract") console.log(c.yellow("  ! no contract deployed on this account"));
  else if (r.verdict === "not-audited")
    console.log(c.yellow(`  ! not audited${trustedSubmitters ? ` by ${trustedSubmitters.join(", ")}` : ""}: no AgentFuzz report covers this exact build`));
  else if (a) {
    const head =
      r.verdict === "clean"
        ? c.green(`  ✓ audited: ${a.held}/${a.total} invariants held, ${a.prompt_breaches} prompt-layer breaches`)
        : r.verdict === "incomplete"
          ? c.yellow(`  ~ audited: nothing broke, but only ${a.held}/${a.total} invariants were exercised`)
          : c.red(`  ✗ audited: ${a.broken}/${a.total} invariants broken${a.broken_invariants.length ? ` (${a.broken_invariants.join(", ")})` : ""}, ${a.prompt_breaches} prompt-layer breaches`);
    console.log(head);
    console.log(c.dim(`    report ${a.run_id} (sha256 ${a.report_sha256.slice(0, 16)}…) as ${a.target}, submitted by ${a.submitter} at block ${a.block_height}`));
    if (r.audits.length > 1) console.log(c.dim(`    ${r.audits.length} audits of this build on record; showing the latest`));
  }
  const verdict = { clean: "safe to trust with a budget, per this audit", broken: "do not trust this guard with funds", incomplete: "not fully tested: run a longer campaign", "not-audited": "unknown: audit it first (agentfuzz fuzz --target guard.wasm)", "no-contract": "nothing to trust" }[r.verdict];
  console.log(`  verdict: ${verdict}`);
  console.log(c.dim("  Audits are claims by their submitter; each names a report you can re-run with agentfuzz verify."));
  return CHECK_EXIT[r.verdict];
}

/** Rebuild web/index.html from a scorecard without re-running or re-anchoring it (used by `make web`). */
export function cmdRenderWeb(positional: string[], flags: Flags): number {
  const file = positional[0] ?? join(REPO_ROOT, "web", "scorecard.json");
  const out = typeof flags.out === "string" ? flags.out : join(REPO_ROOT, "web", "index.html");
  writeFileSync(out, renderScorecardHtml(loadScorecard(file)));
  console.log(`  wrote ${relative(process.cwd(), out)} from ${relative(process.cwd(), file)}`);
  return 0;
}

export async function cmdVerify(positional: string[], flags: Flags): Promise<number> {
  const file = positional[0] ?? "out/scorecard.json";
  console.log(`${c.bold("AgentFuzz verify")} ${c.dim("·")} ${file}`);
  const r = await verifyScorecard(file, { rerun: !flags["no-rerun"], log: (s) => console.log(`  ${c.dim(s)}`) });
  const ok = (b: boolean | undefined) => (b ? c.green("✓") : c.red("✗"));
  console.log(`  ${ok(r.bodyIntact)} body hash ${r.bodyIntact ? "matches" : "DOES NOT match"} the recorded sha256 ${c.dim(r.storedSha256)}`);
  console.log(`  ${ok(r.corpusMatches)} prompt corpus ${r.corpusMatches ? "unchanged" : "differs from the recorded corpus"}`);
  console.log(`  ${ok(r.wasmMismatches.length === 0)} target wasm ${r.wasmMismatches.length ? `differs for ${r.wasmMismatches.join(", ")}` : "identical to the tested builds"}`);
  if (r.recomputedSha256)
    console.log(`  ${ok(r.reproduced)} deterministic re-run ${r.reproduced ? "reproduced the identical hash" : `produced ${r.recomputedSha256}`}`);
  for (const o of r.onchain)
    console.log(`  ${ok(o.matches)} on-chain record on ${o.network} ${o.contractId ?? ""} ${o.matches ? "matches" : o.error ? `unreadable (${o.error})` : `has ${o.sha256 ?? "nothing"}`}`);
  const pass = r.bodyIntact && (r.reproduced ?? true) && r.onchain.every((o) => o.matches);
  console.log(pass ? c.green("\n  verified") : c.red("\n  verification FAILED"));
  return pass ? 0 : 1;
}

export async function cmdAnchor(positional: string[], flags: Flags, outDir: string): Promise<number> {
  const file = positional[0] ?? join(outDir, "scorecard.json");
  const sc = loadScorecard(file);
  const network = str(flags, "network", testnetConfigFromEnv() ? "testnet" : "nearsim");
  if (network === "testnet") {
    const cfg = testnetConfigFromEnv();
    if (!cfg) throw new Error("set NEAR_ACCOUNT_ID and NEAR_PRIVATE_KEY (see .env.example)");
    sc.anchors.push(await anchorTestnet(sc, cfg));
  } else sc.anchors.push(await anchorNearsim(sc));
  const files = writeScorecard(sc, outDir, !flags["no-web"]);
  printScorecardSummary(sc, files);
  return 0;
}

export async function cmdScoreboardDeploy(): Promise<number> {
  const cfg = testnetConfigFromEnv();
  if (!cfg) throw new Error("set NEAR_ACCOUNT_ID, NEAR_PRIVATE_KEY and SCOREBOARD_CONTRACT_ID (see .env.example)");
  const id = await deployScoreboardTestnet(cfg, (s) => console.log(`  ${s}`));
  console.log(c.green(`  scoreboard ready at ${id}`));
  return 0;
}

export async function cmdDemoGuardsDeploy(): Promise<number> {
  const cfg = testnetConfigFromEnv();
  if (!cfg) throw new Error("set NEAR_ACCOUNT_ID and NEAR_PRIVATE_KEY (see .env.example)");
  const ids = await deployDemoGuardsTestnet(cfg, (s) => console.log(`  ${s}`));
  console.log(c.green(`  demo guards: ${ids.join(", ")}`));
  console.log(c.dim(`  check them: agentfuzz check ${ids[0]}`));
  return 0;
}

/**
 * The 90-second demo, offline: no API keys, no network. Mirrors the proposal's demo script:
 * naive guard broken with minimised repros, reference guard holding, prompt layer, hashed scorecard.
 */
export async function cmdDemoOffline(flags: Flags, outDir: string, printers: DemoPrinters): Promise<number> {
  const seed = num(flags, "seed", 42);
  const runs = num(flags, "runs", 200);
  const maxSteps = num(flags, "max-steps", 20);
  const generator = parseGenerator(flags.generator);
  const started = Date.now();
  const banner = (s: string) => console.log(`\n${c.bold(c.magenta("▶"))} ${c.bold(s)}`);
  console.log(c.bold("AgentFuzz demo-offline") + c.dim("  ·  no API keys, no network, deterministic from seed ") + seed);
  console.log(c.dim("Agents on NEAR hold money behind guard contracts. Who tests the guards?"));

  const scenarios = loadCorpus();
  const planner = makePlanner("compromised");
  const targets = ["reference", "naive"];
  const scores: { name: string; score: ReturnType<typeof targetScore> }[] = [];
  for (const name of ["naive", "reference"]) {
    const target = loadTarget(name);
    banner(`make fuzz TARGET=${name}`);
    const campaign = await runCampaign({ target, seed, runs, maxSteps, generator, outDir });
    printers.campaign(campaign);
    banner(`prompt layer vs ${name}: ${scenarios.length} injection / tool-poisoning attacks, planner fully hijacked`);
    const prompt = await runPromptCampaign({ target, planner, scenarios });
    printers.promptSummary(prompt);
    for (const r of prompt.results.filter((x) => x.outcome === "breach").slice(0, 3)) printers.promptResult(r);
    scores.push({ name, score: targetScore(campaign, prompt) });
  }

  banner("scorecard + tamper-evident anchor");
  const settings = makeSettings({ seed, runs, maxSteps, backend: "nearsim", planner: "compromised", targets, corpusSha256: corpusSha256(), generator });
  const ordered = targets.map((t) => scores.find((s) => s.name === t)!.score);
  const sc = buildScorecard(settings, ordered, Date.now() - started);
  sc.anchors.push(await anchorNearsim(sc));
  const testnet = testnetConfigFromEnv();
  if (testnet && flags["anchor-testnet"]) sc.anchors.push(await anchorTestnet(sc, testnet));
  const files = writeScorecard(sc, outDir, Boolean(flags.web));
  printScorecardSummary(sc, files);
  console.log(`\n  ${c.dim("Re-run it yourself:")} agentfuzz verify ${rel(join(outDir, "scorecard.json"))}   ${c.dim("· run it on your guard:")} agentfuzz fuzz --target path/to/guard.wasm`);
  return 0;
}

export interface DemoPrinters {
  campaign: (r: Awaited<ReturnType<typeof runCampaign>>) => void;
  promptSummary: (p: Awaited<ReturnType<typeof runPromptCampaign>>) => void;
  promptResult: (r: Awaited<ReturnType<typeof runPromptCampaign>>["results"][number]) => void;
}
