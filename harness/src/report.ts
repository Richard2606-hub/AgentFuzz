/**
 * Report orchestration: fuzz + prompt-layer every target, build the scorecard, anchor its hash,
 * and write JSON + HTML. `verifyScorecard` re-runs from the recorded settings and recomputes it.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { anchorLocal, anchorNearsim, anchorTestnet, readTestnetRecord, testnetConfigFromEnv } from "./anchor/anchor.js";
import { loadCorpus, makePlanner, runPromptCampaign } from "./prompt-runner.js";
import { renderScorecardHtml } from "./report/html.js";
import { buildScorecard, hashBody, targetScore, type AnchorRecord, type Scorecard, type ScorecardSettings, type TargetScore } from "./report/scorecard.js";
import { auditsOf, TESTNET_RPC } from "./anchor/audit-lookup.js";
import { DEFAULT_GENERATOR, parseGenerator, type GeneratorVersion } from "./generators/contract.js";
import { runCampaign } from "./runner.js";
import { sha256Hex } from "./near/keys.js";
import { loadTarget, REPO_ROOT } from "./targets/registry.js";
import { canonicalJSON, prettyJSON } from "./util/json.js";

export type AnchorMode = "none" | "nearsim" | "testnet" | "local" | "auto";

export interface ReportOptions {
  targets: string[];
  seed: number;
  runs: number;
  maxSteps: number;
  generator?: GeneratorVersion;
  planner: string;
  anchor: AnchorMode;
  outDir: string;
  web: boolean;
  log?: (s: string) => void;
}

/** The generator a scorecard was produced with (absent = v1, from before versioning). */
export function settingsGenerator(s: ScorecardSettings): GeneratorVersion {
  return parseGenerator(s.generator ?? 1);
}

/** Build scorecard settings; v1 leaves `generator` out so its bodies (and hashes) match pre-versioning ones. */
export function makeSettings(s: Omit<ScorecardSettings, "generator"> & { generator: GeneratorVersion }): ScorecardSettings {
  const { generator, ...rest } = s;
  return generator === 1 ? rest : { ...rest, generator };
}

export function corpusSha256(): string {
  const scenarios = loadCorpus().map(({ file: _file, ...s }) => s);
  return sha256Hex(canonicalJSON(scenarios));
}

export async function computeTargets(settings: ScorecardSettings, log: (s: string) => void = () => {}): Promise<TargetScore[]> {
  const out: TargetScore[] = [];
  const scenarios = loadCorpus();
  for (const name of settings.targets) {
    const target = loadTarget(name);
    log(`fuzzing ${name} (${settings.runs} runs/invariant)…`);
    const campaign = await runCampaign({ target, seed: settings.seed, runs: settings.runs, maxSteps: settings.maxSteps, generator: settingsGenerator(settings) });
    log(`prompt layer on ${name} (${scenarios.length} attacks, planner ${settings.planner})…`);
    const prompt = await runPromptCampaign({ target, planner: makePlanner(settings.planner), scenarios });
    out.push(targetScore(campaign, prompt));
  }
  return out;
}

export async function generateReport(opts: ReportOptions): Promise<{ scorecard: Scorecard; files: string[] }> {
  const log = opts.log ?? (() => {});
  const started = Date.now();
  const settings = makeSettings({
    seed: opts.seed,
    runs: opts.runs,
    maxSteps: opts.maxSteps,
    backend: "nearsim",
    planner: opts.planner,
    targets: opts.targets,
    corpusSha256: corpusSha256(),
    generator: opts.generator ?? DEFAULT_GENERATOR,
  });
  const targets = await computeTargets(settings, log);
  const sc = buildScorecard(settings, targets, Date.now() - started);
  sc.anchors.push(...(await anchor(sc, opts.anchor, opts.outDir, log)));
  return { scorecard: sc, files: writeScorecard(sc, opts.outDir, opts.web) };
}

async function anchor(sc: Scorecard, mode: AnchorMode, outDir: string, log: (s: string) => void): Promise<AnchorRecord[]> {
  if (mode === "none") return [];
  const out: AnchorRecord[] = [];
  const testnet = testnetConfigFromEnv();
  if (mode === "testnet" || (mode === "auto" && testnet)) {
    if (!testnet) throw new Error("--anchor testnet needs NEAR_ACCOUNT_ID and NEAR_PRIVATE_KEY (see .env.example)");
    log(`anchoring ${sc.sha256.slice(0, 16)}… on testnet (${testnet.contractId})`);
    out.push(await anchorTestnet(sc, testnet));
  }
  if (mode === "nearsim" || mode === "auto") {
    log("anchoring in nearsim (scoreboard.wasm, offline)…");
    out.push(await anchorNearsim(sc));
  }
  if (mode === "local" || (mode === "auto" && !testnet)) out.push(anchorLocal(sc, outDir));
  return out;
}

export function writeScorecard(sc: Scorecard, outDir: string, web: boolean): string[] {
  mkdirSync(outDir, { recursive: true });
  const files: string[] = [];
  const json = prettyJSON(sc);
  const html = renderScorecardHtml(sc);
  const write = (p: string, s: string) => {
    writeFileSync(p, s);
    files.push(p);
  };
  write(join(outDir, "scorecard.json"), json);
  write(join(outDir, "scorecard.html"), html);
  write(join(outDir, `scorecard-${sc.runId}.json`), json);
  if (web) {
    const webDir = join(REPO_ROOT, "web");
    mkdirSync(webDir, { recursive: true });
    write(join(webDir, "index.html"), html);
    write(join(webDir, "scorecard.json"), json);
  }
  return files;
}

export function loadScorecard(file: string): Scorecard {
  const sc = JSON.parse(readFileSync(file, "utf8")) as Scorecard;
  if (sc.body?.format !== "agentfuzz-scorecard/1") throw new Error(`${file} is not an agentfuzz scorecard`);
  return sc;
}

export interface VerifyResult {
  storedSha256: string;
  bodySha256: string;
  recomputedSha256?: string;
  bodyIntact: boolean;
  reproduced?: boolean;
  corpusMatches: boolean;
  wasmMismatches: string[];
  onchain: { network: string; contractId?: string; sha256?: string; matches: boolean; error?: string }[];
  /** Per guard build: is there an on-chain audit from this run that matches the scorecard? */
  audits: { network: string; target: string; codeHash: string; matches: boolean; error?: string }[];
}

/** Check a scorecard: body hash, deterministic re-run, and on-chain anchors. */
export async function verifyScorecard(file: string, opts: { rerun: boolean; log?: (s: string) => void }): Promise<VerifyResult> {
  const sc = loadScorecard(file);
  const bodySha256 = hashBody(sc.body);
  const res: VerifyResult = {
    storedSha256: sc.sha256,
    bodySha256,
    bodyIntact: bodySha256 === sc.sha256,
    corpusMatches: corpusSha256() === sc.body.settings.corpusSha256,
    wasmMismatches: sc.body.targets.filter((t) => loadTarget(t.name).wasmSha256 !== t.wasmSha256).map((t) => t.name),
    onchain: [],
    audits: [],
  };
  if (opts.rerun) {
    if (sc.body.settings.planner === "llm") throw new Error("scorecards produced with the live LLM planner are not deterministic; re-run with --no-rerun");
    const targets = await computeTargets(sc.body.settings, opts.log);
    const body = { ...sc.body, targets };
    res.recomputedSha256 = hashBody(body);
    res.reproduced = res.recomputedSha256 === sc.sha256;
  }
  for (const a of sc.anchors.filter((x) => x.network === "testnet")) {
    try {
      const rec = await readTestnetRecord(a.contractId!, a.runId, process.env.NEAR_RPC_URL);
      res.onchain.push({ network: a.network, contractId: a.contractId, sha256: rec?.sha256, matches: rec?.sha256 === sc.sha256 });
    } catch (e) {
      res.onchain.push({ network: a.network, contractId: a.contractId, matches: false, error: e instanceof Error ? e.message : String(e) });
    }
    // Anchors made before guard audits existed carry no `audits`; nothing to check for them.
    if (!a.audits?.length) continue;
    for (const t of sc.body.targets) {
      try {
        const list = await auditsOf(t.wasmSha256, a.contractId, process.env.NEAR_RPC_URL ?? TESTNET_RPC);
        const mine = list.find((x) => x.run_id === sc.runId);
        const matches =
          !!mine && mine.report_sha256 === sc.sha256 && mine.held === t.summary.held && mine.broken === t.summary.broken && mine.total === t.summary.total && mine.prompt_breaches === t.summary.promptBreaches;
        res.audits.push({ network: a.network, target: t.name, codeHash: t.wasmSha256, matches, error: mine ? undefined : "no audit from this run" });
      } catch (e) {
        res.audits.push({ network: a.network, target: t.name, codeHash: t.wasmSha256, matches: false, error: e instanceof Error ? e.message : String(e) });
      }
    }
  }
  return res;
}
