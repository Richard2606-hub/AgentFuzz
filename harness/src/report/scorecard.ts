/**
 * Scorecard: the machine-readable result of an AgentFuzz run.
 *
 * The `body` is fully deterministic for a given (seed, runs, target wasm, corpus): no wall-clock
 * times, no durations. Its canonical-JSON SHA-256 is what gets anchored on-chain, and
 * `agentfuzz verify` re-runs everything from `body.settings` to prove the hash.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { PromptCampaign } from "../prompt-runner.js";
import type { CampaignResult } from "../runner.js";
import { INVARIANTS, type InvariantId, type InvariantStatus } from "../invariants/types.js";
import { sha256Hex } from "../near/keys.js";
import { REPO_ROOT } from "../targets/registry.js";
import { canonicalJSON } from "../util/json.js";
import { describeStep } from "../attacks/steps.js";

export const TOOL_VERSION: string = JSON.parse(readFileSync(join(REPO_ROOT, "harness", "package.json"), "utf8")).version;

export interface ScorecardSettings {
  seed: number;
  runs: number;
  maxSteps: number;
  backend: string;
  planner: string;
  targets: string[];
  corpusSha256: string;
  /** Sequence generator version; absent means 1 (scorecards made before versioning). */
  generator?: number;
}

export interface TargetScore {
  name: string;
  source: string;
  wasmSha256: string;
  invariants: {
    id: InvariantId;
    title: string;
    status: InvariantStatus;
    runsChecked: number;
    runsExercised: number;
    violation?: string;
    repro?: { steps: string[]; attackClasses: string[]; numShrinks: number; symbolic: unknown[] };
  }[];
  attacks: { sequences: number; steps: number; byClass: Record<string, number> };
  prompt?: {
    planner: string;
    model: string;
    scenarios: number;
    hijacked: number;
    blocked: number;
    breaches: number;
    resisted: number;
    results: { id: string; class: string; title: string; outcome: string; violations: string[] }[];
  };
  summary: { held: number; broken: number; notExercised: number; total: number; promptBreaches: number };
}

export interface ScorecardBody {
  format: "agentfuzz-scorecard/1";
  tool: { name: "agentfuzz"; version: string };
  settings: ScorecardSettings;
  invariantDefinitions: Record<InvariantId, string>;
  targets: TargetScore[];
}

export interface AnchorRecord {
  network: "testnet" | "mainnet" | "nearsim" | "local";
  contractId?: string;
  runId: string;
  sha256: string;
  txHash?: string;
  explorerUrl?: string;
  blockHeight?: string;
  recordedAt: string;
  note?: string;
}

export interface Scorecard {
  body: ScorecardBody;
  sha256: string;
  runId: string;
  meta: { generatedAt: string; commit: string; durationMs: number; nodeVersion: string };
  anchors: AnchorRecord[];
}

export function hashBody(body: ScorecardBody): string {
  return sha256Hex(canonicalJSON(body));
}

export function gitCommit(): string {
  try {
    return execFileSync("git", ["rev-parse", "--short=12", "HEAD"], { cwd: REPO_ROOT, stdio: ["ignore", "pipe", "ignore"] })
      .toString()
      .trim();
  } catch {
    return "unknown";
  }
}

export function targetScore(c: CampaignResult, p?: PromptCampaign): TargetScore {
  const invariants = c.invariants.map((o) => ({
    id: o.id,
    title: INVARIANTS[o.id].title,
    status: o.status,
    runsChecked: o.runsChecked,
    runsExercised: o.runsExercised,
    violation: o.violation?.message,
    repro: o.repro
      ? {
          steps: o.repro.trace.map((s) => s.description),
          attackClasses: o.repro.attackClasses,
          numShrinks: o.repro.numShrinks,
          symbolic: o.repro.steps,
        }
      : undefined,
  }));
  const prompt = p
    ? {
        planner: p.planner,
        model: p.model,
        scenarios: p.scenarios,
        hijacked: p.attempted,
        blocked: p.blocked,
        breaches: p.breaches,
        resisted: p.resisted,
        results: p.results.map((r) => ({ id: r.id, class: r.class, title: r.title, outcome: r.outcome, violations: r.violations.map((v) => `${v.invariant}: ${v.message}`) })),
      }
    : undefined;
  return {
    name: c.target,
    source: c.source,
    wasmSha256: c.wasmSha256,
    invariants,
    attacks: { sequences: c.distinctSequences, steps: c.stepsExecuted, byClass: sortRecord(c.attackCounts) },
    prompt,
    summary: {
      held: invariants.filter((i) => i.status === "held").length,
      broken: invariants.filter((i) => i.status === "broken").length,
      notExercised: invariants.filter((i) => i.status === "not-exercised").length,
      total: invariants.length,
      promptBreaches: prompt?.breaches ?? 0,
    },
  };
}

export function buildScorecard(settings: ScorecardSettings, targets: TargetScore[], durationMs: number): Scorecard {
  const body: ScorecardBody = {
    format: "agentfuzz-scorecard/1",
    tool: { name: "agentfuzz", version: TOOL_VERSION },
    settings,
    invariantDefinitions: Object.fromEntries(Object.entries(INVARIANTS).map(([k, v]) => [k, v.title])) as Record<InvariantId, string>,
    targets,
  };
  const sha256 = hashBody(body);
  return {
    body,
    sha256,
    runId: `af-${settings.seed}-${sha256.slice(0, 12)}`,
    meta: { generatedAt: new Date().toISOString(), commit: gitCommit(), durationMs, nodeVersion: process.version },
    anchors: [],
  };
}

function sortRecord(r: Record<string, number>): Record<string, number> {
  return Object.fromEntries(Object.entries(r).sort(([a], [b]) => a.localeCompare(b)));
}

export { describeStep };
