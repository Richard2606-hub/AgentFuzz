/**
 * Runner (Node): the campaign core from campaign.ts plus saving and loading repro files.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { runCampaign as runCampaignCore, replayOn, simBackendFactory, type BackendFactory, type CampaignOptions as CoreOptions, type CampaignResult, type ReplayResult, type Repro } from "./campaign.js";
import { sha256Hex } from "./near/keys.js";
import { loadTarget, type LoadedTarget } from "./targets/registry.js";
import { prettyJSON, toJSONSafe } from "./util/json.js";

export * from "./campaign.js";

export interface CampaignOptions extends CoreOptions {
  /** Save each minimised repro as a JSON file in this directory. */
  outDir?: string;
}

export function runCampaign(opts: CampaignOptions): Promise<CampaignResult> {
  const { outDir, ...core } = opts;
  return runCampaignCore({ ...core, saveRepro: outDir ? (r) => saveRepro(outDir, r) : core.saveRepro });
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

/** Re-execute a repro's steps in a fresh world and confirm the invariant still breaks. */
export async function replay(repro: Repro, backendFactory: BackendFactory = simBackendFactory, targetOverride?: LoadedTarget): Promise<ReplayResult> {
  return replayOn(targetOverride ?? loadTarget(repro.target), repro, backendFactory);
}

export { toJSONSafe };
