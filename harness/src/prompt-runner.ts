/**
 * Prompt-layer runner (Node): loads the corpus from corpus/prompt, builds planners (including the
 * live NEAR AI one) and writes recorded cassettes back. The campaign itself is prompt-campaign.ts.
 */
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { openaiChatClient } from "./agent/openai-client.js";
import { CassettePlanner, CompromisedPlanner, LLMPlanner, llmConfigFromEnv } from "./agent/planners.js";
import type { Cassette, CorpusFile, Planner, Scenario } from "./agent/types.js";
import { runPromptCampaign as runPromptCampaignCore, type PromptCampaign, type PromptOptions as CoreOptions } from "./prompt-campaign.js";
import { REPO_ROOT } from "./targets/registry.js";

export * from "./prompt-campaign.js";

export const CORPUS_DIR = join(REPO_ROOT, "corpus", "prompt");

export interface LoadedScenario extends Scenario {
  file: string;
}

export function loadCorpus(dir = CORPUS_DIR): LoadedScenario[] {
  const files = readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
  const out: LoadedScenario[] = [];
  const seen = new Set<string>();
  for (const f of files) {
    const file = join(dir, f);
    const data = JSON.parse(readFileSync(file, "utf8")) as CorpusFile;
    if (data.format !== "agentfuzz-corpus/1") throw new Error(`${file}: not an agentfuzz corpus file`);
    for (const s of data.scenarios) {
      if (seen.has(s.id)) throw new Error(`duplicate scenario id ${s.id} in ${file}`);
      seen.add(s.id);
      out.push({ ...s, file });
    }
  }
  return out;
}

export function makePlanner(kind: string): Planner {
  if (kind === "compromised") return new CompromisedPlanner();
  if (kind === "cassette") return new CassettePlanner(process.env.AGENTFUZZ_MODEL);
  if (kind === "llm") {
    const cfg = llmConfigFromEnv();
    if (!cfg) throw new Error("planner 'llm' needs NEAR_AI_API_KEY (or AGENTFUZZ_LLM_API_KEY / OPENAI_API_KEY); use --planner compromised for offline mode");
    return new LLMPlanner(cfg, openaiChatClient(cfg));
  }
  throw new Error(`unknown planner '${kind}' (compromised | cassette | llm)`);
}

export interface PromptOptions extends CoreOptions {
  /** Record live planner decisions back into the corpus files as cassettes. */
  record?: boolean;
}

export async function runPromptCampaign(opts: PromptOptions): Promise<PromptCampaign> {
  const { record, ...core } = opts;
  const recordings = new Map<string, { id: string; tape: Cassette }[]>();
  const result = await runPromptCampaignCore({
    ...core,
    onRecording: record
      ? (s, tape) => {
          if (!s.file) return;
          recordings.set(s.file, [...(recordings.get(s.file) ?? []), { id: s.id, tape }]);
        }
      : core.onRecording,
  });
  for (const [file, list] of recordings) {
    const data = JSON.parse(readFileSync(file, "utf8")) as CorpusFile;
    for (const rec of list) {
      const s = data.scenarios.find((x) => x.id === rec.id);
      if (!s) continue;
      s.cassettes = [...(s.cassettes ?? []).filter((t) => t.model !== rec.tape.model), rec.tape];
    }
    writeFileSync(file, JSON.stringify(data, null, 2) + "\n");
  }
  return result;
}
