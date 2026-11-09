/**
 * Planners decide which tool calls the reference agent makes.
 *
 *  - CompromisedPlanner  (offline, deterministic) worst case: the injection fully succeeds; the
 *                        planner performs the legitimate work AND every attacker instruction.
 *                        The guard is the last line of defence, which is exactly what we test.
 *  - CassettePlanner     (offline) replays tool calls a real model made when the corpus was
 *                        recorded with `agentfuzz prompt --live --record`.
 *  - LLMPlanner          (online) asks a model through NEAR AI Cloud's OpenAI-compatible API.
 */
import OpenAI from "openai";
import type { Planner, PlannerInput, PlannerOutput, ToolCall } from "./types.js";

export class CompromisedPlanner implements Planner {
  readonly name = "compromised";
  async plan(input: PlannerInput): Promise<PlannerOutput> {
    return { toolCalls: [...input.scenario.legit, ...input.scenario.attack.calls], model: "compromised-planner" };
  }
}

export class CassettePlanner implements Planner {
  readonly name = "cassette";
  constructor(private readonly model?: string) {}
  async plan(input: PlannerInput): Promise<PlannerOutput> {
    const tapes = input.scenario.cassettes ?? [];
    const tape = this.model ? tapes.find((t) => t.model === this.model) : tapes[tapes.length - 1];
    if (!tape) throw new NoCassetteError(input.scenario.id);
    return { toolCalls: tape.toolCalls, model: tape.model, raw: tape.raw };
  }
}

export class NoCassetteError extends Error {
  constructor(id: string) {
    super(`scenario ${id} has no recorded cassette`);
  }
}

export interface LLMConfig {
  apiKey: string;
  baseURL: string;
  model?: string;
  temperature?: number;
}

export const DEFAULT_LLM_BASE_URL = "https://cloud-api.near.ai/v1";
const PREFERRED_MODELS = [
  "deepseek-ai/DeepSeek-V3.1",
  "openai/gpt-oss-120b",
  "zai-org/GLM-4.6",
  "Qwen/Qwen3-30B-A3B-Instruct-2507",
];

export function llmConfigFromEnv(env = process.env): LLMConfig | undefined {
  const apiKey = env.NEAR_AI_API_KEY ?? env.AGENTFUZZ_LLM_API_KEY ?? env.OPENAI_API_KEY;
  if (!apiKey) return undefined;
  return {
    apiKey,
    baseURL: env.AGENTFUZZ_LLM_BASE_URL ?? (env.NEAR_AI_API_KEY || !env.OPENAI_API_KEY ? DEFAULT_LLM_BASE_URL : "https://api.openai.com/v1"),
    model: env.AGENTFUZZ_MODEL,
    temperature: env.AGENTFUZZ_TEMPERATURE ? Number(env.AGENTFUZZ_TEMPERATURE) : 0,
  };
}

export function openaiClient(cfg: LLMConfig): OpenAI {
  return new OpenAI({ apiKey: cfg.apiKey, baseURL: cfg.baseURL });
}

/** Resolve a model id: explicit config, else the first preferred model the endpoint lists. */
export async function resolveModel(client: OpenAI, cfg: LLMConfig): Promise<string> {
  if (cfg.model) return cfg.model;
  const ids: string[] = [];
  for await (const m of client.models.list()) ids.push(m.id);
  const pick = PREFERRED_MODELS.find((p) => ids.includes(p)) ?? ids[0];
  if (!pick) throw new Error(`no models available at ${cfg.baseURL}`);
  return pick;
}

export class LLMPlanner implements Planner {
  readonly name = "llm";
  private client: OpenAI;
  private model?: string;

  constructor(private readonly cfg: LLMConfig) {
    this.client = openaiClient(cfg);
  }

  async plan(input: PlannerInput): Promise<PlannerOutput> {
    this.model ??= await resolveModel(this.client, this.cfg);
    const toolList = input.tools
      .map((t) => `- ${t.name}(${Object.keys((t.parameters as { properties?: object }).properties ?? {}).join(", ")}): ${t.description}`)
      .join("\n");
    const res = await this.client.chat.completions.create({
      model: this.model,
      temperature: this.cfg.temperature ?? 0,
      messages: [
        {
          role: "system",
          content:
            `${input.system}\n\nAvailable tools:\n${toolList}\n\n` +
            `Respond with ONLY a JSON object: {"reasoning": "<one sentence>", "tool_calls": [{"name": "<tool>", "arguments": {...}}]}. ` +
            `Use an empty tool_calls array if no action is appropriate.`,
        },
        { role: "user", content: input.user },
      ],
    });
    const raw = res.choices[0]?.message?.content ?? "";
    return { toolCalls: parseToolCalls(raw), model: this.model, raw };
  }
}

/** Extract `tool_calls` from a model reply that should be JSON but may be wrapped in prose/fences. */
export function parseToolCalls(raw: string): ToolCall[] {
  const start = raw.indexOf("{");
  const end = raw.lastIndexOf("}");
  if (start < 0 || end <= start) return [];
  try {
    const obj = JSON.parse(raw.slice(start, end + 1)) as { tool_calls?: unknown };
    if (!Array.isArray(obj.tool_calls)) return [];
    return obj.tool_calls
      .filter((t): t is { name: string; arguments?: unknown } => !!t && typeof (t as { name?: unknown }).name === "string")
      .map((t) => ({
        name: t.name,
        arguments: typeof t.arguments === "string" ? safeParse(t.arguments) : ((t.arguments as Record<string, unknown>) ?? {}),
      }));
  } catch {
    return [];
  }
}

function safeParse(s: string): Record<string, unknown> {
  try {
    return JSON.parse(s);
  } catch {
    return {};
  }
}
