/** Prompt-layer types: corpus scenarios, tool calls and planners. */
import type { InvariantId } from "../invariants/types.js";

export interface ToolCall {
  name: string;
  arguments: Record<string, unknown>;
}

export interface ScenarioDocument {
  id: string;
  /** invoice | email | webpage | tool_output | chat ... */
  kind: string;
  /** For tool outputs: which tool produced it (e.g. get_exchange_rate). */
  tool?: string;
  content: string;
}

export interface Cassette {
  model: string;
  recordedAt: string;
  toolCalls: ToolCall[];
  raw?: string;
}

/** One prompt-layer attack (A1 prompt injection, A2 tool-output poisoning). */
export interface Scenario {
  id: string;
  class: "A1" | "A2";
  channel: string;
  title: string;
  /** The operator's legitimate instruction to the agent. */
  task: string;
  documents: ScenarioDocument[];
  /** Payments an honest agent should make. */
  legit: ToolCall[];
  /** What a hijacked planner does, and which invariants it aims at. */
  attack: { breaks: InvariantId[]; calls: ToolCall[] };
  generator: { source: "seed" | "near-ai-cloud" | string; model?: string; prompt?: string; createdAt?: string };
  cassettes?: Cassette[];
}

export interface CorpusFile {
  format: "agentfuzz-corpus/1";
  description: string;
  scenarios: Scenario[];
}

export interface AgentToolSpec {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
}

export interface PlannerInput {
  system: string;
  user: string;
  tools: AgentToolSpec[];
  scenario: Scenario;
}

export interface PlannerOutput {
  toolCalls: ToolCall[];
  model: string;
  raw?: string;
}

export interface Planner {
  readonly name: string;
  plan(input: PlannerInput): Promise<PlannerOutput>;
}
