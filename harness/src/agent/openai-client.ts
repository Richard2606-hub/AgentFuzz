/**
 * ChatClient backed by the OpenAI SDK (Node only). The SDK is imported on first use, so commands
 * that never call a model don't load it, and browser bundles never include it.
 */
import type { ChatClient, LLMConfig } from "./planners.js";

export function openaiChatClient(cfg: LLMConfig): ChatClient {
  let client: Promise<import("openai").default> | undefined;
  const get = () => (client ??= import("openai").then(({ default: OpenAI }) => new OpenAI({ apiKey: cfg.apiKey, baseURL: cfg.baseURL })));
  return {
    async listModels() {
      const ids: string[] = [];
      for await (const m of (await get()).models.list()) ids.push(m.id);
      return ids;
    },
    async complete(req) {
      const res = await (await get()).chat.completions.create(req);
      return res.choices[0]?.message?.content ?? "";
    },
  };
}
