/**
 * ChatClient over plain fetch, for the playground's optional live model. NEAR AI Cloud allows
 * cross-origin requests with an Authorization header (checked 2026-11-11), so the visitor's key
 * goes from their browser straight to the API: it is held in memory only, never stored or sent
 * anywhere else.
 */
import type { ChatClient } from "../agent/planners.js";

export function fetchChatClient(baseURL: string, apiKey: string): ChatClient {
  const call = async (path: string, init?: RequestInit) => {
    const res = await fetch(`${baseURL.replace(/\/$/, "")}${path}`, {
      ...init,
      headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
    });
    if (!res.ok) throw new Error(`NEAR AI ${path}: HTTP ${res.status} ${(await res.text()).slice(0, 200)}`);
    return res.json();
  };
  return {
    async listModels() {
      const r = (await call("/models")) as { data?: { id: string }[] };
      return (r.data ?? []).map((m) => m.id);
    },
    async complete(req) {
      const r = (await call("/chat/completions", { method: "POST", body: JSON.stringify(req) })) as { choices?: { message?: { content?: string } }[] };
      return r.choices?.[0]?.message?.content ?? "";
    },
  };
}
