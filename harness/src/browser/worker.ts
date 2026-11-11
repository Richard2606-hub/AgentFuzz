/**
 * Playground Web Worker: fetches the committed guard builds and prompt corpus from the site,
 * then runs the real engine (engine.ts) off the main thread and streams results to the page.
 */
import { CompromisedPlanner, DEFAULT_LLM_BASE_URL, LLMPlanner } from "../agent/planners.js";
import type { Scenario } from "../agent/types.js";
import { BUILTIN_TARGETS, targetFromBytes, type LoadedTarget } from "../targets/specs.js";
import { CRYPTO_IMPL, customScenario, fuzz, prompt } from "./engine.js";
import { fetchChatClient } from "./llm-fetch.js";
import type { FromWorker, FuzzTargetRef, ToWorker } from "./protocol.js";

const post = (m: FromWorker) => (self as unknown as Worker).postMessage(m);

let base = "./";
let available = new Set<string>();
let corpus: Scenario[] = [];
const wasmCache = new Map<string, Uint8Array>();

async function fetchOk(url: string): Promise<Response> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res;
}

async function builtin(name: string): Promise<LoadedTarget> {
  const spec = BUILTIN_TARGETS.find((t) => t.name === name);
  if (!spec || !available.has(spec.artifact)) throw new Error(`unknown target ${name}`);
  let wasm = wasmCache.get(spec.artifact);
  if (!wasm) {
    wasm = new Uint8Array(await (await fetchOk(`${base}wasm/${spec.artifact}`)).arrayBuffer());
    wasmCache.set(spec.artifact, wasm);
  }
  const { artifact: _artifact, ...rest } = spec;
  return targetFromBytes(rest, wasm);
}

async function resolveTarget(ref: FuzzTargetRef): Promise<LoadedTarget> {
  if ("builtin" in ref) return builtin(ref.builtin);
  // Uploaded guards are driven through the agentfuzz-guard-v1 adapter (targetFromBytes default).
  const wasm = new Uint8Array(ref.upload);
  if (wasm.length < 8 || wasm[0] !== 0x00 || wasm[1] !== 0x61 || wasm[2] !== 0x73 || wasm[3] !== 0x6d) throw new Error(`${ref.fileName} is not a wasm module`);
  return targetFromBytes({ name: ref.fileName, description: `uploaded ${ref.fileName}`, source: "upload" }, wasm);
}

async function handle(m: ToWorker) {
  switch (m.type) {
    case "init": {
      base = m.base;
      const manifest = (await (await fetchOk(`${base}wasm/manifest.json`)).json()) as { artifacts: Record<string, unknown> };
      available = new Set(Object.keys(manifest.artifacts));
      corpus = (await (await fetchOk(`${base}corpus.json`)).json()) as Scenario[];
      post({
        type: "ready",
        cryptoImpl: CRYPTO_IMPL,
        targets: BUILTIN_TARGETS.filter((t) => available.has(t.artifact)).map((t) => ({ name: t.name, description: t.description, artifact: t.artifact, expectBroken: t.expectBroken ?? [] })),
        scenarios: corpus.map((s) => ({ id: s.id, class: s.class, channel: s.channel, title: s.title, task: s.task, documents: s.documents.map((d) => ({ kind: d.kind, content: d.content })), aims: s.attack.breaks })),
      });
      return;
    }
    case "fuzz":
      await fuzz(await resolveTarget(m.target), { seed: m.seed, runs: m.runs, maxSteps: m.maxSteps, generator: m.generator }, post, m.job);
      return;
    case "prompt": {
      const wanted = new Set(m.scenarioIds);
      await prompt(await builtin(m.target), corpus.filter((s) => wanted.has(s.id)), new CompromisedPlanner(), post, m.job);
      return;
    }
    case "prompt-custom": {
      const cfg = { apiKey: m.apiKey, baseURL: DEFAULT_LLM_BASE_URL, model: m.model || undefined, temperature: 0 };
      const planner = new LLMPlanner(cfg, fetchChatClient(cfg.baseURL, cfg.apiKey));
      await prompt(await builtin(m.target), [customScenario(m.task, m.document)], planner, post, m.job);
      return;
    }
  }
}

// One job at a time, in order: a campaign is CPU-bound and the page cancels by recreating the worker.
let queue = Promise.resolve();
self.onmessage = (ev: MessageEvent<ToWorker>) => {
  const m = ev.data;
  queue = queue.then(() =>
    handle(m).catch((e: unknown) => post({ type: "error", job: "job" in m ? m.job : undefined, message: e instanceof Error ? e.message : String(e) })),
  );
};
