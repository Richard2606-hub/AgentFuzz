/**
 * The browser playground must give exactly what the CLI gives. These tests bundle the engine the
 * way web/playground-worker.js is built (noble crypto instead of node:crypto, no Node modules),
 * run that bundle in Node, and compare it with runCampaign / runPromptCampaign from src.
 */
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { createRequire } from "node:module";
import { beforeAll, describe, expect, it } from "vitest";
import { CompromisedPlanner } from "../src/agent/planners.js";
import { reproFile } from "../src/browser/engine.js";
import * as nodeCrypto from "../src/platform/crypto.node.js";
import * as browserCrypto from "../src/platform/crypto.browser.js";
import { loadCorpus, runPromptCampaign } from "../src/prompt-runner.js";
import { runCampaign, type CampaignResult } from "../src/runner.js";
import { loadTarget, REPO_ROOT } from "../src/targets/registry.js";
import { toBase64, toHex, utf16leDecode } from "../src/util/bytes.js";

type BuildWeb = {
  browserBundleOptions: (entry: string, extra?: object) => object;
  assertBrowserSafe: (result: unknown, label: string) => void;
};
// The bundle's API, as used here.
type Bundle = {
  CRYPTO_IMPL: string;
  BUILTIN_TARGETS: { name: string; artifact: string }[];
  targetFromBytes: (spec: object, wasm: Uint8Array) => unknown;
  fuzz: (target: unknown, opts: object, emit: (m: unknown) => void) => Promise<{ summary: Summary; result: CampaignResult }>;
  prompt: (target: unknown, scenarios: unknown[], planner: unknown, emit: (m: unknown) => void) => Promise<{ blocked: number; breaches: number; results: { id: string; outcome: string }[] }>;
  CompromisedPlanner: new () => unknown;
};
type Summary = { invariants: { id: string; status: string; runsExercised: number; runsChecked: number; repro?: { json: string; fileName: string } }[]; sequences: number; steps: number };

const esbuild = createRequire(join(REPO_ROOT, "harness", "package.json"))("esbuild") as { build: (o: object) => Promise<{ outputFiles: { text: string }[] }> };
let web: BuildWeb;
let bundle: Bundle;

beforeAll(async () => {
  web = (await import(pathToFileURL(join(REPO_ROOT, "scripts", "build-web.mjs")).href)) as BuildWeb;
  const browserDir = join(REPO_ROOT, "harness", "src", "browser");
  const r = await esbuild.build({
    ...web.browserBundleOptions("unused", { format: "esm", write: false }),
    entryPoints: undefined,
    stdin: {
      contents: [
        'export * from "./engine.ts";',
        'export { BUILTIN_TARGETS, targetFromBytes } from "../targets/specs.ts";',
        'export { CompromisedPlanner } from "../agent/planners.ts";',
      ].join("\n"),
      resolveDir: browserDir,
      loader: "ts",
    },
  });
  web.assertBrowserSafe(r, "engine bundle");
  const file = join(mkdtempSync(join(tmpdir(), "agentfuzz-bundle-")), "engine.mjs");
  writeFileSync(file, r.outputFiles[0].text);
  bundle = (await import(pathToFileURL(file).href)) as Bundle;
}, 60_000);

const wasm = (artifact: string) => new Uint8Array(readFileSync(join(REPO_ROOT, "artifacts", artifact)));
function builtin(name: string) {
  const spec = bundle.BUILTIN_TARGETS.find((t) => t.name === name)!;
  const { artifact, ...rest } = spec;
  return bundle.targetFromBytes(rest, wasm(artifact));
}

describe("browser platform code matches Node", () => {
  it("sha256 and ed25519 give identical bytes", () => {
    for (const len of [0, 1, 31, 32, 55, 56, 64, 1000, 200_000]) {
      const data = randomBytes(len);
      expect(toHex(browserCrypto.sha256(data))).toBe(toHex(nodeCrypto.sha256(data)));
    }
    expect(toHex(browserCrypto.sha256("agentfuzz-key:x"))).toBe(toHex(nodeCrypto.sha256("agentfuzz-key:x")));
    for (let i = 0; i < 20; i++) {
      const seed = randomBytes(32);
      const msg = randomBytes(i * 17);
      const a = nodeCrypto.ed25519FromSeed(seed);
      const b = browserCrypto.ed25519FromSeed(seed);
      expect(toHex(b.publicKey)).toBe(toHex(a.publicKey));
      const sig = b.sign(msg);
      expect(toHex(sig)).toBe(toHex(a.sign(msg)));
      expect(nodeCrypto.ed25519Verify(sig, msg, a.publicKey)).toBe(true);
      expect(browserCrypto.ed25519Verify(sig, msg, b.publicKey)).toBe(true);
      expect(browserCrypto.ed25519Verify(sig, Uint8Array.from([...msg, 1]), b.publicKey)).toBe(false);
    }
  });

  it("byte helpers match Buffer", () => {
    for (const len of [0, 1, 2, 3, 4, 5, 63, 64, 65, 257]) {
      const b = randomBytes(len);
      expect(toHex(b)).toBe(b.toString("hex"));
      expect(toBase64(b)).toBe(b.toString("base64"));
      expect(utf16leDecode(b)).toBe(b.toString("utf16le"));
    }
  });
});

describe("browser bundle", () => {
  it("uses the browser crypto and no Node-only modules", () => {
    expect(bundle.CRYPTO_IMPL).toBe("browser");
  });

  // Same seed, runs and generator as the CLI; verdicts, counts and repro files must be identical.
  for (const [name, generator] of [
    ["naive", 2],
    ["reference", 2],
    ["naive:bug-window-lag", 2],
    ["naive", 1],
  ] as const) {
    it(`fuzz ${name} (generator v${generator}) matches the CLI exactly`, async () => {
      const opts = { seed: 42, runs: 60, maxSteps: 20, generator };
      const events: { type: string }[] = [];
      const { summary } = await bundle.fuzz(builtin(name), opts, (m) => events.push(m as { type: string }));
      const cli = await runCampaign({ target: loadTarget(name), ...opts });
      expect(summary.sequences).toBe(cli.distinctSequences);
      expect(summary.steps).toBe(cli.stepsExecuted);
      for (const o of cli.invariants) {
        const b = summary.invariants.find((i) => i.id === o.id)!;
        expect([b.id, b.status, b.runsExercised, b.runsChecked]).toEqual([o.id, o.status, o.runsExercised, o.runsChecked]);
        if (o.repro) {
          const want = reproFile(o.repro);
          expect(b.repro?.fileName).toBe(want.fileName);
          expect(b.repro?.json).toBe(want.json);
        }
      }
      expect(events[0].type).toBe("fuzz-start");
      expect(events.at(-1)!.type).toBe("fuzz-done");
    }, 120_000);
  }

  it("an uploaded wasm is fuzzed like `agentfuzz fuzz --target file.wasm`", async () => {
    const file = join(REPO_ROOT, "artifacts", "guard_naive__bug-window-lag.wasm");
    const opts = { seed: 42, runs: 60, maxSteps: 20, generator: 2 as const };
    const upload = bundle.targetFromBytes({ name: "guard_naive__bug-window-lag.wasm", description: "upload", source: "upload" }, wasm("guard_naive__bug-window-lag.wasm"));
    const { summary } = await bundle.fuzz(upload, opts, () => {});
    const cli = await runCampaign({ target: loadTarget(file), ...opts });
    expect(summary.invariants.map((i) => [i.id, i.status])).toEqual(cli.invariants.map((o) => [o.id, o.status]));
    expect(summary.invariants.find((i) => i.id === "INV-1")!.status).toBe("broken");
    const steps = (s: string) => JSON.parse(s).steps;
    for (const o of cli.invariants.filter((x) => x.repro)) expect(steps(summary.invariants.find((i) => i.id === o.id)!.repro!.json)).toEqual(o.repro!.steps);
  }, 120_000);

  it("prompt corpus gives the CLI's outcomes on reference and naive", async () => {
    const scenarios = loadCorpus();
    for (const name of ["reference", "naive"]) {
      const b = await bundle.prompt(builtin(name), scenarios, new bundle.CompromisedPlanner(), () => {});
      const cli = await runPromptCampaign({ target: loadTarget(name), planner: new CompromisedPlanner(), scenarios });
      expect([b.blocked, b.breaches]).toEqual([cli.blocked, cli.breaches]);
      expect(b.results.map((r) => [r.id, r.outcome])).toEqual(cli.results.map((r) => [r.id, r.outcome]));
    }
  }, 120_000);

  it("the page and worker bundles build without Node-only code", async () => {
    for (const entry of ["page.ts", "worker.ts"]) {
      const r = await esbuild.build(web.browserBundleOptions(join(REPO_ROOT, "harness", "src", "browser", entry), { format: "iife", write: false }));
      web.assertBrowserSafe(r, entry);
    }
  }, 60_000);
});
