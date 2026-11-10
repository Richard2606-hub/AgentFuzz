import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { DEFAULT_GENERATOR, parseGenerator, sequenceArb } from "../src/generators/contract.js";
import { makeSettings, verifyScorecard } from "../src/report.js";
import { evaluate, runCampaign } from "../src/runner.js";
import { minimise, reductions } from "../src/minimise.js";
import { brokenIn } from "../src/invariants/types.js";
import { loadTarget, REPO_ROOT } from "../src/targets/registry.js";
import { defaultConfig, type World } from "../src/world.js";
import { resolveAmount, type Step } from "../src/attacks/steps.js";

describe("generator versions", () => {
  it("parses known versions and rejects unknown ones", () => {
    expect(parseGenerator(undefined)).toBe(DEFAULT_GENERATOR);
    expect(parseGenerator("1")).toBe(1);
    expect(parseGenerator(2)).toBe(2);
    expect(() => parseGenerator("3")).toThrow(/unknown generator/);
    expect(() => parseGenerator(true)).toThrow(/unknown generator/);
  });

  it("v1 settings omit the generator field so pre-versioning hashes still match", () => {
    const base = { seed: 1, runs: 1, maxSteps: 1, backend: "nearsim", planner: "compromised", targets: ["reference"], corpusSha256: "x" };
    expect(makeSettings({ ...base, generator: 1 })).toEqual(base);
    expect(makeSettings({ ...base, generator: 2 })).toEqual({ ...base, generator: 2 });
  });

  it("v1 and v2 draw different sequences; only v2 draws failPay", () => {
    const kinds = (g: 1 | 2) => new Set(fc.sample(sequenceArb(20, g), { seed: 5, numRuns: 300 }).flat().map((s) => s.k));
    expect(kinds(1).has("failPay")).toBe(false);
    expect(kinds(2).has("failPay")).toBe(true);
  });

  it("records the generator in the campaign result", async () => {
    const r = await runCampaign({ target: loadTarget("reference"), seed: 1, runs: 3, maxSteps: 4, generator: 1 });
    expect(r.generator).toBe(1);
  });
});

describe("failPay step (A6 failing promise)", () => {
  const steps: Step[] = [{ k: "failPay", amount: { kind: "pct", pct: 50 } }];
  const cfg = defaultConfig("agentfuzz/failpay");

  it("breaks INV-5 on a guard that ignores the promise result, in one step", async () => {
    const r = await evaluate(loadTarget("naive:bug-ignore-promise-result"), cfg, steps);
    expect(r.trace.failedTransfers).toBeGreaterThan(0);
    expect(brokenIn(r.verdict).has("INV-5")).toBe(true);
  });

  it("is a failing transfer the reference guard accounts for correctly", async () => {
    const r = await evaluate(loadTarget("reference"), cfg, steps);
    expect(r.trace.failedTransfers).toBeGreaterThan(0);
    expect(r.verdict.exercised).toContain("INV-5");
    expect([...brokenIn(r.verdict)]).toEqual([]);
  });
});

describe("published scorecard", () => {
  // web/scorecard.json is anchored on testnet. It predates generator versioning, so it must keep
  // reproducing with generator v1 forever. Anchors are dropped (they sit outside the hashed body)
  // so the test stays offline.
  it("still reproduces its anchored hash bit-for-bit", async () => {
    const published = JSON.parse(readFileSync(join(REPO_ROOT, "web", "scorecard.json"), "utf8"));
    const file = join(mkdtempSync(join(tmpdir(), "agentfuzz-")), "scorecard.json");
    writeFileSync(file, JSON.stringify({ ...published, anchors: [] }));
    const r = await verifyScorecard(file, { rerun: true });
    expect(r.bodyIntact).toBe(true);
    expect(r.recomputedSha256).toBe(published.sha256);
    expect(r.reproduced).toBe(true);
  }, 120_000);
});

describe("reset-on-failure planted bug (opt-in B8)", () => {
  // Pay half the cap, make a payment fail (the guard wipes the window's spend), pay the full cap again.
  const exploit: Step[] = [
    { k: "pay", to: { kind: "allowed", i: 0 }, amount: { kind: "pct", pct: 50 } },
    { k: "failPay", amount: { kind: "remaining", d: 0 } },
    { k: "pay", to: { kind: "allowed", i: 0 }, amount: { kind: "remaining", d: 0 } },
  ];
  const cfg = defaultConfig("agentfuzz/reset");

  it("turns one failed transfer into a cap bypass", async () => {
    const r = await evaluate(loadTarget("naive:bug-reset-on-failure"), cfg, exploit);
    expect(brokenIn(r.verdict).has("INV-1")).toBe(true);
    expect(brokenIn(r.verdict).has("INV-5")).toBe(true);
  });

  it("is harmless on the fixed guard and the reference guard", async () => {
    for (const name of ["naive-fixed", "reference"]) {
      const r = await evaluate(loadTarget(name), cfg, exploit);
      expect([...brokenIn(r.verdict)], name).toEqual([]);
    }
  });

  it("is not compiled into the default naive guard (published scorecard stays valid)", () => {
    const manifest = JSON.parse(readFileSync(join(REPO_ROOT, "artifacts", "manifest.json"), "utf8"));
    expect(manifest.artifacts["guard_naive.wasm"].features).toBe("default");
    const cargo = readFileSync(join(REPO_ROOT, "contracts", "guard-naive", "Cargo.toml"), "utf8");
    const defaults = cargo.slice(cargo.indexOf("default = ["), cargo.indexOf("]", cargo.indexOf("default = [")));
    expect(defaults).not.toContain("bug-reset-on-failure");
  });
});

describe("post-shrink minimisation", () => {
  it("lists step removals and burst-pay removals", () => {
    const pay = (pct: number) => ({ to: { kind: "allowed" as const, i: 0 }, amount: { kind: "pct" as const, pct } });
    const steps: Step[] = [{ k: "wait", windows: 1, offset: 0 }, { k: "burst", pays: [pay(1), pay(2)] }];
    const r = reductions(steps);
    expect(r).toContainEqual([steps[1]]);
    expect(r).toContainEqual([steps[0]]);
    expect(r).toContainEqual([steps[0], { k: "pay", ...pay(2) }]);
    expect(r).toContainEqual([steps[0], { k: "pay", ...pay(1) }]);
  });

  it("drops irrelevant steps and burst pays", async () => {
    const pay = (pct: number) => ({ to: { kind: "allowed" as const, i: 0 }, amount: { kind: "pct" as const, pct } });
    const steps: Step[] = [{ k: "exploit" }, { k: "burst", pays: [pay(7), pay(42), pay(9)] }, { k: "wait", windows: 0, offset: 1 }];
    // "fails" whenever a 42% pay is present anywhere
    const has42 = async (s: Step[]) => JSON.stringify(s).includes('"pct":42');
    const m = await minimise(steps, has42);
    expect(m.steps).toEqual([{ k: "pay", ...pay(42) }]);
    expect(m.applied).toBe(4);
  });

  it("shrinks a same-block cap bypass down to the two pays that matter", async () => {
    const r = await runCampaign({ target: loadTarget("naive:bug-deferred-accounting"), seed: 42, runs: 100, invariants: ["INV-1"] });
    const steps = r.invariants[0].repro!.steps;
    const pays = steps.flatMap((s) => (s.k === "burst" ? s.pays : s.k === "pay" ? [s] : []));
    expect(pays.length).toBeLessThanOrEqual(2);
  });
});

describe("remaining-budget amount", () => {
  it("falls back to the full cap when the guard's view fails instead of crashing the campaign", async () => {
    const dead = { cfg: { cap: 100n }, adapter: { readAccounting: async () => { throw new Error("Contract method 'get_window' is not found"); } }, view: async () => undefined };
    expect(await resolveAmount(dead as unknown as World, { kind: "remaining", d: 0 })).toBe(100n);
    expect(await resolveAmount(dead as unknown as World, { kind: "remaining", d: 1 })).toBe(101n);
  });
});
