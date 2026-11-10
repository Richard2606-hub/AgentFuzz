import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { computeMatrix } from "../src/matrix.js";
import { loadRepro, replay, runCampaign } from "../src/runner.js";
import { loadTarget } from "../src/targets/registry.js";
import { canonicalJSON } from "../src/util/json.js";

describe("runner", () => {
  it("is deterministic: same seed, same campaign", async () => {
    const target = loadTarget("naive");
    const a = await runCampaign({ target, seed: 11, runs: 40 });
    const b = await runCampaign({ target, seed: 11, runs: 40 });
    const strip = (r: typeof a) => canonicalJSON({ ...r, durationMs: 0 });
    expect(strip(a)).toBe(strip(b));
  });

  it("saves a minimised repro that replays to the same break", async () => {
    const out = mkdtempSync(join(tmpdir(), "agentfuzz-"));
    const r = await runCampaign({ target: loadTarget("naive:bug-window-lag"), seed: 3, runs: 150, invariants: ["INV-1"], outDir: out });
    const inv = r.invariants[0];
    expect(inv.status).toBe("broken");
    expect(inv.reproFile).toBeDefined();
    const repro = loadRepro(inv.reproFile!);
    expect(repro.steps.length).toBeLessThanOrEqual(4);
    expect(repro.attackClasses).toContain("A4");
    const rr = await replay(repro);
    expect(rr.wasmMatches).toBe(true);
    expect(rr.reproduced).toBe(true);
  });

  it("a repro does not reproduce against the fixed guard", async () => {
    const out = mkdtempSync(join(tmpdir(), "agentfuzz-"));
    const r = await runCampaign({ target: loadTarget("naive:bug-prefix-allowlist"), seed: 5, runs: 150, invariants: ["INV-2"], outDir: out });
    const repro = loadRepro(r.invariants[0].reproFile!);
    expect((await replay(repro)).reproduced).toBe(true);
    expect((await replay(repro, undefined, loadTarget("naive-fixed"))).reproduced).toBe(false);
  });
});

describe("planted-bug matrix (end-to-end gate)", () => {
  it("catches every planted bug and keeps the controls clean", async () => {
    const { rows } = await computeMatrix(7, 120);
    const failed = rows.filter((r) => !r.ok);
    expect(failed, JSON.stringify(failed, null, 2)).toEqual([]);
    expect(rows.length).toBe(10);
  });
});
