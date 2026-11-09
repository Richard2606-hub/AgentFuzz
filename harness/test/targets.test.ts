import { describe, expect, it } from "vitest";
import { runCampaign } from "../src/runner.js";
import { listTargets, loadTarget, loadThirdPartyTargets } from "../src/targets/registry.js";

describe("third-party targets", () => {
  it("registers targets/third-party/*/target.json with their adapter modules", async () => {
    const names = await loadThirdPartyTargets();
    expect(names).toContain("tp:example");
    const t = loadTarget("tp:example");
    expect(t.adapter.id).toBe("example-adapter");
    expect(t.source).toContain("@local");
    expect(listTargets().some((x) => x.name === "tp:example")).toBe(true);
  });

  it("fuzzes a third-party target through its adapter", async () => {
    await loadThirdPartyTargets();
    const r = await runCampaign({ target: loadTarget("tp:example"), seed: 4, runs: 40 });
    expect(r.invariants.filter((i) => i.status === "broken")).toEqual([]);
    expect(r.invariants.find((i) => i.id === "INV-5")?.status).not.toBe("n/a");
  });

  it("accepts an arbitrary wasm path with the default adapter", () => {
    const t = loadTarget("../artifacts/guard_naive__fixed.wasm");
    expect(t.adapter.id).toBe("agentfuzz-guard-v1");
    expect(t.wasm.length).toBeGreaterThan(1000);
  });
});
