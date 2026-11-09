import { describe, expect, it } from "vitest";
import type { Step } from "../src/attacks/steps.js";
import { checkInv1, checkInv2, type AgentOutflow } from "../src/invariants/check.js";
import { brokenIn, type InvariantId } from "../src/invariants/types.js";
import { near } from "../src/near/keys.js";
import { evaluate } from "../src/runner.js";
import { loadTarget } from "../src/targets/registry.js";
import { defaultConfig, World } from "../src/world.js";
import { SimBackend } from "../src/sim/backend.js";

const cfg = defaultConfig("fixtures");

async function broken(target: string, steps: Step[]): Promise<Set<InvariantId>> {
  const r = await evaluate(loadTarget(target), cfg, steps);
  return brokenIn(r.verdict);
}

/**
 * Every invariant checker gets one failing fixture (a single-bug guard + the attack that
 * triggers it) and one passing fixture (the same attack against a correct guard).
 */
const fixtures: { inv: InvariantId; failing: string; passing: string; steps: Step[] }[] = [
  {
    inv: "INV-1",
    failing: "naive:bug-window-lag",
    passing: "reference",
    steps: [
      { k: "wait", windows: 3, offset: 5 },
      { k: "pay", to: { kind: "allowed", i: 0 }, amount: { kind: "cap" } },
      { k: "pay", to: { kind: "allowed", i: 1 }, amount: { kind: "cap" } },
    ],
  },
  {
    inv: "INV-1",
    failing: "naive:bug-deferred-accounting",
    passing: "reference",
    steps: [{ k: "burst", pays: [{ to: { kind: "allowed", i: 0 }, amount: { kind: "cap" } }, { to: { kind: "allowed", i: 1 }, amount: { kind: "cap" } }] }],
  },
  {
    inv: "INV-2",
    failing: "naive:bug-prefix-allowlist",
    passing: "reference",
    steps: [{ k: "pay", to: { kind: "lookalike", i: 0 }, amount: { kind: "pct", pct: 50 } }],
  },
  {
    inv: "INV-3",
    failing: "naive:bug-rotate-full-key",
    passing: "naive-fixed",
    steps: [{ k: "extra", i: 0 }, { k: "probe", probe: "addFullKey", i: 0 }],
  },
  { inv: "INV-4", failing: "naive:bug-withdraw-underflow", passing: "reference", steps: [] },
  {
    inv: "INV-5",
    failing: "naive:bug-ignore-promise-result",
    passing: "reference",
    steps: [{ k: "failPayee" }, { k: "pay", to: { kind: "allowed", i: 2 }, amount: { kind: "pct", pct: 30 } }],
  },
  { inv: "INV-6", failing: "naive:bug-no-rekey", passing: "reference", steps: [{ k: "drain", n: 40 }] },
];

describe("invariant checkers: failing and passing fixtures", () => {
  for (const f of fixtures) {
    it(`${f.inv} breaks on ${f.failing}`, async () => {
      expect(await broken(f.failing, f.steps)).toContain(f.inv);
    });
    it(`${f.inv} holds on ${f.passing} under the same attack`, async () => {
      expect(await broken(f.passing, f.steps)).not.toContain(f.inv);
    });
  }

  it("reference guard: a mixed attack sequence breaks nothing", async () => {
    const steps: Step[] = [
      { k: "pay", to: { kind: "allowed", i: 0 }, amount: { kind: "capMinus", d: 1 } },
      { k: "pay", to: { kind: "allowed", i: 0 }, amount: { kind: "one" } },
      { k: "pay", to: { kind: "allowed", i: 0 }, amount: { kind: "one" } },
      { k: "wait", windows: 1, offset: -1 },
      { k: "burst", pays: [{ to: { kind: "allowed", i: 1 }, amount: { kind: "cap" } }, { to: { kind: "allowed", i: 2 }, amount: { kind: "cap" } }] },
      { k: "probe", probe: "transfer", i: 0 },
      { k: "probe", probe: "adminCall", i: 3 },
      { k: "pay", to: { kind: "invalid", i: 2 }, amount: { kind: "one" } },
      { k: "pay", to: { kind: "allowed", i: 0 }, amount: { kind: "u128max" } },
      { k: "owner", op: "rekey", pct: 1 },
      { k: "pay", to: { kind: "allowed", i: 0 }, amount: { kind: "pct", pct: 10 } },
    ];
    expect([...(await broken("reference", steps))]).toEqual([]);
  });
});

describe("pure checker logic", () => {
  const world = new World(new SimBackend(), loadTarget("reference"), cfg);
  const out = (window: number, amount: bigint, to = "alice.test.near"): AgentOutflow => ({
    from: cfg.guardId,
    to,
    amount,
    txHash: `tx${window}${amount}`,
    receiptId: "r",
    signerId: cfg.guardId,
    signerPublicKey: "ed25519:x",
    authTimestamp: 0n,
    settledTimestamp: 0n,
    blockHeight: 0n,
    isRefund: false,
    window: BigInt(window),
  });

  it("INV-1 sums per window and compares to the cap (inclusive)", () => {
    expect(checkInv1(world, [out(0, near(2)), out(0, near(1)), out(1, near(3))])).toEqual([]);
    const v = checkInv1(world, [out(4, near(2)), out(4, near(1) + 1n)]);
    expect(v).toHaveLength(1);
    expect(v[0].evidence?.window).toBe("4");
  });

  it("INV-2 requires exact allowlist equality", () => {
    expect(checkInv2(world, [out(0, 1n, "alice.test.near")])).toEqual([]);
    for (const bad of ["alice.test.near.attacker.test.near", "xalice.test.near", "attacker.test.near"])
      expect(checkInv2(world, [out(0, 1n, bad)])).toHaveLength(1);
  });
});
