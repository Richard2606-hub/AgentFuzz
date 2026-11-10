/**
 * Contract-layer generator: fast-check arbitraries producing attack sequences (A3-A7).
 * Shrinking comes from fast-check, so a failing sequence is minimised automatically.
 */
import fc from "fast-check";
import { PROBES, type AmountRef, type ReceiverRef, type Step } from "../attacks/steps.js";

export const receiverArb: fc.Arbitrary<ReceiverRef> = fc.oneof(
  { weight: 8, arbitrary: fc.nat(5).map((i): ReceiverRef => ({ kind: "allowed", i })) },
  { weight: 4, arbitrary: fc.nat(11).map((i): ReceiverRef => ({ kind: "lookalike", i })) },
  { weight: 1, arbitrary: fc.constant<ReceiverRef>({ kind: "attacker" }) },
  { weight: 1, arbitrary: fc.constant<ReceiverRef>({ kind: "owner" }) },
  { weight: 1, arbitrary: fc.constant<ReceiverRef>({ kind: "self" }) },
  { weight: 1, arbitrary: fc.nat(5).map((i): ReceiverRef => ({ kind: "invalid", i })) },
);

export const amountArb: fc.Arbitrary<AmountRef> = fc.oneof(
  { weight: 4, arbitrary: fc.constant<AmountRef>({ kind: "cap" }) },
  { weight: 2, arbitrary: fc.integer({ min: 1, max: 1000 }).map((d): AmountRef => ({ kind: "capPlus", d })) },
  { weight: 2, arbitrary: fc.integer({ min: 1, max: 1000 }).map((d): AmountRef => ({ kind: "capMinus", d })) },
  { weight: 6, arbitrary: fc.integer({ min: 1, max: 100 }).map((pct): AmountRef => ({ kind: "pct", pct })) },
  { weight: 1, arbitrary: fc.constant<AmountRef>({ kind: "zero" }) },
  { weight: 1, arbitrary: fc.constant<AmountRef>({ kind: "one" }) },
  { weight: 1, arbitrary: fc.constant<AmountRef>({ kind: "u128max" }) },
  { weight: 1, arbitrary: fc.constant<AmountRef>({ kind: "u64max" }) },
  { weight: 1, arbitrary: fc.constant<AmountRef>({ kind: "free" }) },
);

const payArb = fc.record({ to: receiverArb, amount: amountArb });

/** v2 amounts: v1's plus "exactly the budget the guard says is left" (and one yocto over). */
const amountArbV2: fc.Arbitrary<AmountRef> = fc.oneof(
  { weight: 19, arbitrary: amountArb },
  { weight: 5, arbitrary: fc.constantFrom(0, 1).map((d): AmountRef => ({ kind: "remaining", d })) },
);
const payArbV2 = fc.record({ to: receiverArb, amount: amountArbV2 });

/**
 * Generator versions. A scorecard records the version it was produced with (absent = 1), so a
 * published score keeps verifying after the generator improves. Never change a released version's
 * arbitraries: that changes every sequence it draws, and with it every hash made from them.
 *
 *   1  the original mix
 *   2  adds `failPay` (delete a payee, then pay it: a failing transfer in the current window, the
 *      A6 path INV-5 depends on), biases `wait` toward idle periods of 2+ windows (A4) and `drain`
 *      toward allowance-exhausting lengths (INV-6), draws more same-block bursts (A6), and can pay
 *      exactly the budget the guard reports as left (A3). Repros get an extra minimisation pass.
 */
export const GENERATOR_VERSIONS = [1, 2] as const;
export type GeneratorVersion = (typeof GENERATOR_VERSIONS)[number];
export const DEFAULT_GENERATOR: GeneratorVersion = 2;

export function parseGenerator(v: unknown): GeneratorVersion {
  if (v === undefined) return DEFAULT_GENERATOR;
  const n = typeof v === "number" || (typeof v === "string" && /^\d+$/.test(v)) ? Number(v) : NaN;
  if (!(GENERATOR_VERSIONS as readonly number[]).includes(n)) throw new Error(`unknown generator version ${String(v)} (known: ${GENERATOR_VERSIONS.join(", ")})`);
  return n as GeneratorVersion;
}

/** Generator v1 step mix. Frozen: published scorecards were produced with it. */
export const stepArb: fc.Arbitrary<Step> = fc.oneof(
  { weight: 30, arbitrary: payArb.map((p): Step => ({ k: "pay", ...p })) },
  {
    weight: 14,
    arbitrary: fc
      .record({ windows: fc.integer({ min: 0, max: 4 }), offset: fc.integer({ min: -3, max: 3 }) })
      .map((w): Step => ({ k: "wait", ...w })),
  },
  {
    weight: 8,
    arbitrary: fc
      .array(fc.record({ to: fc.nat(5).map((i): ReceiverRef => ({ kind: "allowed", i })), amount: amountArb }), { minLength: 2, maxLength: 5 })
      .map((pays): Step => ({ k: "burst", pays })),
  },
  {
    weight: 8,
    arbitrary: fc.record({ probe: fc.constantFrom(...PROBES), i: fc.nat(9) }).map((p): Step => ({ k: "probe", ...p })),
  },
  { weight: 6, arbitrary: fc.nat(3).map((i): Step => ({ k: "extra", i })) },
  { weight: 3, arbitrary: fc.integer({ min: 1, max: 40 }).map((n): Step => ({ k: "drain", n })) },
  { weight: 4, arbitrary: fc.constant<Step>({ k: "exploit" }) },
  { weight: 6, arbitrary: fc.constant<Step>({ k: "failPayee" }) },
  {
    weight: 3,
    arbitrary: fc
      .record({ op: fc.constantFrom("revoke" as const, "rekey" as const, "withdraw" as const), pct: fc.integer({ min: 1, max: 100 }) })
      .map((o): Step => ({ k: "owner", ...o })),
  },
);

/** Generator v2 step mix. Frozen once released, like v1. */
export const stepArbV2: fc.Arbitrary<Step> = fc.oneof(
  { weight: 36, arbitrary: payArbV2.map((p): Step => ({ k: "pay", ...p })) },
  {
    weight: 16,
    arbitrary: fc
      .record({
        // Half the waits are idle periods of 2+ windows: rollover code that assumes it runs every window breaks there.
        windows: fc.oneof(fc.integer({ min: 0, max: 4 }), fc.integer({ min: 2, max: 4 })),
        offset: fc.integer({ min: -3, max: 3 }),
      })
      .map((w): Step => ({ k: "wait", ...w })),
  },
  {
    weight: 12,
    arbitrary: fc
      .array(fc.record({ to: fc.nat(5).map((i): ReceiverRef => ({ kind: "allowed", i })), amount: amountArbV2 }), { minLength: 2, maxLength: 5 })
      .map((pays): Step => ({ k: "burst", pays })),
  },
  {
    weight: 8,
    arbitrary: fc.record({ probe: fc.constantFrom(...PROBES), i: fc.nat(9) }).map((p): Step => ({ k: "probe", ...p })),
  },
  { weight: 6, arbitrary: fc.nat(3).map((i): Step => ({ k: "extra", i })) },
  {
    weight: 3,
    arbitrary: fc
      // Two thirds of drains are long enough to exhaust the default 0.1 NEAR allowance (~18 calls).
      .oneof({ weight: 1, arbitrary: fc.integer({ min: 1, max: 40 }) }, { weight: 2, arbitrary: fc.integer({ min: 18, max: 40 }) })
      .map((n): Step => ({ k: "drain", n })),
  },
  { weight: 4, arbitrary: fc.constant<Step>({ k: "exploit" }) },
  { weight: 2, arbitrary: fc.constant<Step>({ k: "failPayee" }) },
  { weight: 5, arbitrary: amountArbV2.map((amount): Step => ({ k: "failPay", amount })) },
  {
    weight: 3,
    arbitrary: fc
      .record({ op: fc.constantFrom("revoke" as const, "rekey" as const, "withdraw" as const), pct: fc.integer({ min: 1, max: 100 }) })
      .map((o): Step => ({ k: "owner", ...o })),
  },
);

export function sequenceArb(maxSteps: number, generator: GeneratorVersion = DEFAULT_GENERATOR): fc.Arbitrary<Step[]> {
  return generator === 1
    ? fc.array(stepArb, { minLength: 0, maxLength: maxSteps })
    : fc.array(stepArbV2, { minLength: 0, maxLength: maxSteps, size: "medium" });
}

