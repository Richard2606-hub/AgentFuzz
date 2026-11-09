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

export function sequenceArb(maxSteps: number): fc.Arbitrary<Step[]> {
  return fc.array(stepArb, { minLength: 0, maxLength: maxSteps });
}
