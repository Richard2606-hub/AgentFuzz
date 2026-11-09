/** Invariant identifiers and result shapes. Definitions live in THREAT_MODEL.md. */

export type InvariantId = "INV-1" | "INV-2" | "INV-3" | "INV-4" | "INV-5" | "INV-6";
export const INVARIANT_IDS: InvariantId[] = ["INV-1", "INV-2", "INV-3", "INV-4", "INV-5", "INV-6"];

export const INVARIANTS: Record<InvariantId, { title: string; check: string }> = {
  "INV-1": {
    title: "Total spent by the agent within any window <= the configured cap",
    check: "Sum agent-signed outflows from sandbox receipts per window (by authorisation time); compare to cap",
  },
  "INV-2": {
    title: "No funds reach a receiver outside the allowlist",
    check: "Inspect every agent-signed outgoing value transfer receipt; receiver must equal an allowlisted id exactly",
  },
  "INV-3": {
    title: "The agent key can't add keys, delete keys or transfer directly",
    check: "Attempt each forbidden action with agent keys (expect rejection); audit the guard account's keys after every run",
  },
  "INV-4": {
    title: "The owner can always revoke the agent key and withdraw",
    check: "After every attack sequence run owner revoke + withdraw-all-free; both must succeed and leave the agent keyless",
  },
  "INV-5": {
    title: "Guard state stays consistent after failed cross-contract calls",
    check: "Force transfer failures; compare the guard's recorded spend with actual settled outflows",
  },
  "INV-6": {
    title: "The agent isn't locked out silently by gas-allowance exhaustion",
    check: "Drain the allowance; exhaustion must be surfaced and the owner must be able to restore the agent via the guard",
  },
};

export interface Violation {
  invariant: InvariantId;
  message: string;
  evidence?: Record<string, unknown>;
}

export type InvariantStatus = "held" | "broken" | "not-exercised" | "n/a";

export interface RunVerdict {
  /** Invariants checked in this run, with violations (empty = held). */
  checked: Set<InvariantId>;
  /** Invariants whose attack precondition occurred in this run (e.g. allowance drained). */
  exercised: Set<InvariantId>;
  violations: Violation[];
}

export function brokenIn(v: RunVerdict): Set<InvariantId> {
  return new Set(v.violations.map((x) => x.invariant));
}
