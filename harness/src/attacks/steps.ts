/**
 * Contract-layer attack steps (attack classes A3-A7 of THREAT_MODEL.md).
 *
 * Steps are symbolic ("pay cap+1 to look-alike #2", "wait 2 windows + 1 block") so a minimised
 * repro reads like a test case and replays identically on any backend.
 */
import { fmtNear, near } from "../near/keys.js";
import type { Action, TxResult } from "../near/types.js";
import type { ProbeOutcome, World } from "../world.js";

export type AttackClass = "A1" | "A2" | "A3" | "A4" | "A5" | "A6" | "A7";

export type ReceiverRef =
  | { kind: "allowed"; i: number }
  | { kind: "lookalike"; i: number }
  | { kind: "attacker" }
  | { kind: "owner" }
  | { kind: "self" }
  | { kind: "invalid"; i: number };

export type AmountRef =
  | { kind: "cap" }
  | { kind: "capPlus"; d: number }
  | { kind: "capMinus"; d: number }
  | { kind: "zero" }
  | { kind: "one" }
  | { kind: "u128max" }
  | { kind: "u64max" }
  | { kind: "pct"; pct: number }
  | { kind: "free" };

export const PROBES = [
  "transfer",
  "addFullKey",
  "addWideKey",
  "deleteKey",
  "deploy",
  "deleteAccount",
  "adminCall",
  "depositCall",
  "otherReceiver",
] as const;
export type ProbeKind = (typeof PROBES)[number];

export type Step =
  | { k: "pay"; to: ReceiverRef; amount: AmountRef }
  | { k: "burst"; pays: { to: ReceiverRef; amount: AmountRef }[] }
  | { k: "wait"; windows: number; offset: number }
  | { k: "probe"; probe: ProbeKind; i: number }
  | { k: "extra"; i: number }
  | { k: "drain"; n: number }
  | { k: "exploit" }
  | { k: "failPayee" }
  | { k: "owner"; op: "revoke" | "rekey" | "withdraw"; pct: number };

export function stepClass(s: Step): AttackClass | "owner" {
  switch (s.k) {
    case "pay":
      return s.to.kind === "allowed" ? "A3" : "A5";
    case "burst":
    case "failPayee":
      return "A6";
    case "wait":
      return "A4";
    case "probe":
    case "extra":
    case "drain":
    case "exploit":
      return "A7";
    case "owner":
      return "owner";
  }
}

export interface TxRecord {
  who: "agent" | "owner" | "payee" | "attacker";
  summary: string;
  txHash: string;
  outcome: "success" | "failure" | "rejected";
  error?: string;
}

export interface StepRecord {
  index: number;
  step: Step;
  description: string;
  cls: AttackClass | "owner";
  txs: TxRecord[];
}

/** Everything invariant checkers need to know about what happened during a sequence. */
export interface Trace {
  steps: StepRecord[];
  /** Tx hashes of agent `pay` calls (their outflows are what the guard's accounting tracks). */
  payTxs: Set<string>;
  probes: ProbeOutcome[];
  ownerFailures: { op: string; error: string }[];
  allowanceExhausted: boolean;
  failedTransfers: number;
}

export function newTrace(): Trace {
  return { steps: [], payTxs: new Set(), probes: [], ownerFailures: [], allowanceExhausted: false, failedTransfers: 0 };
}

const U128_MAX = (1n << 128n) - 1n;
const U64_MAX = (1n << 64n) - 1n;

export function resolveReceiver(w: World, r: ReceiverRef): string {
  const c = w.cfg;
  switch (r.kind) {
    case "allowed":
      return c.allowlist[r.i % c.allowlist.length];
    case "lookalike":
      return c.lookalikes[r.i % c.lookalikes.length];
    case "attacker":
      return c.attackerId;
    case "owner":
      return c.ownerId;
    case "self":
      return c.guardId;
    case "invalid":
      return c.invalidReceivers[r.i % c.invalidReceivers.length];
  }
}

export async function resolveAmount(w: World, a: AmountRef): Promise<bigint> {
  const cap = w.cfg.cap;
  switch (a.kind) {
    case "cap":
      return cap;
    case "capPlus":
      return cap + BigInt(a.d);
    case "capMinus":
      return cap > BigInt(a.d) ? cap - BigInt(a.d) : 0n;
    case "zero":
      return 0n;
    case "one":
      return 1n;
    case "u128max":
      return U128_MAX;
    case "u64max":
      return U64_MAX;
    case "pct":
      return (cap * BigInt(a.pct)) / 100n;
    case "free":
      return w.freeBalance();
  }
}

export function describeAmount(a: AmountRef): string {
  switch (a.kind) {
    case "cap":
      return "cap";
    case "capPlus":
      return `cap+${a.d}y`;
    case "capMinus":
      return `cap-${a.d}y`;
    case "pct":
      return `${a.pct}% of cap`;
    case "u128max":
      return "u128::MAX";
    case "u64max":
      return "u64::MAX";
    default:
      return a.kind;
  }
}

export function describeStep(s: Step, w?: World): string {
  const rcv = (r: ReceiverRef) => (w ? resolveReceiver(w, r) : `${r.kind}${"i" in r ? `#${r.i}` : ""}`) || '""';
  switch (s.k) {
    case "pay":
      return `agent pay(${rcv(s.to)}, ${describeAmount(s.amount)})`;
    case "burst":
      return `same-block burst of ${s.pays.length} pays: ${s.pays.map((p) => `${rcv(p.to)}:${describeAmount(p.amount)}`).join(", ")}`;
    case "wait": {
      const blocks = w ? waitBlocks(w, s) : undefined;
      return `wait ${s.windows} window(s) ${s.offset >= 0 ? "+" : "-"} ${Math.abs(s.offset)} block(s)${blocks !== undefined ? ` (${blocks} blocks)` : ""}`;
    }
    case "probe":
      return `agent key probe: ${s.probe}`;
    case "extra":
      return `agent calls extra method #${s.i} with a fresh key`;
    case "drain":
      return `drain allowance with ${s.n} cheap agent calls`;
    case "exploit":
      return "agent uses every key it controls to move funds directly";
    case "failPayee":
      return "delete an allowlisted payee so transfers to it fail";
    case "owner":
      return `owner ${s.op}${s.op === "withdraw" ? ` ${s.pct}% of free balance` : ""}`;
  }
}

export function waitBlocks(w: World, s: Extract<Step, { k: "wait" }>): number {
  return Math.max(1, s.windows * w.cfg.windowBlocks + s.offset);
}

function record(who: TxRecord["who"], summary: string, r: TxResult): TxRecord {
  if (r.rejected) return { who, summary, txHash: r.txHash, outcome: "rejected", error: `${r.rejected.kind}: ${r.rejected.message}` };
  const s = r.status;
  if (!s || s.kind === "failure") return { who, summary, txHash: r.txHash, outcome: "failure", error: s?.kind === "failure" ? s.error : "no outcome" };
  return { who, summary, txHash: r.txHash, outcome: "success" };
}

function countFailedTransfers(r: TxResult): number {
  return r.receipts.filter((o) => o.status.kind === "failure" && o.actions.some((a) => a.type === "Transfer")).length;
}

/** Tiny valid wasm module (no exports) used by the deploy probe. */
const EMPTY_WASM = Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

/** Execute one step against the world, appending to the trace. */
export async function executeStep(w: World, step: Step, trace: Trace): Promise<void> {
  const rec: StepRecord = { index: trace.steps.length, step, description: describeStep(step, w), cls: stepClass(step), txs: [] };
  trace.steps.push(rec);
  const g = w.cfg.guardId;

  const agentPay = async (to: ReceiverRef, amount: AmountRef) => {
    const receiver = resolveReceiver(w, to);
    const amt = await resolveAmount(w, amount);
    return { tx: w.agentTx(w.adapter.pay(receiver, amt)), summary: `pay(${receiver || '""'}, ${fmtNear(amt)})` };
  };

  switch (step.k) {
    case "pay": {
      const { tx, summary } = await agentPay(step.to, step.amount);
      const r = await w.exec(tx);
      if (r.rejected?.kind === "NotEnoughAllowance") trace.allowanceExhausted = true;
      if (!r.rejected) trace.payTxs.add(r.txHash);
      trace.failedTransfers += countFailedTransfers(r);
      rec.txs.push(record("agent", summary, r));
      break;
    }
    case "burst": {
      const subs: { hash: string; summary: string; rejected?: string }[] = [];
      for (const p of step.pays) {
        const { tx, summary } = await agentPay(p.to, p.amount);
        const s = await w.backend.submit(tx);
        if (s.rejected?.kind === "NotEnoughAllowance") trace.allowanceExhausted = true;
        subs.push({ hash: s.txHash, summary, rejected: s.rejected ? `${s.rejected.kind}: ${s.rejected.message}` : undefined });
      }
      await w.backend.settle();
      for (const s of subs) {
        if (s.rejected) {
          rec.txs.push({ who: "agent", summary: s.summary, txHash: s.hash, outcome: "rejected", error: s.rejected });
          continue;
        }
        trace.payTxs.add(s.hash);
        const r = await w.backend.txResult(s.hash);
        trace.failedTransfers += countFailedTransfers(r);
        rec.txs.push(record("agent", s.summary, r));
      }
      break;
    }
    case "wait":
      await w.backend.advanceBlocks(waitBlocks(w, step));
      break;
    case "probe": {
      const fresh = w.freshAgentKey();
      let receiver = g;
      let actions: Action[];
      switch (step.probe) {
        case "transfer":
          receiver = w.cfg.attackerId;
          actions = [{ type: "Transfer", deposit: near(1) }];
          break;
        case "addFullKey":
          actions = [{ type: "AddKey", publicKey: fresh.publicKey, permission: { kind: "FullAccess" } }];
          break;
        case "addWideKey":
          actions = [{ type: "AddKey", publicKey: fresh.publicKey, permission: { kind: "FunctionCall", allowance: null, receiverId: g, methodNames: [] } }];
          break;
        case "deleteKey":
          actions = [{ type: "DeleteKey", publicKey: w.activeAgentKey }];
          break;
        case "deploy":
          actions = [{ type: "DeployContract", code: EMPTY_WASM }];
          break;
        case "deleteAccount":
          actions = [{ type: "DeleteAccount", beneficiaryId: w.cfg.attackerId }];
          break;
        case "adminCall": {
          const methods = w.adapter.adminMethods;
          const m = methods[step.i % methods.length];
          actions = [
            {
              type: "FunctionCall",
              methodName: m,
              args: new TextEncoder().encode(JSON.stringify(adminArgs(w, m, fresh.publicKey))),
              gas: 30n * 10n ** 12n,
              deposit: 0n,
            },
          ];
          break;
        }
        case "depositCall": {
          const { tx } = await agentPay({ kind: "allowed", i: 0 }, { kind: "one" });
          actions = tx.actions.map((a) => (a.type === "FunctionCall" ? { ...a, deposit: 1n } : a));
          break;
        }
        case "otherReceiver":
          receiver = w.cfg.attackerId;
          actions = [{ type: "FunctionCall", methodName: "pay", args: new TextEncoder().encode("{}"), gas: 30n * 10n ** 12n, deposit: 0n }];
          break;
      }
      const r = await w.exec(w.rawAgentTx(receiver, actions));
      if (r.rejected?.kind === "NotEnoughAllowance") trace.allowanceExhausted = true;
      const escaped = !r.rejected && r.status?.kind === "success";
      trace.probes.push({
        probe: step.probe === "adminCall" ? `adminCall:${w.adapter.adminMethods[step.i % w.adapter.adminMethods.length]}` : step.probe,
        publicKey: w.activeAgentKey,
        escaped,
        detail: r.rejected ? r.rejected.kind : r.status?.kind === "failure" ? r.status.error : "succeeded",
      });
      rec.txs.push(record("agent", `probe ${step.probe}`, r));
      break;
    }
    case "extra": {
      const extras = w.adapter.agentExtras;
      if (!extras.length) {
        rec.description += " (target has none: no-op)";
        break;
      }
      const ex = extras[step.i % extras.length];
      const fresh = w.freshAgentKey();
      const r = await w.exec(w.agentTx({ method: ex.method, args: ex.build(fresh.publicKey) }));
      if (r.rejected?.kind === "NotEnoughAllowance") trace.allowanceExhausted = true;
      if (!r.rejected && r.status?.kind === "success" && ex.installsKey) w.activeAgentKey = fresh.publicKey;
      rec.txs.push(record("agent", `${ex.method}(fresh key)`, r));
      break;
    }
    case "drain": {
      for (let i = 0; i < step.n; i++) {
        const { tx } = await agentPay({ kind: "allowed", i: 0 }, { kind: "zero" });
        const r = await w.exec(tx);
        if (r.rejected) {
          if (r.rejected.kind === "NotEnoughAllowance") trace.allowanceExhausted = true;
          rec.txs.push(record("agent", `drain call #${i + 1}`, r));
          break;
        }
      }
      if (!rec.txs.length) rec.txs.push({ who: "agent", summary: `${step.n} drain calls accepted`, txHash: "-", outcome: "success" });
      break;
    }
    case "exploit": {
      const keys = await w.backend.accessKeys(g);
      for (const k of keys) {
        if (!w.agentKeyring.has(k.publicKey) || k.permission.kind !== "FullAccess") continue;
        const free = await w.freeBalance();
        const amount = free > near("0.01") ? free - near("0.01") : 0n;
        if (amount === 0n) continue;
        const r = await w.exec(w.rawAgentTx(w.cfg.attackerId, [{ type: "Transfer", deposit: amount }], k.publicKey));
        rec.txs.push(record("agent", `direct transfer ${fmtNear(amount)} to attacker with full key`, r));
      }
      if (!rec.txs.length) rec.description += " (no escalated keys: no-op)";
      break;
    }
    case "failPayee": {
      const victim = w.cfg.allowlist[w.cfg.allowlist.length - 1];
      if (w.deletedPayees.has(victim)) break;
      const r = await w.exec({
        signerId: victim,
        publicKey: w.keys.payees.get(victim)!.publicKey,
        receiverId: victim,
        actions: [{ type: "DeleteAccount", beneficiaryId: w.cfg.allowlist[0] }],
      });
      if (!r.rejected && r.status?.kind === "success") w.deletedPayees.add(victim);
      rec.txs.push(record("payee", `delete ${victim}`, r));
      break;
    }
    case "owner": {
      if (step.op === "revoke") {
        const r = await w.exec(w.ownerTx(w.adapter.revoke()));
        const tr = record("owner", "revoke_agent", r);
        if (tr.outcome !== "success") trace.ownerFailures.push({ op: "revoke", error: tr.error ?? "" });
        rec.txs.push(tr);
      } else if (step.op === "rekey") {
        if (!w.adapter.rekey) {
          rec.description += " (target has no re-key method: no-op)";
          break;
        }
        const fresh = w.freshAgentKey();
        const r = await w.exec(w.ownerTx(w.adapter.rekey(fresh.publicKey, w.cfg.agentAllowance)));
        if (!r.rejected && r.status?.kind === "success") w.activeAgentKey = fresh.publicKey;
        rec.txs.push(record("owner", "set_agent_key(fresh key)", r));
      } else {
        const free = await w.freeBalance();
        const amount = (free * BigInt(step.pct)) / 100n;
        if (amount === 0n) break;
        const r = await w.exec(w.ownerTx(w.adapter.withdraw(amount)));
        rec.txs.push(record("owner", `withdraw(${fmtNear(amount)})`, r));
      }
      break;
    }
  }
}

function adminArgs(w: World, method: string, freshKey: string): unknown {
  switch (method) {
    case "set_agent_key":
      return { public_key: freshKey, allowance: w.cfg.agentAllowance.toString() };
    case "set_policy":
      return { cap_per_window: U128_MAX.toString(), window_ns: "1" };
    case "add_allowed":
      return { account_id: w.cfg.attackerId };
    case "remove_allowed":
      return { account_id: w.cfg.allowlist[0] };
    case "withdraw":
      return {};
    case "on_pay_complete":
      return { payment_id: "0", window: "0", window_start: "0", amount: w.cfg.cap.toString() };
    default:
      return {};
  }
}

export async function executeSequence(w: World, steps: Step[]): Promise<Trace> {
  const trace = newTrace();
  for (const s of steps) await executeStep(w, s, trace);
  await w.backend.settle();
  return trace;
}
