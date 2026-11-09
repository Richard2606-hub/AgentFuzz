/**
 * Invariant checkers INV-1..INV-6 (definitions in THREAT_MODEL.md).
 *
 * The checkers only trust the chain: the value-transfer ledger, receipt outcomes and access-key
 * lists. They never trust the guard's own views, except INV-5, whose whole point is to compare
 * the guard's recorded state with the ledger.
 *
 * Order matters: passive checks (INV-1, INV-2, INV-3 audit, INV-5) run first; then the active
 * owner checks (INV-6 recovery, INV-4 revoke + withdraw), which change state.
 */
import { fmtNear } from "../near/keys.js";
import type { ValueTransfer } from "../near/types.js";
import type { Trace } from "../attacks/steps.js";
import type { World } from "../world.js";
import type { InvariantId, RunVerdict, Violation } from "./types.js";

export interface AgentOutflow extends ValueTransfer {
  window: bigint;
}

/** Value that left the guard account under agent authority (pay calls or escalated keys). */
export function agentOutflows(w: World, transfers: ValueTransfer[]): AgentOutflow[] {
  return transfers
    .filter((t) => t.from === w.cfg.guardId && !t.isRefund && t.to !== w.cfg.guardId && w.isAgentSigned(t.signerId, t.signerPublicKey))
    .map((t) => ({ ...t, window: (t.authTimestamp - w.initTimestamp) / w.windowNs }));
}

export function checkInv1(w: World, outflows: AgentOutflow[]): Violation[] {
  const perWindow = new Map<bigint, { total: bigint; txs: string[] }>();
  for (const o of outflows) {
    const e = perWindow.get(o.window) ?? { total: 0n, txs: [] };
    e.total += o.amount;
    e.txs.push(o.txHash);
    perWindow.set(o.window, e);
  }
  const out: Violation[] = [];
  for (const [window, e] of perWindow) {
    if (e.total > w.cfg.cap)
      out.push({
        invariant: "INV-1",
        message: `agent spent ${fmtNear(e.total)} in window ${window}, cap is ${fmtNear(w.cfg.cap)}`,
        evidence: { window: window.toString(), spent: e.total.toString(), cap: w.cfg.cap.toString(), txs: e.txs },
      });
  }
  return out;
}

export function checkInv2(w: World, outflows: AgentOutflow[]): Violation[] {
  const allowed = new Set(w.cfg.allowlist);
  return outflows
    .filter((o) => !allowed.has(o.to))
    .map((o) => ({
      invariant: "INV-2" as const,
      message: `${fmtNear(o.amount)} reached non-allowlisted ${o.to}`,
      evidence: { to: o.to, amount: o.amount.toString(), txHash: o.txHash, receiptId: o.receiptId },
    }));
}

export async function checkInv3(w: World, trace: Trace): Promise<Violation[]> {
  const out: Violation[] = [];
  for (const p of trace.probes.filter((p) => p.escaped))
    out.push({ invariant: "INV-3", message: `agent key performed forbidden action '${p.probe}'`, evidence: { ...p } });

  const allowedMethods = new Set(w.allowedAgentMethods());
  for (const k of await w.backend.accessKeys(w.cfg.guardId)) {
    if (k.permission.kind === "FullAccess") {
      out.push({
        invariant: "INV-3",
        message: `full-access key ${short(k.publicKey)} present on the guard account${w.agentKeyring.has(k.publicKey) ? " (agent-controlled)" : ""}`,
        evidence: { publicKey: k.publicKey, agentControlled: w.agentKeyring.has(k.publicKey) },
      });
      continue;
    }
    const p = k.permission;
    const wide = p.receiverId !== w.cfg.guardId || p.methodNames.length === 0 || p.methodNames.some((m) => !allowedMethods.has(m));
    if (wide)
      out.push({
        invariant: "INV-3",
        message: `key ${short(k.publicKey)} exceeds the agent scope (receiver ${p.receiverId}, methods [${p.methodNames.join(",") || "*"}])`,
        evidence: { publicKey: k.publicKey, receiverId: p.receiverId, methodNames: p.methodNames },
      });
  }
  return out;
}

export async function checkInv5(w: World, trace: Trace): Promise<Violation[] | undefined> {
  const read = w.adapter.readAccounting;
  if (!read) return undefined;
  let acct: { window: bigint; spent: bigint };
  try {
    acct = await read((m, a) => w.view(m, a));
  } catch (e) {
    return [{ invariant: "INV-5", message: `guard accounting view failed: ${String(e)}` }];
  }
  const settled = agentOutflows(w, w.backend.transfers())
    .filter((o) => trace.payTxs.has(o.txHash) && o.window === acct.window)
    .reduce((s, o) => s + o.amount, 0n);
  if (settled === acct.spent) return [];
  return [
    {
      invariant: "INV-5",
      message: `guard records ${fmtNear(acct.spent)} spent in window ${acct.window} but ${fmtNear(settled)} actually settled`,
      evidence: { window: acct.window.toString(), recorded: acct.spent.toString(), settled: settled.toString(), failedTransfers: trace.failedTransfers },
    },
  ];
}

/** INV-6: after allowance exhaustion the owner must be able to restore the agent through the guard. */
export async function checkInv6(w: World, trace: Trace): Promise<Violation[]> {
  if (!trace.allowanceExhausted) return [];
  if (!w.adapter.rekey)
    return [{ invariant: "INV-6", message: "allowance exhausted and the guard has no owner re-key method: agent locked out permanently" }];
  const fresh = w.freshAgentKey();
  const r = await w.exec(w.ownerTx(w.adapter.rekey(fresh.publicKey, w.cfg.agentAllowance)));
  if (r.rejected || r.status?.kind !== "success")
    return [
      {
        invariant: "INV-6",
        message: `allowance exhausted and owner re-key failed: ${r.rejected?.message ?? (r.status?.kind === "failure" ? r.status.error : "?")}`,
        evidence: { txHash: r.txHash },
      },
    ];
  await w.backend.settle();
  // The restored key must be usable: the protocol accepts an agent transaction signed with it.
  const probe = await w.backend.submit(w.agentTx(w.adapter.pay(w.cfg.allowlist[0], 1n), fresh.publicKey));
  await w.backend.settle();
  if (probe.rejected)
    return [
      {
        invariant: "INV-6",
        message: `owner re-key succeeded but the agent still cannot transact: ${probe.rejected.kind}`,
        evidence: { rejection: probe.rejected },
      },
    ];
  w.activeAgentKey = fresh.publicKey;
  return [];
}

/** INV-4: owner revoke leaves the agent with no key on the guard, and owner can withdraw all free funds. */
export async function checkInv4(w: World, trace: Trace): Promise<Violation[]> {
  const out: Violation[] = trace.ownerFailures.map((f) => ({
    invariant: "INV-4" as const,
    message: `owner ${f.op} failed mid-sequence: ${f.error}`,
  }));

  const rv = await w.exec(w.ownerTx(w.adapter.revoke()));
  if (rv.rejected || rv.status?.kind !== "success") {
    out.push({
      invariant: "INV-4",
      message: `owner revoke failed: ${rv.rejected?.message ?? (rv.status?.kind === "failure" ? rv.status.error : "?")}`,
      evidence: { txHash: rv.txHash },
    });
  }
  await w.backend.settle();
  // Only the agent ever holds keys on the guard account, so after revoke there must be none.
  const remaining = await w.backend.accessKeys(w.cfg.guardId);
  for (const k of remaining)
    out.push({
      invariant: "INV-4",
      message: `${w.agentKeyring.has(k.publicKey) ? "agent" : "non-owner"} ${k.permission.kind} key ${short(k.publicKey)} still on the guard after owner revoke`,
      evidence: { publicKey: k.publicKey, permission: k.permission.kind, agentControlled: w.agentKeyring.has(k.publicKey) },
    });

  const free = await w.freeBalance();
  const amount = free > w.cfg.withdrawMargin ? free - w.cfg.withdrawMargin : 0n;
  if (amount > 0n) {
    const before = w.backend.transfers().length;
    const wd = await w.exec(w.ownerTx(w.adapter.withdraw(amount)));
    const received = w.backend
      .transfers()
      .slice(before)
      .filter((t) => t.from === w.cfg.guardId && t.to === w.cfg.ownerId)
      .reduce((s, t) => s + t.amount, 0n);
    if (wd.rejected || wd.status?.kind !== "success" || received < amount)
      out.push({
        invariant: "INV-4",
        message: `owner could not withdraw ${fmtNear(amount)} of free balance: ${
          wd.rejected?.message ?? (wd.status?.kind === "failure" ? wd.status.error : `received only ${fmtNear(received)}`)
        }`,
        evidence: { requested: amount.toString(), received: received.toString(), txHash: wd.txHash },
      });
  }
  return out;
}

/** Run every checker for one executed sequence. */
export async function checkRun(w: World, trace: Trace): Promise<RunVerdict> {
  const checked = new Set<InvariantId>(["INV-1", "INV-2", "INV-3", "INV-4"]);
  const exercised = new Set<InvariantId>();
  const violations: Violation[] = [];

  const outflows = agentOutflows(w, w.backend.transfers());
  if (outflows.length) {
    exercised.add("INV-1");
    exercised.add("INV-2");
  }
  violations.push(...checkInv1(w, outflows), ...checkInv2(w, outflows));

  if (trace.probes.length || trace.steps.some((s) => s.step.k === "extra")) exercised.add("INV-3");
  violations.push(...(await checkInv3(w, trace)));

  const inv5 = await checkInv5(w, trace);
  if (inv5) {
    checked.add("INV-5");
    if (trace.failedTransfers > 0) exercised.add("INV-5");
    violations.push(...inv5);
  }

  checked.add("INV-6");
  if (trace.allowanceExhausted) exercised.add("INV-6");
  violations.push(...(await checkInv6(w, trace)));

  exercised.add("INV-4");
  violations.push(...(await checkInv4(w, trace)));

  return { checked, exercised, violations };
}

function short(pk: string): string {
  return pk.length > 20 ? `${pk.slice(0, 14)}…${pk.slice(-4)}` : pk;
}
