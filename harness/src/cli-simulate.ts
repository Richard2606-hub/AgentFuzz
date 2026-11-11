/**
 * agentfuzz simulate: run a transaction on a fork of mainnet or testnet before signing it.
 */
import { readFileSync, existsSync } from "node:fs";
import { parseTransactions, simulate, simulateExitCode, txFromFields, nearText, type TxInput } from "./simulate/simulate.js";
import type { Network, Severity } from "./account/scan.js";
import { units } from "./simulate/intent.js";
import { fmtNear } from "./near/keys.js";
import { c } from "./util/term.js";

type Flags = Record<string, string | boolean>;
const str = (f: Flags, k: string) => (typeof f[k] === "string" ? (f[k] as string) : undefined);

const SEV: Record<Severity, (s: string) => string> = {
  danger: (s) => c.red(`  ✗ ${s}`),
  warn: (s) => c.yellow(`  ! ${s}`),
  info: (s) => c.cyan(`  i ${s}`),
  ok: (s) => c.green(`  ✓ ${s}`),
};

export const SIMULATE_USAGE = `usage:
  agentfuzz simulate --signer you.near --to bob.near --transfer 1.5
  agentfuzz simulate --signer you.near --to wrap.near --call near_deposit --deposit 1
  agentfuzz simulate --signer you.near --to usdt.tether-token.near --call ft_transfer --args '{"receiver_id":"bob.near","amount":"1000000"}' --deposit 0.000000000000000000000001
  agentfuzz simulate --tx tx.json [--signer you.near]   (wallet-selector or RPC transaction JSON, or a list of them)
  options: --network mainnet|testnet  --gas TGAS  --state-rpc URL  --json`;

export async function cmdSimulate(flags: Flags): Promise<number> {
  const signer = str(flags, "signer");
  let txs: TxInput[];
  const txArg = str(flags, "tx");
  if (txArg) {
    const text = existsSync(txArg) ? readFileSync(txArg, "utf8") : txArg;
    txs = parseTransactions(JSON.parse(text), signer);
  } else {
    const to = str(flags, "to");
    if (!signer || !to || (!str(flags, "transfer") && !str(flags, "call"))) throw new Error(SIMULATE_USAGE);
    txs = [txFromFields({ signerId: signer, receiverId: to, transferNear: str(flags, "transfer"), method: str(flags, "call"), args: str(flags, "args"), depositNear: str(flags, "deposit"), gasTgas: str(flags, "gas") })];
  }
  const network = str(flags, "network") as Network | undefined;
  if (network && network !== "mainnet" && network !== "testnet") throw new Error("--network must be mainnet or testnet");
  const json = !!flags.json;
  if (!json) console.log(`${c.bold("AgentFuzz simulate")} ${c.dim("·")} ${txs.map((t) => `${t.signerId} → ${t.receiverId}`).join(", ")}`);
  const r = await simulate(txs, { network, rpcUrl: str(flags, "rpc"), stateRpcUrl: str(flags, "state-rpc"), log: json ? undefined : (s) => console.log(c.dim(`  · ${s}`)) });
  if (json) {
    process.stdout.write(JSON.stringify(r, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2) + "\n");
    return simulateExitCode(r);
  }
  console.log("");
  console.log(c.bold(`  What it asks for`));
  for (const l of r.intent) console.log(`    ${l}`);
  console.log(c.bold(r.mode === "executed" ? `\n  What would happen (simulated on ${r.network} at block ${r.block.height})` : `\n  Not simulated (decoded only)`));
  for (const l of r.summary) console.log(`    ${l}`);
  for (const b of r.tokenBalances) if (b.delta !== "0") console.log(c.dim(`    ${b.accountId} on ${b.contract}: ${units(b.before, b)} → ${units(b.after, b)}`));
  for (const n of r.near) console.log(c.dim(`    ${n.accountId}: ${fmtNear(BigInt(n.before))} → ${n.after === null ? "deleted" : fmtNear(BigInt(n.after))}`));
  console.log("");
  for (const f of r.findings) {
    console.log(SEV[f.severity](f.title));
    console.log(c.dim(`      ${f.detail}`));
  }
  if (r.mode === "executed") {
    console.log(c.dim(`\n  receipts:`));
    for (const t of r.txs) for (const x of t.receipts) console.log(c.dim(`    ${x.status === "success" ? "ok  " : "FAIL"} ${x.predecessorId} → ${x.receiverId}: ${x.actions.join("; ")}${x.error ? ` (${x.error})` : ""}`));
  }
  const verdict = { danger: c.red("danger: do not sign this as it is"), warn: c.yellow("review the ! items before signing"), ok: c.green("nothing risky found") }[r.verdict];
  console.log(`\n  verdict: ${verdict}${r.fees !== "0" ? c.dim(` · fee ≈ ${nearText(BigInt(r.fees))}`) : ""} ${c.dim(`· ${r.stats.ms} ms`)}`);
  console.log(c.dim("  Simulated with nearsim on the network's current state; nothing was signed or sent."));
  return simulateExitCode(r);
}
