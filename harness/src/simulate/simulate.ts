/**
 * Simulate before you sign: run a NEAR transaction against a lazy fork of mainnet or testnet in
 * nearsim (the real contract wasm, the real state at the latest final block) and explain what it
 * would do: NEAR and tokens in and out, keys added or removed, failures, and risk patterns.
 * Read-only; nothing is signed or sent.
 */
import { nameFindings, RPC_OF, networkOf, type Finding, type Network } from "../account/scan.js";
import { viewFunction } from "../anchor/audit-lookup.js";
import { SimChain } from "../sim/chain.js";
import { compileModule } from "../sim/vm.js";
import { fmtNear, isValidAccountId } from "../near/keys.js";
import type { AccessKeyPermission, AccessKeyView, Action, OutcomeStatus, ReceiptOutcome } from "../near/types.js";
import { fromBase64 } from "../util/bytes.js";
import { RemoteFork, StateUnavailable, type ForkStats } from "./fork.js";
import { decodeIntent, tokenContractsOf, units, type TokenMeta } from "./intent.js";

const TGAS = 10n ** 12n;
const ONE_NEAR = 10n ** 24n;
const MAX_ROUNDS = 40;

// ---------------------------------------------------------------- input

export interface TxInput {
  signerId: string;
  receiverId: string;
  actions: Action[];
  /** Key to sign with; default: what a wallet would use (a matching app key, else a full-access key). */
  publicKey?: string;
}

const amount = (v: unknown, what: string): bigint => {
  if (v === undefined || v === null || v === "") return 0n;
  const s = String(v).trim();
  if (!/^\d+$/.test(s)) throw new Error(`${what} must be a whole number of yoctoNEAR, got ${s}`);
  return BigInt(s);
};

/** "1", "0.5", "1.25 NEAR" → yoctoNEAR. */
export function parseNear(s: string): bigint {
  const m = /^\s*(\d+)(?:\.(\d{1,24}))?\s*(?:near|Ⓝ)?\s*$/i.exec(s);
  if (!m) throw new Error(`not a NEAR amount: ${s}`);
  return BigInt(m[1]) * ONE_NEAR + BigInt((m[2] ?? "").padEnd(24, "0"));
}

function argsBytes(args: unknown): Uint8Array {
  if (args === undefined || args === null) return new TextEncoder().encode("{}");
  if (args instanceof Uint8Array) return args;
  if (Array.isArray(args) && args.every((x) => Number.isInteger(x))) return Uint8Array.from(args as number[]);
  if (typeof args === "string") {
    try {
      JSON.parse(args);
      return new TextEncoder().encode(args);
    } catch {
      return fromBase64(args); // explorer / RPC format: base64
    }
  }
  return new TextEncoder().encode(JSON.stringify(args));
}

function permissionFrom(p: unknown): AccessKeyPermission {
  if (p === "FullAccess" || (typeof p === "object" && p !== null && "FullAccess" in p)) return { kind: "FullAccess" };
  const fc = ((p as { FunctionCall?: unknown })?.FunctionCall ?? p) as Record<string, unknown>;
  const receiverId = String(fc.receiverId ?? fc.receiver_id ?? "");
  if (!receiverId) throw new Error("function-call key permission needs a receiverId");
  const allowance = fc.allowance === null || fc.allowance === undefined ? null : amount(fc.allowance, "allowance");
  return { kind: "FunctionCall", receiverId, methodNames: ((fc.methodNames ?? fc.method_names ?? []) as string[]).map(String), allowance };
}

/**
 * One action in any of the shapes wallets and explorers use:
 * wallet-selector `{type:"FunctionCall", params:{methodName,args,gas,deposit}}`,
 * RPC / explorer `{FunctionCall:{method_name,args,gas,deposit}}` or `"CreateAccount"`,
 * or flat `{type:"Transfer", deposit}`.
 */
export function parseAction(raw: unknown): Action {
  if (raw === "CreateAccount") return { type: "CreateAccount" };
  if (typeof raw !== "object" || raw === null) throw new Error(`unrecognised action: ${JSON.stringify(raw)}`);
  const o = raw as Record<string, unknown>;
  let type = typeof o.type === "string" ? o.type : Object.keys(o).length === 1 ? Object.keys(o)[0] : "";
  let p = (typeof o.type === "string" ? (o.params ?? o) : o[type]) as Record<string, unknown>;
  if (p === null || typeof p !== "object") p = {};
  type = type.replace(/^./, (c) => c.toUpperCase());
  switch (type) {
    case "CreateAccount":
      return { type: "CreateAccount" };
    case "Transfer":
      return { type: "Transfer", deposit: amount(p.deposit, "deposit") };
    case "FunctionCall": {
      const methodName = String(p.methodName ?? p.method_name ?? "");
      if (!methodName) throw new Error("FunctionCall needs a methodName");
      return { type: "FunctionCall", methodName, args: argsBytes(p.args), gas: p.gas === undefined ? 30n * TGAS : amount(p.gas, "gas"), deposit: amount(p.deposit, "deposit") };
    }
    case "AddKey": {
      const ak = (p.accessKey ?? p.access_key ?? {}) as Record<string, unknown>;
      return { type: "AddKey", publicKey: String(p.publicKey ?? p.public_key), permission: permissionFrom(ak.permission ?? "FullAccess") };
    }
    case "DeleteKey":
      return { type: "DeleteKey", publicKey: String(p.publicKey ?? p.public_key) };
    case "DeleteAccount":
      return { type: "DeleteAccount", beneficiaryId: String(p.beneficiaryId ?? p.beneficiary_id) };
    case "DeployContract":
      return { type: "DeployContract", code: p.code ? argsBytes(p.code) : new Uint8Array() };
    case "Stake":
      return { type: "Stake", stake: amount(p.stake, "stake"), publicKey: String(p.publicKey ?? p.public_key) };
    default:
      throw new Error(`unsupported action type ${type || JSON.stringify(raw)}`);
  }
}

/** A transaction (or a list, as `signAndSendTransactions` takes) as JSON. The signer can come from `defaultSigner`. */
export function parseTransactions(json: unknown, defaultSigner?: string): TxInput[] {
  const list = Array.isArray(json) ? json : (json as { transactions?: unknown[] })?.transactions ?? [json];
  return list.map((t, i) => {
    const o = t as Record<string, unknown>;
    const signerId = String(o.signerId ?? o.signer_id ?? defaultSigner ?? "").toLowerCase();
    const receiverId = String(o.receiverId ?? o.receiver_id ?? "").toLowerCase();
    if (!isValidAccountId(signerId)) throw new Error(`transaction ${i + 1}: give the signer account (the account that would sign)`);
    if (!isValidAccountId(receiverId)) throw new Error(`transaction ${i + 1}: invalid receiverId ${JSON.stringify(o.receiverId ?? o.receiver_id)}`);
    const actions = (o.actions as unknown[] | undefined) ?? [];
    if (!actions.length) throw new Error(`transaction ${i + 1}: no actions`);
    return { signerId, receiverId, actions: actions.map(parseAction), publicKey: (o.publicKey ?? o.public_key) as string | undefined };
  });
}

// ---------------------------------------------------------------- result

export interface TokenMove {
  contract: string;
  symbol?: string;
  decimals?: number;
  standard: "nep141" | "nep171";
  event: string;
  from?: string;
  to?: string;
  amount?: string;
  tokenIds?: string[];
}

export interface SimTxResult {
  signerId: string;
  receiverId: string;
  /** Key the simulation signed with, and what kind it is. */
  key?: { publicKey: string; kind: "full-access" | "function-call" };
  rejected?: string;
  status: "success" | "failure" | "rejected";
  error?: string;
  returnValue?: string;
  receipts: { receiverId: string; predecessorId: string; actions: string[]; status: "success" | "failure"; error?: string; logs: string[]; isRefund: boolean }[];
}

export interface SimulationResult {
  /** executed: run on a fork of the network. decoded: a contract's state was unreadable, so only the arguments were read. */
  mode: "executed" | "decoded";
  network: Network;
  block: { height: string; hash: string };
  /** False if some code could not be simulated (an unsupported host function); the effects may be incomplete. */
  complete: boolean;
  verdict: "danger" | "warn" | "ok";
  /** What the transaction asks for, decoded from its actions and arguments. */
  intent: string[];
  /** What would happen, from the execution (or the intent, when decoded only). */
  summary: string[];
  /** Why the result is decoded only. */
  note?: string;
  findings: Finding[];
  near: { accountId: string; before: string; after: string | null; delta: string }[];
  fees: string;
  tokens: TokenMove[];
  /** Signers' NEP-141 balances before and after, on every touched token contract. */
  tokenBalances: TokenBalance[];
  keys: { accountId: string; added: (AccessKeyView & { allowanceText?: string })[]; removed: string[] }[];
  txs: SimTxResult[];
  stats: ForkStats & { ms: number };
}

export interface SimulateOptions {
  network?: Network;
  rpcUrl?: string;
  stateRpcUrl?: string;
  log?: (s: string) => void;
}

// ---------------------------------------------------------------- helpers

const errText = (s: OutcomeStatus | undefined) => (s && s.kind === "failure" ? s.error : undefined);

function describeAction(a: ReceiptOutcome["actions"][number]): string {
  switch (a.type) {
    case "Transfer":
      return `transfer ${fmtNear(a.deposit)}`;
    case "FunctionCall": {
      const args = a.args.length > 160 ? `${a.args.slice(0, 160)}…` : a.args;
      return `call ${a.methodName}(${args})${a.deposit ? ` with ${fmtNear(a.deposit)}` : ""}`;
    }
    case "AddKey":
      return `add ${a.permission.kind === "FullAccess" ? "full-access" : "function-call"} key ${a.publicKey}`;
    case "DeleteKey":
      return `delete key ${a.publicKey}`;
    case "DeleteAccount":
      return `delete account, send the rest to ${a.beneficiaryId}`;
    case "DeployContract":
      return `deploy contract ${a.codeHash.slice(0, 12)}…`;
    case "CreateAccount":
      return "create account";
    case "Stake":
      return `stake ${fmtNear(a.stake)}`;
  }
}

/** The key a wallet would sign with: an app key that allows this exact call, else a full-access key. */
function pickKey(keys: AccessKeyView[], tx: TxInput): AccessKeyView | undefined {
  if (tx.publicKey) return keys.find((k) => k.publicKey === tx.publicKey);
  const a = tx.actions[0];
  if (tx.actions.length === 1 && a.type === "FunctionCall" && a.deposit === 0n) {
    const app = keys.find(
      (k) => k.permission.kind === "FunctionCall" && k.permission.receiverId === tx.receiverId && (k.permission.methodNames.length === 0 || k.permission.methodNames.includes(a.methodName)),
    );
    if (app) return app;
  }
  return keys.find((k) => k.permission.kind === "FullAccess");
}

function tokenEvents(outcomes: ReceiptOutcome[]): TokenMove[] {
  const out: TokenMove[] = [];
  for (const o of outcomes) {
    if (o.status.kind !== "success") continue;
    for (const line of o.logs) {
      if (!line.startsWith("EVENT_JSON:")) continue;
      let ev: { standard?: string; event?: string; data?: Record<string, unknown>[] };
      try {
        ev = JSON.parse(line.slice("EVENT_JSON:".length));
      } catch {
        continue;
      }
      if (ev.standard !== "nep141" && ev.standard !== "nep171") continue;
      for (const d of ev.data ?? []) {
        const from = (d.old_owner_id ?? (ev.event?.endsWith("burn") ? d.owner_id : undefined)) as string | undefined;
        const to = (d.new_owner_id ?? (ev.event?.endsWith("mint") ? d.owner_id : undefined)) as string | undefined;
        out.push({ contract: o.receiverId, standard: ev.standard, event: ev.event ?? "", from, to, amount: d.amount as string | undefined, tokenIds: d.token_ids as string[] | undefined });
      }
    }
  }
  return out;
}

export function formatUnits(raw: string, decimals = 0): string {
  const neg = raw.startsWith("-");
  const v = BigInt(neg ? raw.slice(1) : raw);
  if (!decimals) return `${neg ? "-" : ""}${v}`;
  const base = 10n ** BigInt(decimals);
  const frac = (v % base).toString().padStart(decimals, "0").replace(/0+$/, "").slice(0, 6);
  return `${neg ? "-" : ""}${v / base}${frac ? `.${frac}` : ""}`;
}

const allowanceText = (p: AccessKeyPermission) => (p.kind === "FunctionCall" ? (p.allowance === null ? "unlimited gas allowance" : `${fmtNear(p.allowance)} gas allowance`) : undefined);

// ---------------------------------------------------------------- simulate

export async function simulate(txsIn: TxInput[], opts: SimulateOptions = {}): Promise<SimulationResult> {
  if (!txsIn.length) throw new Error("nothing to simulate");
  const t0 = Date.now();
  const network = opts.network ?? networkOf(txsIn[0].signerId);
  const log = opts.log ?? (() => {});
  const fork = await RemoteFork.at(opts.rpcUrl ?? RPC_OF[network], { stateRpcUrl: opts.stateRpcUrl, log });
  log(`forked ${network} at block ${fork.block.height}`);
  const signers = [...new Set(txsIn.map((t) => t.signerId))];
  await fork.preload([...new Set([...signers, ...txsIn.map((t) => t.receiverId)])]);
  for (const s of signers) if (fork.cachedAccount(s) === null) throw new Error(`signer ${s} does not exist on ${network}`);

  let chain!: SimChain;
  let txs: SimTxResult[] = [];
  let outcomes: ReceiptOutcome[] = [];
  for (let round = 1; ; round++) {
    chain = new SimChain({ seed: "simulate", fork, genesisTimestamp: fork.block.timestampNs });
    chain.height = fork.block.height;
    txs = [];
    outcomes = [];
    for (const tx of txsIn) {
      const key = pickKey(chain.accessKeys(tx.signerId), tx);
      const base = { signerId: tx.signerId, receiverId: tx.receiverId };
      if (!key) {
        const why = tx.publicKey ? `key ${tx.publicKey} is not on ${tx.signerId}` : `${tx.signerId} has no key that can sign this`;
        txs.push({ ...base, status: "rejected", rejected: why, receipts: [] });
        continue;
      }
      const r = chain.execTx({ signerId: tx.signerId, receiverId: tx.receiverId, publicKey: key.publicKey, actions: tx.actions }, 256);
      outcomes.push(...r.receipts, ...chain.outcomes.filter((o) => o.txHash === r.txHash && o.isRefund));
      const final = r.finalStatus ?? r.status;
      txs.push({
        ...base,
        key: { publicKey: key.publicKey, kind: key.permission.kind === "FullAccess" ? "full-access" : "function-call" },
        status: r.rejected ? "rejected" : final?.kind === "failure" || r.status?.kind === "failure" ? "failure" : "success",
        rejected: r.rejected ? humanRejection(r.rejected, tx, fork.cachedAccount(tx.signerId)?.amount ?? 0n) : undefined,
        error: errText(final) ?? errText(r.status),
        returnValue: final?.kind === "success" && final.value?.length ? new TextDecoder().decode(final.value).slice(0, 2000) : undefined,
        receipts: chain.outcomes
          .filter((o) => o.txHash === r.txHash)
          .map((o) => ({ receiverId: o.receiverId, predecessorId: o.predecessorId, actions: o.actions.map(describeAction), status: o.status.kind, error: errText(o.status), logs: o.logs, isRefund: o.isRefund })),
      });
    }
    if (!fork.hasMisses) break;
    if (round >= MAX_ROUNDS) throw new Error(`the transaction kept reading new state after ${MAX_ROUNDS} rounds; giving up`);
    try {
      await fork.fetchMisses();
    } catch (e) {
      if (!(e instanceof StateUnavailable)) throw e;
      log(e.message);
      return decodedOnly(txsIn, network, fork, e.message, t0);
    }
  }

  // ------------------------------------------------ effects
  const touched = new Set<string>([...signers]);
  for (const o of outcomes) touched.add(o.receiverId);
  const near: SimulationResult["near"] = [];
  for (const id of touched) {
    const before = fork.cachedAccount(id);
    const after = chain.viewAccount(id);
    const b = before?.amount ?? 0n;
    const a = after?.amount;
    if (a === undefined && !before) continue;
    if (a !== undefined && a === b) continue;
    near.push({ accountId: id, before: b.toString(), after: a === undefined ? null : a.toString(), delta: ((a ?? 0n) - b).toString() });
  }
  const signerSet = new Set(signers);
  const valueMoves = chain.transfers.filter((t) => signerSet.has(t.from) || signerSet.has(t.to));
  // fee = -(balance change) - value that left (delivered, or attached to a step that failed and was refunded) + value that came in.
  const outgoing = valueMoves.filter((t) => signerSet.has(t.from) && !signerSet.has(t.to)).reduce((s, t) => s + t.amount, 0n);
  const incoming = valueMoves.filter((t) => signerSet.has(t.to) && !signerSet.has(t.from)).reduce((s, t) => s + t.amount, 0n);
  const failedAttached = outcomes
    .filter((o) => o.status.kind === "failure" && !o.isRefund && signerSet.has(o.predecessorId))
    .reduce((s, o) => s + o.actions.reduce((x, a) => x + (a.type === "Transfer" || a.type === "FunctionCall" ? a.deposit : 0n), 0n), 0n);
  const signerDelta = near.filter((n) => signerSet.has(n.accountId)).reduce((s, n) => s + BigInt(n.delta), 0n);
  const deleted = signers.some((s) => !chain.viewAccount(s));
  const feesRaw = -signerDelta - outgoing - failedAttached + incoming;
  const fees = deleted || feesRaw < 0n ? 0n : feesRaw;

  const tokens = tokenEvents(outcomes);
  const meta = await tokenMeta([...tokens.filter((t) => t.standard === "nep141").map((t) => t.contract), ...tokenContractsOf(txsIn)], fork.rpcUrl);
  for (const t of tokens) Object.assign(t, meta.get(t.contract) ?? {});
  const intent = decodeIntent(txsIn, network, meta);
  const balances = await tokenBalances(fork, chain, [...touched], signers, meta, log);

  const keys: SimulationResult["keys"] = [];
  for (const s of signers) {
    const before = fork.cachedAccount(s)?.keys ?? [];
    const after = chain.accessKeys(s);
    const added = after.filter((k) => !before.some((b) => b.publicKey === k.publicKey)).map((k) => ({ ...k, allowanceText: allowanceText(k.permission) }));
    const removed = before.filter((b) => !after.some((k) => k.publicKey === b.publicKey)).map((b) => b.publicKey);
    if (added.length || removed.length) keys.push({ accountId: s, added, removed });
  }

  // ------------------------------------------------ explain
  const findings: Finding[] = [];
  const summary: string[] = [];
  const unsupported = outcomes.filter((o) => o.status.kind === "failure" && o.status.errorKind === "UnsupportedHostFunction");
  const complete = unsupported.length === 0;
  if (!complete)
    findings.push({
      severity: "warn",
      area: "contract",
      title: "Could not simulate everything",
      detail: `${[...new Set(unsupported.map((o) => o.receiverId))].join(", ")} called a NEAR host function the simulator does not support yet (${[...new Set(unsupported.map((o) => errText(o.status)))].join("; ")}). The real result may differ.`,
    });

  txs.forEach((t, i) => {
    const label = txs.length > 1 ? `Transaction ${i + 1} ` : "This transaction ";
    if (t.status === "rejected")
      findings.push({ severity: "warn", area: "account", title: `${label}would be refused`, detail: `${t.rejected}. Nothing would happen and no fee would be charged.` });
    else if (t.status === "failure")
      findings.push({ severity: "warn", area: "contract", title: `${label}fails`, detail: `${t.error ?? "a receipt failed"}. Attached NEAR is refunded, but you still pay the fee.` });
    else {
      const inner = t.receipts.filter((r) => r.status === "failure" && !r.isRefund);
      if (inner.length)
        findings.push({ severity: "info", area: "contract", title: `${label}succeeds, but ${inner.length} inner step${inner.length > 1 ? "s" : ""} failed`, detail: inner.map((r) => `${r.receiverId}: ${r.error}`).join(" · ") });
    }
    if (t.key?.kind === "function-call") summary.push(`Signed with your app key for ${t.receiverId}: a wallet may send this without asking you.`);
  });

  for (const s of signers) {
    const before = fork.cachedAccount(s)!;
    const after = chain.viewAccount(s);
    const outs = new Map<string, bigint>();
    const ins = new Map<string, bigint>();
    for (const t of valueMoves) {
      if (signerSet.has(t.from) && t.from === s) outs.set(t.to, (outs.get(t.to) ?? 0n) + t.amount);
      if (t.to === s && !signerSet.has(t.from)) ins.set(t.from, (ins.get(t.from) ?? 0n) + t.amount);
    }
    for (const [to, v] of outs) summary.push(`${s} sends ${fmtNear(v)} to ${to}`);
    for (const [from, v] of ins) summary.push(from === "system" ? `${fmtNear(v)} comes back to ${s} (refund of a failed step)` : `${s} receives ${fmtNear(v)} from ${from}`);
    const sent = [...outs.values()].reduce((a, b) => a + b, 0n) - [...ins.values()].reduce((a, b) => a + b, 0n);
    if (before.amount > 0n && sent * 2n > before.amount && !deleted)
      findings.push({ severity: "warn", area: "account", title: `Sends ${Number((sent * 100n) / before.amount)}% of your NEAR`, detail: `${fmtNear(sent)} of your ${fmtNear(before.amount)} balance. Make sure that is what you meant.` });
    if (!after) {
      const ben = txsIn.flatMap((t) => t.actions).find((a) => a.type === "DeleteAccount") as Extract<Action, { type: "DeleteAccount" }> | undefined;
      summary.push(`Deletes the account ${s}${ben ? ` and sends everything left to ${ben.beneficiaryId}` : ""}`);
      findings.push({ severity: "danger", area: "account", title: `Deletes your account ${s}`, detail: `The account and its name are gone${ben ? `, and its remaining NEAR goes to ${ben.beneficiaryId}` : ""}. Tokens and NFTs it holds are not moved and are lost.` });
    }
    const deployed = txsIn.some((t) => t.signerId === s && t.receiverId === s && t.actions.some((a) => a.type === "DeployContract"));
    if (deployed && after)
      findings.push({ severity: "danger", area: "contract", title: "Replaces your account's code", detail: "A contract deployed on your own account decides what can happen to your funds. Only do this with code you built or audited." });
  }

  for (const k of keys) {
    for (const a of k.added) {
      const p = a.permission;
      if (p.kind === "FullAccess") {
        summary.push(`Adds a full-access key ${a.publicKey} to ${k.accountId}`);
        findings.push({ severity: "danger", area: "keys", title: "Gives someone full control of your account", detail: `It adds the full-access key ${a.publicKey}. Whoever holds it can take every coin and token and delete the account, without asking you again.` });
      } else {
        summary.push(`Adds an app key for ${p.receiverId} (${p.methodNames.length ? p.methodNames.join(", ") : "any method"}, ${a.allowanceText})`);
        if (p.allowance === null) findings.push({ severity: "warn", area: "keys", title: "Adds an app key with unlimited gas allowance", detail: `The key for ${p.receiverId} can keep spending your NEAR on fees. A normal sign-in key has a small allowance (0.25 NEAR).` });
        if (p.receiverId === k.accountId && !p.methodNames.length)
          findings.push({ severity: "danger", area: "keys", title: "Adds a key for every method of your own contract", detail: "It can call anything on your account's contract as you, including admin methods." });
      }
    }
    for (const r of k.removed) summary.push(`Removes the key ${r} from ${k.accountId}`);
    const after = chain.accessKeys(k.accountId);
    if (k.removed.length && !after.some((x) => x.permission.kind === "FullAccess") && fork.cachedAccount(k.accountId)?.keys.some((x) => x.permission.kind === "FullAccess") && !chain.viewAccount(k.accountId)?.codeHash)
      findings.push({ severity: "danger", area: "keys", title: "Removes your last full-access key", detail: "After this, no key can move your NEAR or change the account. Your funds would be locked for good." });
  }

  for (const t of tokens) {
    const amt = t.amount !== undefined ? `${formatUnits(t.amount, t.decimals)} ${t.symbol ?? t.contract}` : `${t.tokenIds?.join(", ")} (${t.contract})`;
    if (t.from && signerSet.has(t.from) && t.to) summary.push(`${t.from} sends ${amt} to ${t.to}`);
    else if (t.to && signerSet.has(t.to) && t.from) summary.push(`${t.to} receives ${amt} from ${t.from}`);
    else if (t.to && signerSet.has(t.to)) summary.push(`${t.to} receives ${amt} (minted by ${t.contract})`);
    else if (t.from && signerSet.has(t.from)) summary.push(`${t.from} gives up ${amt} (burned by ${t.contract})`);
  }
  // Token balances read before and after, for contracts that changed them without NEP-141 events.
  for (const b of balances) {
    const d = BigInt(b.delta);
    if (d === 0n || tokens.some((t) => t.contract === b.contract && (signerSet.has(t.from ?? "") || signerSet.has(t.to ?? "")))) continue;
    summary.push(`${b.accountId} ${d > 0n ? "receives" : "sends"} ${units((d < 0n ? -d : d).toString(), b)} (token ${b.contract})`);
  }

  // What the arguments ask for (approvals, token recipients) and look-alikes anywhere money or tokens go.
  for (const f of intent.findings) if (!findings.some((x) => x.title === f.title)) findings.push(f);
  const recipients = new Set<string>([...txsIn.map((t) => t.receiverId), ...valueMoves.filter((v) => signerSet.has(v.from)).map((v) => v.to), ...tokens.filter((t) => t.from && signerSet.has(t.from) && t.to).map((t) => t.to!)]);
  for (const t of txsIn) for (const a of t.actions) if (a.type === "DeleteAccount") recipients.add(a.beneficiaryId);
  for (const r of recipients) {
    if (r === "system" || signerSet.has(r) || findings.some((f) => f.title.includes(` ${r}:`))) continue;
    for (const f of nameFindings(r, network).filter((f) => f.severity === "danger")) findings.push({ ...f, title: `Recipient ${r}: ${f.title.charAt(0).toLowerCase()}${f.title.slice(1)}` });
    const exists = chain.viewAccount(r) ?? fork.cachedAccount(r);
    if (!exists && !/^[0-9a-f]{64}$/.test(r) && !findings.some((f) => f.title.includes(r)))
      findings.push({ severity: "warn", area: "account", title: `${r} does not exist on ${network}`, detail: "Anything sent there fails and is refunded. Check the spelling and the network." });
  }

  if (fees > 0n) summary.push(`Network fee: about ${nearText(fees)}`);
  if (!summary.length) summary.push("No NEAR, tokens or keys change hands.");
  const verdict = findings.some((f) => f.severity === "danger") ? "danger" : findings.some((f) => f.severity === "warn") ? "warn" : "ok";
  if (verdict === "ok") findings.push({ severity: "ok", area: "account", title: "No risk pattern found", detail: "It does what the summary says. Check the amounts and recipients are what you expect." });

  log(`done in ${Date.now() - t0} ms: ${fork.stats.rounds + 1} rounds, ${fork.stats.accounts} accounts, ${fork.stats.storageKeys + fork.stats.wholeStates} state reads`);
  return {
    mode: "executed",
    network,
    block: { height: fork.block.height.toString(), hash: fork.block.hash },
    complete,
    verdict,
    intent: intent.lines,
    summary,
    findings: sortFindings(findings),
    near,
    fees: fees.toString(),
    tokens,
    tokenBalances: balances,
    keys,
    txs,
    stats: { ...fork.stats, ms: Date.now() - t0 },
  };
}

export interface TokenBalance {
  accountId: string;
  contract: string;
  symbol?: string;
  decimals?: number;
  before: string;
  after: string;
  delta: string;
}

const viewBalance = (chain: SimChain, contract: string, accountId: string): string | undefined => {
  try {
    const v = chain.view(contract, "ft_balance_of", { account_id: accountId });
    return typeof v === "string" && /^\d+$/.test(v) ? v : undefined;
  } catch {
    return undefined;
  }
};

/** The signers' balance on every touched contract that exports ft_balance_of, before and after. */
async function tokenBalances(fork: RemoteFork, post: SimChain, touched: string[], signers: string[], meta: Map<string, TokenMeta>, log: (s: string) => void): Promise<TokenBalance[]> {
  const contracts = touched.filter((id) => {
    const code = fork.cachedAccount(id)?.code;
    return !!code && WebAssembly.Module.exports(compileModule(code)).some((e) => e.name === "ft_balance_of");
  });
  if (!contracts.length) return [];
  for (const [c, m] of await tokenMeta(contracts.filter((c) => !meta.has(c)), fork.rpcUrl)) meta.set(c, m);
  for (let round = 0; round < 8; round++) {
    const pre = new SimChain({ seed: "simulate-before", fork, genesisTimestamp: fork.block.timestampNs });
    const out: TokenBalance[] = [];
    for (const c of contracts)
      for (const s of signers) {
        const before = viewBalance(pre, c, s);
        const after = viewBalance(post, c, s);
        if (before !== undefined && after !== undefined) out.push({ accountId: s, contract: c, ...meta.get(c), before, after, delta: (BigInt(after) - BigInt(before)).toString() });
      }
    if (!fork.hasMisses) return out;
    try {
      await fork.fetchMisses();
    } catch (e) {
      if (e instanceof StateUnavailable) {
        log(`token balances skipped: ${e.message}`);
        return [];
      }
      throw e;
    }
  }
  return [];
}

const sortFindings = (f: Finding[]) => f.sort((a, b) => ["danger", "warn", "info", "ok"].indexOf(a.severity) - ["danger", "warn", "info", "ok"].indexOf(b.severity));

/** NEAR amount readable at fee scale: "0.000045 NEAR". */
export function nearText(yocto: bigint): string {
  if (yocto === 0n) return "0 NEAR";
  if (yocto < 10n ** 18n) return "less than 0.000001 NEAR";
  const whole = yocto / ONE_NEAR;
  const frac = (yocto % ONE_NEAR).toString().padStart(24, "0").slice(0, 6).replace(/0+$/, "");
  return `${whole}${frac ? `.${frac}` : ""} NEAR`;
}

function humanRejection(r: { kind: string; message: string }, tx: TxInput, balance: bigint): string {
  const attached = tx.actions.reduce((s, a) => s + (a.type === "Transfer" || a.type === "FunctionCall" ? a.deposit : 0n), 0n);
  switch (r.kind) {
    case "NotEnoughBalance":
      return `Not enough NEAR: ${tx.signerId} has ${nearText(balance)}, and this needs ${nearText(attached)} plus fees`;
    case "LackBalanceForState":
      return `${tx.signerId} would keep too little NEAR to pay for its own storage (every account must keep some NEAR for the data it stores)`;
    case "NotEnoughAllowance":
      return "The app key's gas allowance is used up; the wallet would need your full-access key";
    case "ReceiverMismatch":
    case "MethodNameMismatch":
    case "DepositWithFunctionCall":
    case "RequiresFullAccess":
      return `The chosen key cannot sign this (${r.message})`;
    default:
      return `${r.kind}: ${r.message}`;
  }
}

async function tokenMeta(contracts: string[], rpcUrl: string): Promise<Map<string, TokenMeta>> {
  const meta = new Map<string, TokenMeta>();
  await Promise.all(
    [...new Set(contracts)].map(async (c) => {
      try {
        const m = (await viewFunction(c, "ft_metadata", {}, rpcUrl)) as TokenMeta;
        meta.set(c, { symbol: m.symbol, decimals: m.decimals });
      } catch {
        meta.set(c, {});
      }
    }),
  );
  return meta;
}

/** When a contract's state cannot be read: what the transaction asks for, decoded from its arguments, not executed. */
async function decodedOnly(txsIn: TxInput[], network: Network, fork: RemoteFork, reason: string, t0: number): Promise<SimulationResult> {
  const meta = await tokenMeta(tokenContractsOf(txsIn), fork.rpcUrl);
  const intent = decodeIntent(txsIn, network, meta);
  const findings: Finding[] = [
    {
      severity: "warn",
      area: "contract",
      title: "Not executed: decoded from the transaction only",
      detail: `The simulator ${reason.replace(/^could not/, "could not")}. Below is what the transaction asks for, read from its arguments; whether it succeeds, and what the contract gives back, was not simulated.`,
    },
    ...intent.findings,
  ];
  const signers = [...new Set(txsIn.map((t) => t.signerId))];
  for (const s of signers) {
    const bal = fork.cachedAccount(s)?.amount ?? 0n;
    const mine = txsIn.filter((t) => t.signerId === s);
    const attached = decodeIntent(mine, network, meta).attached;
    if (attached > bal) findings.push({ severity: "warn", area: "account", title: "Not enough NEAR", detail: `${s} has ${nearText(bal)}, and this attaches ${nearText(attached)} plus fees. It would be refused.` });
    else if (bal > 0n && attached * 2n > bal) findings.push({ severity: "warn", area: "account", title: `Sends ${Number((attached * 100n) / bal)}% of your NEAR`, detail: `${nearText(attached)} of your ${nearText(bal)} balance. Make sure that is what you meant.` });
    for (const t of mine)
      for (const a of t.actions) {
        if (t.receiverId !== s) continue;
        if (a.type === "AddKey" && a.permission.kind === "FullAccess")
          findings.push({ severity: "danger", area: "keys", title: "Gives someone full control of your account", detail: `It adds the full-access key ${a.publicKey}. Whoever holds it can take every coin and token and delete the account.` });
        if (a.type === "DeleteAccount") findings.push({ severity: "danger", area: "account", title: `Deletes your account ${s}`, detail: `Its remaining NEAR goes to ${a.beneficiaryId}; tokens and NFTs it holds are lost.` });
        if (a.type === "DeployContract") findings.push({ severity: "danger", area: "contract", title: "Replaces your account's code", detail: "A contract deployed on your own account decides what can happen to your funds." });
      }
  }
  const verdict = findings.some((f) => f.severity === "danger") ? "danger" : "warn";
  return {
    mode: "decoded",
    network,
    block: { height: fork.block.height.toString(), hash: fork.block.hash },
    complete: false,
    verdict,
    intent: intent.lines,
    summary: [...intent.lines, "Plus a network fee"],
    findings: sortFindings(findings),
    near: [],
    fees: "0",
    tokens: [],
    tokenBalances: [],
    keys: [],
    txs: [],
    note: reason,
    stats: { ...fork.stats, ms: Date.now() - t0 },
  };
}


/** A transaction from simple fields (the CLI flags and the playground form). Amounts in NEAR, gas in Tgas. */
export function txFromFields(f: { signerId: string; receiverId: string; transferNear?: string; method?: string; args?: string; depositNear?: string; gasTgas?: string }): TxInput {
  const signerId = f.signerId.trim().toLowerCase();
  const receiverId = f.receiverId.trim().toLowerCase();
  if (!isValidAccountId(signerId)) throw new Error(`"${f.signerId}" is not a valid signer account id`);
  if (!isValidAccountId(receiverId)) throw new Error(`"${f.receiverId}" is not a valid receiver account id`);
  const actions: Action[] = [];
  if (f.method) {
    const args = f.args?.trim() || "{}";
    try {
      JSON.parse(args);
    } catch {
      throw new Error("arguments must be JSON, e.g. {\"receiver_id\":\"bob.near\",\"amount\":\"1000\"}");
    }
    const gas = f.gasTgas?.trim() ? BigInt(Math.round(Number(f.gasTgas) * 1000)) * (TGAS / 1000n) : 30n * TGAS;
    actions.push({ type: "FunctionCall", methodName: f.method.trim(), args: new TextEncoder().encode(args), gas, deposit: f.depositNear?.trim() ? parseNear(f.depositNear) : 0n });
  } else actions.push({ type: "Transfer", deposit: parseNear(f.transferNear ?? "0") });
  return { signerId, receiverId, actions };
}

/** Exit codes of `agentfuzz simulate`: 0 nothing risky, 2 danger, 3 review (fails, refused, or not fully simulated). */
export function simulateExitCode(r: SimulationResult): number {
  return r.verdict === "danger" ? 2 : r.verdict === "warn" || !r.complete ? 3 : 0;
}
