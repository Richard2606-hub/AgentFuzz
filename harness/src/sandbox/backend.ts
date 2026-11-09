/**
 * Sandbox backend: the Backend interface over a real nearcore sandbox (JSON-RPC + near-api-js).
 *
 * The runner, world and invariant checkers are unchanged; only the chain differs. Used to
 * confirm nearsim findings on nearcore: `agentfuzz replay <repro> --backend sandbox`, and the
 * differential test (`agentfuzz diff`).
 *
 * The value-transfer ledger is rebuilt from EXPERIMENTAL_tx_status receipts (predecessor,
 * signer, signer key, actions, outcome) and block timestamps, exactly the fields nearsim records.
 */
import { actions as A, JsonRpcProvider, KeyPair as NearKeyPair, PublicKey, Signature, SignedTransaction, Transaction, baseDecode } from "near-api-js";
import type { Backend } from "../near/backend.js";
import { base58Encode, keyPairFor, sha256 } from "../near/keys.js";
import type { AccessKeyPermission, AccessKeyView, Action, ActionSummary, OutcomeStatus, ReceiptOutcome, SubmitResult, Transaction as AfTx, TxRejection, TxResult, ValueTransfer } from "../near/types.js";
import { startSandbox, type SandboxHandle } from "./process.js";

type Json = any; // eslint-disable-line @typescript-eslint/no-explicit-any

const REJECTIONS: TxRejection[] = [
  "NotEnoughAllowance",
  "ReceiverMismatch",
  "MethodNameMismatch",
  "RequiresFullAccess",
  "DepositWithFunctionCall",
  "NotEnoughBalance",
  "LackBalanceForState",
  "SignerDoesNotExist",
  "InvalidReceiver",
  "Expired",
];

function classifyRejection(text: string): TxRejection {
  for (const k of REJECTIONS) if (text.includes(k)) return k;
  if (text.includes("AccessKeyNotFound") || text.includes("does not exist while viewing access key")) return "AccessKeyNotFound";
  if (text.includes("InvalidReceiverId")) return "InvalidReceiver";
  return "Expired";
}

function toNearAction(a: Action) {
  switch (a.type) {
    case "CreateAccount":
      return A.createAccount();
    case "DeployContract":
      return A.deployContract(a.code);
    case "FunctionCall":
      return A.functionCall(a.methodName, a.args, a.gas, a.deposit);
    case "Transfer":
      return A.transfer(a.deposit);
    case "AddKey":
      return a.permission.kind === "FullAccess"
        ? A.addFullAccessKey(PublicKey.fromString(a.publicKey))
        : A.addFunctionCallAccessKey(PublicKey.fromString(a.publicKey), a.permission.receiverId, a.permission.methodNames, a.permission.allowance ?? undefined);
    case "DeleteKey":
      return A.deleteKey(PublicKey.fromString(a.publicKey));
    case "DeleteAccount":
      return A.deleteAccount(a.beneficiaryId);
    case "Stake":
      return A.stake(a.stake, PublicKey.fromString(a.publicKey));
  }
}

function permissionFromRpc(p: Json): AccessKeyPermission {
  if (p === "FullAccess" || p?.FullAccess !== undefined) return { kind: "FullAccess" };
  const fc = p.FunctionCall ?? p.function_call ?? p;
  return {
    kind: "FunctionCall",
    allowance: fc.allowance === null || fc.allowance === undefined ? null : BigInt(fc.allowance),
    receiverId: fc.receiver_id ?? fc.receiverId,
    methodNames: fc.method_names ?? fc.methodNames ?? [],
  };
}

function actionFromRpc(a: Json): ActionSummary {
  if (a === "CreateAccount") return { type: "CreateAccount" };
  const [kind, v] = Object.entries(a)[0] as [string, Json];
  switch (kind) {
    case "Transfer":
      return { type: "Transfer", deposit: BigInt(v.deposit) };
    case "FunctionCall":
      return { type: "FunctionCall", methodName: v.method_name, args: Buffer.from(v.args ?? "", "base64").toString(), gas: BigInt(v.gas), deposit: BigInt(v.deposit) };
    case "AddKey":
      return { type: "AddKey", publicKey: v.public_key, permission: permissionFromRpc(v.access_key.permission) };
    case "DeleteKey":
      return { type: "DeleteKey", publicKey: v.public_key };
    case "DeleteAccount":
      return { type: "DeleteAccount", beneficiaryId: v.beneficiary_id };
    case "DeployContract":
      return { type: "DeployContract", codeHash: "" };
    case "Stake":
      return { type: "Stake", stake: BigInt(v.stake) };
    default:
      return { type: "CreateAccount" };
  }
}

function statusFromRpc(s: Json): OutcomeStatus {
  if (s?.SuccessValue !== undefined) return { kind: "success", value: s.SuccessValue ? new Uint8Array(Buffer.from(s.SuccessValue, "base64")) : new Uint8Array() };
  if (s?.SuccessReceiptId !== undefined) return { kind: "success" };
  const f = s?.Failure ?? s;
  const text = JSON.stringify(f);
  const panic = /"ExecutionError":"([^"]+)"/.exec(text)?.[1];
  const kind = /"kind":\{"(\w+)"/.exec(text)?.[1] ?? Object.keys(f?.ActionError?.kind ?? {})[0] ?? "Failure";
  return { kind: "failure", error: panic ?? text, errorKind: panic ? "GuestPanic" : kind };
}

export class SandboxBackend implements Backend {
  readonly name = "sandbox" as const;
  /** Measured at start: chain nanoseconds advanced per fast-forwarded block. */
  blockTimeNs = 1_000_000_000n;
  private handle?: SandboxHandle;
  private provider!: JsonRpcProvider;
  private accountKeys = new Map<string, string>();
  private nonces = new Map<string, bigint>();
  private pending: { hash: string; signerId: string }[] = [];
  private processed = new Map<string, TxResult>();
  private ledger: ValueTransfer[] = [];
  private outcomeLog: ReceiptOutcome[] = [];
  private blockInfo = new Map<string, { height: bigint; ts: bigint }>();

  static async start(log?: (s: string) => void): Promise<SandboxBackend> {
    const b = new SandboxBackend();
    b.handle = await startSandbox({ log });
    b.provider = new JsonRpcProvider({ url: b.handle.rpcUrl });
    b.accountKeys.set(b.handle.rootAccountId, b.handle.rootSecretKey);
    await b.calibrate();
    return b;
  }

  async dispose() {
    await this.handle?.stop();
  }

  private async rpc(method: string, params: unknown): Promise<Json> {
    const r = await fetch(this.handle!.rpcUrl, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: "af", method, params }) });
    const j = (await r.json()) as Json;
    if (j.error) throw new Error(JSON.stringify(j.error));
    return j.result;
  }

  private async latest(): Promise<{ height: bigint; ts: bigint; hash: string }> {
    const b = await this.rpc("block", { finality: "optimistic" });
    return { height: BigInt(b.header.height), ts: BigInt(b.header.timestamp_nanosec), hash: b.header.hash };
  }

  private async calibrate() {
    const a = await this.latest();
    await this.rpc("sandbox_fast_forward", { delta_height: 100 });
    await this.waitHeight(a.height + 100n);
    const b = await this.latest();
    const per = (b.ts - a.ts) / (b.height - a.height);
    if (per > 0n) this.blockTimeNs = per;
  }

  private async waitHeight(h: bigint) {
    for (let i = 0; i < 600; i++) {
      if ((await this.latest()).height >= h) return;
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error(`sandbox did not reach height ${h}`);
  }

  private async block(hash: string) {
    let info = this.blockInfo.get(hash);
    if (!info) {
      const b = await this.rpc("block", { block_id: hash });
      info = { height: BigInt(b.header.height), ts: BigInt(b.header.timestamp_nanosec) };
      this.blockInfo.set(hash, info);
    }
    return info;
  }

  private secretFor(accountId: string, publicKey?: string): string {
    if (publicKey) {
      const kp = keyPairFor(publicKey);
      if (kp) return kp.secretKey;
      if (this.handle && publicKey === NearKeyPair.fromString(this.handle.rootSecretKey as never).getPublicKey().toString()) return this.handle.rootSecretKey;
    }
    const k = this.accountKeys.get(accountId);
    if (!k) throw new Error(`no known key for ${accountId}`);
    return k;
  }

  private async sign(tx: AfTx): Promise<{ signed: SignedTransaction; hash: string }> {
    const secret = this.secretFor(tx.signerId, tx.publicKey);
    const kp = NearKeyPair.fromString(secret as never);
    const pk = kp.getPublicKey();
    const nonceKey = `${tx.signerId}/${pk.toString()}`;
    let nonce = this.nonces.get(nonceKey);
    if (nonce === undefined) {
      const ak = await this.rpc("query", { request_type: "view_access_key", finality: "optimistic", account_id: tx.signerId, public_key: pk.toString() });
      nonce = BigInt(ak.nonce);
    }
    nonce += 1n;
    this.nonces.set(nonceKey, nonce);
    const head = await this.latest();
    const transaction = new Transaction({
      signerId: tx.signerId,
      publicKey: pk,
      nonce,
      receiverId: tx.receiverId,
      actions: tx.actions.map(toNearAction),
      blockHash: baseDecode(head.hash),
    });
    const digest = sha256(transaction.encode());
    const sig = kp.sign(digest);
    const signed = new SignedTransaction({ transaction, signature: new Signature({ keyType: pk.keyType, data: sig.signature }) });
    return { signed, hash: base58Encode(digest) };
  }

  // ------------------------------------------------------------------ Backend

  async createAccount(id: string, amount: bigint, fullAccessKeys: string[]) {
    const parent = id.slice(id.indexOf(".") + 1);
    if (!this.accountKeys.has(parent) && !(await this.accountExists(parent))) {
      await this.createAccount(parent, amount + 3n * 10n ** 24n, fullAccessKeys);
    }
    const actions: Action[] = [{ type: "CreateAccount" }, { type: "Transfer", deposit: amount }];
    for (const pk of fullAccessKeys) actions.push({ type: "AddKey", publicKey: pk, permission: { kind: "FullAccess" } });
    const parentKey = this.accountKeys.get(parent);
    if (!parentKey) throw new Error(`cannot create ${id}: no key for parent ${parent}`);
    const parentPk = NearKeyPair.fromString(parentKey as never).getPublicKey().toString();
    const r = await this.execTx({ signerId: parent, publicKey: parentPk, receiverId: id, actions });
    if (r.rejected || r.status?.kind !== "success") throw new Error(`create ${id} failed: ${JSON.stringify(r.rejected ?? r.status)}`);
    if (fullAccessKeys[0]) {
      const kp = keyPairFor(fullAccessKeys[0]);
      if (kp) this.accountKeys.set(id, kp.secretKey);
    }
  }

  async accountExists(id: string) {
    try {
      await this.rpc("query", { request_type: "view_account", finality: "optimistic", account_id: id });
      return true;
    } catch {
      return false;
    }
  }

  async balance(id: string) {
    try {
      const a = await this.rpc("query", { request_type: "view_account", finality: "optimistic", account_id: id });
      return BigInt(a.amount);
    } catch {
      return 0n;
    }
  }

  async storageUsage(id: string) {
    const a = await this.rpc("query", { request_type: "view_account", finality: "optimistic", account_id: id });
    return BigInt(a.storage_usage);
  }

  async accessKeys(id: string): Promise<AccessKeyView[]> {
    try {
      const r = await this.rpc("query", { request_type: "view_access_key_list", finality: "optimistic", account_id: id });
      return r.keys.map((k: Json) => ({ publicKey: k.public_key, nonce: BigInt(k.access_key.nonce), permission: permissionFromRpc(k.access_key.permission) }));
    } catch {
      return [];
    }
  }

  async view(accountId: string, method: string, args: unknown = {}) {
    const r = await this.rpc("query", {
      request_type: "call_function",
      finality: "optimistic",
      account_id: accountId,
      method_name: method,
      args_base64: Buffer.from(JSON.stringify(args ?? {})).toString("base64"),
    });
    const text = Buffer.from(r.result as number[]).toString();
    return text.length ? JSON.parse(text) : undefined;
  }

  async submit(tx: AfTx): Promise<SubmitResult> {
    let signed: SignedTransaction;
    let hash: string;
    try {
      ({ signed, hash } = await this.sign(tx));
    } catch (e) {
      const text = e instanceof Error ? e.message : String(e);
      return { txHash: "unsigned", rejected: { kind: classifyRejection(text), message: text } };
    }
    try {
      await this.rpc("broadcast_tx_async", [Buffer.from(signed.encode()).toString("base64")]);
    } catch (e) {
      const text = e instanceof Error ? e.message : String(e);
      return { txHash: hash, rejected: { kind: classifyRejection(text), message: text } };
    }
    this.pending.push({ hash, signerId: tx.signerId });
    return { txHash: hash };
  }

  async settle() {
    const list = this.pending;
    this.pending = [];
    for (const p of list) await this.fetch(p.hash, p.signerId);
  }

  async execTx(tx: AfTx): Promise<TxResult> {
    const sub = await this.submit(tx);
    if (sub.rejected) return { txHash: sub.txHash, rejected: sub.rejected, receipts: [], logs: [] };
    this.pending = this.pending.filter((p) => p.hash !== sub.txHash);
    return this.fetch(sub.txHash, tx.signerId);
  }

  async txResult(txHash: string): Promise<TxResult> {
    const r = this.processed.get(txHash);
    if (r) return r;
    const p = this.pending.find((x) => x.hash === txHash);
    if (!p) throw new Error(`unknown transaction ${txHash}`);
    return this.fetch(txHash, p.signerId);
  }

  private async fetch(hash: string, signerId: string): Promise<TxResult> {
    const done = this.processed.get(hash);
    if (done) return done;
    let res: Json;
    for (let i = 0; ; i++) {
      try {
        res = await this.rpc("EXPERIMENTAL_tx_status", { tx_hash: hash, sender_account_id: signerId, wait_until: "EXECUTED" });
        break;
      } catch (e) {
        const text = e instanceof Error ? e.message : String(e);
        if (/InvalidTransaction|InvalidTxError|NotEnoughAllowance|RequiresFullAccess|MethodNameMismatch|ReceiverMismatch|DepositWithFunctionCall|AccessKeyNotFound|NotEnoughBalance/.test(text)) {
          const r: TxResult = { txHash: hash, rejected: { kind: classifyRejection(text), message: text }, receipts: [], logs: [] };
          this.processed.set(hash, r);
          return r;
        }
        if (i > 100) throw e;
        await new Promise((r) => setTimeout(r, 150));
      }
    }
    const byId = new Map<string, Json>((res.receipts ?? []).map((r: Json) => [r.receipt_id, r]));
    const firstId: string | undefined = res.transaction_outcome?.outcome?.status?.SuccessReceiptId;
    const outcomes: ReceiptOutcome[] = [];
    for (const ro of res.receipts_outcome ?? []) {
      const rec = byId.get(ro.id);
      const action = rec?.receipt?.Action;
      const b = await this.block(ro.block_hash);
      outcomes.push({
        receiptId: ro.id,
        txHash: hash,
        predecessorId: rec?.predecessor_id ?? "system",
        receiverId: ro.outcome.executor_id,
        signerId: action?.signer_id ?? signerId,
        signerPublicKey: action?.signer_public_key ?? "",
        actions: (action?.actions ?? []).map(actionFromRpc),
        status: statusFromRpc(ro.outcome.status),
        logs: ro.outcome.logs ?? [],
        blockHeight: b.height,
        blockTimestamp: b.ts,
        gasBurnt: BigInt(ro.outcome.gas_burnt ?? 0),
        isRefund: (rec?.predecessor_id ?? "system") === "system",
      });
    }
    outcomes.sort((x, y) => (x.blockHeight === y.blockHeight ? 0 : x.blockHeight < y.blockHeight ? -1 : 1));
    const first = outcomes.find((o) => o.receiptId === firstId) ?? outcomes[0];
    const authTs = first?.blockTimestamp ?? 0n;
    for (const o of outcomes) {
      this.outcomeLog.push(o);
      if (o.status.kind !== "success" || o.predecessorId === o.receiverId) continue;
      const value = o.actions.reduce((s, a) => s + (a.type === "Transfer" || a.type === "FunctionCall" ? a.deposit : 0n), 0n);
      if (value > 0n)
        this.ledger.push({
          from: o.predecessorId,
          to: o.receiverId,
          amount: value,
          txHash: hash,
          receiptId: o.receiptId,
          signerId: o.signerId,
          signerPublicKey: o.signerPublicKey,
          authTimestamp: authTs,
          settledTimestamp: o.blockTimestamp,
          blockHeight: o.blockHeight,
          isRefund: o.isRefund,
        });
    }
    const result: TxResult = {
      txHash: hash,
      status: first?.status,
      finalStatus: statusFromRpc(res.status),
      receipts: outcomes.filter((o) => !o.isRefund),
      logs: outcomes.flatMap((o) => o.logs),
    };
    this.processed.set(hash, result);
    return result;
  }

  async advanceBlocks(n: number) {
    if (n <= 0) return;
    const h = (await this.latest()).height;
    await this.rpc("sandbox_fast_forward", { delta_height: n });
    await this.waitHeight(h + BigInt(n));
  }

  async now() {
    return (await this.latest()).ts;
  }

  transfers(): ValueTransfer[] {
    return this.ledger;
  }

  outcomes(): ReceiptOutcome[] {
    return this.outcomeLog;
  }
}
