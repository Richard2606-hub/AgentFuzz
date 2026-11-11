/**
 * nearsim chain: a deterministic single-shard NEAR runtime model.
 *
 * What it models (the parts guard contracts and invariant checkers depend on):
 *  - accounts, balances, storage staking (LackBalanceForState), contract code
 *  - access keys: full-access vs function-call (receiver, method names, allowance, no deposit)
 *  - transaction validation and fees (InvalidTxError family) incl. allowance exhaustion
 *  - receipts executed block by block; promises, `then` callbacks, joint promises,
 *    promise_return forwarding, data receipts; deposit refunds on failure; state rollback
 *  - an outcome log and a value-transfer ledger with authorisation timestamps
 *
 * Everything is deterministic given the chain seed.
 */
import type {
  AccessKeyPermission,
  AccessKeyView,
  Action,
  ActionSummary,
  OutcomeStatus,
  ReceiptOutcome,
  SubmitResult,
  Transaction,
  TxRejection,
  TxResult,
  ValueTransfer,
} from "../near/types.js";
import { isImplicitAccount, isValidAccountId, publicKeyToBorsh, sha256, sha256Hex } from "../near/keys.js";
import { actionSendCost, codeHash, compileModule, execute, GAS, type ExecResult, type PromiseResultInput } from "./vm.js";

export const STORAGE_BYTE_COST = 10n ** 19n;
export const GAS_PRICE = 100_000_000n;
export const ACCOUNT_BASE_BYTES = 100n;
export const RECORD_OVERHEAD = 40n;
export const GENESIS_TIMESTAMP = 1_767_225_600_000_000_000n; // 2026-01-01T00:00:00Z
export const DEFAULT_BLOCK_TIME = 1_000_000_000n; // 1 s

interface SimAccessKey {
  nonce: bigint;
  permission: AccessKeyPermission;
}

interface SimAccount {
  id: string;
  amount: bigint;
  locked: bigint;
  code?: { hash: string; bytes: Uint8Array; module: WebAssembly.Module };
  storage: Map<string, Uint8Array>;
  dataUsage: bigint;
  keys: Map<string, SimAccessKey>;
}

interface ActionReceipt {
  id: string;
  txHash: string;
  predecessorId: string;
  receiverId: string;
  signerId: string;
  signerPk: string;
  actions: Action[];
  inputDataIds: string[];
  outputDataReceivers: { dataId: string; receiverId: string }[];
  isRefund: boolean;
  /** Price at which this receipt's gas was reserved (inherited by child receipts). */
  gasPrice: bigint;
}

type QueueItem = { kind: "action"; r: ActionReceipt } | { kind: "data"; dataId: string; data: Uint8Array | null };

class ActionError extends Error {
  constructor(
    public readonly kind: string,
    message: string,
  ) {
    super(message);
  }
}

/**
 * Contract storage that can fall back to a remote copy (a fork of a live network). Reads of keys
 * not held locally go to `loader`; deletions leave a tombstone so a removed key is not re-read.
 */
export class LazyStorage extends Map<string, Uint8Array> {
  private tombs = new Set<string>();
  constructor(private readonly loader: (hexKey: string) => Uint8Array | undefined) {
    super();
  }
  override get(k: string): Uint8Array | undefined {
    const v = super.get(k);
    if (v !== undefined || this.tombs.has(k)) return v;
    const remote = this.loader(k);
    if (remote !== undefined) super.set(k, remote);
    return remote;
  }
  override has(k: string): boolean {
    return this.get(k) !== undefined;
  }
  override set(k: string, v: Uint8Array): this {
    this.tombs?.delete(k);
    return super.set(k, v);
  }
  override delete(k: string): boolean {
    const existed = this.has(k);
    super.delete(k);
    this.tombs.add(k);
    return existed;
  }
  clone(): LazyStorage {
    const c = new LazyStorage(this.loader);
    for (const [k, v] of super.entries()) c.set(k, v);
    for (const t of this.tombs) c.tombs.add(t);
    return c;
  }
}

/** An account as a live network reports it, for forking (see simulate/fork.ts). */
export interface ForkedAccount {
  amount: bigint;
  locked: bigint;
  /** Total storage usage as the network reports it (code, keys and data). */
  storageUsage: bigint;
  code?: Uint8Array;
  keys: { publicKey: string; nonce: bigint; permission: AccessKeyPermission }[];
  storage: LazyStorage;
}

/** Where a forked chain gets accounts it has not seen yet: null = does not exist there either. */
export interface ForkSource {
  account(id: string): ForkedAccount | null;
}

export interface SimChainOptions {
  seed?: string;
  blockTimeNs?: bigint;
  genesisTimestamp?: bigint;
  /** Fork a live network: accounts not created locally are loaded from here on first use. */
  fork?: ForkSource;
}

export class SimChain {
  readonly seed: string;
  readonly blockTimeNs: bigint;
  height = 1n;
  timestamp: bigint;

  private accounts = new Map<string, SimAccount>();
  private queue: QueueItem[] = [];
  private postponed = new Map<string, ActionReceipt>();
  private awaitingData = new Map<string, string>(); // dataId -> receiptId
  private receivedData = new Map<string, Uint8Array | null>();
  private idCounter = 0;
  private txFirstTs = new Map<string, bigint>();
  private returnedTo = new Map<string, string>(); // receiptId -> receiptId it promise_returned
  private readonly fork?: ForkSource;
  /** Forked accounts deleted locally, so they are not loaded again. */
  private gone = new Set<string>();

  readonly outcomes: ReceiptOutcome[] = [];
  readonly transfers: ValueTransfer[] = [];

  constructor(opts: SimChainOptions = {}) {
    this.seed = opts.seed ?? "nearsim";
    this.blockTimeNs = opts.blockTimeNs ?? DEFAULT_BLOCK_TIME;
    this.timestamp = opts.genesisTimestamp ?? GENESIS_TIMESTAMP;
    this.fork = opts.fork;
  }

  /** The account, loading it from the fork source on first use. */
  private acct(id: string): SimAccount | undefined {
    const a = this.accounts.get(id);
    if (a || !this.fork || this.gone.has(id)) return a;
    const f = this.fork.account(id);
    if (!f) return undefined;
    const acc: SimAccount = { id, amount: f.amount, locked: f.locked, storage: f.storage.clone(), dataUsage: 0n, keys: new Map() };
    for (const k of f.keys) acc.keys.set(k.publicKey, { nonce: k.nonce, permission: clonePermission(k.permission) });
    if (f.code) acc.code = { hash: codeHash(f.code), bytes: f.code, module: compileModule(f.code) };
    acc.dataUsage = f.storageUsage - storageUsageWithoutData(acc);
    this.accounts.set(id, acc);
    return acc;
  }

  // ------------------------------------------------------------------ genesis-style setup

  /** Create an account directly (like genesis / sandbox root creation). */
  createAccount(id: string, amount: bigint, opts: { fullAccessKeys?: string[]; code?: Uint8Array } = {}) {
    if (!isValidAccountId(id)) throw new Error(`invalid account id '${id}'`);
    if (this.acct(id)) throw new Error(`account '${id}' already exists`);
    const acc: SimAccount = { id, amount, locked: 0n, storage: new Map(), dataUsage: 0n, keys: new Map() };
    for (const pk of opts.fullAccessKeys ?? []) acc.keys.set(pk, { nonce: 0n, permission: { kind: "FullAccess" } });
    if (opts.code) acc.code = { hash: codeHash(opts.code), bytes: opts.code, module: compileModule(opts.code) };
    this.accounts.set(id, acc);
  }

  hasAccount(id: string): boolean {
    return this.acct(id) !== undefined;
  }

  // ------------------------------------------------------------------ queries

  viewAccount(id: string): { amount: bigint; locked: bigint; storageUsage: bigint; codeHash: string | null } | undefined {
    const a = this.acct(id);
    if (!a) return undefined;
    return { amount: a.amount, locked: a.locked, storageUsage: storageUsage(a), codeHash: a.code?.hash ?? null };
  }

  balance(id: string): bigint {
    return this.acct(id)?.amount ?? 0n;
  }

  accessKeys(id: string): AccessKeyView[] {
    const a = this.acct(id);
    if (!a) return [];
    return [...a.keys.entries()].map(([publicKey, k]) => ({ publicKey, nonce: k.nonce, permission: clonePermission(k.permission) }));
  }

  accessKey(id: string, pk: string): AccessKeyView | undefined {
    const k = this.acct(id)?.keys.get(pk);
    return k ? { publicKey: pk, nonce: k.nonce, permission: clonePermission(k.permission) } : undefined;
  }

  /** Read-only contract call. Throws on contract error. */
  view(accountId: string, method: string, args: unknown = {}): unknown {
    const acc = this.acct(accountId);
    if (!acc) throw new Error(`account '${accountId}' does not exist`);
    if (!acc.code) throw new Error(`account '${accountId}' has no contract`);
    const res = execute(acc.code.module, acc.code.bytes.length, method, {
      currentAccountId: accountId,
      signerId: "",
      signerPk: "",
      predecessorId: "",
      input: new TextEncoder().encode(JSON.stringify(args ?? {})),
      blockHeight: this.height,
      blockTimestamp: this.timestamp,
      epochHeight: this.epochHeight(),
      balance: acc.amount,
      locked: acc.locked,
      attachedDeposit: 0n,
      prepaidGas: GAS.maxPrepaid,
      randomSeed: this.randomSeed("view"),
      isView: true,
      storage: acc.storage instanceof LazyStorage ? acc.storage.clone() : new Map(acc.storage),
      storageUsage: storageUsage(acc),
      storageByteCost: STORAGE_BYTE_COST,
      promiseResults: [],
    });
    if (res.error) throw new Error(`view ${accountId}.${method} failed: ${res.error.message}`);
    if (res.returnData.kind !== "value") return undefined;
    const text = new TextDecoder().decode(res.returnData.data);
    return text.length ? JSON.parse(text) : undefined;
  }

  // ------------------------------------------------------------------ transactions

  /** Validate, charge and queue a transaction. Its receipt executes in the next block. */
  submit(tx: Transaction): SubmitResult {
    const txHash = this.newId("tx");
    const reject = (kind: TxRejection, message: string): SubmitResult => ({ txHash, rejected: { kind, message } });

    const signer = this.acct(tx.signerId);
    if (!signer) return reject("SignerDoesNotExist", `signer ${tx.signerId} does not exist`);
    if (!isValidAccountId(tx.receiverId)) return reject("InvalidReceiver", `invalid receiver ${tx.receiverId}`);
    const key = signer.keys.get(tx.publicKey);
    if (!key) return reject("AccessKeyNotFound", `access key ${tx.publicKey} not found on ${tx.signerId}`);

    const sendGas = GAS.receiptCreation + tx.actions.reduce((s, a) => s + actionSendCost(a), 0n);
    const prepaid = tx.actions.reduce((s, a) => s + (a.type === "FunctionCall" ? a.gas : 0n), 0n);
    if (prepaid > GAS.maxPrepaid) return reject("Expired", "total prepaid gas exceeds 300 Tgas");
    // nearcore tx_cost: send fees are burnt at the current gas price; prepaid + exec gas is
    // reserved at a pessimistically inflated price (1.03^depth) and refunded later. A
    // function-call key's allowance is charged the whole reservation and never refunded.
    const receiptGasPrice = pessimisticGasPrice(GAS_PRICE, tx.signerId === tx.receiverId ? 0n : 1n, prepaid);
    const gasCost = sendGas * GAS_PRICE + (prepaid + sendGas) * receiptGasPrice;
    const deposit = tx.actions.reduce((s, a) => s + actionDeposit(a), 0n);

    if (key.permission.kind === "FunctionCall") {
      const perm = key.permission;
      if (tx.actions.length !== 1 || tx.actions[0].type !== "FunctionCall")
        return reject("RequiresFullAccess", "function-call access key can only sign a single FunctionCall action");
      const fc = tx.actions[0];
      if (fc.deposit > 0n) return reject("DepositWithFunctionCall", "function-call access key cannot attach a deposit");
      if (tx.receiverId !== perm.receiverId)
        return reject("ReceiverMismatch", `key is scoped to ${perm.receiverId}, not ${tx.receiverId}`);
      if (perm.methodNames.length > 0 && !perm.methodNames.includes(fc.methodName))
        return reject("MethodNameMismatch", `method '${fc.methodName}' is not allowed by the access key`);
      if (perm.allowance !== null && perm.allowance < gasCost)
        return reject("NotEnoughAllowance", `allowance ${perm.allowance} < cost ${gasCost}`);
    }
    if (signer.amount < gasCost + deposit) return reject("NotEnoughBalance", `${tx.signerId} cannot cover ${gasCost + deposit}`);
    if (signer.amount - gasCost - deposit < storageUsage(signer) * STORAGE_BYTE_COST)
      return reject("LackBalanceForState", `${tx.signerId} would fall below its storage stake`);

    signer.amount -= gasCost + deposit;
    key.nonce += 1n;
    if (key.permission.kind === "FunctionCall" && key.permission.allowance !== null) key.permission.allowance -= gasCost;

    this.queue.push({
      kind: "action",
      r: {
        id: this.newId("r"),
        txHash,
        predecessorId: tx.signerId,
        receiverId: tx.receiverId,
        signerId: tx.signerId,
        signerPk: tx.publicKey,
        actions: tx.actions,
        inputDataIds: [],
        outputDataReceivers: [],
        isRefund: false,
        gasPrice: receiptGasPrice,
      },
    });
    return { txHash };
  }

  /** Submit and run blocks until the transaction's whole receipt tree has settled. */
  execTx(tx: Transaction, maxBlocks = 64): TxResult {
    const sub = this.submit(tx);
    if (sub.rejected) return { txHash: sub.txHash, rejected: sub.rejected, receipts: [], logs: [] };
    this.runUntilIdle(maxBlocks);
    return this.txResult(sub.txHash);
  }

  txResult(txHash: string): TxResult {
    const receipts = this.outcomes.filter((o) => o.txHash === txHash && !o.isRefund);
    const first = receipts[0];
    let final = first;
    const seen = new Set<string>();
    while (final && this.returnedTo.has(final.receiptId) && !seen.has(final.receiptId)) {
      seen.add(final.receiptId);
      const next = this.outcomes.find((o) => o.receiptId === this.returnedTo.get(final!.receiptId));
      if (!next) break;
      final = next;
    }
    return {
      txHash,
      status: first?.status,
      finalStatus: final?.status,
      receipts,
      logs: receipts.flatMap((r) => r.logs),
    };
  }

  // ------------------------------------------------------------------ blocks

  get idle(): boolean {
    return this.queue.length === 0;
  }

  produceBlock() {
    this.height += 1n;
    this.timestamp += this.blockTimeNs;
    const items = this.queue;
    this.queue = [];
    for (const item of items) {
      if (item.kind === "data") this.onData(item.dataId, item.data);
      else this.onActionReceipt(item.r);
    }
  }

  runUntilIdle(maxBlocks = 64) {
    for (let i = 0; i < maxBlocks && !this.idle; i++) this.produceBlock();
  }

  /** Advance `n` blocks, executing anything queued; empty stretches are skipped in O(1). */
  advanceBlocks(n: number | bigint) {
    let left = BigInt(n);
    while (left > 0n && !this.idle) {
      this.produceBlock();
      left -= 1n;
    }
    if (left > 0n) {
      this.height += left;
      this.timestamp += left * this.blockTimeNs;
    }
  }

  // ------------------------------------------------------------------ receipt processing

  private onData(dataId: string, data: Uint8Array | null) {
    this.receivedData.set(dataId, data);
    const rid = this.awaitingData.get(dataId);
    if (!rid) return;
    this.awaitingData.delete(dataId);
    const r = this.postponed.get(rid);
    if (r && r.inputDataIds.every((d) => this.receivedData.has(d))) {
      this.postponed.delete(rid);
      this.applyReceipt(r);
    }
  }

  private onActionReceipt(r: ActionReceipt) {
    const missing = r.inputDataIds.filter((d) => !this.receivedData.has(d));
    if (missing.length === 0) return this.applyReceipt(r);
    this.postponed.set(r.id, r);
    for (const d of missing) this.awaitingData.set(d, r.id);
  }

  private applyReceipt(r: ActionReceipt) {
    if (!this.txFirstTs.has(r.txHash)) this.txFirstTs.set(r.txHash, this.timestamp);
    const promiseResults: PromiseResultInput[] = r.inputDataIds.map((d) => {
      const v = this.receivedData.get(d);
      this.receivedData.delete(d);
      return v === null || v === undefined ? { ok: false } : { ok: true, data: v };
    });

    const existing = this.acct(r.receiverId);
    const snapshot = existing ? cloneAccount(existing) : undefined;
    let acc = existing;
    let created = false;
    let deleted = false;
    const logs: string[] = [];
    let burnt = GAS.receiptCreation;
    let prepaid = 0n;
    let lastExec: ExecResult | undefined;
    const spawned: ActionReceipt[] = [];
    let returnPromiseReceipt: ActionReceipt | undefined;
    let returnValue: Uint8Array | undefined;
    let error: { kind: string; message: string } | undefined;

    try {
      for (const a of r.actions) {
        if (a.type === "FunctionCall") prepaid += a.gas;
        if (!acc) {
          if (a.type === "CreateAccount") {
            const parent = r.receiverId.slice(r.receiverId.indexOf(".") + 1);
            const allowed = r.receiverId.includes(".") && parent === r.predecessorId;
            if (!allowed && !isImplicitAccount(r.receiverId))
              throw new ActionError("CreateAccountNotAllowed", `${r.predecessorId} cannot create ${r.receiverId}`);
            acc = { id: r.receiverId, amount: 0n, locked: 0n, storage: new Map(), dataUsage: 0n, keys: new Map() };
            this.accounts.set(acc.id, acc);
            this.gone.delete(acc.id);
            created = true;
            continue;
          }
          if (a.type === "Transfer" && isImplicitAccount(r.receiverId)) {
            acc = { id: r.receiverId, amount: 0n, locked: 0n, storage: new Map(), dataUsage: 0n, keys: new Map() };
            this.accounts.set(acc.id, acc);
            this.gone.delete(acc.id);
            created = true;
          } else {
            throw new ActionError("AccountDoesNotExist", `account ${r.receiverId} does not exist`);
          }
        }
        if (deleted) throw new ActionError("AccountDoesNotExist", `account ${r.receiverId} was deleted`);
        const needsActor = a.type === "DeployContract" || a.type === "AddKey" || a.type === "DeleteKey" || a.type === "DeleteAccount" || a.type === "Stake";
        if (needsActor && r.predecessorId !== r.receiverId && !created)
          throw new ActionError("ActorNoPermission", `${r.predecessorId} cannot do ${a.type} on ${r.receiverId}`);

        switch (a.type) {
          case "CreateAccount":
            throw new ActionError("AccountAlreadyExists", `account ${r.receiverId} already exists`);
          case "Transfer":
            acc.amount += a.deposit;
            burnt += GAS.actionTransfer;
            break;
          case "DeployContract": {
            let module: WebAssembly.Module;
            try {
              module = compileModule(a.code);
            } catch (e) {
              throw new ActionError("CompilationError", `contract compilation failed: ${String(e)}`);
            }
            acc.code = { hash: codeHash(a.code), bytes: a.code, module };
            burnt += GAS.actionDeploy;
            break;
          }
          case "AddKey":
            if (acc.keys.has(a.publicKey)) throw new ActionError("AddKeyAlreadyExists", `key ${a.publicKey} already exists`);
            acc.keys.set(a.publicKey, { nonce: 0n, permission: clonePermission(a.permission) });
            burnt += GAS.actionAddKey;
            break;
          case "DeleteKey":
            if (!acc.keys.delete(a.publicKey)) throw new ActionError("DeleteKeyDoesNotExist", `key ${a.publicKey} does not exist`);
            burnt += GAS.actionDeleteKey;
            break;
          case "DeleteAccount": {
            if (acc.locked > 0n) throw new ActionError("DeleteAccountStaking", "account is staking");
            spawned.push(this.makeReceipt(r, acc.id, a.beneficiaryId, [{ type: "Transfer", deposit: acc.amount }]));
            acc.amount = 0n;
            deleted = true;
            break;
          }
          case "Stake":
            throw new ActionError("UnsupportedAction", "staking is not supported by nearsim");
          case "FunctionCall": {
            acc.amount += a.deposit;
            if (!acc.code) throw new ActionError("CodeDoesNotExist", `account ${acc.id} has no contract`);
            const res = execute(acc.code.module, acc.code.bytes.length, a.methodName, {
              currentAccountId: acc.id,
              signerId: r.signerId,
              signerPk: r.signerPk,
              predecessorId: r.predecessorId,
              input: a.args,
              blockHeight: this.height,
              blockTimestamp: this.timestamp,
              epochHeight: this.epochHeight(),
              balance: acc.amount,
              locked: acc.locked,
              attachedDeposit: a.deposit,
              prepaidGas: a.gas,
              randomSeed: this.randomSeed(r.id),
              isView: false,
              storage: acc.storage,
              storageUsage: storageUsage(acc),
              storageByteCost: STORAGE_BYTE_COST,
              promiseResults,
            });
            logs.push(...res.logs);
            burnt += res.burntGas;
            lastExec = res;
            if (res.error) throw new ActionError(res.error.kind, res.error.message);
            acc.amount = res.balance;
            acc.dataUsage = res.storageUsage - storageUsageWithoutData(acc);
            const made = res.promises.map((p) =>
              p.kind === "receipt" ? this.makeReceipt(r, acc!.id, p.receiverId, p.actions) : undefined,
            );
            res.promises.forEach((p, i) => {
              if (p.kind !== "receipt") return;
              for (const dep of p.deps) {
                const dataId = this.newId("d");
                made[dep]!.outputDataReceivers.push({ dataId, receiverId: made[i]!.receiverId });
                made[i]!.inputDataIds.push(dataId);
              }
            });
            spawned.push(...(made.filter(Boolean) as ActionReceipt[]));
            if (res.returnData.kind === "promise") {
              returnPromiseReceipt = made[res.returnData.index];
              returnValue = undefined;
            } else {
              returnPromiseReceipt = undefined;
              returnValue = res.returnData.kind === "value" ? res.returnData.data : new Uint8Array();
            }
            break;
          }
        }
      }
      if (acc && !deleted && acc.amount < storageUsage(acc) * STORAGE_BYTE_COST)
        throw new ActionError("LackBalanceForState", `${acc.id} lacks balance for its storage stake`);
    } catch (e) {
      error = e instanceof ActionError ? { kind: e.kind, message: e.message } : { kind: "InternalError", message: String(e) };
    }

    let status: OutcomeStatus;
    if (error) {
      // Roll back the receiver's state and refund attached deposits to the predecessor.
      if (created) {
        this.accounts.delete(r.receiverId);
        if (this.fork) this.gone.add(r.receiverId);
      } else if (snapshot) this.accounts.set(r.receiverId, snapshot);
      const refund = r.actions.reduce((s, a) => s + actionDeposit(a), 0n);
      if (refund > 0n && !r.isRefund && r.predecessorId !== "system") {
        const rr = this.makeReceipt(r, "system", r.predecessorId, [{ type: "Transfer", deposit: refund }]);
        rr.isRefund = true;
        this.queue.push({ kind: "action", r: rr });
      }
      for (const out of r.outputDataReceivers) this.queue.push({ kind: "data", dataId: out.dataId, data: null });
      status = { kind: "failure", error: error.message, errorKind: error.kind };
    } else {
      if (deleted) {
        this.accounts.delete(r.receiverId);
        if (this.fork) this.gone.add(r.receiverId);
      }
      for (const s of spawned) this.queue.push({ kind: "action", r: s });
      if (returnPromiseReceipt) {
        returnPromiseReceipt.outputDataReceivers.push(...r.outputDataReceivers);
        this.returnedTo.set(r.id, returnPromiseReceipt.id);
      } else {
        for (const out of r.outputDataReceivers)
          this.queue.push({ kind: "data", dataId: out.dataId, data: returnValue ?? new Uint8Array() });
      }
      status = { kind: "success", value: returnValue };
      const value = r.actions.reduce((s, a) => s + actionDeposit(a), 0n);
      if (value > 0n && r.predecessorId !== r.receiverId) {
        this.transfers.push({
          from: r.predecessorId,
          to: r.receiverId,
          amount: value,
          txHash: r.txHash,
          receiptId: r.id,
          signerId: r.signerId,
          signerPublicKey: r.signerPk,
          authTimestamp: this.txFirstTs.get(r.txHash) ?? this.timestamp,
          settledTimestamp: this.timestamp,
          blockHeight: this.height,
          isRefund: r.isRefund,
        });
      }
    }

    // Gas refund to the signer: unused prepaid gas at the reserved price, plus the difference
    // between the reserved and the actual price on burnt gas (credited directly; nearsim
    // simplification of nearcore's refund receipts).
    const used = lastExec ? lastExec.usedGas : 0n;
    const unused = prepaid > used ? prepaid - used : 0n;
    const signer = this.acct(r.signerId);
    const refund = unused * r.gasPrice + (r.gasPrice > GAS_PRICE ? burnt * (r.gasPrice - GAS_PRICE) : 0n);
    if (signer && refund > 0n && !r.isRefund) signer.amount += refund;

    this.outcomes.push({
      receiptId: r.id,
      txHash: r.txHash,
      predecessorId: r.predecessorId,
      receiverId: r.receiverId,
      signerId: r.signerId,
      signerPublicKey: r.signerPk,
      actions: r.actions.map(summarise),
      status,
      logs,
      blockHeight: this.height,
      blockTimestamp: this.timestamp,
      gasBurnt: burnt,
      isRefund: r.isRefund,
    });
  }

  private makeReceipt(parent: ActionReceipt, predecessorId: string, receiverId: string, actions: Action[]): ActionReceipt {
    return {
      id: this.newId("r"),
      txHash: parent.txHash,
      predecessorId,
      receiverId,
      signerId: parent.signerId,
      signerPk: parent.signerPk,
      actions,
      inputDataIds: [],
      outputDataReceivers: [],
      isRefund: false,
      gasPrice: parent.gasPrice,
    };
  }

  private newId(prefix: string): string {
    this.idCounter += 1;
    return `${prefix}_${sha256Hex(`${this.seed}/${prefix}/${this.idCounter}`).slice(0, 24)}`;
  }

  private randomSeed(salt: string): Uint8Array {
    return sha256(`${this.seed}/random/${this.height}/${salt}`);
  }

  private epochHeight(): bigint {
    return 1n + this.height / 43_200n;
  }
}

// ---------------------------------------------------------------------------- helpers

/** nearcore `min_receipt_with_function_call_gas`: new_action_receipt + function_call base. */
export const MIN_RECEIPT_WITH_FUNCTION_CALL_GAS = GAS.receiptCreation + GAS.actionFunctionCall;

/** nearcore pessimistic gas price: price * (103/100)^(hop + prepaid / min_receipt_gas), exponent capped at 255. */
export function pessimisticGasPrice(price: bigint, initialHop: bigint, prepaid: bigint): bigint {
  let exponent = initialHop + prepaid / MIN_RECEIPT_WITH_FUNCTION_CALL_GAS;
  if (exponent > 255n) exponent = 255n;
  return (price * 103n ** exponent) / 100n ** exponent;
}

function actionDeposit(a: Action): bigint {
  if (a.type === "Transfer") return a.deposit;
  if (a.type === "FunctionCall") return a.deposit;
  return 0n;
}

function accessKeyBytes(pk: string, perm: AccessKeyPermission): bigint {
  let n = BigInt(publicKeyToBorsh(pk).length) + 8n + 1n;
  if (perm.kind === "FunctionCall") {
    n += perm.allowance === null ? 1n : 17n;
    n += 4n + BigInt(perm.receiverId.length);
    n += 4n + perm.methodNames.reduce((s, m) => s + 4n + BigInt(m.length), 0n);
  }
  return n + RECORD_OVERHEAD;
}

function storageUsageWithoutData(a: SimAccount): bigint {
  let n = ACCOUNT_BASE_BYTES + BigInt(a.code?.bytes.length ?? 0);
  for (const [pk, k] of a.keys) n += accessKeyBytes(pk, k.permission);
  return n;
}

export function storageUsage(a: SimAccount): bigint {
  return storageUsageWithoutData(a) + a.dataUsage;
}

function clonePermission(p: AccessKeyPermission): AccessKeyPermission {
  return p.kind === "FullAccess" ? { kind: "FullAccess" } : { ...p, methodNames: [...p.methodNames] };
}

function cloneAccount(a: SimAccount): SimAccount {
  const keys = new Map<string, SimAccessKey>();
  for (const [pk, k] of a.keys) keys.set(pk, { nonce: k.nonce, permission: clonePermission(k.permission) });
  return { ...a, storage: a.storage instanceof LazyStorage ? a.storage.clone() : new Map(a.storage), keys };
}

function summarise(a: Action): ActionSummary {
  switch (a.type) {
    case "FunctionCall":
      return { type: "FunctionCall", methodName: a.methodName, args: new TextDecoder().decode(a.args), gas: a.gas, deposit: a.deposit };
    case "DeployContract":
      return { type: "DeployContract", codeHash: codeHash(a.code) };
    case "AddKey":
      return { type: "AddKey", publicKey: a.publicKey, permission: clonePermission(a.permission) };
    case "Stake":
      return { type: "Stake", stake: a.stake };
    default:
      return { ...a } as ActionSummary;
  }
}
