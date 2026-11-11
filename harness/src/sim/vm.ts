/**
 * nearsim VM: runs real NEAR contract wasm in Node by implementing the NEAR host-function
 * ABI (`env.*` imports from near-vm-logic) on top of WebAssembly.
 *
 * Fidelity notes (documented in ARCHITECTURE.md):
 *  - Semantics of registers, storage, promises, balances, deposits and promise results follow
 *    near-vm-logic. Errors use nearcore's names (GuestPanic, BalanceExceeded, GasExceeded...).
 *  - Gas is a deterministic approximation: host calls, storage bytes, action creation and
 *    contract loading are charged with nearcore-like constants, but wasm instructions are not
 *    metered. Use the sandbox backend for exact gas.
 */
import { sha256 as sha256Bytes } from "../platform/crypto.js";
import { toHex, utf16leDecode } from "../util/bytes.js";
import type { Action, AccessKeyPermission } from "../near/types.js";
import {
  ed25519Verify,
  isValidAccountId,
  isImplicitAccount,
  publicKeyFromBorsh,
  publicKeyToBorsh,
  u128FromLeBytes,
  u128ToLeBytes,
} from "../near/keys.js";

export class HostError extends Error {
  constructor(
    public readonly kind: string,
    message: string,
  ) {
    super(message);
  }
}

export interface PromiseReceipt {
  kind: "receipt";
  receiverId: string;
  actions: Action[];
  /** Indices (into the promise table) of receipts whose output this receipt waits for. */
  deps: number[];
}
export interface PromiseJoint {
  kind: "and";
  receipts: number[];
}
export type PromiseEntry = PromiseReceipt | PromiseJoint;

export type PromiseResultInput = { ok: true; data: Uint8Array } | { ok: false };

export interface ExecContext {
  currentAccountId: string;
  signerId: string;
  signerPk: string;
  predecessorId: string;
  input: Uint8Array;
  blockHeight: bigint;
  blockTimestamp: bigint;
  epochHeight: bigint;
  /** Account balance with the attached deposit already credited. */
  balance: bigint;
  locked: bigint;
  attachedDeposit: bigint;
  prepaidGas: bigint;
  randomSeed: Uint8Array;
  isView: boolean;
  /** Working copy; mutated in place. Keys are hex strings. */
  storage: Map<string, Uint8Array>;
  storageUsage: bigint;
  storageByteCost: bigint;
  promiseResults: PromiseResultInput[];
}

export type ReturnData = { kind: "none" } | { kind: "value"; data: Uint8Array } | { kind: "promise"; index: number };

export interface ExecResult {
  error?: { kind: string; message: string };
  returnData: ReturnData;
  logs: string[];
  promises: PromiseEntry[];
  /** Gas used including gas attached to created promises. */
  usedGas: bigint;
  /** Gas burnt by this execution alone. */
  burntGas: bigint;
  balance: bigint;
  storageUsage: bigint;
}

// ---- gas schedule (nearcore-like constants, deterministic) --------------------------------
export const GAS = {
  hostCall: 264_768_111n,
  contractLoadBase: 35_445_963n,
  contractLoadPerByte: 216_750n,
  wasmFlat: 500_000_000_000n,
  storageWriteBase: 64_196_736_000n,
  storageWritePerByte: 70_482_867n,
  storageReadBase: 56_356_845_750n,
  storageReadPerByte: 30_952_533n,
  storageRemoveBase: 53_473_030_500n,
  storageHasKeyBase: 54_039_896_625n,
  logBase: 3_543_313_050n,
  logPerByte: 13_198_791n,
  sha256Base: 4_540_970_250n,
  sha256PerByte: 24_117_351n,
  receiptCreation: 108_059_500_000n,
  actionFunctionCall: 2_319_861_500_000n,
  actionFunctionCallPerByte: 2_235_934n,
  actionTransfer: 115_123_062_500n,
  actionCreateAccount: 3_850_000_000_000n,
  actionDeploy: 184_765_750_000n,
  actionDeployPerByte: 6_812_999n,
  actionAddKey: 101_765_125_000n,
  actionDeleteKey: 94_946_625_000n,
  actionDeleteAccount: 147_489_000_000n,
  maxPrepaid: 300n * 10n ** 12n,
} as const;

export function actionSendCost(a: Action): bigint {
  switch (a.type) {
    case "FunctionCall":
      return GAS.actionFunctionCall + GAS.actionFunctionCallPerByte * BigInt(a.args.length + a.methodName.length);
    case "Transfer":
      return GAS.actionTransfer;
    case "CreateAccount":
      return GAS.actionCreateAccount / 10n;
    case "DeployContract":
      return GAS.actionDeploy + GAS.actionDeployPerByte * BigInt(a.code.length);
    case "AddKey":
      return GAS.actionAddKey;
    case "DeleteKey":
      return GAS.actionDeleteKey;
    case "DeleteAccount":
      return GAS.actionDeleteAccount;
    case "Stake":
      return GAS.actionTransfer;
  }
}

const U64_MAX = (1n << 64n) - 1n;
const STORAGE_RECORD_OVERHEAD = 40n;
const moduleCache = new Map<string, WebAssembly.Module>();

export function codeHash(code: Uint8Array): string {
  return toHex(sha256Bytes(code));
}

export function compileModule(code: Uint8Array): WebAssembly.Module {
  const h = codeHash(code);
  let m = moduleCache.get(h);
  if (!m) {
    m = new WebAssembly.Module(code as Uint8Array<ArrayBuffer>);
    moduleCache.set(h, m);
  }
  return m;
}

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });
const utf8 = (s: string) => enc.encode(s);

/** Execute `method` of `module` in `ctx`. Never throws: failures are reported in `error`. */
export function execute(module: WebAssembly.Module, codeLen: number, method: string, ctx: ExecContext): ExecResult {
  const registers = new Map<bigint, Uint8Array>();
  const logs: string[] = [];
  const promises: PromiseEntry[] = [];
  let returnData: ReturnData = { kind: "none" };
  let balance = ctx.balance;
  let burnt = 0n;
  let attachedToPromises = 0n;
  let memory: WebAssembly.Memory | undefined;

  const charge = (g: bigint) => {
    burnt += g;
    if (burnt + attachedToPromises > ctx.prepaidGas) throw new HostError("GasExceeded", "Exceeded the prepaid gas.");
  };

  const mem = (): Uint8Array => {
    if (!memory) throw new HostError("MemoryAccessViolation", "memory not initialised");
    return new Uint8Array(memory.buffer);
  };
  const read = (ptr: bigint, len: bigint): Uint8Array => {
    const m = mem();
    const p = Number(ptr);
    const l = Number(len);
    if (p < 0 || l < 0 || p + l > m.length) throw new HostError("MemoryAccessViolation", "out of bounds read");
    return m.slice(p, p + l);
  };
  const write = (ptr: bigint, data: Uint8Array) => {
    const m = mem();
    const p = Number(ptr);
    if (p < 0 || p + data.length > m.length) throw new HostError("MemoryAccessViolation", "out of bounds write");
    m.set(data, p);
  };
  const readUtf8 = (len: bigint, ptr: bigint): string => {
    let bytes: Uint8Array;
    if (len === U64_MAX) {
      const m = mem();
      let end = Number(ptr);
      while (end < m.length && m[end] !== 0) end++;
      bytes = m.slice(Number(ptr), end);
    } else bytes = read(ptr, len);
    try {
      return dec.decode(bytes);
    } catch {
      throw new HostError("BadUTF8", "String encoding is bad UTF-8 sequence.");
    }
  };
  const readU128 = (ptr: bigint) => u128FromLeBytes(read(ptr, 16n));
  const readAccountId = (len: bigint, ptr: bigint): string => {
    const id = readUtf8(len, ptr);
    if (!isValidAccountId(id)) throw new HostError("InvalidAccountId", `invalid account id '${id}'`);
    return id;
  };
  const noView = (name: string) => {
    if (ctx.isView) throw new HostError("ProhibitedInView", `${name} is not allowed in view calls`);
  };
  const setReg = (id: bigint, data: Uint8Array) => registers.set(id, data);

  const receiptAt = (idx: bigint): PromiseReceipt => {
    const p = promises[Number(idx)];
    if (!p) throw new HostError("InvalidPromiseIndex", `promise index ${idx} does not exist`);
    if (p.kind !== "receipt") throw new HostError("CannotAppendActionToJointPromise", "cannot append to joint promise");
    return p;
  };
  const receiptsOf = (idx: bigint): number[] => {
    const p = promises[Number(idx)];
    if (!p) throw new HostError("InvalidPromiseIndex", `promise index ${idx} does not exist`);
    return p.kind === "and" ? p.receipts : [Number(idx)];
  };
  const newReceipt = (receiverId: string, deps: number[]): bigint => {
    noView("promise creation");
    charge(GAS.receiptCreation);
    promises.push({ kind: "receipt", receiverId, actions: [], deps });
    return BigInt(promises.length - 1);
  };
  const deduct = (amount: bigint) => {
    if (amount > balance) throw new HostError("BalanceExceeded", `Exceeded the account balance.`);
    balance -= amount;
  };
  const pushAction = (idx: bigint, a: Action) => {
    noView("promise actions");
    const r = receiptAt(idx);
    charge(actionSendCost(a));
    r.actions.push(a);
  };
  const storageKey = (len: bigint, ptr: bigint) => toHex(read(ptr, len));

  const env: Record<string, (...args: any[]) => any> = {
    // registers
    read_register(id: bigint, ptr: bigint) {
      charge(GAS.hostCall);
      const r = registers.get(id);
      if (!r) throw new HostError("InvalidRegisterId", `register ${id} does not exist`);
      write(ptr, r);
    },
    register_len(id: bigint) {
      charge(GAS.hostCall);
      const r = registers.get(id);
      return r ? BigInt(r.length) : U64_MAX;
    },
    write_register(id: bigint, len: bigint, ptr: bigint) {
      charge(GAS.hostCall);
      setReg(id, read(ptr, len));
    },
    // context
    current_account_id(id: bigint) {
      charge(GAS.hostCall);
      setReg(id, utf8(ctx.currentAccountId));
    },
    signer_account_id(id: bigint) {
      noView("signer_account_id");
      charge(GAS.hostCall);
      setReg(id, utf8(ctx.signerId));
    },
    signer_account_pk(id: bigint) {
      noView("signer_account_pk");
      charge(GAS.hostCall);
      setReg(id, publicKeyToBorsh(ctx.signerPk));
    },
    predecessor_account_id(id: bigint) {
      noView("predecessor_account_id");
      charge(GAS.hostCall);
      setReg(id, utf8(ctx.predecessorId));
    },
    input(id: bigint) {
      charge(GAS.hostCall);
      setReg(id, ctx.input);
    },
    block_index() {
      charge(GAS.hostCall);
      return ctx.blockHeight;
    },
    block_height() {
      charge(GAS.hostCall);
      return ctx.blockHeight;
    },
    block_timestamp() {
      charge(GAS.hostCall);
      return ctx.blockTimestamp;
    },
    epoch_height() {
      charge(GAS.hostCall);
      return ctx.epochHeight;
    },
    storage_usage() {
      charge(GAS.hostCall);
      return ctx.storageUsage;
    },
    account_balance(ptr: bigint) {
      charge(GAS.hostCall);
      write(ptr, u128ToLeBytes(balance));
    },
    account_locked_balance(ptr: bigint) {
      charge(GAS.hostCall);
      write(ptr, u128ToLeBytes(ctx.locked));
    },
    attached_deposit(ptr: bigint) {
      noView("attached_deposit");
      charge(GAS.hostCall);
      write(ptr, u128ToLeBytes(ctx.attachedDeposit));
    },
    prepaid_gas() {
      noView("prepaid_gas");
      charge(GAS.hostCall);
      return ctx.prepaidGas;
    },
    used_gas() {
      noView("used_gas");
      charge(GAS.hostCall);
      return burnt + attachedToPromises;
    },
    random_seed(id: bigint) {
      charge(GAS.hostCall);
      setReg(id, ctx.randomSeed);
    },
    // crypto
    sha256(len: bigint, ptr: bigint, id: bigint) {
      charge(GAS.sha256Base + GAS.sha256PerByte * len);
      setReg(id, sha256Bytes(read(ptr, len)));
    },
    ed25519_verify(sigLen: bigint, sigPtr: bigint, msgLen: bigint, msgPtr: bigint, pkLen: bigint, pkPtr: bigint) {
      charge(GAS.sha256Base * 10n);
      return ed25519Verify(read(sigPtr, sigLen), read(msgPtr, msgLen), read(pkPtr, pkLen)) ? 1n : 0n;
    },
    // results / logging / panics
    value_return(len: bigint, ptr: bigint) {
      charge(GAS.hostCall);
      returnData = { kind: "value", data: read(ptr, len) };
    },
    panic() {
      throw new HostError("GuestPanic", "explicit guest panic");
    },
    panic_utf8(len: bigint, ptr: bigint) {
      throw new HostError("GuestPanic", readUtf8(len, ptr));
    },
    abort(msgPtr: number, filePtr: number, line: number, col: number) {
      throw new HostError("GuestPanic", `abort at ${line}:${col} (${msgPtr},${filePtr})`);
    },
    log_utf8(len: bigint, ptr: bigint) {
      const s = readUtf8(len, ptr);
      charge(GAS.logBase + GAS.logPerByte * BigInt(s.length));
      logs.push(s);
    },
    log_utf16(len: bigint, ptr: bigint) {
      const bytes = read(ptr, len);
      const s = utf16leDecode(bytes);
      charge(GAS.logBase + GAS.logPerByte * BigInt(bytes.length));
      logs.push(s);
    },
    // promises
    promise_create(aLen: bigint, aPtr: bigint, fLen: bigint, fPtr: bigint, argLen: bigint, argPtr: bigint, amtPtr: bigint, gas: bigint) {
      const idx = newReceipt(readAccountId(aLen, aPtr), []);
      env.promise_batch_action_function_call(idx, fLen, fPtr, argLen, argPtr, amtPtr, gas);
      return idx;
    },
    promise_then(prev: bigint, aLen: bigint, aPtr: bigint, fLen: bigint, fPtr: bigint, argLen: bigint, argPtr: bigint, amtPtr: bigint, gas: bigint) {
      const idx = newReceipt(readAccountId(aLen, aPtr), receiptsOf(prev));
      env.promise_batch_action_function_call(idx, fLen, fPtr, argLen, argPtr, amtPtr, gas);
      return idx;
    },
    promise_and(idxPtr: bigint, count: bigint) {
      noView("promise_and");
      charge(GAS.hostCall);
      const raw = read(idxPtr, count * 8n);
      const view = new DataView(raw.buffer);
      const receipts: number[] = [];
      for (let i = 0; i < Number(count); i++) receipts.push(...receiptsOf(view.getBigUint64(i * 8, true)));
      promises.push({ kind: "and", receipts });
      return BigInt(promises.length - 1);
    },
    promise_batch_create(aLen: bigint, aPtr: bigint) {
      return newReceipt(readAccountId(aLen, aPtr), []);
    },
    promise_batch_then(prev: bigint, aLen: bigint, aPtr: bigint) {
      return newReceipt(readAccountId(aLen, aPtr), receiptsOf(prev));
    },
    promise_batch_action_create_account(idx: bigint) {
      pushAction(idx, { type: "CreateAccount" });
    },
    promise_batch_action_deploy_contract(idx: bigint, len: bigint, ptr: bigint) {
      pushAction(idx, { type: "DeployContract", code: read(ptr, len) });
    },
    promise_batch_action_function_call(idx: bigint, fLen: bigint, fPtr: bigint, argLen: bigint, argPtr: bigint, amtPtr: bigint, gas: bigint) {
      env.promise_batch_action_function_call_weight(idx, fLen, fPtr, argLen, argPtr, amtPtr, gas, 0n);
    },
    promise_batch_action_function_call_weight(
      idx: bigint, fLen: bigint, fPtr: bigint, argLen: bigint, argPtr: bigint, amtPtr: bigint, gas: bigint, weight: bigint,
    ) {
      const methodName = readUtf8(fLen, fPtr);
      const args = read(argPtr, argLen);
      const deposit = readU128(amtPtr);
      pushAction(idx, { type: "FunctionCall", methodName, args, gas, deposit, gasWeight: weight });
      attachedToPromises += gas;
      charge(0n);
      deduct(deposit);
    },
    promise_batch_action_transfer(idx: bigint, amtPtr: bigint) {
      const deposit = readU128(amtPtr);
      pushAction(idx, { type: "Transfer", deposit });
      deduct(deposit);
    },
    promise_batch_action_stake(idx: bigint, amtPtr: bigint, pkLen: bigint, pkPtr: bigint) {
      pushAction(idx, { type: "Stake", stake: readU128(amtPtr), publicKey: publicKeyFromBorsh(read(pkPtr, pkLen)) });
    },
    promise_batch_action_add_key_with_full_access(idx: bigint, pkLen: bigint, pkPtr: bigint, nonce: bigint) {
      pushAction(idx, {
        type: "AddKey",
        publicKey: decodePk(read(pkPtr, pkLen)),
        permission: { kind: "FullAccess" },
        nonce,
      });
    },
    promise_batch_action_add_key_with_function_call(
      idx: bigint, pkLen: bigint, pkPtr: bigint, nonce: bigint, allowancePtr: bigint,
      rLen: bigint, rPtr: bigint, fnLen: bigint, fnPtr: bigint,
    ) {
      const allowance = readU128(allowancePtr);
      const names = readUtf8(fnLen, fnPtr);
      const permission: AccessKeyPermission = {
        kind: "FunctionCall",
        allowance: allowance === 0n ? null : allowance,
        receiverId: readAccountId(rLen, rPtr),
        methodNames: names.length ? names.split(",") : [],
      };
      pushAction(idx, { type: "AddKey", publicKey: decodePk(read(pkPtr, pkLen)), permission, nonce });
    },
    promise_batch_action_delete_key(idx: bigint, pkLen: bigint, pkPtr: bigint) {
      pushAction(idx, { type: "DeleteKey", publicKey: decodePk(read(pkPtr, pkLen)) });
    },
    promise_batch_action_delete_account(idx: bigint, bLen: bigint, bPtr: bigint) {
      pushAction(idx, { type: "DeleteAccount", beneficiaryId: readAccountId(bLen, bPtr) });
    },
    promise_results_count() {
      noView("promise_results_count");
      charge(GAS.hostCall);
      return BigInt(ctx.promiseResults.length);
    },
    promise_result(i: bigint, id: bigint) {
      noView("promise_result");
      charge(GAS.hostCall);
      const r = ctx.promiseResults[Number(i)];
      if (!r) throw new HostError("InvalidPromiseResultIndex", `promise result ${i} does not exist`);
      if (!r.ok) return 2n;
      setReg(id, r.data);
      return 1n;
    },
    promise_return(idx: bigint) {
      noView("promise_return");
      charge(GAS.hostCall);
      const p = promises[Number(idx)];
      if (!p) throw new HostError("InvalidPromiseIndex", `promise index ${idx} does not exist`);
      if (p.kind !== "receipt") throw new HostError("CannotReturnJointPromise", "cannot return joint promise");
      returnData = { kind: "promise", index: Number(idx) };
    },
    // storage
    storage_write(kLen: bigint, kPtr: bigint, vLen: bigint, vPtr: bigint, id: bigint) {
      charge(GAS.storageWriteBase + GAS.storageWritePerByte * (kLen + vLen));
      const key = storageKey(kLen, kPtr);
      const value = read(vPtr, vLen);
      const old = ctx.storage.get(key);
      ctx.storage.set(key, value);
      if (old) {
        ctx.storageUsage += BigInt(value.length - old.length);
        setReg(id, old);
        return 1n;
      }
      ctx.storageUsage += kLen + vLen + STORAGE_RECORD_OVERHEAD;
      return 0n;
    },
    storage_read(kLen: bigint, kPtr: bigint, id: bigint) {
      charge(GAS.storageReadBase + GAS.storageReadPerByte * kLen);
      const v = ctx.storage.get(storageKey(kLen, kPtr));
      if (!v) return 0n;
      setReg(id, v);
      return 1n;
    },
    storage_remove(kLen: bigint, kPtr: bigint, id: bigint) {
      charge(GAS.storageRemoveBase);
      const key = storageKey(kLen, kPtr);
      const old = ctx.storage.get(key);
      if (!old) return 0n;
      ctx.storage.delete(key);
      ctx.storageUsage -= kLen + BigInt(old.length) + STORAGE_RECORD_OVERHEAD;
      setReg(id, old);
      return 1n;
    },
    storage_has_key(kLen: bigint, kPtr: bigint) {
      charge(GAS.storageHasKeyBase);
      return ctx.storage.has(storageKey(kLen, kPtr)) ? 1n : 0n;
    },
    // validators (no staking in nearsim)
    validator_stake(_aLen: bigint, _aPtr: bigint, stakePtr: bigint) {
      write(stakePtr, u128ToLeBytes(0n));
    },
    validator_total_stake(stakePtr: bigint) {
      write(stakePtr, u128ToLeBytes(0n));
    },
    gas(_opcodes: number) {
      /* legacy instrumentation hook: no-op */
    },
  };

  // Stub every import we do not implement so instantiation succeeds; calling one is an error.
  const importObject: WebAssembly.Imports = { env: {} };
  const envImports = importObject.env as Record<string, WebAssembly.ImportValue>;
  for (const imp of WebAssembly.Module.imports(module)) {
    if (imp.module !== "env") continue;
    if (imp.kind === "memory") {
      memory = new WebAssembly.Memory({ initial: 17, maximum: 2048 });
      envImports[imp.name] = memory;
    } else if (imp.kind === "function") {
      envImports[imp.name] =
        env[imp.name] ??
        (() => {
          throw new HostError("UnsupportedHostFunction", `host function '${imp.name}' is not implemented by nearsim`);
        });
    }
  }

  const finish = (error?: { kind: string; message: string }): ExecResult => ({
    error,
    returnData: error ? { kind: "none" } : returnData,
    logs,
    promises: error ? [] : promises,
    usedGas: burnt + attachedToPromises,
    burntGas: burnt,
    balance: error ? ctx.balance : balance,
    storageUsage: ctx.storageUsage,
  });

  try {
    charge(GAS.contractLoadBase + GAS.contractLoadPerByte * BigInt(codeLen) + GAS.wasmFlat);
    const instance = new WebAssembly.Instance(module, importObject);
    const exported = instance.exports;
    if (!memory) memory = exported.memory as WebAssembly.Memory;
    const fn = exported[method];
    if (typeof fn !== "function") return finish({ kind: "MethodNotFound", message: `Contract method '${method}' is not found` });
    (fn as () => void)();
    if ((returnData as ReturnData).kind === "promise" && ctx.isView) throw new HostError("ProhibitedInView", "promise_return in view");
    distributeWeightedGas(promises, ctx.prepaidGas - (burnt + attachedToPromises), (g) => (attachedToPromises += g));
    return finish();
  } catch (e) {
    if (e instanceof HostError) {
      const message = e.kind === "GuestPanic" ? `Smart contract panicked: ${e.message}` : e.message;
      return finish({ kind: e.kind, message });
    }
    if (e instanceof WebAssembly.RuntimeError) return finish({ kind: "WasmTrap", message: `WebAssembly trap: ${e.message}` });
    if (e instanceof RangeError) return finish({ kind: "WasmTrap", message: `WebAssembly trap: ${e.message}` });
    return finish({ kind: "WasmUnknownError", message: String(e) });
  }
}

/** near-sdk's default: unused gas is split across function calls by `gas_weight`. */
function distributeWeightedGas(promises: PromiseEntry[], unused: bigint, onAttach: (g: bigint) => void) {
  if (unused <= 0n) return;
  const weighted: Extract<Action, { type: "FunctionCall" }>[] = [];
  let total = 0n;
  for (const p of promises) {
    if (p.kind !== "receipt") continue;
    for (const a of p.actions) {
      if (a.type === "FunctionCall" && (a.gasWeight ?? 0n) > 0n) {
        weighted.push(a);
        total += a.gasWeight!;
      }
    }
  }
  if (total === 0n) return;
  let distributed = 0n;
  weighted.forEach((a, i) => {
    const share = i === weighted.length - 1 ? unused - distributed : (unused * a.gasWeight!) / total;
    a.gas += share;
    distributed += share;
  });
  onAttach(distributed);
}

function decodePk(bytes: Uint8Array): string {
  try {
    return publicKeyFromBorsh(bytes);
  } catch {
    throw new HostError("InvalidPublicKey", "VM Logic provided an invalid public key");
  }
}

export { isImplicitAccount };
