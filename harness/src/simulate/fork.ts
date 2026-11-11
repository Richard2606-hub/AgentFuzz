/**
 * A lazy, read-only fork of a live NEAR network for nearsim.
 *
 * nearsim executes synchronously, but the network is behind async RPC. So the simulator runs in
 * rounds: during a round every account or storage key the execution touches that is not cached
 * yet is recorded as a miss and treated as absent; after the round the misses are fetched and the
 * whole transaction is re-run from scratch. When a round finishes with no misses, every read it
 * made came from the network, so its result is the real one (up to nearsim's fidelity).
 *
 * Accounts, code and keys come from `rpcUrl`. Contract storage of small contracts is read whole
 * in one call; public RPCs refuse `view_state` on contracts over 50 kB, so those are read key by
 * key from `stateRpcUrl`, an RPC that serves large state.
 */
import { rpc, RpcUnreachable } from "../anchor/audit-lookup.js";
import { LazyStorage, type ForkedAccount, type ForkSource } from "../sim/chain.js";
import type { AccessKeyPermission } from "../near/types.js";
import { fromBase64, toBase64, toHex } from "../util/bytes.js";

/** Serves `view_state` for contracts over the 50 kB limit (no API key: about one second per request). */
export const LARGE_STATE_RPC = "https://rpc.intea.rs";
/** When the large-state RPC last failed to answer: skip it for a while instead of waiting on it again. */
const downUntil = new Map<string, number>();
const NO_CODE = "11111111111111111111111111111111";

type RpcKey = { public_key: string; access_key: { nonce: number | string; permission: "FullAccess" | { FunctionCall: { allowance: string | null; receiver_id: string; method_names: string[] } } } };

/** A contract's storage could not be read (too large for the main RPC, and the large-state RPC failed). */
export class StateUnavailable extends Error {
  constructor(
    readonly accountId: string,
    reason: string,
  ) {
    super(`could not read the state of ${accountId}: it is larger than public RPCs serve (50 kB), and ${reason}`);
  }
}

export interface ForkStats {
  rounds: number;
  accounts: number;
  storageKeys: number;
  wholeStates: number;
  rpcCalls: number;
}

export class RemoteFork implements ForkSource {
  readonly block: { height: bigint; timestampNs: bigint; hash: string };
  private accounts = new Map<string, Omit<ForkedAccount, "storage"> | null>();
  private storage = new Map<string, Map<string, Uint8Array | null>>();
  /** Accounts whose whole state is cached, so an uncached key is known to be absent. */
  private whole = new Set<string>();
  /** Accounts too large for `view_state` on the main RPC. */
  private large = new Set<string>();
  private missAccounts = new Set<string>();
  private missKeys = new Map<string, Set<string>>();
  readonly stats: ForkStats = { rounds: 0, accounts: 0, storageKeys: 0, wholeStates: 0, rpcCalls: 0 };

  private constructor(
    readonly rpcUrl: string,
    readonly stateRpcUrl: string,
    block: { height: bigint; timestampNs: bigint; hash: string },
    private readonly log: (s: string) => void,
  ) {
    this.block = block;
  }

  /** Pin the fork to the latest final block, so every read sees the same state. */
  static async at(rpcUrl: string, opts: { stateRpcUrl?: string; log?: (s: string) => void } = {}): Promise<RemoteFork> {
    const b = await rpc(rpcUrl, "block", { finality: "final" });
    return new RemoteFork(rpcUrl, opts.stateRpcUrl ?? LARGE_STATE_RPC, { height: BigInt(b.header.height), timestampNs: BigInt(b.header.timestamp_nanosec), hash: b.header.hash }, opts.log ?? (() => {}));
  }

  // ------------------------------------------------------------ ForkSource (sync, used by nearsim)

  account(id: string): ForkedAccount | null {
    if (!this.accounts.has(id)) {
      this.missAccounts.add(id);
      return null;
    }
    const a = this.accounts.get(id)!;
    if (!a) return null;
    return { ...a, storage: new LazyStorage((k) => this.readKey(id, k)) };
  }

  /** Cached account as the network reports it (for before/after comparisons); undefined if never loaded. */
  cachedAccount(id: string): Omit<ForkedAccount, "storage"> | null | undefined {
    return this.accounts.get(id);
  }

  private readKey(id: string, hexKey: string): Uint8Array | undefined {
    const m = this.storage.get(id);
    if (m?.has(hexKey)) return m.get(hexKey) ?? undefined;
    if (this.whole.has(id)) return undefined;
    let s = this.missKeys.get(id);
    if (!s) this.missKeys.set(id, (s = new Set()));
    s.add(hexKey);
    return undefined;
  }

  // ------------------------------------------------------------ rounds

  get hasMisses(): boolean {
    return this.missAccounts.size > 0 || this.missKeys.size > 0;
  }

  /** Fetch everything the last round missed. */
  async fetchMisses(): Promise<void> {
    const accounts = [...this.missAccounts];
    const keys = [...this.missKeys.entries()];
    this.missAccounts.clear();
    this.missKeys.clear();
    this.stats.rounds++;
    if (accounts.length) this.log(`loading ${accounts.length} account${accounts.length > 1 ? "s" : ""}: ${accounts.join(", ")}`);
    await Promise.all(accounts.map((id) => this.loadAccount(id)));
    const nKeys = keys.reduce((n, [, s]) => n + s.size, 0);
    if (nKeys) this.log(`reading ${nKeys} storage key${nKeys > 1 ? "s" : ""} of ${keys.map(([id]) => id).join(", ")}`);
    await Promise.all(keys.map(([id, s]) => this.loadKeys(id, [...s])));
  }

  /** Load accounts ahead of the first round (the signer and receiver are always needed). */
  async preload(ids: string[]): Promise<void> {
    await Promise.all(ids.filter((id) => !this.accounts.has(id)).map((id) => this.loadAccount(id)));
  }

  private async call(url: string, method: string, params: unknown, timeoutMs?: number) {
    this.stats.rpcCalls++;
    return rpc(url, method, params, timeoutMs);
  }

  private async loadAccount(id: string): Promise<void> {
    if (this.accounts.has(id)) return;
    const at = { block_id: Number(this.block.height) };
    let view: { amount: string; locked: string; code_hash: string; storage_usage: number };
    try {
      view = await this.call(this.rpcUrl, "query", { request_type: "view_account", ...at, account_id: id });
    } catch (e) {
      if (/does not exist|UNKNOWN_ACCOUNT/.test(String(e))) {
        this.accounts.set(id, null);
        return;
      }
      throw e;
    }
    const [code, keys] = await Promise.all([
      view.code_hash === NO_CODE ? undefined : this.call(this.rpcUrl, "query", { request_type: "view_code", ...at, account_id: id }).then((r: { code_base64: string }) => fromBase64(r.code_base64)),
      this.call(this.rpcUrl, "query", { request_type: "view_access_key_list", ...at, account_id: id }).then((r: { keys: RpcKey[] }) => r.keys),
    ]);
    this.stats.accounts++;
    this.accounts.set(id, {
      amount: BigInt(view.amount),
      locked: BigInt(view.locked),
      storageUsage: BigInt(view.storage_usage),
      code,
      keys: keys.map((k) => ({ publicKey: k.public_key, nonce: BigInt(k.access_key.nonce), permission: permissionOf(k.access_key.permission) })),
    });
  }

  private put(id: string, values: { key: string; value: string }[]) {
    let m = this.storage.get(id);
    if (!m) this.storage.set(id, (m = new Map()));
    for (const v of values) m.set(toHex(fromBase64(v.key)), fromBase64(v.value));
    return m;
  }

  private async loadKeys(id: string, hexKeys: string[]): Promise<void> {
    const at = { block_id: Number(this.block.height) };
    // Small contracts: the whole state in one call.
    if (!this.large.has(id) && !this.whole.has(id)) {
      try {
        const r = await this.call(this.rpcUrl, "query", { request_type: "view_state", ...at, account_id: id, prefix_base64: "", include_proof: false });
        this.put(id, r.values);
        this.whole.add(id);
        this.stats.wholeStates++;
        return;
      } catch (e) {
        if (!/TOO_LARGE_CONTRACT_STATE|too large/i.test(String(e))) throw e;
        this.large.add(id);
      }
    }
    // Large contracts: key by key (a prefix query returns the key itself plus any it prefixes).
    const down = downUntil.get(this.stateRpcUrl) ?? 0;
    if (Date.now() < down) throw new StateUnavailable(id, `${new URL(this.stateRpcUrl).host} did not answer a moment ago`);
    let i = 0;
    const worker = async () => {
      while (i < hexKeys.length) {
        const k = hexKeys[i++];
        const bytes = Uint8Array.from(k.match(/../g)?.map((h) => parseInt(h, 16)) ?? []);
        let r: { values: { key: string; value: string }[] } | undefined;
        for (let attempt = 1; !r; attempt++) {
          try {
            r = await this.call(this.stateRpcUrl, "query", { request_type: "view_state", finality: "final", account_id: id, prefix_base64: toBase64(bytes), include_proof: false }, 8_000);
          } catch (e) {
            if (attempt < 2 && e instanceof RpcUnreachable) continue; // one retry: this RPC is rate-limited without a key
            if (e instanceof RpcUnreachable) downUntil.set(this.stateRpcUrl, Date.now() + 120_000);
            throw new StateUnavailable(id, e instanceof RpcUnreachable ? e.message : `${new URL(this.stateRpcUrl).host} answered: ${e instanceof Error ? e.message : String(e)}`);
          }
        }
        const m = this.put(id, r.values.slice(0, 64));
        if (!m.has(k)) m.set(k, null);
        this.stats.storageKeys++;
      }
    };
    await Promise.all(Array.from({ length: Math.min(4, hexKeys.length) }, worker));
  }
}

function permissionOf(p: RpcKey["access_key"]["permission"]): AccessKeyPermission {
  if (p === "FullAccess") return { kind: "FullAccess" };
  return { kind: "FunctionCall", receiverId: p.FunctionCall.receiver_id, methodNames: [...p.FunctionCall.method_names], allowance: p.FunctionCall.allowance === null ? null : BigInt(p.FunctionCall.allowance) };
}
