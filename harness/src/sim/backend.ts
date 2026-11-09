import type { Backend } from "../near/backend.js";
import type { AccessKeyView, ReceiptOutcome, SubmitResult, Transaction, TxResult, ValueTransfer } from "../near/types.js";
import { SimChain, type SimChainOptions } from "./chain.js";

/** Backend over the in-process nearsim chain. Fully deterministic for a given seed. */
export class SimBackend implements Backend {
  readonly name = "nearsim" as const;
  readonly chain: SimChain;

  constructor(opts: SimChainOptions = {}) {
    this.chain = new SimChain(opts);
  }

  get blockTimeNs() {
    return this.chain.blockTimeNs;
  }

  async createAccount(id: string, amount: bigint, fullAccessKeys: string[]) {
    this.chain.createAccount(id, amount, { fullAccessKeys });
  }
  async accountExists(id: string) {
    return this.chain.hasAccount(id);
  }
  async balance(id: string) {
    return this.chain.balance(id);
  }
  async storageUsage(id: string) {
    return this.chain.viewAccount(id)?.storageUsage ?? 0n;
  }
  async accessKeys(id: string): Promise<AccessKeyView[]> {
    return this.chain.accessKeys(id);
  }
  async view(accountId: string, method: string, args: unknown = {}) {
    return this.chain.view(accountId, method, args);
  }
  async submit(tx: Transaction): Promise<SubmitResult> {
    return this.chain.submit(tx);
  }
  async settle() {
    this.chain.runUntilIdle(256);
  }
  async execTx(tx: Transaction): Promise<TxResult> {
    return this.chain.execTx(tx);
  }
  async txResult(txHash: string): Promise<TxResult> {
    return this.chain.txResult(txHash);
  }
  async advanceBlocks(n: number) {
    this.chain.advanceBlocks(n);
  }
  async now() {
    return this.chain.timestamp;
  }
  transfers(): ValueTransfer[] {
    return this.chain.transfers;
  }
  outcomes(): ReceiptOutcome[] {
    return this.chain.outcomes;
  }
}
