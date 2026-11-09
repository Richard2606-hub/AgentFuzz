/**
 * Backend abstraction: everything the runner, agent and invariant checkers need from a chain.
 * Implemented by nearsim (in-process, deterministic) and by the near-workspaces sandbox.
 */
import type { AccessKeyView, ReceiptOutcome, SubmitResult, Transaction, TxResult, ValueTransfer } from "./types.js";

export interface Backend {
  readonly name: "nearsim" | "sandbox";
  /** Nanoseconds per block (used to express windows in blocks). */
  readonly blockTimeNs: bigint;

  createAccount(id: string, amount: bigint, fullAccessKeys: string[]): Promise<void>;
  accountExists(id: string): Promise<boolean>;
  balance(id: string): Promise<bigint>;
  storageUsage(id: string): Promise<bigint>;
  accessKeys(id: string): Promise<AccessKeyView[]>;
  view(accountId: string, method: string, args?: unknown): Promise<unknown>;

  /** Queue a transaction for the next block without waiting (used for same-block bursts). */
  submit(tx: Transaction): Promise<SubmitResult>;
  /** Run blocks until nothing is queued. */
  settle(): Promise<void>;
  /** Submit, settle, and return everything the transaction caused. */
  execTx(tx: Transaction): Promise<TxResult>;
  txResult(txHash: string): Promise<TxResult>;
  advanceBlocks(n: number): Promise<void>;
  now(): Promise<bigint>;

  /** All value transfers observed so far (the ledger invariant checkers read). */
  transfers(): ValueTransfer[];
  outcomes(): ReceiptOutcome[];
  /** Release resources (e.g. stop a sandbox process). */
  dispose?(): Promise<void>;
}

export const STORAGE_BYTE_COST = 10n ** 19n;
