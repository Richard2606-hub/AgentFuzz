/**
 * Backend-neutral NEAR types used by the harness, invariant checkers and both backends
 * (nearsim and near-workspaces sandbox).
 */

export type AccessKeyPermission =
  | { kind: "FullAccess" }
  | { kind: "FunctionCall"; allowance: bigint | null; receiverId: string; methodNames: string[] };

export interface AccessKeyView {
  publicKey: string;
  nonce: bigint;
  permission: AccessKeyPermission;
}

export type Action =
  | { type: "CreateAccount" }
  | { type: "DeployContract"; code: Uint8Array }
  | { type: "FunctionCall"; methodName: string; args: Uint8Array; gas: bigint; deposit: bigint; gasWeight?: bigint }
  | { type: "Transfer"; deposit: bigint }
  | { type: "AddKey"; publicKey: string; permission: AccessKeyPermission; nonce?: bigint }
  | { type: "DeleteKey"; publicKey: string }
  | { type: "DeleteAccount"; beneficiaryId: string }
  | { type: "Stake"; stake: bigint; publicKey: string };

export interface Transaction {
  signerId: string;
  publicKey: string;
  receiverId: string;
  actions: Action[];
}

/** Why a transaction was refused before inclusion (nearcore InvalidTxError family). */
export type TxRejection =
  | "SignerDoesNotExist"
  | "AccessKeyNotFound"
  | "ReceiverMismatch"
  | "MethodNameMismatch"
  | "RequiresFullAccess"
  | "DepositWithFunctionCall"
  | "NotEnoughAllowance"
  | "NotEnoughBalance"
  | "LackBalanceForState"
  | "InvalidReceiver"
  | "Expired";

export interface SubmitResult {
  txHash: string;
  /** Present when the transaction was refused and never produced a receipt. */
  rejected?: { kind: TxRejection; message: string };
}

export type OutcomeStatus =
  | { kind: "success"; value?: Uint8Array }
  | { kind: "failure"; error: string; errorKind: string };

/** One executed receipt, as an invariant checker sees it. */
export interface ReceiptOutcome {
  receiptId: string;
  txHash: string;
  predecessorId: string;
  receiverId: string;
  signerId: string;
  signerPublicKey: string;
  actions: ActionSummary[];
  status: OutcomeStatus;
  logs: string[];
  blockHeight: bigint;
  blockTimestamp: bigint;
  gasBurnt: bigint;
  isRefund: boolean;
}

export type ActionSummary =
  | { type: "CreateAccount" }
  | { type: "DeployContract"; codeHash: string }
  | { type: "FunctionCall"; methodName: string; args: string; gas: bigint; deposit: bigint }
  | { type: "Transfer"; deposit: bigint }
  | { type: "AddKey"; publicKey: string; permission: AccessKeyPermission }
  | { type: "DeleteKey"; publicKey: string }
  | { type: "DeleteAccount"; beneficiaryId: string }
  | { type: "Stake"; stake: bigint };

/** Value that left `from` and arrived at `to` in a successful receipt. */
export interface ValueTransfer {
  from: string;
  to: string;
  amount: bigint;
  txHash: string;
  receiptId: string;
  signerId: string;
  signerPublicKey: string;
  /** Block timestamp of the first receipt of the originating transaction (authorisation time). */
  authTimestamp: bigint;
  settledTimestamp: bigint;
  blockHeight: bigint;
  isRefund: boolean;
}

export interface TxResult {
  txHash: string;
  rejected?: { kind: TxRejection; message: string };
  /** Status of the first receipt (the one the transaction converted into). */
  status?: OutcomeStatus;
  /** Final status following promise_return chains, as near-api-js reports it. */
  finalStatus?: OutcomeStatus;
  receipts: ReceiptOutcome[];
  logs: string[];
}

export function decodeValue(status: OutcomeStatus | undefined): unknown {
  if (!status || status.kind !== "success" || !status.value || status.value.length === 0) return undefined;
  const text = new TextDecoder().decode(status.value);
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export function encodeArgs(args: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(args ?? {}));
}

export function functionCall(
  methodName: string,
  args: unknown,
  gas: bigint = 30n * 10n ** 12n,
  deposit = 0n,
): Action {
  return { type: "FunctionCall", methodName, args: encodeArgs(args), gas, deposit };
}
