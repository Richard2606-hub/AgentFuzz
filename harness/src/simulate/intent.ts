/**
 * What a transaction asks for, read from its actions and arguments without executing anything:
 * the well-known token and NFT methods (NEP-141, NEP-145, NEP-171/178, NEP-245, wNEAR) decoded
 * into plain sentences, with the risk patterns that are visible from the arguments alone.
 * Used in every simulation (it catches what execution alone would not flag, like an NFT
 * approval) and on its own when a contract's state cannot be read.
 */
import { nameFindings, type Finding, type Network } from "../account/scan.js";
import { fmtNear } from "../near/keys.js";
import type { Action } from "../near/types.js";

export interface TokenMeta {
  symbol?: string;
  decimals?: number;
}

export interface Intent {
  lines: string[];
  findings: Finding[];
  /** NEAR leaving the signer by attachment (transfers and deposits), before fees. */
  attached: bigint;
  /** Token contracts whose metadata the sentences need. */
  ftContracts: string[];
}

export function units(raw: string, meta?: TokenMeta): string {
  if (!/^\d+$/.test(raw)) return `${raw} units`;
  const d = meta?.decimals ?? 0;
  const v = BigInt(raw);
  let s = String(v);
  if (d) {
    const base = 10n ** BigInt(d);
    const frac = (v % base).toString().padStart(d, "0").replace(/0+$/, "").slice(0, 6);
    s = `${v / base}${frac ? `.${frac}` : ""}`;
  }
  return `${s} ${meta?.symbol ?? "tokens"}`;
}

const json = (a: Uint8Array): Record<string, unknown> | undefined => {
  try {
    const v = JSON.parse(new TextDecoder().decode(a));
    return v && typeof v === "object" && !Array.isArray(v) ? v : undefined;
  } catch {
    return undefined;
  }
};

const FT_METHODS = new Set(["ft_transfer", "ft_transfer_call"]);

/** Contracts whose ft_metadata the decoder will want. */
export function tokenContractsOf(txs: { receiverId: string; actions: Action[] }[]): string[] {
  return [...new Set(txs.filter((t) => t.actions.some((a) => a.type === "FunctionCall" && FT_METHODS.has(a.methodName))).map((t) => t.receiverId))];
}

export function decodeIntent(
  txs: { signerId: string; receiverId: string; actions: Action[] }[],
  network: Network,
  meta: Map<string, TokenMeta> = new Map(),
): Intent {
  const lines: string[] = [];
  const findings: Finding[] = [];
  let attached = 0n;
  const lookalike = (who: string, role: string) => {
    for (const f of nameFindings(who, network).filter((x) => x.severity === "danger")) findings.push({ ...f, title: `${role} ${who}: ${f.title.charAt(0).toLowerCase()}${f.title.slice(1)}` });
  };

  for (const t of txs) {
    const R = t.receiverId;
    const self = R === t.signerId;
    if (!self) lookalike(R, "Receiver");
    for (const a of t.actions) {
      switch (a.type) {
        case "Transfer":
          attached += a.deposit;
          lines.push(`Send ${fmtNear(a.deposit)} to ${R}`);
          break;
        case "CreateAccount":
          lines.push(`Create the account ${R}`);
          break;
        case "DeployContract":
          lines.push(`Deploy contract code on ${R}`);
          break;
        case "AddKey":
          lines.push(
            a.permission.kind === "FullAccess"
              ? `Add a full-access key ${a.publicKey} to ${R}`
              : `Add an app key for ${a.permission.receiverId} on ${R} (${a.permission.methodNames.length ? a.permission.methodNames.join(", ") : "any method"})`,
          );
          break;
        case "DeleteKey":
          lines.push(`Remove the key ${a.publicKey} from ${R}`);
          break;
        case "DeleteAccount":
          lines.push(`Delete the account ${R} and send what is left to ${a.beneficiaryId}`);
          lookalike(a.beneficiaryId, "Beneficiary");
          break;
        case "Stake":
          lines.push(`Stake ${fmtNear(a.stake)} from ${R}`);
          break;
        case "FunctionCall": {
          attached += a.deposit;
          const args = json(a.args) ?? {};
          const m = a.methodName;
          const dep = a.deposit ? ` (attaching ${fmtNear(a.deposit)})` : "";
          const recv = typeof args.receiver_id === "string" ? args.receiver_id : undefined;
          const acct = typeof args.account_id === "string" ? args.account_id : undefined;
          if ((m === "ft_transfer" || m === "ft_transfer_call") && recv && typeof args.amount === "string") {
            lines.push(`Send ${units(args.amount, meta.get(R))} (token ${R}) to ${recv}${m === "ft_transfer_call" ? `, which then runs its own code with msg ${JSON.stringify(String(args.msg ?? "")).slice(0, 120)}` : ""}`);
            lookalike(recv, "Token recipient");
          } else if ((m === "nft_transfer" || m === "nft_transfer_call") && recv) {
            lines.push(`Send NFT ${String(args.token_id)} (collection ${R}) to ${recv}`);
            lookalike(recv, "NFT recipient");
          } else if (m === "nft_approve" && acct) {
            lines.push(`Allow ${acct} to transfer your NFT ${String(args.token_id)} (collection ${R})${dep}`);
            findings.push({ severity: "warn", area: "contract", title: `Lets ${acct} move your NFT ${String(args.token_id)}`, detail: `An approval lasts until you revoke it: ${acct} can transfer the NFT at any time, without asking again. Normal for a marketplace listing; make sure you trust ${acct}.` });
            lookalike(acct, "Approved account");
          } else if ((m === "mt_transfer" || m === "mt_transfer_call") && recv) {
            lines.push(`Send ${String(args.amount ?? "")} of multi-token ${String(args.token_id ?? "")} on ${R} to ${recv}`);
            lookalike(recv, "Recipient");
          } else if (m === "mt_batch_transfer" || m === "mt_batch_transfer_call") {
            lines.push(`Send several multi-tokens on ${R}${recv ? ` to ${recv}` : ""}`);
            if (recv) lookalike(recv, "Recipient");
          } else if (m === "storage_deposit") {
            lines.push(`Pay a ${fmtNear(a.deposit)} storage deposit on ${R}${acct && acct !== t.signerId ? ` for ${acct}` : ""} (needed before holding its tokens)`);
          } else if (m === "storage_unregister") {
            lines.push(`Unregister from ${R}`);
            if (args.force === true) findings.push({ severity: "warn", area: "contract", title: `Force-unregisters you from ${R}`, detail: "With force=true, any token balance you still hold there is burned." });
          } else if (m === "near_deposit") {
            lines.push(`Wrap ${fmtNear(a.deposit)} into wrapped NEAR on ${R}`);
          } else if (m === "near_withdraw" && typeof args.amount === "string") {
            lines.push(`Unwrap ${fmtNear(BigInt(/^\d+$/.test(args.amount) ? args.amount : "0"))} of wrapped NEAR on ${R}`);
          } else {
            const shown = new TextDecoder().decode(a.args);
            lines.push(`Call ${m} on ${R}${dep}${shown && shown !== "{}" ? ` with ${shown.length > 160 ? `${shown.slice(0, 160)}…` : shown}` : ""}`);
          }
          break;
        }
      }
    }
  }
  return { lines, findings, attached, ftContracts: tokenContractsOf(txs) };
}
