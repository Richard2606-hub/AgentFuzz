/**
 * Guard audits on the scoreboard, read over plain NEAR JSON-RPC with fetch, so the CLI
 * (`agentfuzz check`) and the browser playground share it.
 *
 * A guard's identity is its code: NEAR reports every account's `code_hash` (base58 SHA-256 of the
 * deployed wasm), and the scoreboard keys audits by that SHA-256 in hex. So "is the wallet I'm
 * about to trust an audited build?" is two view calls.
 */
import { base58Decode } from "../near/keys.js";
import { toBase64, toHex } from "../util/bytes.js";

export const PUBLISHED_SCOREBOARD = "scoreboard.agentfuzz-28213.testnet";
export const TESTNET_RPC = "https://test.rpc.fastnear.com";

/** The demo guards deployed by `agentfuzz demo-guards-deploy` as sub-accounts of the scoreboard's parent. */
export const DEMO_GUARDS = [
  { prefix: "guard-reference", artifact: "guard_reference.wasm" },
  { prefix: "guard-naive", artifact: "guard_naive.wasm" },
] as const;

/** Demo guard account ids next to a scoreboard deployed as scoreboard.<parent>. */
export function demoGuardAccounts(scoreboard: string): string[] {
  return scoreboard.startsWith("scoreboard.") ? DEMO_GUARDS.map((g) => `${g.prefix}.${scoreboard.slice("scoreboard.".length)}`) : [];
}

export interface GuardAudit {
  code_hash: string;
  target: string;
  held: number;
  broken: number;
  total: number;
  broken_invariants: string[];
  prompt_breaches: number;
  run_id: string;
  report_sha256: string;
  submitter: string;
  block_height: string;
  timestamp_ns: string;
}

/** The scoreboard's per-target audit input, derived from a scorecard target. */
export interface AuditInput {
  code_hash: string;
  target: string;
  held: number;
  broken: number;
  total: number;
  broken_invariants: string[];
  prompt_breaches: number;
}

async function rpc(url: string, method: string, params: unknown): Promise<any> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "agentfuzz", method, params }),
  });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  const body = (await res.json()) as { result?: any; error?: { cause?: { name?: string }; data?: string; message?: string } };
  if (body.error) {
    const name = body.error.cause?.name;
    if (name === "UNKNOWN_ACCOUNT") throw new Error(`account ${(params as { account_id?: string }).account_id ?? ""} does not exist on this network`);
    throw new Error(name ?? body.error.data ?? body.error.message ?? "RPC error");
  }
  if (body.result?.error) throw new Error(String(body.result.error));
  return body.result;
}

/** Base58 code hash as NEAR reports it, to the hex SHA-256 the scoreboard uses. */
export function codeHashToHex(base58: string): string {
  return toHex(base58Decode(base58));
}

/** All-zero code hash means the account has no contract. */
export const NO_CODE_HASH = "0".repeat(64);

export async function accountCodeHash(accountId: string, rpcUrl = TESTNET_RPC): Promise<string> {
  const r = await rpc(rpcUrl, "query", { request_type: "view_account", finality: "final", account_id: accountId });
  return codeHashToHex(r.code_hash);
}

export async function viewFunction(contractId: string, method: string, args: unknown, rpcUrl = TESTNET_RPC): Promise<unknown> {
  const r = await rpc(rpcUrl, "query", {
    request_type: "call_function",
    finality: "final",
    account_id: contractId,
    method_name: method,
    args_base64: toBase64(new TextEncoder().encode(JSON.stringify(args))),
  });
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(r.result as number[])));
}

export async function auditsOf(codeHashHex: string, scoreboard = PUBLISHED_SCOREBOARD, rpcUrl = TESTNET_RPC): Promise<GuardAudit[]> {
  try {
    return (await viewFunction(scoreboard, "audits_of", { code_hash: codeHashHex }, rpcUrl)) as GuardAudit[];
  } catch (e) {
    if (String(e).includes("MethodNotFound")) throw new Error(`${scoreboard} runs a scoreboard version without guard audits (no audits_of); upgrade it with agentfuzz scoreboard-deploy`);
    throw e;
  }
}

/** clean: every invariant held, no prompt breach. incomplete: nothing broke, but some invariant was never exercised. */
export type CheckVerdict = "clean" | "broken" | "incomplete" | "not-audited" | "no-contract";

export interface CheckResult {
  accountId?: string;
  codeHash: string;
  verdict: CheckVerdict;
  latest?: GuardAudit;
  audits: GuardAudit[];
}

/** What a careful agent asks before trusting a wallet guard. Latest audit wins. */
export function verdictOf(codeHash: string, audits: GuardAudit[], trustedSubmitters?: string[]): Omit<CheckResult, "accountId"> {
  if (codeHash === NO_CODE_HASH) return { codeHash, verdict: "no-contract", audits: [] };
  const usable = trustedSubmitters?.length ? audits.filter((a) => trustedSubmitters.includes(a.submitter)) : audits;
  const latest = usable[usable.length - 1];
  if (!latest) return { codeHash, verdict: "not-audited", audits: usable };
  const verdict: CheckVerdict =
    latest.broken > 0 || latest.prompt_breaches > 0 ? "broken" : latest.held === latest.total ? "clean" : "incomplete";
  return { codeHash, verdict, latest, audits: usable };
}

/** Check a deployed account (or a raw code hash) against the scoreboard. */
export async function checkGuard(
  ref: { accountId: string } | { codeHash: string },
  opts: { scoreboard?: string; rpcUrl?: string; trustedSubmitters?: string[] } = {},
): Promise<CheckResult> {
  const rpcUrl = opts.rpcUrl ?? TESTNET_RPC;
  const codeHash = "codeHash" in ref ? ref.codeHash : await accountCodeHash(ref.accountId, rpcUrl);
  const audits = codeHash === NO_CODE_HASH ? [] : await auditsOf(codeHash, opts.scoreboard, rpcUrl);
  return { accountId: "accountId" in ref ? ref.accountId : undefined, ...verdictOf(codeHash, audits, opts.trustedSubmitters) };
}
