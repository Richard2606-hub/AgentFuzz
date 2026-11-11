/**
 * Account safety scan for any NEAR account, mainnet or testnet: who can move this account's money
 * (its access keys), what code runs on it (and whether AgentFuzz audited that exact build), and
 * whether its name imitates a well-known account. Read-only: two or three RPC view calls, no keys,
 * no signing. Shared by `agentfuzz scan` and the playground's Account safety tab.
 *
 * The analysis functions are pure (keys, names, audits in → findings out) so they are tested
 * offline; `scanAccount` only fetches their inputs.
 */
import { auditsOf, codeHashToHex, NO_CODE_HASH, PUBLISHED_SCOREBOARD, rpc, TESTNET_RPC, verdictOf, type GuardAudit } from "../anchor/audit-lookup.js";
import { fmtNear, isImplicitAccount, isValidAccountId } from "../near/keys.js";

export type Network = "mainnet" | "testnet";
export const MAINNET_RPC = "https://rpc.mainnet.fastnear.com";
export const RPC_OF: Record<Network, string> = { mainnet: MAINNET_RPC, testnet: TESTNET_RPC };

/** `.testnet` names live on testnet; everything else (.near, .tg, implicit, top-level) defaults to mainnet. */
export function networkOf(accountId: string): Network {
  return accountId.endsWith(".testnet") ? "testnet" : "mainnet";
}

export type Severity = "danger" | "warn" | "info" | "ok";
export type FindingArea = "keys" | "contract" | "name" | "account";
export interface Finding {
  severity: Severity;
  area: FindingArea;
  title: string;
  detail: string;
}

/** Access key as `view_access_key_list` returns it. */
export interface RawAccessKey {
  public_key: string;
  access_key: {
    nonce: number | string;
    permission: "FullAccess" | { FunctionCall: { allowance: string | null; receiver_id: string; method_names: string[] } };
  };
}

export interface KeyView {
  publicKey: string;
  kind: "full-access" | "function-call";
  receiver?: string;
  methods?: string[];
  /** yoctoNEAR the key may spend on gas; null = unlimited. */
  allowance?: string | null;
  /** Worst finding about this key. */
  severity: Severity;
  note: string;
}

export interface ScanResult {
  accountId: string;
  network: Network;
  exists: boolean;
  verdict: "danger" | "warn" | "ok";
  balance?: { total: string; staked: string; storageBytes: number };
  codeHash?: string;
  audit?: GuardAudit;
  keys: KeyView[];
  findings: Finding[];
}

const ONE_NEAR = 10n ** 24n;
const SEVERITY_ORDER: Severity[] = ["danger", "warn", "info", "ok"];
const worst = (a: Severity, b: Severity) => (SEVERITY_ORDER.indexOf(a) <= SEVERITY_ORDER.indexOf(b) ? a : b);
const shortKey = (k: string) => (k.length > 22 ? `${k.slice(0, 16)}…${k.slice(-4)}` : k);

// ---------------------------------------------------------------- names

/** Well-known accounts people send to or sign in to; a near-miss of one is the classic scam. */
export const WELL_KNOWN: Record<Network, Record<string, string>> = {
  mainnet: {
    near: "the NEAR top-level account",
    "wrap.near": "Wrapped NEAR (wNEAR)",
    "usdt.tether-token.near": "Tether USDt",
    "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1": "native USDC",
    "v2.ref-finance.near": "Ref Finance exchange",
    "token.v2.ref-finance.near": "REF token",
    "meta-pool.near": "Meta Pool staking",
    "linear-protocol.near": "LiNEAR staking",
    "intents.near": "NEAR Intents",
    "social.near": "NEAR Social",
    "token.sweat": "SWEAT token",
    "game.hot.tg": "HOT wallet",
    "contract.main.burrow.near": "Burrow lending",
    "token.burrow.near": "BRRR token",
    "sputnik-dao.near": "Sputnik DAO factory",
    aurora: "Aurora EVM",
  },
  testnet: {
    testnet: "the testnet top-level account",
    "wrap.testnet": "Wrapped NEAR (wNEAR) on testnet",
    "usdc.fakes.testnet": "test USDC",
    "usdt.fakes.testnet": "test USDT",
    "v1.social08.testnet": "NEAR Social on testnet",
    "ref-finance-101.testnet": "Ref Finance on testnet",
    aurora: "Aurora EVM on testnet",
  },
};

const TOP_LEVEL = new Set(["near", "testnet", "tg", "sweat", "aurora"]);

/** Characters that read alike at a glance, folded to one form: 0/o, 1/l/i, 5/s, rn/m, vv/w, and separators dropped. */
export function skeleton(s: string): string {
  return s.replace(/rn/g, "m").replace(/vv/g, "w").replace(/0/g, "o").replace(/[1i]/g, "l").replace(/5/g, "s").replace(/[-_.]/g, "");
}

function editDistance(a: string, b: string): number {
  const prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0];
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j];
      prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
    }
  }
  return prev[b.length];
}

/** The account whose owner controls `id`: NEAR sub-accounts can only be created by their parent. */
function parentOf(id: string): string | undefined {
  const i = id.indexOf(".");
  return i < 0 ? undefined : id.slice(i + 1);
}

/** Does this name imitate another account? Pure; `known` defaults to the network's well-known list. */
export function nameFindings(id: string, network: Network, known: Record<string, string> = WELL_KNOWN[network]): Finding[] {
  const out: Finding[] = [];
  if (isImplicitAccount(id)) {
    out.push({
      severity: "info",
      area: "name",
      title: "Implicit account (a 64-character key address)",
      detail: "There is no name to imitate, but a single wrong character is a different account. Copy it from its owner; never retype it.",
    });
  } else if (/^0x[0-9a-f]{40}$/.test(id)) {
    out.push({ severity: "info", area: "name", title: "Ethereum-style address", detail: "An EVM-compatible implicit account. Check every character against what its owner gave you." });
  }

  // alice.near.attacker.near reads as "alice.near…" but belongs to attacker.near.
  const parts = id.split(".");
  const embedded = parts.slice(0, -1).findIndex((p, i) => i > 0 && TOP_LEVEL.has(p));
  if (embedded > 0) {
    const shown = parts.slice(0, embedded + 1).join(".");
    const realOwner = parts.slice(embedded + 1).join(".");
    out.push({
      severity: "danger",
      area: "name",
      title: `Starts like ${shown}, but it is not ${shown}`,
      detail: `This is a sub-account of ${realOwner}: whoever owns ${realOwner} controls it. Scammers use this to look like ${shown} in a short preview.`,
    });
  }

  if (known[id]) {
    out.push({ severity: "ok", area: "name", title: `Known account: ${known[id]}`, detail: `${id} is the well-known ${known[id]} account.` });
    return out;
  }
  const body = id.replace(/\.(near|testnet|tg)$/, "");
  for (const [k, label] of Object.entries(known)) {
    if (k.length < 5) continue; // "near", "aurora" sub-accounts are legitimate everywhere
    const ancestor = id.endsWith(`.${k}`);
    if (ancestor) continue; // a sub-account of the real one is controlled by the real owner
    const sameSkeleton = skeleton(id) === skeleton(k) || (k.includes(".") && skeleton(body) === skeleton(k));
    const close = !isImplicitAccount(id) && k.length >= 10 && editDistance(id, k) <= (k.length >= 14 ? 2 : 1);
    if (sameSkeleton || close) {
      out.push({
        severity: "danger",
        area: "name",
        title: `Looks like ${k} (${label}), but is a different account`,
        detail: sameSkeleton
          ? `It differs from ${k} only in characters that read alike (0/o, 1/l, rn/m, dots and dashes). Funds sent here do not reach ${label}.`
          : `It is ${editDistance(id, k)} character(s) away from ${k}. Funds sent here do not reach ${label}.`,
      });
      break;
    }
  }
  const parent = parentOf(id);
  if (parent && known[parent] && !TOP_LEVEL.has(parent) && embedded < 0)
    out.push({ severity: "info", area: "name", title: `Sub-account of ${parent}`, detail: `Only the owner of ${parent} (${known[parent]}) could have created ${id}.` });
  return out;
}

// ---------------------------------------------------------------- keys

/** Method names that usually change who controls the account or its rules, not day-to-day actions. */
export const ADMIN_METHOD = /^(rotate|add|remove|delete|set|update|upgrade|migrate|withdraw|change|grant|revoke|deploy|transfer_owner|admin|owner|init|new)(_|$)/;

/** Who can sign for this account, and what can each key do? Pure. */
export function keyFindings(accountId: string, raw: RawAccessKey[], hasContract: boolean, network: Network): { keys: KeyView[]; findings: Finding[] } {
  const findings: Finding[] = [];
  const keys: KeyView[] = [];
  const full = raw.filter((k) => k.access_key.permission === "FullAccess");
  const fc = raw.filter((k) => k.access_key.permission !== "FullAccess");

  for (const k of full)
    keys.push({
      publicKey: k.public_key,
      kind: "full-access",
      severity: hasContract ? "warn" : full.length > 1 ? "warn" : "ok",
      note: hasContract ? "can replace the contract or move every coin, past any limit the contract sets" : "can move every coin and delete the account",
    });

  if (full.length === 0)
    findings.push(
      hasContract
        ? { severity: "ok", area: "keys", title: "Locked account: no full-access key", detail: "No key can bypass or replace the contract: funds move only by its code. That is how an agent wallet guard, or any contract holding other people's money, should be deployed." }
        : { severity: "warn", area: "keys", title: "No full-access key and no contract", detail: "Nobody can send these funds anywhere: app keys cannot transfer NEAR. If this is your wallet, it is locked." },
    );
  else if (full.length === 1)
    findings.push({ severity: "ok", area: "keys", title: "One full-access key", detail: "Normally your wallet's own key. Whoever holds it controls the whole account, so make sure it is yours." });
  else
    findings.push({
      severity: "warn",
      area: "keys",
      title: `${full.length} full-access keys`,
      detail: `Each one alone can take every coin and delete the account. Recognise every one (your wallet, a Ledger, a recovery phrase); remove any you don't.`,
    });
  if (full.length && hasContract)
    findings.push({
      severity: "warn",
      area: "keys",
      title: "Runs a contract but still has a full-access key",
      detail: "The contract's limits do not bind whoever holds that key: they can replace the code or drain the account. Fine for an upgradable app you trust; wrong for an agent wallet guard.",
    });

  let unlimited = 0;
  for (const k of fc) {
    const p = (k.access_key.permission as { FunctionCall: { allowance: string | null; receiver_id: string; method_names: string[] } }).FunctionCall;
    const self = p.receiver_id === accountId;
    const admin = p.method_names.filter((m) => ADMIN_METHOD.test(m));
    let severity: Severity = "info";
    let note: string;
    if (self && !hasContract) note = "key for this account's own contract, but no contract is deployed";
    else if (self && p.method_names.length === 0) {
      severity = "danger";
      note = "can call every method of this account's own contract as the account itself, admin methods included";
    } else if (self && admin.length) {
      severity = "warn";
      note = `can call ${admin.join(", ")} on this account's own contract: an admin method, not a spending one`;
    } else if (self) {
      severity = "ok";
      note = `scoped key: only ${p.method_names.join(", ")} on this account's own contract`;
    } else note = `app key for ${p.receiver_id}: ${p.method_names.length ? p.method_names.join(", ") : "any method"}; cannot transfer NEAR`;
    if (p.allowance === null) {
      unlimited++;
      severity = worst(severity, "warn");
      note += "; unlimited gas allowance";
    } else if (BigInt(p.allowance) > ONE_NEAR) {
      severity = worst(severity, "warn");
      note += `; may spend up to ${fmtNear(BigInt(p.allowance))} on gas`;
    }
    const lookalike = self ? [] : nameFindings(p.receiver_id, network).filter((f) => f.severity === "danger");
    if (lookalike.length) {
      severity = "danger";
      note += `; receiver ${lookalike[0].title.charAt(0).toLowerCase()}${lookalike[0].title.slice(1)}`;
    }
    keys.push({ publicKey: k.public_key, kind: "function-call", receiver: p.receiver_id, methods: p.method_names, allowance: p.allowance, severity, note });
  }

  const selfKeys = keys.filter((k) => k.kind === "function-call" && k.receiver === accountId && hasContract);
  for (const k of selfKeys.filter((k) => k.severity === "danger" || k.severity === "warn"))
    findings.push({
      severity: k.severity,
      area: "keys",
      title: k.methods?.length ? `Key ${shortKey(k.publicKey)} can call admin methods` : `Key ${shortKey(k.publicKey)} can call any method of this account's contract`,
      detail: `An agent or app holding it ${k.note}. A key that only pays should be scoped to the payment method (AgentFuzz invariant INV-3, key scope).`,
    });
  if (selfKeys.length && selfKeys.every((k) => k.severity === "ok"))
    findings.push({ severity: "ok", area: "keys", title: "Agent key is scoped", detail: `The key for this account's contract can only call ${[...new Set(selfKeys.flatMap((k) => k.methods ?? []))].join(", ")}.` });
  for (const k of keys.filter((k) => k.kind === "function-call" && k.receiver !== accountId && k.severity === "danger"))
    findings.push({ severity: "danger", area: "keys", title: `App key for a look-alike account: ${k.receiver}`, detail: `You signed in to ${k.receiver}, which imitates a well-known app. Remove key ${shortKey(k.publicKey)} and check what you approved there.` });
  if (unlimited)
    findings.push({ severity: "warn", area: "keys", title: `${unlimited} app key${unlimited > 1 ? "s" : ""} with unlimited gas allowance`, detail: "They cannot transfer NEAR, but can keep spending your balance on transaction fees. Remove the ones you don't use." });
  const apps = fc.filter((k) => (k.access_key.permission as { FunctionCall: { receiver_id: string } }).FunctionCall.receiver_id !== accountId).length;
  if (apps > 10)
    findings.push({ severity: "info", area: "keys", title: `${apps} app sign-in keys`, detail: "Each app you signed in to left a key. Remove old ones in your wallet's connected-apps settings." });
  return { keys, findings };
}

// ---------------------------------------------------------------- contract

export function contractFindings(codeHash: string, audits: GuardAudit[] | undefined): { findings: Finding[]; audit?: GuardAudit } {
  if (codeHash === NO_CODE_HASH) return { findings: [{ severity: "ok", area: "contract", title: "Plain account, no contract", detail: "Only its keys can move its funds." }] };
  if (audits === undefined)
    return { findings: [{ severity: "info", area: "contract", title: "Runs a contract", detail: `Code hash ${codeHash.slice(0, 16)}…; the AgentFuzz audit lookup was unavailable.` }] };
  const v = verdictOf(codeHash, audits);
  const a = v.latest;
  if (!a)
    return {
      findings: [{ severity: "info", area: "contract", title: "Runs a contract AgentFuzz has not audited", detail: `Code hash ${codeHash.slice(0, 16)}…. If it is an agent wallet guard, fuzz it: agentfuzz fuzz --target guard.wasm.` }],
    };
  const finding: Finding =
    v.verdict === "broken"
      ? { severity: "danger", area: "contract", title: `Audited wallet guard: ${a.broken}/${a.total} safety invariants broken`, detail: `This exact build failed ${a.broken_invariants.join(", ")} in AgentFuzz report ${a.run_id}${a.prompt_breaches ? `, and ${a.prompt_breaches} prompt-injection attacks got through` : ""}. Do not give an agent a budget on it.` }
      : v.verdict === "clean"
        ? { severity: "ok", area: "contract", title: `Audited wallet guard: ${a.held}/${a.total} safety invariants held`, detail: `This exact build held every invariant and blocked every prompt-injection attack in AgentFuzz report ${a.run_id}.` }
        : { severity: "warn", area: "contract", title: "Audited wallet guard, not fully exercised", detail: `Nothing broke in report ${a.run_id}, but only ${a.held}/${a.total} invariants were tested.` };
  return { findings: [finding], audit: a };
}

// ---------------------------------------------------------------- scan

export function overall(findings: Finding[]): ScanResult["verdict"] {
  return findings.some((f) => f.severity === "danger") ? "danger" : findings.some((f) => f.severity === "warn") ? "warn" : "ok";
}

function sortFindings(f: Finding[]): Finding[] {
  return f.map((x, i) => [x, i] as const).sort((a, b) => SEVERITY_ORDER.indexOf(a[0].severity) - SEVERITY_ORDER.indexOf(b[0].severity) || a[1] - b[1]).map(([x]) => x);
}

export interface ScanOptions {
  network?: Network;
  rpcUrl?: string;
  /** Where guard audits live (testnet). Code hashes are the same on every network, so mainnet accounts are looked up here too. */
  scoreboard?: string;
  auditRpcUrl?: string;
}

export async function scanAccount(input: string, opts: ScanOptions = {}): Promise<ScanResult> {
  const accountId = input.trim().toLowerCase();
  if (!isValidAccountId(accountId)) throw new Error(`"${input}" is not a valid NEAR account id (lowercase letters, digits, - _ and dots; 2–64 characters)`);
  const network = opts.network ?? networkOf(accountId);
  const url = opts.rpcUrl ?? RPC_OF[network];
  const names = nameFindings(accountId, network);

  let acct: { amount: string; locked: string; code_hash: string; storage_usage: number };
  try {
    acct = await rpc(url, "query", { request_type: "view_account", finality: "final", account_id: accountId });
  } catch (e) {
    if (!String(e).includes("does not exist")) throw e;
    const missing: Finding = isImplicitAccount(accountId)
      ? { severity: "info", area: "account", title: `Not created on ${network} yet`, detail: "Sending NEAR to an implicit address creates it; only safe if you got this exact address from its owner." }
      : { severity: "warn", area: "account", title: `Does not exist on ${network}`, detail: "A transfer to it would fail. Check the spelling and the network: mainnet names end in .near, testnet names in .testnet." };
    const findings = sortFindings([missing, ...names]);
    return { accountId, network, exists: false, verdict: overall(findings), keys: [], findings };
  }

  const codeHash = codeHashToHex(acct.code_hash);
  const hasContract = codeHash !== NO_CODE_HASH;
  const [keyList, audits] = await Promise.all([
    rpc(url, "query", { request_type: "view_access_key_list", finality: "final", account_id: accountId }) as Promise<{ keys: RawAccessKey[] }>,
    hasContract ? auditsOf(codeHash, opts.scoreboard ?? PUBLISHED_SCOREBOARD, opts.auditRpcUrl ?? TESTNET_RPC).catch(() => undefined) : Promise.resolve([]),
  ]);
  const k = keyFindings(accountId, keyList.keys, hasContract, network);
  const c = contractFindings(codeHash, audits);
  const findings = sortFindings([...k.findings, ...c.findings, ...names]);
  return {
    accountId,
    network,
    exists: true,
    verdict: overall(findings),
    balance: { total: acct.amount, staked: acct.locked, storageBytes: acct.storage_usage },
    codeHash: hasContract ? codeHash : undefined,
    audit: c.audit,
    keys: k.keys.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)),
    findings,
  };
}

/** Exit codes of `agentfuzz scan`: 0 nothing risky, 2 danger, 3 warnings, 4 account does not exist. */
export function scanExitCode(r: ScanResult): number {
  if (!r.exists) return 4;
  return r.verdict === "danger" ? 2 : r.verdict === "warn" ? 3 : 0;
}
