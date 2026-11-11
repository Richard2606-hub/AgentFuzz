/**
 * Anchoring: write a scorecard's SHA-256 to the scoreboard contract so a published score can't be
 * edited later.
 *
 *  nearsim  deploys artifacts/scoreboard.wasm in an in-process chain and records there. Needs no
 *           network or keys; proves the exact contract path in CI and in `make demo-offline`.
 *  testnet  calls `record` on a deployed scoreboard with near-api-js (NEAR_ACCOUNT_ID,
 *           NEAR_PRIVATE_KEY, SCOREBOARD_CONTRACT_ID).
 *
 * After the report hash, both on-chain modes attach one audit per tested guard build
 * (`record_audits`): its wasm SHA-256, which is the code hash NEAR reports for any account running
 * that build, and how many invariants held. `agentfuzz check <account>` reads them back.
 *  local    appends to out/anchors.local.json (fallback when no credentials are configured).
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Account, actions, JsonRpcProvider, PublicKey } from "near-api-js";
import { SimChain } from "../sim/chain.js";
import { deriveKeyPair, near } from "../near/keys.js";
import { decodeValue, functionCall } from "../near/types.js";
import { ARTIFACTS, REPO_ROOT } from "../targets/registry.js";
import type { AnchorRecord, Scorecard } from "../report/scorecard.js";
import type { AuditInput } from "./audit-lookup.js";

export const DEFAULT_TESTNET_RPC = "https://test.rpc.fastnear.com";
export const DEFAULT_SCOREBOARD = "agentfuzz-scoreboard.testnet";

export interface ScoreboardRecord {
  run_id: string;
  sha256: string;
  target: string;
  commit: string;
  submitter: string;
  block_height: string;
  timestamp_ns: string;
}

function recordArgs(sc: Scorecard) {
  return {
    run_id: sc.runId,
    sha256: sc.sha256,
    target: sc.body.targets.map((t) => t.name).join(",").slice(0, 128),
    commit: sc.meta.commit.slice(0, 128),
  };
}

/** One audit per tested guard build in the scorecard. */
export function auditInputs(sc: Scorecard): AuditInput[] {
  return sc.body.targets.map((t) => ({
    code_hash: t.wasmSha256,
    target: t.name.slice(0, 128),
    held: t.summary.held,
    broken: t.summary.broken,
    total: t.summary.total,
    broken_invariants: t.invariants.filter((i) => i.status === "broken").map((i) => i.id),
    prompt_breaches: t.summary.promptBreaches,
  }));
}

const auditSummary = (inputs: AuditInput[]): NonNullable<AnchorRecord["audits"]> =>
  inputs.map((a) => ({ target: a.target, codeHash: a.code_hash, held: a.held, broken: a.broken, total: a.total, promptBreaches: a.prompt_breaches }));

export async function anchorNearsim(sc: Scorecard): Promise<AnchorRecord> {
  const chain = new SimChain({ seed: `scoreboard/${sc.runId}` });
  const deployer = deriveKeyPair("scoreboard/deployer");
  const submitter = deriveKeyPair("scoreboard/submitter");
  const contractId = "scoreboard.test.near";
  chain.createAccount(contractId, near(5), { fullAccessKeys: [deployer.publicKey] });
  chain.createAccount("agentfuzz.test.near", near(5), { fullAccessKeys: [submitter.publicKey] });
  const code = new Uint8Array(readFileSync(join(ARTIFACTS, "scoreboard.wasm")));
  const init = chain.execTx({
    signerId: contractId,
    publicKey: deployer.publicKey,
    receiverId: contractId,
    actions: [{ type: "DeployContract", code }, functionCall("new", {})],
  });
  if (init.status?.kind !== "success") throw new Error(`scoreboard deploy failed: ${JSON.stringify(init.status)}`);
  const res = chain.execTx({
    signerId: "agentfuzz.test.near",
    publicKey: submitter.publicKey,
    receiverId: contractId,
    actions: [functionCall("record", recordArgs(sc), 30n * 10n ** 12n, near("0.05"))],
  });
  if (res.status?.kind !== "success") throw new Error(`scoreboard record failed: ${JSON.stringify(res.status)}`);
  const stored = chain.view(contractId, "get", { run_id: sc.runId }) as ScoreboardRecord;
  if (stored?.sha256 !== sc.sha256) throw new Error("scoreboard read-back mismatch");
  const inputs = auditInputs(sc);
  const audit = chain.execTx({
    signerId: "agentfuzz.test.near",
    publicKey: submitter.publicKey,
    receiverId: contractId,
    actions: [functionCall("record_audits", { run_id: sc.runId, audits_in: inputs }, 100n * 10n ** 12n, near("0.1"))],
  });
  if (audit.status?.kind !== "success") throw new Error(`scoreboard record_audits failed: ${JSON.stringify(audit.status)}`);
  for (const a of inputs) {
    const back = chain.view(contractId, "audit_of", { code_hash: a.code_hash }) as { run_id?: string; held?: number } | null;
    if (back?.run_id !== sc.runId || back.held !== a.held) throw new Error(`audit read-back mismatch for ${a.target}`);
  }
  const recorded = decodeValue(res.status) as ScoreboardRecord;
  return {
    network: "nearsim",
    contractId,
    runId: sc.runId,
    sha256: sc.sha256,
    txHash: res.txHash,
    auditTxHash: audit.txHash,
    audits: auditSummary(inputs),
    blockHeight: recorded.block_height,
    recordedAt: new Date().toISOString(),
    note: "offline proof: scoreboard.wasm executed in nearsim; use --anchor testnet to publish",
  };
}

export interface TestnetConfig {
  accountId: string;
  privateKey: string;
  contractId: string;
  rpcUrl: string;
}

export function testnetConfigFromEnv(env = process.env): TestnetConfig | undefined {
  if (!env.NEAR_ACCOUNT_ID || !env.NEAR_PRIVATE_KEY) return undefined;
  return {
    accountId: env.NEAR_ACCOUNT_ID,
    privateKey: env.NEAR_PRIVATE_KEY,
    contractId: env.SCOREBOARD_CONTRACT_ID ?? DEFAULT_SCOREBOARD,
    rpcUrl: env.NEAR_RPC_URL ?? DEFAULT_TESTNET_RPC,
  };
}

export function explorerTx(hash: string, network = "testnet"): string {
  return network === "mainnet" ? `https://nearblocks.io/txns/${hash}` : `https://testnet.nearblocks.io/txns/${hash}`;
}

/** Attach this scorecard's audits on testnet unless they are already there. Returns the tx hash, if one was sent. */
async function attachAuditsTestnet(sc: Scorecard, cfg: TestnetConfig): Promise<string | undefined> {
  const inputs = auditInputs(sc);
  const provider = new JsonRpcProvider({ url: cfg.rpcUrl });
  const missing: AuditInput[] = [];
  for (const a of inputs) {
    const list = (await provider.callFunction({ contractId: cfg.contractId, method: "audits_of", args: { code_hash: a.code_hash } })) as { run_id: string }[] | undefined;
    if (!list?.some((x) => x.run_id === sc.runId)) missing.push(a);
  }
  if (!missing.length) return undefined;
  const account = new Account(cfg.accountId, cfg.rpcUrl, cfg.privateKey as `ed25519:${string}`);
  const res = (await account.callFunctionRaw({
    contractId: cfg.contractId,
    methodName: "record_audits",
    args: { run_id: sc.runId, audits_in: missing },
    deposit: near("0.1"),
    gas: 100n * 10n ** 12n,
  })) as { transaction: { hash: string } };
  return res.transaction.hash;
}

export async function anchorTestnet(sc: Scorecard, cfg: TestnetConfig): Promise<AnchorRecord> {
  const existing = await readTestnetRecord(cfg.contractId, sc.runId, cfg.rpcUrl).catch(() => undefined);
  if (existing) {
    if (existing.sha256 === sc.sha256) {
      let txHash = existing.sha256;
      let recordedAt = new Date().toISOString();
      try {
        const prev = JSON.parse(readFileSync(join(REPO_ROOT, "web", "scorecard.json"), "utf8"));
        const prevAnchor = prev.anchors?.find((a: any) => a.network === "testnet" && a.runId === sc.runId);
        if (prevAnchor?.txHash) txHash = prevAnchor.txHash;
        if (prevAnchor?.recordedAt) recordedAt = prevAnchor.recordedAt;
      } catch {}
      let auditTxHash: string | undefined;
      try {
        const prev = JSON.parse(readFileSync(join(REPO_ROOT, "web", "scorecard.json"), "utf8"));
        auditTxHash = prev.anchors?.find((a: any) => a.network === "testnet" && a.runId === sc.runId)?.auditTxHash;
      } catch {}
      auditTxHash = (await attachAuditsTestnet(sc, cfg)) ?? auditTxHash;
      return {
        network: "testnet",
        contractId: cfg.contractId,
        runId: sc.runId,
        sha256: sc.sha256,
        txHash,
        explorerUrl: explorerTx(txHash),
        auditTxHash,
        audits: auditSummary(auditInputs(sc)),
        recordedAt,
        note: "already anchored on testnet (immutable)",
      };
    }
    throw new Error(`testnet already has run_id ${sc.runId} with different sha256: ${existing.sha256}`);
  }
  const account = new Account(cfg.accountId, cfg.rpcUrl, cfg.privateKey as `ed25519:${string}`);
  const res = (await account.callFunctionRaw({
    contractId: cfg.contractId,
    methodName: "record",
    args: recordArgs(sc),
    deposit: near("0.02"),
    gas: 30n * 10n ** 12n,
  })) as { transaction: { hash: string }; status?: unknown };
  const hash = res.transaction.hash;
  const auditTxHash = await attachAuditsTestnet(sc, cfg);
  return {
    network: "testnet",
    contractId: cfg.contractId,
    runId: sc.runId,
    sha256: sc.sha256,
    txHash: hash,
    explorerUrl: explorerTx(hash),
    auditTxHash,
    audits: auditSummary(auditInputs(sc)),
    recordedAt: new Date().toISOString(),
  };
}

export async function readTestnetRecord(contractId: string, runId: string, rpcUrl = DEFAULT_TESTNET_RPC): Promise<ScoreboardRecord | undefined> {
  const provider = new JsonRpcProvider({ url: rpcUrl });
  const r = await provider.callFunction({ contractId, method: "get", args: { run_id: runId } });
  return (r ?? undefined) as ScoreboardRecord | undefined;
}

export function anchorLocal(sc: Scorecard, outDir: string): AnchorRecord {
  mkdirSync(outDir, { recursive: true });
  const rec: AnchorRecord = {
    network: "local",
    runId: sc.runId,
    sha256: sc.sha256,
    recordedAt: new Date().toISOString(),
    note: "no testnet credentials configured; hash recorded in out/anchors.local.json",
  };
  const file = join(outDir, "anchors.local.json");
  const list: AnchorRecord[] = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : [];
  list.push(rec);
  writeFileSync(file, JSON.stringify(list, null, 2) + "\n");
  return rec;
}

/** The two demo guards `agentfuzz check` points at: the same builds the scorecard audits. */
export const DEMO_GUARDS = [
  { prefix: "guard-reference", artifact: "guard_reference.wasm" },
  { prefix: "guard-naive", artifact: "guard_naive.wasm" },
] as const;

/**
 * Deploy the reference and naive guard builds to sub-accounts of NEAR_ACCOUNT_ID, the way the test
 * world does: deploy + init + delete the deploy key in one transaction, so no full-access key is
 * left on the guard. The owner is NEAR_ACCOUNT_ID; the agent key is a derived demo key. They exist
 * so that `agentfuzz check guard-reference.<account>` has a real deployed guard to look at.
 */
export async function deployDemoGuardsTestnet(cfg: TestnetConfig, log: (s: string) => void): Promise<string[]> {
  const parent = new Account(cfg.accountId, cfg.rpcUrl, cfg.privateKey as `ed25519:${string}`);
  const provider = new JsonRpcProvider({ url: cfg.rpcUrl });
  const signerKey = (await parent.getSigner()!.getPublicKey()).toString();
  const ids: string[] = [];
  for (const g of DEMO_GUARDS) {
    const id = `${g.prefix}.${cfg.accountId}`;
    ids.push(id);
    const exists = await provider.viewAccount({ accountId: id }).then(() => true, () => false);
    if (exists) {
      log(`${id} already exists; leaving it as is`);
      continue;
    }
    const code = new Uint8Array(readFileSync(join(ARTIFACTS, g.artifact)));
    log(`creating ${id} and deploying ${g.artifact} (${code.length} bytes)`);
    await parent.createSubAccount({ accountOrPrefix: id, publicKey: signerKey, nearToTransfer: near("2.1") });
    const guard = new Account(id, cfg.rpcUrl, cfg.privateKey as `ed25519:${string}`);
    const init = {
      owner_id: cfg.accountId,
      agent_public_key: deriveKeyPair(`demo-guard/${id}/agent`).publicKey,
      cap_per_window: near(3).toString(),
      window_ns: (3600n * 10n ** 9n).toString(),
      allowlist: [cfg.accountId],
      agent_allowance: near("0.1").toString(),
    };
    await guard.signAndSendTransaction({
      receiverId: id,
      actions: [actions.deployContract(code), actions.functionCall("new", init, 100n * 10n ** 12n, 0n), actions.deleteKey(PublicKey.fromString(signerKey))],
    });
    log(`${id}: initialised (owner ${cfg.accountId}, cap 3 NEAR/hour); deploy key deleted`);
  }
  return ids;
}

/** Deploy the scoreboard contract to testnet (sub-account of NEAR_ACCOUNT_ID unless it exists). */
export async function deployScoreboardTestnet(cfg: TestnetConfig, log: (s: string) => void): Promise<string> {
  const code = new Uint8Array(readFileSync(join(ARTIFACTS, "scoreboard.wasm")));
  const parent = new Account(cfg.accountId, cfg.rpcUrl, cfg.privateKey as `ed25519:${string}`);
  const provider = new JsonRpcProvider({ url: cfg.rpcUrl });
  let exists = true;
  try {
    await provider.viewAccount({ accountId: cfg.contractId });
  } catch {
    exists = false;
  }
  if (!exists) {
    if (!cfg.contractId.endsWith(`.${cfg.accountId}`))
      throw new Error(`${cfg.contractId} does not exist and is not a sub-account of ${cfg.accountId}; set SCOREBOARD_CONTRACT_ID=scoreboard.${cfg.accountId}`);
    const signerKey = (await parent.getSigner()!.getPublicKey()).toString();
    log(`creating ${cfg.contractId} (2.5 NEAR for code storage)`);
    await parent.createSubAccount({ accountOrPrefix: cfg.contractId, publicKey: signerKey, nearToTransfer: near("2.5") });
  }
  const contract = new Account(cfg.contractId, cfg.rpcUrl, cfg.privateKey as `ed25519:${string}`);
  log(`deploying scoreboard.wasm (${code.length} bytes) to ${cfg.contractId}`);
  await contract.deployContract(code);
  try {
    await contract.callFunction({ contractId: cfg.contractId, methodName: "new", args: {} });
    log("initialised");
  } catch (e) {
    log(`init skipped: ${e instanceof Error ? e.message : String(e)}`);
  }
  return cfg.contractId;
}
