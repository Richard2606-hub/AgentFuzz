/**
 * Anchoring: write a scorecard's SHA-256 to the scoreboard contract so a published score can't be
 * edited later.
 *
 *  nearsim  deploys artifacts/scoreboard.wasm in an in-process chain and records there. Needs no
 *           network or keys; proves the exact contract path in CI and in `make demo-offline`.
 *  testnet  calls `record` on a deployed scoreboard with near-api-js (NEAR_ACCOUNT_ID,
 *           NEAR_PRIVATE_KEY, SCOREBOARD_CONTRACT_ID).
 *  local    appends to out/anchors.local.json (fallback when no credentials are configured).
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Account, JsonRpcProvider } from "near-api-js";
import { SimChain } from "../sim/chain.js";
import { deriveKeyPair, near } from "../near/keys.js";
import { decodeValue, functionCall } from "../near/types.js";
import { ARTIFACTS, REPO_ROOT } from "../targets/registry.js";
import type { AnchorRecord, Scorecard } from "../report/scorecard.js";

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
  const recorded = decodeValue(res.status) as ScoreboardRecord;
  return {
    network: "nearsim",
    contractId,
    runId: sc.runId,
    sha256: sc.sha256,
    txHash: res.txHash,
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
      return {
        network: "testnet",
        contractId: cfg.contractId,
        runId: sc.runId,
        sha256: sc.sha256,
        txHash,
        explorerUrl: explorerTx(txHash),
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
  return {
    network: "testnet",
    contractId: cfg.contractId,
    runId: sc.runId,
    sha256: sc.sha256,
    txHash: hash,
    explorerUrl: explorerTx(hash),
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
