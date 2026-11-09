/**
 * World: one fresh, isolated fixture per fuzz run.
 *
 * Accounts (all under test.near, so the same layout works in a near-workspaces sandbox):
 *   guard.test.near     the target guard contract; after setup it holds only the agent key
 *   owner.test.near     administers the guard
 *   alice/bob/carol     allowlisted payees (carol can be deleted to force transfer failures)
 *   attacker.test.near  attacker-controlled; plus look-alike accounts of every payee
 */
import type { Backend } from "./near/backend.js";
import { STORAGE_BYTE_COST } from "./near/backend.js";
import { deriveKeyPair, near, type KeyPair } from "./near/keys.js";
import type { Action, Transaction, TxResult } from "./near/types.js";
import { callToAction, type Call, type GuardAdapter } from "./targets/adapter.js";
import type { LoadedTarget } from "./targets/registry.js";

export interface WorldConfig {
  seed: string;
  guardId: string;
  ownerId: string;
  attackerId: string;
  /** Allowlisted payees. The last one is "fragile": the fuzzer may delete it (A6). */
  allowlist: string[];
  lookalikes: string[];
  invalidReceivers: string[];
  guardBalance: bigint;
  cap: bigint;
  windowBlocks: number;
  agentAllowance: bigint;
  blockTimeNs: bigint;
  /** Owner may keep this much above the storage stake when withdrawing "everything". */
  withdrawMargin: bigint;
}

export function defaultConfig(seed: string, blockTimeNs = 1_000_000_000n): WorldConfig {
  const allowlist = ["alice.test.near", "bob.test.near", "carol.test.near"];
  return {
    seed,
    guardId: "guard.test.near",
    ownerId: "owner.test.near",
    attackerId: "attacker.test.near",
    allowlist,
    lookalikes: allowlist.flatMap((a) => [`${a}.attacker.test.near`, `x${a}`]),
    invalidReceivers: ["ALICE.test.near", "alice.test.near ", "alic\u0435.test.near", "", "alice..test.near", "a"],
    guardBalance: near(20),
    cap: near(3),
    windowBlocks: 60,
    agentAllowance: near("0.1"),
    blockTimeNs,
    withdrawMargin: near("0.05"),
  };
}

export interface ProbeOutcome {
  probe: string;
  publicKey: string;
  escaped: boolean;
  detail: string;
}

export class World {
  readonly keys: { deployer: KeyPair; owner: KeyPair; attacker: KeyPair; payees: Map<string, KeyPair> };
  /** Every key the agent has ever controlled (agent authority = any of these). */
  readonly agentKeyring = new Map<string, KeyPair>();
  activeAgentKey: string;
  initTimestamp = 0n;
  private keyCounter = 0;
  readonly deletedPayees = new Set<string>();

  constructor(
    readonly backend: Backend,
    readonly target: LoadedTarget,
    readonly cfg: WorldConfig,
  ) {
    const k = (label: string) => deriveKeyPair(`${cfg.seed}/${label}`);
    this.keys = {
      deployer: k("deployer"),
      owner: k("owner"),
      attacker: k("attacker"),
      payees: new Map(cfg.allowlist.map((a) => [a, k(`payee/${a}`)])),
    };
    const agent = this.freshAgentKey();
    this.activeAgentKey = agent.publicKey;
  }

  get adapter(): GuardAdapter {
    return this.target.adapter;
  }

  get windowNs(): bigint {
    return BigInt(this.cfg.windowBlocks) * this.cfg.blockTimeNs;
  }

  /** Mint a new agent-controlled key (deterministic) and add it to the keyring. */
  freshAgentKey(): KeyPair {
    const kp = deriveKeyPair(`${this.cfg.seed}/agent/${this.keyCounter++}`);
    this.agentKeyring.set(kp.publicKey, kp);
    return kp;
  }

  async setup(): Promise<void> {
    const { backend, cfg } = this;
    await backend.createAccount(cfg.ownerId, near(100), [this.keys.owner.publicKey]);
    await backend.createAccount(cfg.attackerId, near(5), [this.keys.attacker.publicKey]);
    for (const a of cfg.allowlist) await backend.createAccount(a, near(1), [this.keys.payees.get(a)!.publicKey]);
    for (const l of cfg.lookalikes) await backend.createAccount(l, near(1), [this.keys.attacker.publicKey]);
    await backend.createAccount(cfg.guardId, cfg.guardBalance, [this.keys.deployer.publicKey]);

    const init = this.adapter.initCall(cfg, this.activeAgentKey);
    const res = await backend.execTx({
      signerId: cfg.guardId,
      publicKey: this.keys.deployer.publicKey,
      receiverId: cfg.guardId,
      actions: [
        { type: "DeployContract", code: this.target.wasm },
        callToAction(init),
        { type: "DeleteKey", publicKey: this.keys.deployer.publicKey },
      ],
    });
    if (res.rejected || res.status?.kind !== "success")
      throw new Error(`guard setup failed for ${this.target.name}: ${JSON.stringify(res.rejected ?? res.status)}`);
    this.initTimestamp = res.receipts[0].blockTimestamp;
    await backend.settle();
  }

  // ------------------------------------------------------------------ transactions

  agentTx(call: Call, publicKey = this.activeAgentKey): Transaction {
    return { signerId: this.cfg.guardId, publicKey, receiverId: this.cfg.guardId, actions: [callToAction(call)] };
  }

  rawAgentTx(receiverId: string, actions: Action[], publicKey = this.activeAgentKey): Transaction {
    return { signerId: this.cfg.guardId, publicKey, receiverId, actions };
  }

  ownerTx(call: Call): Transaction {
    return { signerId: this.cfg.ownerId, publicKey: this.keys.owner.publicKey, receiverId: this.cfg.guardId, actions: [callToAction(call)] };
  }

  async exec(tx: Transaction): Promise<TxResult> {
    return this.backend.execTx(tx);
  }

  async view(method: string, args: unknown = {}): Promise<unknown> {
    return this.backend.view(this.cfg.guardId, method, args);
  }

  /** Balance the guard could release without breaking its storage stake. */
  async freeBalance(): Promise<bigint> {
    const bal = await this.backend.balance(this.cfg.guardId);
    const stake = (await this.backend.storageUsage(this.cfg.guardId)) * STORAGE_BYTE_COST;
    return bal > stake ? bal - stake : 0n;
  }

  /** Is this outflow agent-authorised (signed on the guard account by an agent-controlled key)? */
  isAgentSigned(signerId: string, publicKey: string): boolean {
    return signerId === this.cfg.guardId && this.agentKeyring.has(publicKey);
  }

  allowedAgentMethods(): string[] {
    return ["pay", ...this.adapter.agentExtras.map((e) => e.method)];
  }
}

export async function createWorld(backend: Backend, target: LoadedTarget, cfg: WorldConfig): Promise<World> {
  const w = new World(backend, target, cfg);
  await w.setup();
  return w;
}
