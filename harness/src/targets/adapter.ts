/**
 * Guard adapters translate AgentFuzz's abstract operations (pay, revoke, withdraw, re-key,
 * read accounting) into a concrete guard's method names and argument shapes.
 *
 * `agentfuzz-guard-v1` is the interface implemented by guard-reference and guard-naive.
 * Third-party guards get their own adapter (see targets/third-party/README.md).
 */
import { encodeArgs, type Action } from "../near/types.js";
import type { WorldConfig } from "../world.js";

export interface Call {
  method: string;
  args: unknown;
  deposit?: bigint;
  gas?: bigint;
}

export interface AgentExtraMethod {
  /** Method name; must be in the agent key's scope. */
  method: string;
  /** Build arguments; `freshKey` is a new agent-controlled public key the call may install. */
  build(freshKey: string): unknown;
  /** True if a successful call means the agent now signs with `freshKey`. */
  installsKey: boolean;
}

export interface GuardAdapter {
  readonly id: string;
  initCall(cfg: WorldConfig, agentPublicKey: string): Call;
  pay(receiverId: string, amount: bigint | string): Call;
  revoke(): Call;
  withdraw(amount?: bigint): Call;
  /** Owner re-provisions the agent key. Undefined = the guard has no recovery path. */
  rekey?(publicKey: string, allowance: bigint): Call;
  /** Agent-callable methods besides `pay` (e.g. key rotation). */
  agentExtras: AgentExtraMethod[];
  /** Admin methods the agent must never be able to use successfully. */
  adminMethods: string[];
  /** Raw stored accounting for INV-5. Undefined = not observable, INV-5 is reported n/a. */
  readAccounting?(view: (method: string, args?: unknown) => Promise<unknown>): Promise<{ window: bigint; spent: bigint }>;
}

export const ONE_YOCTO = 1n;
export const DEFAULT_GAS = 30n * 10n ** 12n;

export const guardV1: GuardAdapter = {
  id: "agentfuzz-guard-v1",
  initCall: (cfg, agentPublicKey) => ({
    method: "new",
    args: {
      owner_id: cfg.ownerId,
      agent_public_key: agentPublicKey,
      cap_per_window: cfg.cap.toString(),
      window_ns: (BigInt(cfg.windowBlocks) * cfg.blockTimeNs).toString(),
      allowlist: cfg.allowlist,
      agent_allowance: cfg.agentAllowance.toString(),
    },
    gas: 100n * 10n ** 12n,
  }),
  pay: (receiverId, amount) => ({ method: "pay", args: { receiver_id: receiverId, amount: amount.toString() } }),
  revoke: () => ({ method: "revoke_agent", args: {}, deposit: ONE_YOCTO }),
  withdraw: (amount) => ({ method: "withdraw", args: amount === undefined ? {} : { amount: amount.toString() }, deposit: ONE_YOCTO }),
  rekey: (publicKey, allowance) => ({
    method: "set_agent_key",
    args: { public_key: publicKey, allowance: allowance.toString() },
    deposit: ONE_YOCTO,
  }),
  agentExtras: [],
  adminMethods: ["withdraw", "revoke_agent", "set_agent_key", "set_policy", "add_allowed", "remove_allowed", "on_pay_complete"],
  readAccounting: async (view) => {
    const w = (await view("get_window")) as { stored_window: string | number; stored_spent: string };
    return { window: BigInt(w.stored_window), spent: BigInt(w.stored_spent) };
  },
};

/** guard-naive: same v1 interface plus an agent-callable `rotate_key`. */
export const guardV1WithRotate: GuardAdapter = {
  ...guardV1,
  id: "agentfuzz-guard-v1+rotate",
  agentExtras: [{ method: "rotate_key", build: (freshKey) => ({ new_public_key: freshKey }), installsKey: true }],
};

export function callToAction(c: Call): Action {
  return {
    type: "FunctionCall",
    methodName: c.method,
    args: encodeArgs(c.args),
    gas: c.gas ?? DEFAULT_GAS,
    deposit: c.deposit ?? 0n,
  };
}
