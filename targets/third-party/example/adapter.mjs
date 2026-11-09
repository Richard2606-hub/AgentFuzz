// Adapter template for a third-party guard. Copy this folder, point target.json at the guard's
// wasm and change the method names / argument shapes below to match its interface.
//
// Amounts are bigint yoctoNEAR; NEAR JSON APIs expect them as decimal strings.

const ONE_YOCTO = 1n;

/** @type {import("../../../harness/src/targets/adapter.ts").GuardAdapter} */
const adapter = {
  id: "example-adapter",

  // Deploy-time init. cfg: { ownerId, cap, windowBlocks, blockTimeNs, allowlist, agentAllowance, ... }
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

  // The agent's payment method.
  pay: (receiverId, amount) => ({ method: "pay", args: { receiver_id: receiverId, amount: amount.toString() } }),

  // Owner controls.
  revoke: () => ({ method: "revoke_agent", args: {}, deposit: ONE_YOCTO }),
  withdraw: (amount) => ({ method: "withdraw", args: amount === undefined ? {} : { amount: amount.toString() }, deposit: ONE_YOCTO }),
  rekey: (publicKey, allowance) => ({
    method: "set_agent_key",
    args: { public_key: publicKey, allowance: allowance.toString() },
    deposit: ONE_YOCTO,
  }),

  // Other agent-callable methods (none here). Example for a guard with key rotation:
  //   [{ method: "rotate_key", build: (freshKey) => ({ new_public_key: freshKey }), installsKey: true }]
  agentExtras: [],

  // Owner-only methods the agent must never be able to call successfully.
  adminMethods: ["withdraw", "revoke_agent", "set_agent_key", "set_policy", "add_allowed", "remove_allowed"],

  // Stored accounting for INV-5 (delete this member if the guard doesn't expose it).
  readAccounting: async (view) => {
    const w = await view("get_window");
    return { window: BigInt(w.stored_window), spent: BigInt(w.stored_spent) };
  },
};

export default adapter;
