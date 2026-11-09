import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SimChain } from "../src/sim/chain.js";
import { deriveKeyPair, near } from "../src/near/keys.js";
import { decodeValue, functionCall, type Action } from "../src/near/types.js";

const ART = join(__dirname, "..", "..", "artifacts");
const wasm = (name: string) => new Uint8Array(readFileSync(join(ART, name)));

const G = "guard.test.near";
const OWNER = "owner.test.near";
const ALICE = "alice.test.near";
const WINDOW_NS = 60n * 1_000_000_000n;

function setup(code = "guard_reference.wasm") {
  const chain = new SimChain({ seed: "unit" });
  const deployer = deriveKeyPair("unit/deployer");
  const agent = deriveKeyPair("unit/agent");
  const owner = deriveKeyPair("unit/owner");
  chain.createAccount(G, near(30), { fullAccessKeys: [deployer.publicKey] });
  chain.createAccount(OWNER, near(100), { fullAccessKeys: [owner.publicKey] });
  chain.createAccount(ALICE, near(1));
  const init: Action[] = [
    { type: "DeployContract", code: wasm(code) },
    functionCall("new", {
      owner_id: OWNER,
      agent_public_key: agent.publicKey,
      cap_per_window: near(3).toString(),
      window_ns: WINDOW_NS.toString(),
      allowlist: [ALICE],
      agent_allowance: near("0.1").toString(),
    }),
    { type: "DeleteKey", publicKey: deployer.publicKey },
  ];
  const res = chain.execTx({ signerId: G, publicKey: deployer.publicKey, receiverId: G, actions: init });
  return { chain, agent, owner, deployer, res };
}

const pay = (receiver: string, amount: bigint) => functionCall("pay", { receiver_id: receiver, amount: amount.toString() });

describe("nearsim executes real guard wasm", () => {
  it("deploys, initialises and scopes the agent key", () => {
    const { chain, agent, deployer, res } = setup();
    expect(res.status?.kind, JSON.stringify(res.status)).toBe("success");
    const keys = chain.accessKeys(G);
    expect(keys.map((k) => k.publicKey)).toEqual([agent.publicKey]);
    expect(keys[0].permission).toMatchObject({ kind: "FunctionCall", receiverId: G, methodNames: ["pay"] });
    expect(keys.find((k) => k.publicKey === deployer.publicKey)).toBeUndefined();
    const policy = chain.view(G, "get_policy") as any;
    expect(policy.owner_id).toBe(OWNER);
    expect(policy.allowlist).toEqual([ALICE]);
  });

  it("agent pays an allowlisted receiver through the function-call key", () => {
    const { chain, agent } = setup();
    const before = chain.balance(ALICE);
    const r = chain.execTx({ signerId: G, publicKey: agent.publicKey, receiverId: G, actions: [pay(ALICE, near(2))] });
    expect(r.status?.kind, JSON.stringify(r.status)).toBe("success");
    expect(r.finalStatus?.kind).toBe("success");
    expect(decodeValue(r.finalStatus)).toBe(true); // on_pay_complete returned true
    expect(chain.balance(ALICE) - before).toBe(near(2));
    expect((chain.view(G, "get_window") as any).spent).toBe(near(2).toString());
    expect(r.logs.some((l) => l.includes('"event":"pay_settled"'))).toBe(true);
    expect(chain.transfers.filter((t) => t.from === G && t.to === ALICE)).toHaveLength(1);
  });

  it("rejects over-cap payments with the contract's panic message", () => {
    const { chain, agent } = setup();
    chain.execTx({ signerId: G, publicKey: agent.publicKey, receiverId: G, actions: [pay(ALICE, near(2))] });
    const r = chain.execTx({ signerId: G, publicKey: agent.publicKey, receiverId: G, actions: [pay(ALICE, near(2))] });
    expect(r.status).toMatchObject({ kind: "failure" });
    expect((r.status as any).error).toContain("window cap exceeded");
  });

  it("enforces function-call key scope at the protocol level", () => {
    const { chain, agent } = setup();
    const transfer = chain.submit({ signerId: G, publicKey: agent.publicKey, receiverId: "attacker.test.near", actions: [{ type: "Transfer", deposit: 1n }] });
    expect(transfer.rejected?.kind).toBe("RequiresFullAccess");
    const wrongMethod = chain.submit({ signerId: G, publicKey: agent.publicKey, receiverId: G, actions: [functionCall("withdraw", {})] });
    expect(wrongMethod.rejected?.kind).toBe("MethodNameMismatch");
    const deposit = chain.submit({ signerId: G, publicKey: agent.publicKey, receiverId: G, actions: [functionCall("pay", {}, 30n * 10n ** 12n, 1n)] });
    expect(deposit.rejected?.kind).toBe("DepositWithFunctionCall");
  });

  it("refunds a failed transfer and the reference callback releases the reservation", () => {
    const { chain, agent } = setup();
    // allowlisted account that does not exist -> transfer fails, deposit refunded
    chain.execTx({ signerId: OWNER, publicKey: deriveKeyPair("unit/owner").publicKey, receiverId: G, actions: [functionCall("add_allowed", { account_id: "ghost.test.near" }, 30n * 10n ** 12n, 1n)] });
    const before = chain.balance(G);
    const r = chain.execTx({ signerId: G, publicKey: agent.publicKey, receiverId: G, actions: [pay("ghost.test.near", near(1))] });
    expect(decodeValue(r.finalStatus)).toBe(false);
    expect((chain.view(G, "get_window") as any).spent).toBe("0");
    // only gas was spent
    expect(before - chain.balance(G)).toBeLessThan(near("0.01"));
  });

  it("owner revokes the agent key via the contract", () => {
    const { chain, agent, owner } = setup();
    const r = chain.execTx({ signerId: OWNER, publicKey: owner.publicKey, receiverId: G, actions: [functionCall("revoke_agent", {}, 30n * 10n ** 12n, 1n)] });
    expect(r.status?.kind, JSON.stringify(r.status)).toBe("success");
    expect(chain.accessKeys(G)).toHaveLength(0);
    const after = chain.submit({ signerId: G, publicKey: agent.publicKey, receiverId: G, actions: [pay(ALICE, 1n)] });
    expect(after.rejected?.kind).toBe("AccessKeyNotFound");
  });

  it("drains the allowance until the protocol refuses agent transactions", () => {
    const { chain, agent } = setup();
    let rejected: string | undefined;
    for (let i = 0; i < 100 && !rejected; i++) {
      const s = chain.submit({ signerId: G, publicKey: agent.publicKey, receiverId: G, actions: [pay(ALICE, 0n)] });
      rejected = s.rejected?.kind;
      chain.runUntilIdle();
    }
    expect(rejected).toBe("NotEnoughAllowance");
  });

  it("charges allowances at nearcore's pessimistic gas price (300 Tgas ~ 1 NEAR, as observed on the sandbox)", () => {
    const { chain, agent } = setup(); // agent allowance 0.1 NEAR
    const max = chain.submit({ signerId: G, publicKey: agent.publicKey, receiverId: G, actions: [functionCall("pay", {}, 300n * 10n ** 12n)] });
    expect(max.rejected?.kind).toBe("NotEnoughAllowance");
    const cost = BigInt(/cost (\d+)/.exec(max.rejected!.message)![1]);
    expect(cost).toBeGreaterThan(near("0.8"));
    expect(cost).toBeLessThan(near("1.3"));
    const normal = chain.submit({ signerId: G, publicKey: agent.publicKey, receiverId: G, actions: [pay(ALICE, 1n)] });
    expect(normal.rejected).toBeUndefined();
  });

  it("naive guard: concurrent pays in one block bypass the cap (deferred accounting)", () => {
    const { chain, agent } = setup("guard_naive__bug-deferred-accounting.wasm");
    for (let i = 0; i < 3; i++) chain.submit({ signerId: G, publicKey: agent.publicKey, receiverId: G, actions: [pay(ALICE, near(3))] });
    chain.runUntilIdle();
    const paid = chain.transfers.filter((t) => t.from === G && t.to === ALICE).reduce((s, t) => s + t.amount, 0n);
    expect(paid).toBe(near(9));
  });

  it("reference guard: concurrent pays in one block respect the cap", () => {
    const { chain, agent } = setup();
    for (let i = 0; i < 3; i++) chain.submit({ signerId: G, publicKey: agent.publicKey, receiverId: G, actions: [pay(ALICE, near(3))] });
    chain.runUntilIdle();
    const paid = chain.transfers.filter((t) => t.from === G && t.to === ALICE).reduce((s, t) => s + t.amount, 0n);
    expect(paid).toBe(near(3));
  });
});
