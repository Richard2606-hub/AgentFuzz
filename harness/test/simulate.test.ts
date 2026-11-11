import { afterEach, describe, expect, it, vi } from "vitest";
import { SimBackend } from "../src/sim/backend.js";
import { LazyStorage, storageUsage } from "../src/sim/chain.js";
import { World, defaultConfig } from "../src/world.js";
import { loadTarget } from "../src/targets/registry.js";
import { base58Encode, near, sha256 } from "../src/near/keys.js";
import { fromBase64, fromHex, toBase64 } from "../src/util/bytes.js";
import { decodeIntent } from "../src/simulate/intent.js";
import { nearText, parseAction, parseNear, parseTransactions, simulate, simulateExitCode, txFromFields } from "../src/simulate/simulate.js";

const RPC = "https://fake-rpc.test";
const STATE_RPC = "https://fake-state-rpc.test";
const enc = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));

describe("simulate: parsing", () => {
  it("reads wallet-selector, RPC/explorer and flat action shapes", () => {
    const ws = parseAction({ type: "FunctionCall", params: { methodName: "ft_transfer", args: { receiver_id: "bob.near", amount: "5" }, gas: "30000000000000", deposit: "1" } });
    expect(ws).toMatchObject({ type: "FunctionCall", methodName: "ft_transfer", gas: 30_000_000_000_000n, deposit: 1n });
    expect(new TextDecoder().decode((ws as { args: Uint8Array }).args)).toBe('{"receiver_id":"bob.near","amount":"5"}');
    const rpc = parseAction({ FunctionCall: { method_name: "near_deposit", args: toBase64(enc({})), gas: 1, deposit: "10" } });
    expect(rpc).toMatchObject({ type: "FunctionCall", methodName: "near_deposit", deposit: 10n });
    expect(new TextDecoder().decode((rpc as { args: Uint8Array }).args)).toBe("{}");
    expect(parseAction({ Transfer: { deposit: "7" } })).toEqual({ type: "Transfer", deposit: 7n });
    expect(parseAction("CreateAccount")).toEqual({ type: "CreateAccount" });
    expect(parseAction({ type: "AddKey", params: { publicKey: "ed25519:x", accessKey: { permission: { receiverId: "app.near", methodNames: ["a"], allowance: "250" } } } })).toEqual({
      type: "AddKey",
      publicKey: "ed25519:x",
      permission: { kind: "FunctionCall", receiverId: "app.near", methodNames: ["a"], allowance: 250n },
    });
    expect(parseAction({ AddKey: { public_key: "ed25519:y", access_key: { permission: "FullAccess" } } })).toMatchObject({ permission: { kind: "FullAccess" } });
    expect(() => parseAction({ type: "Teleport" })).toThrow(/unsupported action/);
  });

  it("takes one transaction, a list, or {transactions}; the signer can come from outside", () => {
    const one = { receiverId: "Wrap.Near", actions: [{ type: "Transfer", params: { deposit: "1" } }] };
    expect(parseTransactions(one, "me.near")[0]).toMatchObject({ signerId: "me.near", receiverId: "wrap.near" });
    expect(parseTransactions({ transactions: [one, one] }, "me.near")).toHaveLength(2);
    expect(() => parseTransactions(one)).toThrow(/give the signer/);
    expect(() => parseTransactions({ receiverId: "a.near", actions: [] }, "me.near")).toThrow(/no actions/);
  });

  it("builds transactions from form fields", () => {
    expect(parseNear("1.5")).toBe(1_500_000_000_000_000_000_000_000n);
    expect(parseNear("2 NEAR")).toBe(2n * 10n ** 24n);
    expect(() => parseNear("abc")).toThrow();
    expect(txFromFields({ signerId: "Me.near", receiverId: "bob.near", transferNear: "0.25" })).toEqual({ signerId: "me.near", receiverId: "bob.near", actions: [{ type: "Transfer", deposit: 250_000_000_000_000_000_000_000n }] });
    const call = txFromFields({ signerId: "me.near", receiverId: "wrap.near", method: "near_deposit", depositNear: "1", gasTgas: "50" });
    expect(call.actions[0]).toMatchObject({ type: "FunctionCall", methodName: "near_deposit", gas: 50n * 10n ** 12n, deposit: 10n ** 24n });
    expect(() => txFromFields({ signerId: "me.near", receiverId: "x.near", method: "m", args: "{not json" })).toThrow(/arguments must be JSON/);
    expect(nearText(44_636_512_500_000_000_000n)).toBe("0.000044 NEAR");
    expect(nearText(1n)).toBe("less than 0.000001 NEAR");
  });
});

describe("simulate: intent decoding", () => {
  const meta = new Map([["usdt.tether-token.near", { symbol: "USDt", decimals: 6 }]]);
  const call = (receiverId: string, methodName: string, args: unknown, deposit = 0n) => ({ signerId: "me.near", receiverId, actions: [{ type: "FunctionCall" as const, methodName, args: enc(args), gas: 1n, deposit }] });
  it("turns token, NFT and storage methods into sentences and flags what the arguments reveal", () => {
    const ft = decodeIntent([call("usdt.tether-token.near", "ft_transfer", { receiver_id: "wrap-near.near", amount: "5000000" }, 1n)], "mainnet", meta);
    expect(ft.lines[0]).toBe("Send 5 USDt (token usdt.tether-token.near) to wrap-near.near");
    expect(ft.findings[0]).toMatchObject({ severity: "danger", title: expect.stringMatching(/^Token recipient wrap-near\.near: looks like wrap\.near/) });
    const nft = decodeIntent([call("x.paras.near", "nft_approve", { token_id: "7", account_id: "market.near" }, 10n ** 21n)], "mainnet");
    expect(nft.findings[0].title).toBe("Lets market.near move your NFT 7");
    expect(decodeIntent([call("t.near", "storage_unregister", { force: true }, 1n)], "mainnet").findings[0].title).toBe("Force-unregisters you from t.near");
    expect(decodeIntent([call("wrap.near", "near_deposit", {}, 10n ** 24n)], "mainnet")).toMatchObject({ lines: ["Wrap 1 NEAR into wrapped NEAR on wrap.near"], attached: 10n ** 24n });
    expect(decodeIntent([call("app.near", "do_thing", { x: 1 })], "mainnet").lines[0]).toBe('Call do_thing on app.near with {"x":1}');
  });
});

describe("LazyStorage", () => {
  it("falls back to the loader, remembers deletions, and clones with both", () => {
    const remote = new Map([["aa", new Uint8Array([1])], ["bb", new Uint8Array([2])]]);
    const loads: string[] = [];
    const s = new LazyStorage((k) => (loads.push(k), remote.get(k)));
    expect(s.get("aa")).toEqual(new Uint8Array([1]));
    expect(s.get("aa")).toEqual(new Uint8Array([1]));
    expect(loads).toEqual(["aa"]); // cached after the first read
    expect(s.has("zz")).toBe(false);
    expect(s.delete("bb")).toBe(true);
    expect(s.get("bb")).toBeUndefined(); // tombstone: not re-read from the remote
    s.set("bb", new Uint8Array([3]));
    const c = s.clone();
    expect(c.get("bb")).toEqual(new Uint8Array([3]));
    c.delete("aa");
    expect(c.get("aa")).toBeUndefined();
    expect(s.get("aa")).toEqual(new Uint8Array([1])); // the clone's deletion does not leak back
  });
});

/** A fake NEAR RPC serving a real nearsim world: the naive guard as deployed by the fuzzer. */
async function fakeNetwork(opts: { large?: boolean; stateRpcDown?: boolean } = {}) {
  const backend = new SimBackend({ seed: "sim-test" });
  const world = new World(backend, loadTarget("naive"), defaultConfig("sim-test"));
  await world.setup();
  const accounts = (backend.chain as unknown as { accounts: Map<string, { amount: bigint; locked: bigint; code?: { bytes: Uint8Array }; storage: Map<string, Uint8Array>; keys: Map<string, { nonce: bigint; permission: { kind: string; receiverId?: string; methodNames?: string[]; allowance?: bigint | null } }> }> }).accounts;
  const calls = { state: 0, stateRpc: 0 };
  const result = (r: unknown) => new Response(JSON.stringify({ jsonrpc: "2.0", id: "x", result: r }));
  const error = (name: string, data = name) => new Response(JSON.stringify({ jsonrpc: "2.0", id: "x", error: { cause: { name }, data } }));
  vi.stubGlobal("fetch", async (url: string, init: { body: string }) => {
    const { method, params } = JSON.parse(init.body);
    if (method === "block") return result({ header: { height: 1000, timestamp_nanosec: "1767225600000000000", hash: "fakeblock" } });
    if (url === STATE_RPC && opts.stateRpcDown) throw new TypeError("fetch failed");
    const a = accounts.get(params.account_id);
    if (params.request_type === "call_function") return error("MethodNotFound");
    if (!a) return error("UNKNOWN_ACCOUNT");
    switch (params.request_type) {
      case "view_account":
        return result({ amount: a.amount.toString(), locked: a.locked.toString(), code_hash: a.code ? base58Encode(sha256(a.code.bytes)) : "11111111111111111111111111111111", storage_usage: Number(storageUsage(a as never)) });
      case "view_code":
        return result({ code_base64: toBase64(a.code!.bytes) });
      case "view_access_key_list":
        return result({
          keys: [...a.keys].map(([pk, k]) => ({
            public_key: pk,
            access_key: { nonce: Number(k.nonce), permission: k.permission.kind === "FullAccess" ? "FullAccess" : { FunctionCall: { receiver_id: k.permission.receiverId, method_names: k.permission.methodNames, allowance: k.permission.allowance === null ? null : String(k.permission.allowance) } } },
          })),
        });
      case "view_state": {
        if (url === STATE_RPC) calls.stateRpc++;
        else calls.state++;
        if (url === RPC && opts.large) return error("TOO_LARGE_CONTRACT_STATE", `State of contract ${params.account_id} is too large to be viewed`);
        const prefix = Array.from(fromBase64(params.prefix_base64), (b) => b.toString(16).padStart(2, "0")).join("");
        return result({ values: [...a.storage].filter(([k]) => k.startsWith(prefix)).map(([k, v]) => ({ key: toBase64(fromHex(k)), value: toBase64(v) })) });
      }
    }
    return error("UNSUPPORTED");
  });
  return { world, calls };
}

describe("simulate: on a fork", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("runs the real guard wasm on forked state: the naive guard's rotate_key installs a full-access key", async () => {
    const { world, calls } = await fakeNetwork();
    const g = world.cfg.guardId;
    const tx = { signerId: g, receiverId: g, actions: [{ type: "FunctionCall" as const, methodName: "rotate_key", args: enc({ new_public_key: world.keys.attacker.publicKey }), gas: 60n * 10n ** 12n, deposit: 0n }] };
    const r = await simulate([tx], { rpcUrl: RPC, stateRpcUrl: STATE_RPC });
    expect(r.mode).toBe("executed");
    expect(r.complete).toBe(true);
    expect(r.txs[0]).toMatchObject({ status: "success", key: { publicKey: world.activeAgentKey, kind: "function-call" } });
    expect(r.keys[0].added.map((k) => [k.publicKey, k.permission.kind])).toEqual([[world.keys.attacker.publicKey, "FullAccess"]]);
    expect(r.keys[0].removed).toEqual([world.activeAgentKey]);
    expect(r.findings[0]).toMatchObject({ severity: "danger", title: "Gives someone full control of your account" });
    expect(r.verdict).toBe("danger");
    expect(simulateExitCode(r)).toBe(2);
    expect(r.stats.wholeStates).toBe(1); // small contract: its whole state in one call
    expect(calls.stateRpc).toBe(0);
    expect(BigInt(r.fees)).toBeGreaterThan(0n);
  });

  it("an agent payment to an allowlisted payee goes through; to the attacker it fails in the contract", async () => {
    const { world } = await fakeNetwork();
    const g = world.cfg.guardId;
    const pay = (to: string) => ({ signerId: g, receiverId: g, actions: [{ type: "FunctionCall" as const, methodName: "pay", args: enc({ receiver_id: to, amount: near("0.5").toString() }), gas: 60n * 10n ** 12n, deposit: 0n }] });
    const ok = await simulate([pay(world.cfg.allowlist[0])], { rpcUrl: RPC, stateRpcUrl: STATE_RPC });
    expect(ok.txs[0].status).toBe("success");
    expect(ok.summary).toContain(`${g} sends 0.5 NEAR to ${world.cfg.allowlist[0]}`);
    expect(ok.near.find((n) => n.accountId === world.cfg.allowlist[0])!.delta).toBe(near("0.5").toString());
    const bad = await simulate([pay(world.cfg.attackerId)], { rpcUrl: RPC, stateRpcUrl: STATE_RPC });
    expect(bad.txs[0].status).toBe("failure");
    expect(bad.txs[0].error).toMatch(/allowlist/i);
    expect(bad.findings.map((f) => f.title)).toContain("This transaction fails");
  });

  it("reads a large contract key by key over several rounds and gets the same answer", async () => {
    const { world, calls } = await fakeNetwork({ large: true });
    const g = world.cfg.guardId;
    const tx = { signerId: g, receiverId: g, actions: [{ type: "FunctionCall" as const, methodName: "rotate_key", args: enc({ new_public_key: world.keys.attacker.publicKey }), gas: 60n * 10n ** 12n, deposit: 0n }] };
    const r = await simulate([tx], { rpcUrl: RPC, stateRpcUrl: STATE_RPC });
    expect(r.mode).toBe("executed");
    expect(r.verdict).toBe("danger");
    expect(calls.stateRpc).toBeGreaterThan(0);
    expect(r.stats.storageKeys).toBeGreaterThan(0);
    expect(r.stats.rounds).toBeGreaterThanOrEqual(1);
  });

  it("falls back to decoding when the large-state RPC does not answer, and says so", async () => {
    const { world } = await fakeNetwork({ large: true, stateRpcDown: true });
    const g = world.cfg.guardId;
    const tx = { signerId: g, receiverId: g, actions: [{ type: "FunctionCall" as const, methodName: "pay", args: enc({ receiver_id: world.cfg.allowlist[0], amount: "1" }), gas: 60n * 10n ** 12n, deposit: 0n }] };
    const r = await simulate([tx], { rpcUrl: RPC, stateRpcUrl: STATE_RPC });
    expect(r.mode).toBe("decoded");
    expect(r.complete).toBe(false);
    expect(r.findings.map((f) => f.title)).toContain("Not executed: decoded from the transaction only");
    expect(r.note).toMatch(/did not answer/);
    expect(simulateExitCode(r)).toBe(3);
  });

  it("plain account actions: transfers, refusals, look-alikes, deleting the account", async () => {
    const { world } = await fakeNetwork();
    const owner = world.cfg.ownerId;
    const send = await simulate([{ signerId: owner, receiverId: world.cfg.allowlist[1], actions: [{ type: "Transfer", deposit: near(2) }] }], { rpcUrl: RPC, stateRpcUrl: STATE_RPC });
    expect(send.verdict).toBe("ok");
    expect(send.summary[0]).toBe(`${owner} sends 2 NEAR to ${world.cfg.allowlist[1]}`);
    expect(send.findings.at(-1)!.title).toBe("No risk pattern found");
    const broke = await simulate([{ signerId: world.cfg.attackerId, receiverId: owner, actions: [{ type: "Transfer", deposit: near(500) }] }], { rpcUrl: RPC, stateRpcUrl: STATE_RPC });
    expect(broke.txs[0].status).toBe("rejected");
    expect(broke.txs[0].rejected).toMatch(/^Not enough NEAR: attacker\.test\.near has 5 NEAR, and this needs 500 NEAR plus fees/);
    const prefix = await simulate([{ signerId: owner, receiverId: world.cfg.lookalikes[0], actions: [{ type: "Transfer", deposit: near(1) }] }], { rpcUrl: RPC, stateRpcUrl: STATE_RPC });
    expect(prefix.verdict).toBe("danger");
    expect(prefix.findings[0].title).toMatch(/^Receiver alice\.test\.near\.attacker\.test\.near: starts like alice\.test\.near/);
    const del = await simulate([{ signerId: owner, receiverId: owner, actions: [{ type: "DeleteAccount", beneficiaryId: world.cfg.attackerId }] }], { rpcUrl: RPC, stateRpcUrl: STATE_RPC });
    expect(del.findings[0]).toMatchObject({ severity: "danger", title: `Deletes your account ${owner}` });
    expect(del.near.find((n) => n.accountId === owner)!.after).toBeNull();
  });
});
