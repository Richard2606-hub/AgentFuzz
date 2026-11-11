import { afterEach, describe, expect, it, vi } from "vitest";
import { contractFindings, keyFindings, nameFindings, networkOf, overall, scanAccount, scanExitCode, skeleton, type RawAccessKey } from "../src/account/scan.js";
import { NO_CODE_HASH, type GuardAudit } from "../src/anchor/audit-lookup.js";
import { base58Encode } from "../src/near/keys.js";

const full = (pk = "ed25519:full1"): RawAccessKey => ({ public_key: pk, access_key: { nonce: 1, permission: "FullAccess" } });
const fc = (receiver: string, methods: string[], allowance: string | null = "250000000000000000000000", pk = `ed25519:fc-${receiver}-${methods.join("+")}`): RawAccessKey => ({
  public_key: pk,
  access_key: { nonce: 1, permission: { FunctionCall: { allowance, receiver_id: receiver, method_names: methods } } },
});
const sev = (f: { severity: string }[]) => f.map((x) => x.severity);
const danger = (f: { severity: string; title: string }[]) => f.filter((x) => x.severity === "danger").map((x) => x.title);

describe("account scan: names", () => {
  it("knows the network from the name", () => {
    expect(networkOf("alice.testnet")).toBe("testnet");
    expect(networkOf("alice.near")).toBe("mainnet");
    expect(networkOf("game.hot.tg")).toBe("mainnet");
  });

  it("folds characters that read alike", () => {
    expect(skeleton("v2.ref-flnance.near")).toBe(skeleton("v2.ref-finance.near"));
    expect(skeleton("rnetapool")).toBe(skeleton("metapool"));
    expect(skeleton("w0rap")).not.toBe(skeleton("wrap"));
  });

  it("flags look-alikes of well-known accounts", () => {
    expect(danger(nameFindings("wrap-near.near", "mainnet"))[0]).toMatch(/Looks like wrap\.near/);
    expect(danger(nameFindings("v2.ref-flnance.near", "mainnet"))[0]).toMatch(/v2\.ref-finance\.near/);
    expect(danger(nameFindings("usdt.tether-t0ken.near", "mainnet"))[0]).toMatch(/usdt\.tether-token\.near/);
    expect(danger(nameFindings("wrap.testnett", "testnet"))[0]).toMatch(/wrap.testnet/);
    expect(danger(nameFindings("intents1.near", "mainnet"))[0]).toMatch(/intents\.near/);
  });

  it("flags a name that embeds another account as its prefix", () => {
    const f = nameFindings("alice.near.attacker.near", "mainnet");
    expect(danger(f)[0]).toBe("Starts like alice.near, but it is not alice.near");
    expect(f[0].detail).toContain("sub-account of attacker.near");
  });

  it("does not flag ordinary, well-known or genuinely related names", () => {
    for (const id of ["alice.near", "trap.near", "aurora.near", "bob.testnet", "lookup.near"]) expect(danger(nameFindings(id, networkOf(id))), id).toEqual([]);
    expect(sev(nameFindings("wrap.near", "mainnet"))).toEqual(["ok"]);
    const sub = nameFindings("x.v2.ref-finance.near", "mainnet");
    expect(danger(sub)).toEqual([]);
    expect(sub[0].title).toBe("Sub-account of v2.ref-finance.near");
    expect(nameFindings("alice.near", "mainnet")).toEqual([]); // no "sub-account of near" noise
  });

  it("explains implicit addresses", () => {
    expect(nameFindings("a".repeat(64), "mainnet")[0].title).toMatch(/Implicit account/);
    expect(nameFindings("0x" + "ab".repeat(20), "mainnet")[0].title).toMatch(/Ethereum-style/);
  });
});

describe("account scan: keys", () => {
  it("a deployed reference guard (locked, agent key scoped to pay) is clean", () => {
    const { findings, keys } = keyFindings("g.testnet", [fc("g.testnet", ["pay"], "100000000000000000000000")], true, "testnet");
    expect(overall(findings)).toBe("ok");
    expect(findings.map((f) => f.title)).toEqual(["Locked account: no full-access key", "Agent key is scoped"]);
    expect(keys[0].note).toBe("scoped key: only pay on this account's own contract");
  });

  it("an agent key that can call rotate_key is a key-scope problem (INV-3)", () => {
    const { findings } = keyFindings("g.testnet", [fc("g.testnet", ["pay", "rotate_key"])], true, "testnet");
    expect(overall(findings)).toBe("warn");
    expect(findings.find((f) => f.severity === "warn")!.detail).toContain("rotate_key");
  });

  it("an agent key for every method of the account's own contract is dangerous", () => {
    const { findings } = keyFindings("g.near", [fc("g.near", [])], true, "mainnet");
    expect(overall(findings)).toBe("danger");
    expect(danger(findings)[0]).toMatch(/can call any method/);
  });

  it("a contract with a full-access key can be bypassed", () => {
    const { findings } = keyFindings("app.near", [full()], true, "mainnet");
    expect(findings.map((f) => f.title)).toContain("Runs a contract but still has a full-access key");
    expect(overall(findings)).toBe("warn");
  });

  it("a plain wallet: one full key is fine, several need review, none means locked funds", () => {
    expect(overall(keyFindings("a.near", [full()], false, "mainnet").findings)).toBe("ok");
    expect(keyFindings("a.near", [full("k1"), full("k2"), full("k3")], false, "mainnet").findings[0].title).toBe("3 full-access keys");
    expect(keyFindings("a.near", [fc("app.near", [])], false, "mainnet").findings[0].title).toBe("No full-access key and no contract");
  });

  it("app keys: unlimited and large allowances, many sign-ins, look-alike receivers", () => {
    const unlimited = keyFindings("a.near", [full(), fc("social.near", ["set"], null)], false, "mainnet");
    expect(unlimited.findings.map((f) => f.title)).toContain("1 app key with unlimited gas allowance");
    const big = keyFindings("a.near", [full(), fc("social.near", [], "5000000000000000000000000")], false, "mainnet");
    expect(big.keys.find((k) => k.kind === "function-call")!.note).toContain("may spend up to 5 NEAR on gas");
    const many = keyFindings("a.near", [full(), ...Array.from({ length: 11 }, (_, i) => fc(`app${i}.near`, []))], false, "mainnet");
    expect(many.findings.map((f) => f.title)).toContain("11 app sign-in keys");
    const phish = keyFindings("a.near", [full(), fc("v2.ref-flnance.near", [])], false, "mainnet");
    expect(danger(phish.findings)[0]).toBe("App key for a look-alike account: v2.ref-flnance.near");
  });
});

describe("account scan: contract", () => {
  const audit = (broken: number, prompt_breaches = 0): GuardAudit => ({
    code_hash: "ab".repeat(32), target: "x", held: 6 - broken, broken, total: 6, broken_invariants: broken ? ["INV-1"] : [], prompt_breaches,
    run_id: "af-1", report_sha256: "00".repeat(32), submitter: "s.testnet", block_height: "1", timestamp_ns: "1",
  });
  it("maps audits to findings", () => {
    expect(contractFindings(NO_CODE_HASH, []).findings[0].title).toBe("Plain account, no contract");
    expect(contractFindings("ab".repeat(32), []).findings[0].severity).toBe("info");
    expect(contractFindings("ab".repeat(32), undefined).findings[0].detail).toContain("unavailable");
    expect(contractFindings("ab".repeat(32), [audit(0)]).findings[0].severity).toBe("ok");
    expect(contractFindings("ab".repeat(32), [audit(2)]).findings[0].severity).toBe("danger");
    expect(contractFindings("ab".repeat(32), [audit(0, 3)]).findings[0].severity).toBe("danger");
  });
});

describe("account scan: over RPC", () => {
  afterEach(() => vi.unstubAllGlobals());

  /** A fake NEAR RPC: one account with a contract and a naive-style agent key; audits_of returns a broken audit. */
  function stubRpc(accounts: Record<string, { code: Uint8Array; keys: RawAccessKey[] }>, audits: unknown[] = []) {
    const calls: string[] = [];
    vi.stubGlobal("fetch", async (url: string, init: { body: string }) => {
      const { params } = JSON.parse(init.body);
      calls.push(`${url} ${params.request_type} ${params.account_id}`);
      const ok = (result: unknown) => new Response(JSON.stringify({ jsonrpc: "2.0", id: "x", result }));
      if (params.request_type === "call_function") return ok({ result: [...new TextEncoder().encode(JSON.stringify(audits))] });
      const a = accounts[params.account_id];
      if (!a) return new Response(JSON.stringify({ jsonrpc: "2.0", id: "x", error: { cause: { name: "UNKNOWN_ACCOUNT" } } }));
      if (params.request_type === "view_account") return ok({ amount: "2000000000000000000000000", locked: "0", code_hash: base58Encode(a.code), storage_usage: 1000 });
      return ok({ keys: a.keys });
    });
    return calls;
  }

  it("scans a naive guard on testnet and looks its build up on the scoreboard", async () => {
    const code = new Uint8Array(32).fill(7);
    const calls = stubRpc(
      { "guard-naive.x.testnet": { code, keys: [fc("guard-naive.x.testnet", ["pay", "rotate_key"])] } },
      [{ code_hash: "07".repeat(32), target: "naive", held: 0, broken: 6, total: 6, broken_invariants: ["INV-1"], prompt_breaches: 9, run_id: "af-1", report_sha256: "00".repeat(32), submitter: "s.testnet", block_height: "1", timestamp_ns: "1" }],
    );
    const r = await scanAccount("Guard-Naive.x.testnet");
    expect(r.accountId).toBe("guard-naive.x.testnet");
    expect(r.network).toBe("testnet");
    expect(r.codeHash).toBe("07".repeat(32));
    expect(r.verdict).toBe("danger");
    expect(r.findings[0].title).toBe("Audited wallet guard: 6/6 safety invariants broken");
    expect(scanExitCode(r)).toBe(2);
    expect(calls.some((c) => c.startsWith("https://test.rpc.fastnear.com view_access_key_list"))).toBe(true);
  });

  it("uses mainnet for .near names and still reads audits from the testnet scoreboard", async () => {
    const calls = stubRpc({ "alice.near": { code: new Uint8Array(32), keys: [full()] } });
    const r = await scanAccount("alice.near");
    expect(r.network).toBe("mainnet");
    expect(r.verdict).toBe("ok");
    expect(scanExitCode(r)).toBe(0);
    expect(calls.every((c) => c.startsWith("https://rpc.mainnet.fastnear.com"))).toBe(true); // no contract → no audit lookup
  });

  it("reports a missing account with its name findings, and rejects invalid ids", async () => {
    stubRpc({});
    const r = await scanAccount("alice.near.attacker.near");
    expect(r.exists).toBe(false);
    expect(r.verdict).toBe("danger");
    expect(scanExitCode(r)).toBe(4);
    await expect(scanAccount("Not Valid!")).rejects.toThrow(/not a valid NEAR account id/);
  });
});
