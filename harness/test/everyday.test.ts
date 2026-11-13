import { afterEach, describe, expect, it, vi } from "vitest";
import { everydaySummary, EVERYDAY_LIMITS } from "../src/account/everyday.js";
import { scanAccount, type RawAccessKey } from "../src/account/scan.js";
import { base58Encode } from "../src/near/keys.js";

const full = (pk: string): RawAccessKey => ({ public_key: pk, access_key: { nonce: 1, permission: "FullAccess" } });
const app = (receiver: string, methods: string[], allowance: string | null = "250000000000000000000000"): RawAccessKey => ({
  public_key: `ed25519:app-${receiver}-${methods.join("+")}`,
  access_key: { nonce: 1, permission: { FunctionCall: { allowance, receiver_id: receiver, method_names: methods } } },
});

/** Scan through a fake RPC, as the front box does. */
function stub(accounts: Record<string, { keys: RawAccessKey[]; code?: boolean; amount?: string }>, audits: unknown[] = []) {
  vi.stubGlobal("fetch", async (_url: string, init: { body: string }) => {
    const { params } = JSON.parse(init.body);
    const ok = (result: unknown) => new Response(JSON.stringify({ jsonrpc: "2.0", id: "x", result }));
    if (params.request_type === "call_function") return ok({ result: [...new TextEncoder().encode(JSON.stringify(audits))] });
    const a = accounts[params.account_id];
    if (!a) return new Response(JSON.stringify({ jsonrpc: "2.0", id: "x", error: { cause: { name: "UNKNOWN_ACCOUNT" } } }));
    if (params.request_type === "view_account")
      return ok({ amount: a.amount ?? "12500000000000000000000000", locked: "0", code_hash: base58Encode(new Uint8Array(32).fill(a.code ? 7 : 0)), storage_usage: 500 });
    return ok({ keys: a.keys });
  });
}
const check = async (id: string) => everydaySummary(await scanAccount(id));
const jargon = /full-access|function-call|allowance|INV-\d|invariant|receiver_id|yocto|code hash/i;

describe("everyday summary of the account scan", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("a normal wallet with one key: green, says which key, and how to confirm it is yours", async () => {
    stub({ "me.near": { keys: [full("ed25519:CZNxavjUWsDE8rt8jbW1qkuzdCp2T5QFkiSqKKoi2hGj"), app("social.near", ["set"])] } });
    const e = await check("me.near");
    expect(e.light).toBe("green");
    expect(e.headline).toBe("No problems found");
    expect(e.balance).toBe("12.5 NEAR");
    expect(e.points[0]).toBe("Only one key can move the money: ed25519:CZNxav…2hGj. Check that it matches the key shown in your wallet's security settings. If it does, only you control this account.");
    expect(e.points[1]).toMatch(/connected to 1 app\. Apps can call their own contract for you but cannot send your NEAR away/);
    expect(e.limits).toBe(EVERYDAY_LIMITS);
  });

  it("several keys that can take everything: yellow, with what to do", async () => {
    stub({ "me.near": { keys: [full("ed25519:a"), full("ed25519:b"), full("ed25519:c")] } });
    const e = await check("me.near");
    expect(e.light).toBe("yellow");
    expect(e.headline).toBe("One thing to check");
    expect(e.points[0]).toMatch(/^3 different keys can each take all the money in this account\. If you do not recognise every one/);
  });

  it("signed in to a fake app and apps with unlimited fees: red, plain advice", async () => {
    stub({ "me.near": { keys: [full("ed25519:a"), app("v2.ref-flnance.near", []), app("social.near", [], null)] } });
    const e = await check("me.near");
    expect(e.light).toBe("red");
    expect(e.headline).toBe("Warning: problems found");
    expect(e.points.join(" ")).toContain("You connected this account to v2.ref-flnance.near, a fake copy of a well-known app. Remove that app's access in your wallet now");
    expect(e.points.join(" ")).toContain("A connected app can keep spending your NEAR on network fees without asking. It cannot send your money away");
  });

  it("a look-alike name: red, says it is very likely a scam", async () => {
    stub({ "wrap-near.near": { keys: [full("ed25519:x")] } });
    const e = await check("wrap-near.near");
    expect(e.light).toBe("red");
    expect(e.points[0]).toBe("This name imitates wrap.near (Wrapped NEAR (wNEAR)), but it is a different account. If someone asked you to send money here, it is very likely a scam.");
    expect(e.points.join(" ")).not.toContain("only you control");
  });

  it("a fake prefix that does not exist: still red, and explains both", async () => {
    stub({});
    const e = await check("alice.near.attacker.near");
    expect(e.light).toBe("red");
    expect(e.headline).toBe("Warning: this name looks like a scam");
    expect(e.points[0]).toMatch(/^This is not alice\.near: it belongs to whoever owns attacker\.near/);
    expect(e.points.at(-1)).toMatch(/^There is no account called alice\.near\.attacker\.near on NEAR mainnet/);
  });

  it("a missing account: grey, check the spelling", async () => {
    stub({});
    const e = await check("nobody-here-123.near");
    expect(e).toMatchObject({ light: "missing", headline: "We could not find nobody-here-123.near on mainnet" });
  });

  it("an AI-agent wallet whose guard failed the tests and whose agent key can change control: red", async () => {
    const audit = { code_hash: "07".repeat(32), target: "naive", held: 0, broken: 6, total: 6, broken_invariants: ["INV-1"], prompt_breaches: 9, run_id: "af-1", report_sha256: "00".repeat(32), submitter: "s.testnet", block_height: "1", timestamp_ns: "1" };
    stub({ "g.testnet": { code: true, keys: [app("g.testnet", ["pay", "rotate_key"])] } }, [audit]);
    const e = await check("g.testnet");
    expect(e.light).toBe("red");
    expect(e.points).toContain("This account runs wallet-protection code that failed AgentFuzz's safety tests. Do not trust it with money.");
    expect(e.points.join(" ")).toContain("An app or AI-agent key on this account can change who controls the account");
  });

  it("speaks without jargon in every case", async () => {
    const cases: [Record<string, { keys: RawAccessKey[]; code?: boolean }>, string][] = [
      [{ "me.near": { keys: [full("ed25519:a")] } }, "me.near"],
      [{ "me.near": { keys: [full("ed25519:a"), full("ed25519:b")] } }, "me.near"],
      [{ "me.near": { keys: [full("ed25519:a"), app("v2.ref-flnance.near", [], null)] } }, "me.near"],
      [{ "me.near": { keys: [app("x.near", [])] } }, "me.near"],
      [{ "g.near": { code: true, keys: [full("ed25519:a"), app("g.near", [])] } }, "g.near"],
    ];
    for (const [accounts, id] of cases) {
      stub(accounts);
      const e = await check(id);
      for (const p of [e.headline, ...e.points]) expect(p, p).not.toMatch(jargon);
    }
  });
});
