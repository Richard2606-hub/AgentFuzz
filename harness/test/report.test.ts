import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { anchorNearsim } from "../src/anchor/anchor.js";
import { codeHashToHex, NO_CODE_HASH, verdictOf, type GuardAudit } from "../src/anchor/audit-lookup.js";
import { renderScorecardHtml } from "../src/report/html.js";
import { buildScorecard, hashBody, targetScore, type ScorecardSettings } from "../src/report/scorecard.js";
import { CompromisedPlanner } from "../src/agent/planners.js";
import { loadCorpus, runPromptCampaign } from "../src/prompt-runner.js";
import { runCampaign } from "../src/runner.js";
import { loadTarget, REPO_ROOT } from "../src/targets/registry.js";
import { base58Decode, base58Encode, deriveKeyPair, ed25519Verify, fmtNear, isValidAccountId, near, sha256, sha256Hex } from "../src/near/keys.js";
import { canonicalJSON } from "../src/util/json.js";

async function scorecard(seed = 9) {
  const settings: ScorecardSettings = { seed, runs: 30, maxSteps: 12, backend: "nearsim", planner: "compromised", targets: ["reference", "naive"], corpusSha256: "x" };
  const scores = [];
  for (const name of settings.targets) {
    const target = loadTarget(name);
    const c = await runCampaign({ target, seed, runs: settings.runs, maxSteps: settings.maxSteps });
    const p = await runPromptCampaign({ target, planner: new CompromisedPlanner(), scenarios: loadCorpus() });
    scores.push(targetScore(c, p));
  }
  return buildScorecard(settings, scores, 0);
}

describe("scorecard", () => {
  it("hash is deterministic and covers the body", async () => {
    const a = await scorecard();
    const b = await scorecard();
    expect(a.sha256).toBe(b.sha256);
    expect(a.runId).toBe(`af-9-${a.sha256.slice(0, 12)}`);
    const tampered = structuredClone(a.body);
    tampered.targets[1].summary.broken = 0;
    expect(hashBody(tampered)).not.toBe(a.sha256);
  });

  it("renders a self-contained HTML page", async () => {
    const sc = await scorecard();
    const html = renderScorecardHtml(sc);
    expect(html).toContain(sc.sha256);
    expect(html).toContain("INV-6");
    expect(html).not.toMatch(/https?:\/\/[^"]*\.js/);
  });

  it("anchors through the real scoreboard wasm in nearsim", async () => {
    const sc = await scorecard();
    const a = await anchorNearsim(sc);
    expect(a.network).toBe("nearsim");
    expect(a.sha256).toBe(sc.sha256);
    expect(a.txHash).toMatch(/^tx_/);
    // One audit per guard build, keyed by its wasm SHA-256 (= the code hash NEAR reports).
    expect(a.auditTxHash).toMatch(/^tx_/);
    expect(a.audits?.map((x) => [x.target, x.codeHash])).toEqual(sc.body.targets.map((t) => [t.name, t.wasmSha256]));
    for (const t of sc.body.targets) {
      const x = a.audits!.find((y) => y.target === t.name)!;
      expect([x.held, x.broken, x.total, x.promptBreaches]).toEqual([t.summary.held, t.summary.broken, t.summary.total, t.summary.promptBreaches]);
    }
    expect(a.audits!.find((x) => x.target === "reference")!.broken).toBe(0);
    expect(a.audits!.find((x) => x.target === "naive")!.broken).toBeGreaterThan(0);
  });
});

describe("guard audit lookup", () => {
  const audit = (over: Partial<GuardAudit>): GuardAudit => ({
    code_hash: "ab".repeat(32), target: "t", held: 6, broken: 0, total: 6, broken_invariants: [], prompt_breaches: 0,
    run_id: "af-1", report_sha256: "cd".repeat(32), submitter: "agentfuzz.testnet", block_height: "1", timestamp_ns: "1", ...over,
  });

  it("NEAR's base58 code hash is the wasm SHA-256", () => {
    const wasm = new Uint8Array(readFileSync(join(REPO_ROOT, "artifacts", "guard_reference.wasm")));
    expect(codeHashToHex(base58Encode(sha256(wasm)))).toBe(sha256Hex(wasm));
  });

  it("the latest audit decides; breaks and prompt breaches make it unsafe", () => {
    const h = "ab".repeat(32);
    expect(verdictOf(h, []).verdict).toBe("not-audited");
    expect(verdictOf(NO_CODE_HASH, []).verdict).toBe("no-contract");
    expect(verdictOf(h, [audit({})]).verdict).toBe("clean");
    expect(verdictOf(h, [audit({}), audit({ held: 5, broken: 1, broken_invariants: ["INV-1"], run_id: "af-2" })]).verdict).toBe("broken");
    expect(verdictOf(h, [audit({ prompt_breaches: 1 })]).verdict).toBe("broken");
    // nothing broke, but one invariant was never exercised: not a pass, not a break
    expect(verdictOf(h, [audit({ held: 5 })]).verdict).toBe("incomplete");
  });

  it("only counts audits from trusted submitters when asked to", () => {
    const h = "ab".repeat(32);
    const list = [audit({ submitter: "someone.testnet", held: 0, broken: 6, broken_invariants: ["INV-1", "INV-2", "INV-3", "INV-4", "INV-5", "INV-6"] })];
    expect(verdictOf(h, list).verdict).toBe("broken");
    expect(verdictOf(h, list, ["agentfuzz.testnet"]).verdict).toBe("not-audited");
  });
});

describe("keys and encodings", () => {
  it("base58 round-trips including leading zeros", () => {
    for (const bytes of [new Uint8Array([0, 0, 1, 2, 255]), new Uint8Array(32).fill(7), new Uint8Array([])])
      expect(base58Decode(base58Encode(bytes))).toEqual(bytes);
  });

  it("derives deterministic, valid ed25519 keys", () => {
    const a = deriveKeyPair("x");
    expect(deriveKeyPair("x").publicKey).toBe(a.publicKey);
    expect(deriveKeyPair("y").publicKey).not.toBe(a.publicKey);
    const msg = new TextEncoder().encode("hello");
    expect(ed25519Verify(a.sign(msg), msg, base58Decode(a.publicKey.slice(8)))).toBe(true);
  });

  it("validates NEAR account ids like nearcore", () => {
    for (const ok of ["alice.test.near", "a-b_c.near", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]) expect(isValidAccountId(ok)).toBe(true);
    for (const bad of ["ALICE.near", "alice..near", "a", "", "alice.near ", "\u0430lice.near", "-alice.near"]) expect(isValidAccountId(bad)).toBe(false);
  });

  it("formats amounts for humans", () => {
    expect(fmtNear(near(3))).toBe("3 NEAR");
    expect(fmtNear(near("0.03"))).toBe("0.03 NEAR");
    expect(fmtNear(18n)).toBe("18 yocto");
  });

  it("canonical JSON is key-order independent", () => {
    expect(canonicalJSON({ b: 1, a: { d: 2n, c: [1] } })).toBe(canonicalJSON({ a: { c: [1], d: 2n }, b: 1 }));
  });
});
