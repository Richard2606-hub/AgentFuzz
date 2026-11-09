import { describe, expect, it } from "vitest";
import { anchorNearsim } from "../src/anchor/anchor.js";
import { renderScorecardHtml } from "../src/report/html.js";
import { buildScorecard, hashBody, targetScore, type ScorecardSettings } from "../src/report/scorecard.js";
import { CompromisedPlanner } from "../src/agent/planners.js";
import { loadCorpus, runPromptCampaign } from "../src/prompt-runner.js";
import { runCampaign } from "../src/runner.js";
import { loadTarget } from "../src/targets/registry.js";
import { base58Decode, base58Encode, deriveKeyPair, ed25519Verify, fmtNear, isValidAccountId, near } from "../src/near/keys.js";
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
    expect(html).not.toMatch(/<script|https?:\/\/[^"]*\.js/);
  });

  it("anchors through the real scoreboard wasm in nearsim", async () => {
    const sc = await scorecard();
    const a = await anchorNearsim(sc);
    expect(a.network).toBe("nearsim");
    expect(a.sha256).toBe(sc.sha256);
    expect(a.txHash).toMatch(/^tx_/);
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
