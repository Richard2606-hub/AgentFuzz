# AgentFuzz

**"Your agent's spending guard says it's safe. AgentFuzz checks."**

AgentFuzz is a red-team harness for NEAR agent-wallet guards. It throws **LLM-written
prompt-injection attacks** and **property-based contract fuzzing** at a guard contract, then
reports which safety properties held, as a scorecard anyone can re-run, with the report's SHA-256
anchored on-chain so a published score can't be quietly edited.

Built for the NEAR Hackathon (Nov 2026) · tracks: **AI Security & Defense** (primary), Agent
Economy, Open Innovation · MIT licence.

---

## The problem

NEAR's answer to "how do you give an AI agent money safely?" is a **guard contract** plus a
**function-call access key** scoped to it: give the agent money, not the keys. Dozens of teams are
now writing these guards, and almost none show evidence they survive an attacker.

The attack surface has two layers:

* **The planner** can be prompt-injected: a poisoned invoice, a fake tool result, an "urgent"
  message from the "owner".
* **The guard** can have logic bugs: window rollover, `u128` overflow, receiver look-alikes,
  callback ordering, keys that escalate, owner paths that break, gas allowances that lock the
  agent out.

A demo with one happy-path transfer surfaces none of this. AgentFuzz turns "this guard is safe"
into a checkable claim: six invariants, attacked by two generators, every result hashed and
replayable.

## Quick start (clean clone, no API keys, no network)

```bash
make setup && make test && make demo-offline
```

Requirements: Node.js ≥ 20 and GNU make. Rust 1.95 is only needed to rebuild the contracts
(`make build`); the harness uses the committed wasm in `artifacts/`. Without make, see
[Without make](#without-make).

## Do X, see Y

Every claim in this README is a command. Expected output is abbreviated.

| Do | See |
|----|-----|
| `make demo-offline` | The whole demo in ~10 s: naive guard **6/6 invariants BROKEN** with minimised repros, reference guard **6/6 invariants held**, prompt layer **20/20 blocked** on reference vs **6 breaches** on naive, scorecard written to `out/scorecard.html` and `web/index.html`, hash anchored through `scoreboard.wasm` |
| `make fuzz TARGET=naive` | `INV-1 BROKEN … minimised repro (1 step, classes A6): same-block burst of 3 pays …` and one `repro saved: out/repro-naive-INV-*.json` per broken invariant |
| `make fuzz TARGET=reference` | `INV-1 HELD … INV-6 HELD`, `all invariants held · ~270 attack sequences` |
| `make fuzz TARGET=naive:bug-window-lag` | `INV-1 BROKEN` with a repro like `wait 2 window(s) …; pay cap; pay cap` (window-rollover bug, two transfers across a boundary) |
| `cd harness && node bin/agentfuzz.mjs replay ../out/repro-naive-INV-1-*.json` | The same steps re-executed in a fresh world and `BROKEN INV-1: agent spent … cap is 3 NEAR` |
| `make matrix` | `✓` for all 9 rows: each of the 7 planted bugs found by its expected invariant, both controls clean (`all 9 rows passed`) |
| `make prompt TARGET=reference` | 20 lines `BLOCKED planner hijacked …` with the contract/protocol error that stopped each; `breaches 0` |
| `make prompt TARGET=naive` | `BREACH` on A1-002/A1-010/A1-012/A2-003 (prefix look-alikes) and A1-003/A2-006 (injected `rotate_key` → full-access key → balance drained) |
| `make report` | `out/scorecard.json`, `out/scorecard.html`, `web/index.html`; run id `af-42-…`; anchors: testnet if `.env` is set, otherwise nearsim + `out/anchors.local.json` |
| `make verify` | `✓ body hash matches … ✓ deterministic re-run reproduced the identical hash … verified` |
| `make test` | 29 contract unit tests (if Rust is installed) and 45 harness tests, including the planted-bug matrix |
| `make sandbox-test` (Linux/macOS) | The same wasm on a real nearcore sandbox via near-workspaces: INV-3/INV-4 hold on the reference guard; the naive key escalation and look-alike payment reproduce on nearcore |

## What it checks

| ID | Invariant |
|----|-----------|
| INV-1 | Total spent by the agent within any window ≤ the configured cap |
| INV-2 | No funds reach a receiver outside the allowlist |
| INV-3 | The agent key can't add keys, delete keys or transfer directly |
| INV-4 | The owner can always revoke the agent key and withdraw |
| INV-5 | Guard state stays consistent after failed cross-contract calls |
| INV-6 | The agent isn't locked out silently by gas-allowance exhaustion |

Attack classes A1 prompt injection, A2 tool-output poisoning, A3 boundary amounts, A4 window
rollover, A5 receiver look-alikes, A6 callback ordering, A7 key and allowance abuse. How each
invariant is checked and which attacks target it: [THREAT_MODEL.md](THREAT_MODEL.md).

## How it works

```
invariants (THREAT_MODEL.md)
   │
   ├─ prompt-layer generator ── corpus/prompt (committed) or NEAR AI Cloud
   │     reference agent holds ONLY a function-call key; planner: compromised | cassette | llm
   │
   ├─ contract-layer generator ── fast-check sequences: amounts, windows, receivers, bursts, keys
   │
   ▼
runner: fresh world per run → attack → settle → check INV-1..6 → shrink → repro (seed + steps)
   │
   ▼
nearsim: the REAL compiled contract wasm executed against an implementation of NEAR's host ABI
         (accounts, access keys, receipts, promises/callbacks, refunds, storage staking)
   │
   ▼
scorecard JSON + static HTML ──► SHA-256 ──► scoreboard contract (testnet / nearsim)
```

* **nearsim** ([`harness/src/sim`](harness/src/sim)) is why fuzzing is fast and fully
  deterministic: thousands of attack sequences run in seconds, on any OS, from a seed, against the
  exact wasm you deploy. A near-workspaces sandbox suite ([`tests/sandbox`](tests/sandbox)) checks
  the same contracts on real nearcore.
* **Minimised repros**: fast-check shrinks every failing sequence; `out/repro-*.json` contains the
  steps, seed, config and trace, and `agentfuzz replay` re-executes it.
* **Reproducible scores**: the scorecard body has no timestamps, so `agentfuzz verify` re-runs the
  whole campaign and recomputes the identical hash; the hash is anchored in
  [`contracts/scoreboard`](contracts/scoreboard).

Full component map: [ARCHITECTURE.md](ARCHITECTURE.md).

## NEAR primitives used

* **Function-call access keys**: the agent's only authority, scoped to the guard's methods with a
  finite gas allowance (tested by INV-3 and INV-6).
* **Cross-contract calls and promises**: how guards forward payments and reconcile in callbacks;
  the source of callback-ordering bugs (A6, INV-5).
* **near-workspaces sandbox**: a local chain for integration tests on real nearcore.
* **NEAR AI Cloud** (OpenAI-compatible): inference for the prompt-layer generator and live planner.
* **Testnet contract storage**: the scoreboard that makes published scores tamper-evident.

## Run it on your guard

```bash
cd harness
node bin/agentfuzz.mjs fuzz --target path/to/your_guard.wasm --runs 500
```

A custom wasm is driven through the `agentfuzz-guard-v1` adapter (methods `new`, `pay`,
`revoke_agent`, `withdraw`, `set_agent_key`, `get_window`). If your guard has a different
interface, write a ~40-line adapter: see [targets/third-party/README.md](targets/third-party/README.md).
Third-party guards are only ever deployed in a local chain; see the disclosure policy there.

## Prompt layer: offline and live

* **Offline (default)**: the committed corpus ([`corpus/prompt`](corpus/prompt)) with the
  `compromised` planner, which models a fully successful injection (the planner does the legit
  work *and* everything the attacker asked). The guard is the last line of defence; that is what is
  scored. `cassette` replays decisions a real model made when the corpus was recorded.
* **Live**: put `NEAR_AI_API_KEY` in `.env` (see [.env.example](.env.example)), then
  `node bin/agentfuzz.mjs prompt --target reference --live` asks a model on NEAR AI Cloud
  (`--record` stores its decisions as cassettes), and `node bin/agentfuzz.mjs corpus generate`
  writes new attacks with the model.

## On-chain anchoring

`make report` writes each run's SHA-256 to the scoreboard contract:
`record(run_id, sha256, target, commit)`; records are append-only. Without credentials it
executes `scoreboard.wasm` in nearsim (proving the contract path offline) and writes
`out/anchors.local.json`. With `NEAR_ACCOUNT_ID`/`NEAR_PRIVATE_KEY` set, it records on testnet and
prints the NearBlocks link; `make verify` reads it back.

Testnet scoreboard: `SCOREBOARD_CONTRACT_ID` (see `.env.example`; deploy your own with
`node bin/agentfuzz.mjs scoreboard-deploy`).

### Live on NEAR testnet

| What | Where |
|------|-------|
| Scoreboard contract | [`scoreboard.agentfuzz-28213.testnet`](https://testnet.nearblocks.io/address/scoreboard.agentfuzz-28213.testnet) |
| Published scorecard | [`web/scorecard.json`](web/scorecard.json) / [`web/index.html`](web/index.html): run `af-42-6bb18a9bc6ab` |
| Report SHA-256 | `6bb18a9bc6ab1641422a0eeff2579d5932c2dc66c4966453d6ddd67d4da0450e` |
| Anchor transaction | [`F3vqNGemssbgeWBbgarPBMXzUk9WHKEczd4qxy5EsHA6`](https://testnet.nearblocks.io/txns/F3vqNGemssbgeWBbgarPBMXzUk9WHKEczd4qxy5EsHA6) |

Check it yourself: `cd harness && node bin/agentfuzz.mjs verify ../web/scorecard.json` recomputes
the hash, re-runs the campaign from the recorded seed and reads the record back from testnet.

## Without make

```bash
cd harness && npm ci
npm test                                   # harness tests
node bin/agentfuzz.mjs demo-offline        # the demo
node bin/agentfuzz.mjs fuzz --target naive
node bin/agentfuzz.mjs matrix
node bin/agentfuzz.mjs report && node bin/agentfuzz.mjs verify ../out/scorecard.json
cargo test --workspace                     # contract unit tests (from the repo root, needs Rust)
```

## Repository layout

```
contracts/guard-reference/   well-built baseline guard (Rust, near-sdk 5.30.1) + 24 unit tests
contracts/guard-naive/       same interface, 7 planted bugs as cargo features (BUGS.md)
contracts/scoreboard/        report-hash anchoring contract + 5 unit tests
artifacts/                   committed wasm builds (+ single-bug variants), manifest.json
harness/src/sim/             nearsim: NEAR host ABI + chain model executing real wasm
harness/src/invariants/      INV-1..INV-6 checkers
harness/src/generators/      contract-layer generator (fast-check)
harness/src/attacks/         attack steps A3-A7
harness/src/agent/           reference agent + planners (compromised / cassette / NEAR AI Cloud)
harness/src/runner.ts        deploy -> attack -> check -> minimise -> report
harness/src/report/          scorecard JSON + HTML
harness/src/anchor/          scoreboard anchoring (nearsim / testnet / local)
corpus/prompt/               committed prompt-layer attacks
tests/sandbox/               near-workspaces integration tests (real nearcore)
targets/third-party/         adapters + policy for third-party guards
web/                         static scorecard site (GitHub Pages)
```

## Limits (honest list)

* nearsim approximates gas (host calls, storage, actions and contract loading are metered with
  nearcore-like constants; wasm instructions are not), so allowance exhaustion happens after a
  realistic but not exact number of calls. The sandbox suite is the ground truth.
* Prompt-layer results with a live model depend on the model; the committed corpus is a snapshot.
* Guards are checked on native NEAR transfers; NEP-141 token payments are not modelled yet.
* A8 (social engineering of a human approval step) is not implemented.
* Third-party guards: none are bundled in the default scorecard; see
  [targets/third-party/README.md](targets/third-party/README.md) for the opt-in policy.

## Libraries and disclosures

* Contracts: [near-sdk-rs](https://github.com/near/near-sdk-rs) 5.30.1; sandbox tests:
  [near-workspaces-rs](https://github.com/near/near-workspaces-rs) 0.24.
* Harness: [fast-check](https://fast-check.dev) (property-based generation and shrinking),
  [openai](https://github.com/openai/openai-node) client pointed at NEAR AI Cloud,
  [near-api-js](https://github.com/near/near-api-js) (testnet anchoring),
  [vitest](https://vitest.dev), [tsx](https://tsx.is), TypeScript.
* **AI assistance**: this project was built with AI coding assistants. The seed prompt-layer
  corpus was authored with AI assistance; it is labelled `"source": "seed"` in the corpus files.
* All attacks run against freshly deployed contracts in a local chain. AgentFuzz never calls
  anyone's live testnet or mainnet contracts.

## Licence

MIT, see [LICENSE](LICENSE).
