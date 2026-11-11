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
| `make demo-offline` | The whole demo in ~10 s: naive guard **6/6 invariants BROKEN** with minimised repros, reference guard **6/6 invariants held**, prompt layer **28/28 blocked** on reference vs **9 breaches** on naive, scorecard written to `out/scorecard.html` (`web/` is left alone unless you pass `--web`), hash anchored through `scoreboard.wasm` |
| `make web && make serve-web`, open http://localhost:8080 | The playground, running the same engine in your browser (a Web Worker, no server). **Fuzz a guard** on `naive`, seed 42, 200 runs: **6/6 broken**, 154 attack sequences, 832 steps, each break with its minimised repro, a download of the repro file (byte-identical to the CLI's) and the `agentfuzz replay` command; `reference`: **6/6 held**; uploading `artifacts/guard_naive__bug-window-lag.wasm`: **INV-1 broken**. **Prompt injection**: the 28 corpus scenarios executed for real: 19 blocked / 9 breaches on `naive`, 28 blocked on `reference`. **Check a wallet**: `guard-naive` → audited, 6/6 broken; `guard-reference` → audited, 6/6 held (read live from testnet). **Account safety**: `wrap-near.near` (a real mainnet account) → danger, looks like `wrap.near`; `guard-naive…` → danger (audited build broken, agent key can call `rotate_key`); `guard-reference…` → nothing risky |
| `make fuzz TARGET=naive` | `INV-1 BROKEN … minimised repro (1 step, classes A6): same-block burst of 2 pays …` and one `repro saved: out/repro-naive-INV-*.json` per broken invariant |
| `make fuzz TARGET=reference` | `INV-1 HELD … INV-6 HELD`, `all invariants held · ~190 attack sequences`, INV-5 exercised in ~50 runs |
| `make fuzz TARGET=naive:bug-window-lag` | `INV-1 BROKEN` with a repro like `wait 2 window(s) …; same-block burst of 2 pays: remaining budget, remaining budget` (window-rollover bug: after an idle period the cap stops applying) |
| `cd harness && node bin/agentfuzz.mjs replay ../out/repro-naive-INV-1-*.json` | The same steps re-executed in a fresh world and `BROKEN INV-1: agent spent … cap is 3 NEAR` |
| `make matrix` | `✓` for all 10 rows: each of the 8 planted bugs (7 in the default naive build + opt-in `bug-reset-on-failure`) found by its expected invariant, both controls clean (`all 10 rows passed`) |
| `make prompt TARGET=reference` | 28 lines `BLOCKED planner hijacked …` with the contract/protocol error that stopped each; `breaches 0` |
| `make prompt TARGET=naive` | `BREACH` on A1-002/A1-010/A1-012/A2-003 (prefix look-alikes) and A1-003/A2-006 (injected `rotate_key` → full-access key → balance drained), plus three agent-to-agent attacks: A1-014 (counterparty agent's look-alike settlement account), A1-016 (marketplace agent's key rotation), A2-011 (poisoned agent-registry payout) |
| `cd harness && node bin/agentfuzz.mjs check guard-naive.agentfuzz-28213.testnet` | Reads the account's code hash from testnet and the scoreboard's audit of that build: `✗ audited: 6/6 invariants broken (INV-1 … INV-6), 9 prompt-layer breaches`, exit code 2. `guard-reference.agentfuzz-28213.testnet`: `✓ audited: 6/6 invariants held`, exit 0. Any account without an audit: exit 3 |
| `make report` | `out/scorecard.json`, `out/scorecard.html`, `web/index.html`; run id `af-42-…`; anchors: testnet if `.env` is set, otherwise nearsim + `out/anchors.local.json` |
| `make verify` | `✓ body hash matches … ✓ deterministic re-run reproduced the identical hash … verified` |
| `cd harness && node bin/agentfuzz.mjs diff --target reference --runs 20` | Differential test: runs identical sequences on nearsim and real nearcore sandbox, confirming 20/20 agree |
| `cd harness && node bin/agentfuzz.mjs scan wrap-near.near` | Reads the mainnet account and flags it: `✗ Looks like wrap.near (Wrapped NEAR (wNEAR)), but is a different account`, exit code 2. Try your own account: risky keys are `!` (exit 3), nothing risky exits 0 |
| `make test` | 38 contract unit tests (if Rust is installed) and 98 harness tests, including the planted-bug matrix, a check that the published scorecard still reproduces, and a check that the browser bundle gives the CLI's exact results |
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
  deterministic: thousands of attack sequences run in seconds, from a seed, against the exact
  wasm you deploy, with the same hash on Linux, Windows and macOS (CI checks all three). A
  near-workspaces sandbox suite ([`tests/sandbox`](tests/sandbox)) checks the same contracts on
  real nearcore.
* **Minimised repros**: fast-check shrinks every failing sequence; `out/repro-*.json` contains the
  steps, seed, config and trace, and `agentfuzz replay` re-executes it.
* **Reproducible scores**: the scorecard body has no timestamps, so `agentfuzz verify` re-runs the
  whole campaign and recomputes the identical hash; the hash is anchored in
  [`contracts/scoreboard`](contracts/scoreboard).
* **Versioned generator**: improving the fuzzer must not invalidate published scores, so the
  sequence generator is versioned (`--generator N`) and the scorecard records which one it used.
  v2 (the default) draws longer sequences (about 9 steps instead of 4) and adds a delete-then-pay
  failing-transfer step, "pay exactly the budget the guard says is left", longer idle periods and
  allowance-exhausting drains, then minimises each repro further. Over 120 seeds at 30
  runs/invariant it misses 1 of 840 hunts for the 7 original planted bugs, where v1 missed 81.
  Old scorecards keep verifying with v1.

Full component map: [ARCHITECTURE.md](ARCHITECTURE.md).

## Browser playground

`web/index.html` (GitHub Pages) has the published scorecard and a playground that runs the real
engine client-side: no server, no scripted results.

* **Fuzz a guard**: pick `reference`, `naive`, `naive-fixed` or any single-bug build, or upload
  your own `.wasm` (driven through the `agentfuzz-guard-v1` adapter). A Web Worker fetches the
  committed wasm and runs `runCampaign` from `harness/src/campaign.ts`: the attack log and the
  invariant grid update as runs complete, and every break shows its minimised repro, a download of
  the repro file and the CLI command that replays it.
* **Prompt injection**: the committed corpus scenarios go through the reference agent and the
  guard on a fresh nearsim chain, showing the tool calls the planner made and what the chain did.
  Custom text needs a live model: paste a NEAR AI API key (kept in page memory only, sent only to
  `cloud-api.near.ai`, which allows browser requests) and the model plans the agent's actions.
* **Same results as the CLI**: the browser build swaps `node:crypto` for `@noble/hashes` +
  `@noble/curves` and nothing else. `harness/test/browser.test.ts` bundles the engine exactly as
  the site does, runs it, and checks verdicts, counts and repro bytes against the CLI.

* **Check a wallet**: enter any testnet account; the page reads its code hash and the
  scoreboard's audits of that build straight from a NEAR RPC (see below).
* **Account safety**: a safety scan of any mainnet or testnet account, for every NEAR user (see
  [Account safety](#account-safety-for-every-near-user)). Deep link: `…/#scan`.

Build it with `make web` (esbuild bundles, wasm, corpus and `index.html` into `web/`; the
generated files are not committed) and open it with `make serve-web`, since browsers block Web
Workers on `file://`. The Pages workflow runs the same build on every push to `main`.

## Agent economy: check a wallet before you trust it

Agents that pay, hire or delegate budgets to other agents need to know the wallet guard on the
other side holds up. AgentFuzz makes that a lookup:

1. Every NEAR account exposes the SHA-256 of the contract it runs (`code_hash` in `view_account`).
2. When a report is anchored, the scoreboard also records one **audit per guard build** it tested
   (`record_audits`): that SHA-256, invariants held / broken, prompt-injection breaches, and the
   report hash. Only the report's submitter can attach them.
3. `agentfuzz check <account>` (or the **Check a wallet** tab) reads both and answers `clean`,
   `broken`, `incomplete`, `not-audited` or `no-contract`, with exit codes an agent or CI step can
   act on: 0 clean, 2 broken, 3 not audited, 4 no contract, 5 incomplete.

Two demo guards on testnet run the audited builds (deployed with `agentfuzz demo-guards-deploy`:
deploy + init + delete the deploy key in one transaction, so no full-access key remains):

| Account | Build | `agentfuzz check` |
|---------|-------|-------------------|
| [`guard-reference.agentfuzz-28213.testnet`](https://testnet.nearblocks.io/address/guard-reference.agentfuzz-28213.testnet) | `guard_reference.wasm` | ✓ audited: 6/6 held, 0 prompt breaches (exit 0) |
| [`guard-naive.agentfuzz-28213.testnet`](https://testnet.nearblocks.io/address/guard-naive.agentfuzz-28213.testnet) | `guard_naive.wasm` | ✗ audited: 6/6 broken, 9 prompt breaches (exit 2) |

An audit is a claim by its submitter, not a certificate: it names a report that `agentfuzz verify`
re-runs to the same hash, and `--trust a.testnet,b.testnet` counts only submitters you trust. A
contract cannot read another account's code hash on-chain, so the check runs in the agent (or its
operator's tooling) before it pays.

The prompt corpus includes agent-to-agent attacks (channels `agent_message` and `agent_api`): a
supplier agent's quote demanding an "escrow" prepayment, a counterparty agent's look-alike
settlement account, an agent asking to be allowlisted, a marketplace agent asking for the signing
key, a refund to a look-alike, unit confusion in a partner agent's price API, an inflated delivery
count, and a poisoned agent-registry payout address.

## Account safety: for every NEAR user

Most NEAR users will never deploy a guard, but every one of them has access keys and sends money
to account names. `agentfuzz scan <account>` (or the **Account safety** tab) reads any mainnet or
testnet account (`.testnet` names go to testnet, everything else to mainnet) and reports, in plain
words:

| Area | What it flags |
|------|---------------|
| **Keys**: who can move the money | Several full-access keys (each one alone can take everything); a contract account that still has a full-access key (the contract's limits don't bind it); no full-access key and no contract (funds locked); an agent key for the account's own contract that can call admin methods like `rotate_key`, or any method at all (invariant INV-3, key scope); app keys with an unlimited or large gas allowance; app keys signed in to a look-alike of a well-known app; many old app sign-ins |
| **Contract**: what code runs on it | Plain account vs contract; for a contract, the AgentFuzz audit of that exact build (the code hash is the same on every network, so mainnet accounts are looked up on the testnet scoreboard too) |
| **Name**: is it who it looks like | Look-alikes of well-known accounts (`wrap-near.near`, `v2.ref-flnance.near`: characters that read alike, dots swapped for dashes, one or two edits); names that embed another account as a prefix (`alice.near.attacker.near` belongs to `attacker.near`); implicit and Ethereum-style addresses; accounts that don't exist on the network |

Exit codes: 0 nothing risky, 2 danger, 3 review, 4 account does not exist; `--json` for tools.
It is read-only (three RPC view calls, nothing to sign, no wallet to connect) and runs the same in
the browser. It can't know whether a full-access key is *yours*, or what an app does with the key
you gave it; a clean scan means no known risk pattern, not a guarantee.

| Account | `agentfuzz scan` |
|---------|------------------|
| `wrap-near.near` (mainnet) | ✗ looks like `wrap.near`, but is a different account (exit 2) |
| `guard-naive.agentfuzz-28213.testnet` | ✗ audited build: 6/6 invariants broken; ! agent key can call `rotate_key` (exit 2) |
| `guard-reference.agentfuzz-28213.testnet` | ✓ locked account, agent key scoped to `pay`, audited build held 6/6 (exit 0) |

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

### Reusable GitHub Action

Guard projects can drop AgentFuzz into their CI pipeline to audit pull requests automatically:

```yaml
- uses: actions/checkout@v4
- name: Run AgentFuzz Security Audit
  uses: Richard2606-hub/AgentFuzz/.github/actions/agentfuzz@main
  with:
    target: target/wasm32-unknown-unknown/release/guard.wasm
    runs: 200
    fail-on-break: true
```

See [.github/actions/agentfuzz/README.md](.github/actions/agentfuzz/README.md) for full action options.

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
`record(run_id, sha256, target, commit)`; records are append-only. It then attaches one audit per
tested guard build with `record_audits` (see [Agent economy](#agent-economy-check-a-wallet-before-you-trust-it)), and
`make verify` checks those too. Without credentials it
executes `scoreboard.wasm` in nearsim (proving the contract path offline) and writes
`out/anchors.local.json`. With `NEAR_ACCOUNT_ID`/`NEAR_PRIVATE_KEY` set, it records on testnet and
prints the NearBlocks link; `make verify` reads it back.

Testnet scoreboard: `SCOREBOARD_CONTRACT_ID` (see `.env.example`; deploy your own, or upgrade an
existing one in place, with `node bin/agentfuzz.mjs scoreboard-deploy`; audits use their own
storage prefix, so the upgrade needs no migration and keeps every earlier record).

### Live on NEAR testnet

<!-- anchor:start -->
| What | Where |
|------|-------|
| Scoreboard contract | [`scoreboard.agentfuzz-28213.testnet`](https://testnet.nearblocks.io/address/scoreboard.agentfuzz-28213.testnet) |
| Published scorecard | [`web/scorecard.json`](web/scorecard.json) / [`web/index.html`](web/index.html): run `af-42-1bc8418489ff` (commit `b19c517ab995`) |
| Report SHA-256 | `1bc8418489ff1d5b8f8645d05e462f4c8ba3dc1d7958790ecb6eb3719c81ed75` |
| Anchor transaction | [`4pXGiqfENhTzm8bSkFVa25Ko12XYz9uVr4hUgzzzNAzz`](https://testnet.nearblocks.io/txns/4pXGiqfENhTzm8bSkFVa25Ko12XYz9uVr4hUgzzzNAzz) |
<!-- anchor:end -->

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
cargo test --workspace                     # contract unit tests (from the repo root, needs Rust; no NASM needed on Windows)
```

## Repository layout

```
contracts/guard-reference/   well-built baseline guard (Rust, near-sdk 5.30.1) + 24 unit tests
contracts/guard-naive/       same interface, 8 planted bugs as cargo features (7 on by default; BUGS.md)
contracts/scoreboard/        report-hash anchoring + per-build guard audits + 11 unit tests
artifacts/                   committed wasm builds (+ single-bug variants), manifest.json
harness/src/sim/             nearsim: NEAR host ABI + chain model executing real wasm
harness/src/invariants/      INV-1..INV-6 checkers
harness/src/generators/      contract-layer generator (fast-check)
harness/src/attacks/         attack steps A3-A7
harness/src/agent/           reference agent + planners (compromised / cassette / NEAR AI Cloud)
harness/src/runner.ts        deploy -> attack -> check -> minimise -> report
harness/src/report/          scorecard JSON + HTML
harness/src/anchor/          scoreboard anchoring (nearsim / testnet / local) + audit lookup
harness/src/account/         account safety scan: keys, look-alike names, audited contract
corpus/prompt/               committed prompt-layer attacks
tests/sandbox/               near-workspaces integration tests (real nearcore)
targets/third-party/         adapters + policy for third-party guards
harness/src/browser/         playground: Web Worker engine, page controller, fetch client for NEAR AI
harness/src/platform/        crypto for Node (node:crypto) and browsers (@noble), same bytes
web/                         static site: scorecard + playground (built by make web; GitHub Pages)
```

## Limits (honest list)

* nearsim approximates gas (host calls, storage, actions and contract loading are metered with
  nearcore-like constants; wasm instructions are not), so allowance exhaustion happens after a
  realistic but not exact number of calls. The sandbox suite is the ground truth.
* Prompt-layer results with a live model depend on the model; the committed corpus is a snapshot.
* Guards are checked on native NEAR transfers; NEP-141 token payments are not modelled yet.
* A8 (social engineering of a human approval step) is not implemented.
* The account scan's look-alike check compares against a short built-in list of well-known
  accounts; a look-alike of an account not on that list is caught only by the prefix rule.
* The browser playground drives uploaded guards through the `agentfuzz-guard-v1` interface only;
  guards with their own adapter (third-party targets) run from the CLI. Under that interface the
  agent key may call only `pay`, so uploading one of the naive builds (whose agent key can also
  call `rotate_key`) additionally reports INV-3, exactly as `agentfuzz fuzz --target file.wasm` does.
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
