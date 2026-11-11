# ARCHITECTURE.md

Everything that attacks runs locally against freshly deployed contracts. The only thing written
to a public network is the SHA-256 of a report.

```mermaid
flowchart TD
  TM["THREAT_MODEL.md<br/>INV-1..INV-6, A1..A7"] --> GEN
  subgraph GEN["Generators"]
    PG["Prompt layer<br/>harness/src/agent, corpus/prompt<br/>NEAR AI Cloud or committed corpus"]
    CG["Contract layer<br/>harness/src/generators/contract.ts<br/>fast-check step sequences"]
  end
  GEN --> RUN["Runner<br/>harness/src/runner.ts, prompt-runner.ts<br/>fresh world per run, shrink, repro"]
  RUN --> W["World<br/>harness/src/world.ts<br/>owner, payees, attacker, look-alikes"]
  W --> B{"Backend<br/>harness/src/near/backend.ts"}
  B --> SIM["nearsim<br/>harness/src/sim<br/>real contract wasm + NEAR host ABI"]
  B --> SBX["near-workspaces sandbox<br/>tests/sandbox (Rust)"]
  SIM --> CHK["Invariant checkers<br/>harness/src/invariants/check.ts<br/>ledger, receipts, access keys"]
  CHK --> SC["Scorecard<br/>harness/src/report<br/>JSON + static HTML (web/)"]
  SC --> ANC["Scoreboard contract<br/>contracts/scoreboard<br/>record(run_id, sha256, target, commit)"]
  RUN -.same code, bundled.-> WEB["Browser playground<br/>harness/src/browser (Web Worker)<br/>web/ on GitHub Pages"]
```

## Components

| Component | Folder | Responsibility |
|-----------|--------|----------------|
| Reference guard | `contracts/guard-reference` | The well-built baseline (Rust, near-sdk 5.30.1). Fixed windows aligned to init time, spend reserved before the transfer and released on failure, exact-match allowlist, agent key scoped to `pay`, owner revoke / withdraw / re-key / policy. 24 unit tests. |
| Naive guard | `contracts/guard-naive` | Same interface + `rotate_key`, eight planted bugs as cargo features, seven of them in the default build (`BUGS.md`). |
| Scoreboard | `contracts/scoreboard` | Append-only `run_id → {sha256, target, commit, submitter, block}` registry, plus guard audits keyed by wasm SHA-256 (`record_audits` by the report's submitter; `audit_of` / `audits_of`), stored under their own prefix so the deployed contract upgrades in place; caller pays storage. 11 unit tests. |
| Wasm artifacts | `artifacts/`, `scripts/build-contracts.mjs` | Committed builds of every contract and every single-bug variant, with `manifest.json` (sha256 per file). Built with `--cfg near` (what `cargo near build` sets) and path remapping. |
| nearsim | `harness/src/sim` | In-process NEAR runtime. `vm.ts` implements the `env.*` host-function ABI over the platform's WebAssembly (Node or a browser) so the **real compiled contracts** execute; `chain.ts` models accounts, access keys (full / function-call with receiver, method list, allowance), transaction validation and fees, receipts executed block by block, promises/callbacks/joint promises/`promise_return`, data receipts, deposit refunds, state rollback, storage staking, and a value-transfer ledger. |
| Backend interface | `harness/src/near/backend.ts` | What the harness needs from a chain; implemented by nearsim (`harness/src/sim/backend.ts`) and by real nearcore sandbox (`harness/src/sandbox/backend.ts`). The near-workspaces sandbox is the ground-truth backend for integration tests (`tests/sandbox`). |
| Differential engine | `harness/src/differential.ts` | Differential testing engine: feeds identical fast-check attack sequences through both nearsim and a real nearcore sandbox, verifying agreement across all invariant verdicts (`agentfuzz diff`). |
| World | `harness/src/world.ts` | One fixture per run: owner, three payees (one deletable), attacker + look-alikes, guard deployed with deploy+init+delete-deployer-key; agent keyring. |
| Target registry + adapters | `harness/src/targets` | Which wasm to attack and how to call it (`specs.ts` is the pure target table, `registry.ts` reads files). `agentfuzz-guard-v1` adapter for our guards; any third-party guard plugs in with its own adapter. Each target can declare `expectBroken` for the planted-bug matrix. |
| Contract-layer generator | `harness/src/generators/contract.ts` | fast-check arbitraries over symbolic steps (`pay`, `burst`, `wait`, `probe`, `extra`, `drain`, `exploit`, `failPayee`, `failPay`, `owner`). Versioned (`GENERATOR_VERSIONS`): a released version's mix is frozen, and scorecards record the version so `verify` replays the same sequence stream. |
| Attack steps | `harness/src/attacks/steps.ts` | Resolve symbolic steps against the world and execute them; record a trace (pay txs, probe outcomes, owner failures, allowance exhaustion, failed transfers). |
| Invariant checkers | `harness/src/invariants` | INV-1..INV-6 exactly as in THREAT_MODEL.md. Passive checks read the ledger/keys; active end-of-run checks (INV-6 recovery, INV-4 revoke+withdraw) run last. |
| Runner | `harness/src/campaign.ts` (pure), `harness/src/runner.ts` (repro files) | One fast-check search per invariant (same seed ⇒ same sequence stream), memoised so each distinct sequence executes once; counterexamples are shrunk and saved as `out/repro-*.json`; `replay` re-executes a repro. |
| Planted-bug matrix | `harness/src/matrix.ts` | AgentFuzz's own end-to-end gate: every single-bug build must break its invariant; controls must stay clean. |
| Reference agent | `harness/src/agent` | Minimal payments agent whose only authority is the function-call key. Planners: `CompromisedPlanner` (offline, worst case), `CassettePlanner` (offline replay of recorded model decisions), `LLMPlanner` (NEAR AI Cloud, OpenAI-compatible, through a small `ChatClient`: the OpenAI SDK in Node, loaded lazily, or `fetch` in the browser). After the agent acts, the attacker cashes in any key it got onto `G`. |
| Prompt corpus | `corpus/prompt` | Committed A1/A2 scenarios with legitimate work, attacker calls and the invariants they aim at. |
| Prompt runner | `harness/src/prompt-campaign.ts` (pure), `harness/src/prompt-runner.ts` (corpus files, cassettes, planners) | Runs every scenario on a fresh world, scores resisted / blocked / breach. |
| Scorecard | `harness/src/report` | Deterministic body (no wall-clock data) → canonical JSON → SHA-256 → run id. Self-contained HTML. |
| Guard audit lookup | `harness/src/anchor/audit-lookup.ts` | Plain-fetch NEAR JSON-RPC: account code hash → scoreboard `audits_of` → verdict (clean / broken / incomplete / not-audited / no-contract). Shared by `agentfuzz check` and the playground's Check a wallet tab. |
| Account safety scan | `harness/src/account/scan.ts` | Any mainnet or testnet account: `view_account` + `view_access_key_list` (+ `audits_of` on the testnet scoreboard when it runs a contract) → findings on keys, contract and name, with a danger / warn / ok verdict. The analysis is pure functions over those RPC results, tested offline. Shared by `agentfuzz scan` and the playground's Account safety tab. |
| Anchoring | `harness/src/anchor/anchor.ts` | nearsim (executes `scoreboard.wasm` offline), testnet (near-api-js), local file fallback; testnet read-back for `verify`. |
| Report orchestration | `harness/src/report.ts` | `report`, `verify` (body hash, deterministic re-run, on-chain record). |
| Simulate before you sign | `harness/src/simulate/fork.ts`, `simulate.ts`, `intent.ts` | `RemoteFork` feeds nearsim (`SimChainOptions.fork`, `LazyStorage`) accounts, code, keys and storage from a NEAR RPC pinned to one final block; the simulator re-runs the transaction until a round reads nothing new, then reports balance, token, key and receipt effects plus risk findings. `intent.ts` decodes token/NFT/storage methods from the arguments alone (also the fallback when large state is unreadable). Shared by `agentfuzz simulate` and the playground's worker. |
| CLI | `harness/src/cli.ts`, `cli-report.ts`, `cli-simulate.ts`, `bin/agentfuzz.mjs` | `targets`, `fuzz`, `diff`, `replay`, `matrix`, `prompt`, `report`, `verify`, `check`, `scan`, `simulate`, `render-web`, `anchor`, `scoreboard-deploy`, `demo-guards-deploy`, `demo-offline`. |
| GitHub Action | `.github/actions/agentfuzz` | Drop-in reusable composite action (`agentfuzz-action`) allowing any external guard repository to run AgentFuzz fuzzing and prompt injection in CI. |
| Platform crypto | `harness/src/platform`, `harness/src/util/bytes.ts` | sha256 and ed25519 behind one interface: `node:crypto` in Node, `@noble/hashes` + `@noble/curves` in browser bundles (byte-identical, tested); Buffer-free hex/base64/UTF-16 helpers. |
| Browser playground | `harness/src/browser` | `worker.ts` (Web Worker) fetches the committed wasm, manifest and corpus and runs `engine.ts`, which calls the same `runCampaign` / `runPromptCampaign` as the CLI and streams progress, repros (same bytes and file names as the CLI) and prompt results; `page.ts` renders them; `llm-fetch.ts` is the optional NEAR AI client for custom text. No result is stored in the page. |
| Static site | `web/`, `scripts/build-web.mjs`, `scripts/serve-web.mjs` | `scorecard.json` written by `make report`; `make web` bundles the playground with esbuild (failing if a bundle pulls in `node:` modules or the OpenAI SDK), copies `artifacts/` and the corpus, and re-renders `index.html` (`agentfuzz render-web`). The Pages workflow runs the same build. |

## Run lifecycle

1. **Deploy**: a new nearsim chain; accounts created; the guard account signs one transaction
   `[DeployContract, FunctionCall new(...), DeleteKey(deployer)]`. The init adds the agent's
   function-call key via a promise. The init block's timestamp is the window origin.
2. **Attack**: steps execute through the agent's key (or the owner / a payee for control and A6
   steps). Same-block bursts submit several transactions before producing a block.
3. **Settle**: blocks are produced until no receipts are queued.
4. **Check**: INV-1/INV-2 from the ledger, INV-3 probes + key audit, INV-5 guard view vs ledger,
   then INV-6 recovery (if the allowance was exhausted) and INV-4 revoke + withdraw.
5. **Minimise**: fast-check shrinks failing sequences; the minimal one is saved with its seed,
   fast-check path, config and trace.
6. **Report**: per-target results → scorecard body → SHA-256 → anchored.

## Determinism

* Keys: ed25519 key pairs derived from `sha256("agentfuzz-key:" + label)` (`near/keys.ts`).
* Chain: ids, random seeds and block timestamps derive from the chain seed and counters.
* Generation: fast-check with `--seed`; the corpus is committed.
* The scorecard body contains no timestamps or durations, so `agentfuzz verify` recomputes the
  identical hash from `body.settings` (tested in `harness/test/report.test.ts`).

## nearsim fidelity

Faithful: host-function semantics used by near-sdk (registers, storage, promises, results, logs,
panics, balances, deposits, `signer_account_pk`), function-call key rules (single FunctionCall, no
deposit, receiver and method checks, allowance charged on prepaid gas), actor permissions,
sub-account creation rules, refunds on failure, state rollback, `LackBalanceForState`.

Forking: with `SimChainOptions.fork`, accounts that were not created locally are loaded from a
fork source on first use, with `LazyStorage` reading uncached keys through it (deletions leave a
tombstone). Without a fork source nothing changes: the fuzzer's results and every published hash
are identical. `keccak256` / `keccak512` are implemented for mainnet contracts that import them.

Approximate: gas. Host calls, storage bytes, receipt/action creation and contract loading are
charged with nearcore-like constants; wasm instructions are not metered, and gas refunds are
credited to the signer immediately instead of through refund receipts. Transaction cost follows
nearcore's `tx_cost`: send fees are burnt at the gas price, and prepaid + exec gas is reserved at
the **pessimistic gas price** `price × 1.03^(hop + prepaid / min_receipt_with_function_call_gas)`.
A function-call key's allowance is charged that whole reservation and never refunded, so a
300 Tgas agent call costs ≈1 NEAR of allowance while a 30 Tgas call costs ≈0.005 NEAR. (This
was found by running the sandbox suite: the first nearsim model charged allowances at the plain
gas price and was ~30× too optimistic for max-gas calls; `harness/test/sim.test.ts` now pins the
nearcore behaviour.) Not modelled: staking, sharding, cross-shard delays beyond one block per
receipt hop, yield/resume, global contracts, gas keys.

Ground truth: `tests/sandbox` runs the same committed wasm on a real nearcore sandbox via
near-workspaces (Linux/macOS/WSL): the reference guard's agent key is scoped, pays within policy,
refuses over-cap and non-allowlisted payments (INV-1/2), cannot transfer, add keys or call admin
methods (INV-3), and the owner can revoke and withdraw (INV-4); the naive guard's key escalation
(B3, then a direct drain with the injected key) and prefix look-alike payment (B2, to
`alice.test.near.attacker.test.near`) reproduce on nearcore.
