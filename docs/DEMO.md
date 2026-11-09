# Demo, post and submission kit

## 90-second video

Record a terminal at ~110 columns (`make demo-offline` prints everything in order), then the
scorecard page and the NearBlocks link.

| Time | On screen | Voice-over / caption |
|------|-----------|----------------------|
| 0:00–0:10 | Title card: "AgentFuzz" + one line of the problem | "Agents on NEAR hold money behind guard contracts. Who tests the guards?" |
| 0:10–0:30 | `make fuzz TARGET=naive`, attacks streaming | "AgentFuzz throws LLM-written injections and fuzzed call sequences at a guard in a local sandbox." |
| 0:30–0:50 | `make fuzz TARGET=naive:bug-window-lag` → `INV-1 BROKEN`, minimised repro (idle, then two transfers across a window boundary) | "It found a window-rollover bug and shrank it to a two-step repro." |
| 0:50–1:05 | `make fuzz TARGET=reference`: all six invariants held; `make prompt TARGET=naive`: injected `rotate_key` drains the wallet | "The reference guard holds all six invariants. The naive one loses its whole balance to one poisoned email." |
| 1:05–1:20 | `web/index.html` scorecard + testnet explorer showing the report hash | "Every score is hashed on NEAR testnet, so it can't be edited later. `agentfuzz verify` re-runs it." |
| 1:20–1:30 | Repo URL, `agentfuzz fuzz --target your_guard.wasm` | "Run it on your guard." |

Tips: `NO_COLOR=1` for plain logs; `--runs 100` makes every command finish in about a second.

## X post draft (edit before posting)

> Built at NEAR HACKATHON: AgentFuzz, a red-team harness for AI agent wallets. It fuzzes guard
> contracts + prompt-injects the agent, then scores which safety invariants hold. 7/7 planted bugs
> found, minimised to replayable repros. Results hashed on NEAR testnet. Try it on your guard:
> [repo link] @NEARProtocol #NEARHackathon

Attach the video. Post **before** submitting: the form needs the post's link, and submissions
can't be edited afterwards.

## Submission checklist

- [ ] Repo public, MIT licence, CI green, `make setup && make test && make demo-offline` passes from a clean clone
- [ ] README: problem, "Do X, see Y" table, architecture, NEAR primitives, limits, libraries, AI-assist disclosure
- [ ] ARCHITECTURE.md and THREAT_MODEL.md match the code
- [ ] Testnet contract id and transaction links in the README (refresh with `make report` right before submitting)
- [ ] Third-party targets credited; permission or disclosure handled
- [ ] Demo video ≤ 2 min recorded
- [ ] X post published: "built at NEAR HACKATHON", @NEARProtocol, #NEARHackathon, video attached
- [ ] Mainnet NEAR payout address ready
- [ ] Form: tracks = AI Security & Defense, Agent Economy, Open Innovation; description 20–2,000 characters; Website field left empty
- [ ] Submitted no later than Sat Nov 14, 20:00 MYT (deadline Nov 14, 23:59 UTC)
- [ ] Scorecard page kept online through Nov 25 (GitHub Pages workflow `pages.yml`)
- [ ] Re-read the live HACKATHON.md for last-minute rule changes

## Form description (≈900 characters)

AgentFuzz is a red-team harness for NEAR agent-wallet guards. Teams give AI agents money through a
guard contract and a function-call key, but almost none test those guards adversarially.
AgentFuzz attacks them on two layers: LLM-written prompt injections and tool-output poisoning fed
to a reference agent that holds only a function-call key, and property-based fuzzing of the
contract (boundary amounts, window rollover, look-alike receivers, same-block callback races, key
and gas-allowance abuse). Six invariants are checked against the chain's own receipts; every break
is shrunk to a minimal, replayable repro. The real contract wasm runs in nearsim, a deterministic
in-process NEAR runtime, and is confirmed on a near-workspaces sandbox. Results become a
scorecard whose SHA-256 is anchored in a testnet scoreboard contract; `agentfuzz verify` re-runs
it and recomputes the hash. All 7 planted bugs are found; the reference guard holds all 6
invariants.
