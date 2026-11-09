# guard-naive: planted bugs

`guard-naive` has the same interface as `guard-reference` (plus an agent-callable `rotate_key`)
and **seven planted bugs**. Each bug is a cargo feature; the default build enables all of them.
They are realistic: every one is a pattern that shows up in hand-written spending guards.

The planted-bug matrix (`make matrix`, and `harness/test/runner.test.ts`) builds every bug in
isolation (`artifacts/guard_naive__<feature>.wasm`) and fails CI if AgentFuzz misses any of them,
or if the controls (`guard-reference`, `guard_naive__fixed.wasm`) break anything.

| # | Feature | What's wrong | Breaks | Attack that finds it | Typical minimised repro |
|---|---------|--------------|--------|----------------------|-------------------------|
| B1 | `bug-window-lag` | On rollover the window start advances by exactly one window (`window_start += W`). After an idle period of 2+ windows the start stays in the past, so **every** `pay` resets the counter and the cap stops applying. | INV-1 | A4 window rollover | wait 2+ windows; pay cap; pay cap |
| B2 | `bug-prefix-allowlist` | Receivers are matched with `starts_with`, so `alice.test.near.attacker.test.near` (a sub-account of the attacker) passes as `alice.test.near`. | INV-2 | A5 look-alikes | pay any amount to the look-alike |
| B3 | `bug-rotate-full-key` | The agent-callable `rotate_key` installs the new key as a **full-access** key. The agent (or whoever talked it into rotating) can then add keys, deploy code and transfer everything. | INV-3 (and INV-1/2/4 once exploited) | A7 key abuse | rotate_key(fresh key) |
| B4 | `bug-deferred-accounting` | Spend is recorded in the transfer callback instead of before the transfer is scheduled. Several `pay` calls executed in the same block all pass the cap check before any callback runs. | INV-1 | A6 callback ordering | one block with 2 pays of `cap` |
| B5 | `bug-ignore-promise-result` | The callback never checks whether the transfer failed: a failed transfer stays counted (or is counted) as spend. Recorded spend drifts from reality and the agent's budget can be burnt by failing payees. | INV-5 | A6 failing promise | delete a payee; pay it |
| B6 | `bug-withdraw-underflow` | `withdraw` keeps one window's cap "in reserve for the agent" using plain `balance - stake - cap`. The owner can never withdraw everything, and once the balance drops below `cap + stake` the subtraction panics (overflow checks are on) and the owner can't withdraw at all. | INV-4 | A3 boundary amounts / end-of-run owner check | (none needed) owner withdraws all free funds |
| B7 | `bug-no-rekey` | There is no owner path to re-provision the agent key. Once the key's gas allowance is exhausted the agent is locked out for good: `G` has no full-access key, so nobody can add a new one. | INV-6 | A7 allowance drain | drain the allowance |

## Fixing them

`guard_naive__fixed.wasm` is the same source with every feature off; each `#[cfg(not(feature = ...))]`
branch shows the fix. `guard-reference` is the clean implementation of the same design.

**Do not deploy guard-naive with real funds.**
