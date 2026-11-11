# Privacy

Short version: the AgentFuzz website collects nothing. It has no accounts, cookies, browser
storage, analytics or trackers. Everything it computes, it computes in your browser. When you
press a button that needs the blockchain or an AI model, your browser talks **directly** to the
service named below, and to nothing else: the page's Content-Security-Policy makes the browser
block every other destination.

This notice covers the web playground at https://richard2606-hub.github.io/AgentFuzz and the
`agentfuzz` command-line tool. Last updated 2026-11-12.

## What the website sends, and to whom

Nothing is contacted when the page loads, except the site itself (GitHub Pages). These hosts are
contacted only when you use the feature listed:

| Host | Operator | Used by | What it receives |
|------|----------|---------|------------------|
| `test.rpc.fastnear.com` | FastNEAR (NEAR testnet RPC) | Check a wallet, Account safety and Simulate on testnet | The testnet account ids you enter; read-only queries (accounts, keys, contract code and state) |
| `rpc.mainnet.fastnear.com` | FastNEAR (NEAR mainnet RPC) | Account safety and Simulate on mainnet | The mainnet account ids you enter; read-only queries (accounts, keys, contract code and state, token metadata) |
| `rpc.intea.rs` | Intear (RPC that serves large contract state) | Simulate, only for contracts over 50 kB of state | The contract account id and the storage keys the simulation reads |
| `cloud-api.near.ai` | NEAR AI Cloud | Prompt injection → "Your own injection, with a live model" (optional) | Your NEAR AI API key, the task and document you typed, and the agent's tool definitions |

Like any web request, each of these also reveals your IP address and browser type to that host,
under its own privacy policy. GitHub, which hosts the site, keeps standard server logs under the
[GitHub Privacy Statement](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement).
The page sends `Referrer-Policy: no-referrer`, so these hosts are not told which page you came
from.

This table is generated from `harness/src/report/site-policy.ts`, which also generates the
page's security policy; a test fails if the site's code could contact any host not listed.

## What the website does not do

* No cookies, `localStorage`, `sessionStorage` or IndexedDB: close the tab and nothing remains.
* No analytics, tracking pixels, fonts, ads or other third-party scripts.
* No wallet connection. It never asks for a seed phrase or private key, and never signs or sends
  a transaction. "Simulate before you sign" runs your transaction on a local copy of the chain.
* No server of ours: we cannot see what you enter.

## Your NEAR AI API key

Optional, and only for the live-model box. The key is typed into a password field, kept in the
tab's memory for that request, sent only to `cloud-api.near.ai`, and never stored, logged or sent
to us. Use a separate key with a low spending limit and revoke it when you are done.

## Blockchain data

Account ids, balances, access keys and contract state on NEAR are public by design: anyone can
read them from any RPC or explorer. Looking them up here does not make them more public, but the
RPC operator does see which accounts your IP address looked up.

## The command-line tool

The CLI runs on your machine. It contacts the same services only when you run a command that
needs them (`scan`, `check`, `simulate`, `verify`, testnet anchoring, the live planner), plus the
testnet RPC set in `NEAR_RPC_URL`. Your keys stay in your local `.env` file. The CLI sends no
telemetry.

## Contact

Questions or concerns: open an issue at https://github.com/Richard2606-hub/AgentFuzz/issues, or
for anything sensitive use the private channel in [SECURITY.md](SECURITY.md).
