# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub's
[private vulnerability reporting](https://github.com/Richard2606-hub/AgentFuzz/security/advisories/new)
for this repository, not in a public issue (if that page is not available, open an issue that only
asks for a private contact, without details). Include what you found, how to reproduce it, and what
an attacker could do with it. We aim to acknowledge reports within 3 days. AgentFuzz is a
hackathon project maintained on a best-effort basis; there is no bug bounty.

In scope: the web playground (https://richard2606-hub.github.io/AgentFuzz), the harness and CLI
in `harness/`, the scoreboard contract in `contracts/scoreboard`, and the build and deploy
workflows. Bugs in `contracts/guard-naive` are planted on purpose (see its `BUGS.md`); real bugs in
`contracts/guard-reference` are in scope.

## How the web playground protects visitors

The site is static files on GitHub Pages: no server, no accounts, no database.

| Measure | What it guarantees | Checked by |
|---------|--------------------|------------|
| **Content-Security-Policy** (`<meta http-equiv>`) | The browser refuses to connect anywhere except the site itself and the four hosts in [PRIVACY.md](PRIVACY.md); no other scripts, no `eval`, no plugins, no form submissions, no `<base>` hijacking | `harness/test/site-policy.test.ts` |
| **Worker started from a `blob:` URL** | The Web Worker that does the network work inherits that policy (a worker loaded from its own URL would get the policy of its response headers, and GitHub Pages sends none) | same test, and checked in a browser: a `fetch` to any other host fails in the page and in a worker |
| **Single source of truth** | `harness/src/report/site-policy.ts` lists every allowed host with its purpose; the CSP and the page's privacy notice are generated from it | a test bundles the page and worker exactly as the site does and fails if their code contains any other `https://` host |
| **One inline script, pinned by hash** | The tab-switching script is allowed by its SHA-256 only; there are no inline event handlers | the CSP is computed from the script's hash at build time |
| **No storage, no cookies, no analytics** | Nothing persists in the visitor's browser and nothing tracks them | the bundle test fails on `localStorage`, `sessionStorage`, `indexedDB` or `document.cookie` |
| **`Referrer-Policy: no-referrer`** | RPC providers and NEAR AI do not learn which page sent a request | rendered into every page |
| **Read-only chain tools** | Check a wallet, Account safety and Simulate never ask for keys, never sign and never send a transaction | by construction: the browser bundle has no signing path for them; Simulate runs on a local copy |
| **Output escaping** | Everything shown from the chain, a model or a contract (account ids, logs, errors) is HTML-escaped before display | code review; CSP blocks injected scripts even if one slipped through |

The optional **NEAR AI API key** (Prompt injection → "Your own injection, with a live model") is
typed into a password field, kept in the tab's memory for the one request, sent only to
`cloud-api.near.ai` in the `Authorization` header, and never stored or logged. Visitors should still
use a separate key with a low spending limit and revoke it afterwards.

Known limits of static hosting: GitHub Pages cannot send custom headers, so `frame-ancestors`
(clickjacking protection) and a header-delivered CSP are not available. The page has no
state-changing actions to clickjack: nothing is signed or sent from it.

## The CLI and harness

* Secrets live only in `.env` (git-ignored; `.env.example` lists the variables, all optional).
  `NEAR_PRIVATE_KEY` is used only by `report`/`anchor`/`scoreboard-deploy`/`demo-guards-deploy`
  to sign testnet transactions; `NEAR_AI_API_KEY` only for the live planner and corpus
  generator. Neither is ever printed or written to reports.
* Fuzzing and prompt attacks run against freshly deployed contracts on a local chain (nearsim or a
  local sandbox); they never touch anyone's deployed contracts. `scan`, `check` and `simulate`
  only read public state from live networks.
* Dependencies are installed from the lockfile (`npm ci`); the crypto libraries used in the
  browser (`@noble/hashes`, `@noble/curves`) and the bundler (`esbuild`) are pinned to exact
  versions. CI runs `npm audit --omit=dev --audit-level=high` on every push.
* Contract builds are reproducible from the committed sources; `artifacts/manifest.json` records
  each wasm's SHA-256, and `agentfuzz verify` checks the published scorecard against them.
