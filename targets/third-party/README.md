# Third-party guards

AgentFuzz is meant to be run on guards it didn't write. This folder holds **adapters** for
third-party guard contracts: one sub-folder per target with a `target.json` manifest, the compiled
wasm (or a script that builds it at a pinned commit), and an adapter module if the guard's
interface differs from `agentfuzz-guard-v1`.

## Rules (non-negotiable)

1. **Only open-source code with a permissive licence** (MIT / Apache-2.0). Keep the upstream
   licence file next to the wasm and credit the repo in the manifest and the README.
2. **Local only.** Third-party guards are deployed exclusively in AgentFuzz's local chain
   (nearsim or a near-workspaces sandbox). AgentFuzz never calls anyone's live testnet or mainnet
   contracts.
3. **Disclose first.** If a real bug turns up, message the author before publishing anything
   (a GitHub issue *without* exploit details, or a DM). Publish scores as
   "tested version X, commit Y" and frame them constructively.
4. **Opt-in publication.** `"publish": false` is the default; the public scorecard only lists our
   own two guards plus authors who agreed. If an author asks to be removed, remove them.

## Manifest

```json
{
  "name": "tp:example",
  "description": "What the guard does",
  "repo": "https://github.com/<owner>/<repo>",
  "commit": "<full commit sha>",
  "license": "MIT",
  "wasm": "guard.wasm",
  "adapter": "./adapter.mjs",
  "publish": false
}
```

`adapter` is either `"agentfuzz-guard-v1"` (the guard already speaks AgentFuzz's interface) or a
path to an ES module whose default export implements `GuardAdapter`
([`harness/src/targets/adapter.ts`](../../harness/src/targets/adapter.ts)):

| Member | Purpose |
|--------|---------|
| `initCall(cfg, agentPublicKey)` | init method + args: owner, agent key, cap per window, window length (ns), allowlist, allowance |
| `pay(receiverId, amount)` | the agent's payment call (amount in yoctoNEAR) |
| `revoke()`, `withdraw(amount?)` | owner calls (attach 1 yocto if the guard requires it) |
| `rekey?(publicKey, allowance)` | owner re-provisions the agent key; omit if the guard has no such path (INV-6 will report it) |
| `agentExtras` | other agent-callable methods (e.g. key rotation) the fuzzer should exercise |
| `adminMethods` | owner-only methods the agent must never be able to use |
| `readAccounting?(view)` | stored `{window, spent}` for INV-5; omit if not observable (INV-5 → n/a) |

Every registered target appears in `agentfuzz targets` and can be fuzzed by name:
`node bin/agentfuzz.mjs fuzz --target tp:example`.

## Folders

* [`example/`](example/) is a working template: it points at our own reference guard and spells
  out the v1 adapter by hand, so you can copy it and change method names for a real target.
