# AgentFuzz GitHub Action

Add automated red-team fuzzing and prompt injection auditing to your NEAR agent-wallet guard repository.

## Usage

```yaml
name: Guard Security Audit

on:
  push:
    branches: [main]
  pull_request:

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Guard Contract
        run: |
          cargo build --target wasm32-unknown-unknown --release

      - name: Run AgentFuzz Security Audit
        uses: agentfuzz/agentfuzz/.github/actions/agentfuzz@main
        with:
          target: target/wasm32-unknown-unknown/release/guard.wasm
          runs: 200
          seed: 42
          fail-on-break: true

      - name: Upload Security Scorecard
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: guard-security-scorecard
          path: out/
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `target` | Guard target name (`reference`, `naive`) or path to custom `.wasm` | `reference` |
| `runs` | Number of fuzzing iterations per safety invariant | `150` |
| `seed` | Deterministic pseudo-random seed | `42` |
| `max-steps` | Maximum attack sequence length | `20` |
| `fail-on-break` | Break CI workflow if any invariant is broken | `true` |
| `prompt` | Run prompt-layer injection scenarios (offline corpus) | `true` |
| `out-dir` | Output directory for scorecard & minimised repros | `out` |

## Outputs

| Output | Description |
|--------|-------------|
| `scorecard-json` | Path to generated machine-readable `scorecard.json` |
| `scorecard-html` | Path to generated standalone, interactive `scorecard.html` |
