# AgentFuzz: one command per claim. Windows users without make: see README "Without make".
#
#   make setup && make test && make demo-offline     # clean clone, no API keys, no network
#
SHELL := /bin/bash
TARGET ?= naive
SEED   ?= 42
RUNS   ?= 200
AF     := cd harness && node bin/agentfuzz.mjs

.PHONY: help setup build build-check test test-contracts test-harness fuzz prompt matrix demo-offline report verify replay sandbox-test web serve-web clean

help:
	@echo "make setup          install harness dependencies (npm ci)"
	@echo "make build          build all contracts to wasm into artifacts/ (needs Rust; artifacts are committed)"
	@echo "make test           contract unit tests (if cargo is installed) + harness tests"
	@echo "make fuzz           fuzz one guard:   make fuzz TARGET=naive|reference|path/to.wasm SEED=42 RUNS=200"
	@echo "make prompt         prompt-layer attacks through the reference agent: make prompt TARGET=reference"
	@echo "make matrix         planted-bug matrix: every planted bug must be found, controls clean"
	@echo "make diff           differential test: run sequences against nearsim and nearcore sandbox"
	@echo "make demo-offline   the full demo, no API keys, no network"
	@echo "make report         scorecard JSON + HTML (web/), report hash anchored (testnet if .env set, else nearsim)"
	@echo "make verify         re-run out/scorecard.json deterministically and check its hash"
	@echo "make sandbox-test   near-workspaces integration tests on a real nearcore sandbox (Linux/macOS)"
	@echo "make web            build the static site + browser playground into web/ (esbuild; no re-run, no anchoring)"
	@echo "make serve-web      serve web/ at http://localhost:8080 (needs make web first)"

setup:
	cd harness && npm ci

build:
	node scripts/build-contracts.mjs

build-check:
	node scripts/build-contracts.mjs --check

test: test-contracts test-harness

test-contracts:
	@if command -v cargo >/dev/null 2>&1; then cargo test --workspace; \
	else echo "cargo not found: skipping contract unit tests (prebuilt wasm in artifacts/ is used by the harness)"; fi

test-harness:
	cd harness && npm run typecheck && npm test

fuzz:
	$(AF) fuzz --target $(TARGET) --seed $(SEED) --runs $(RUNS)

prompt:
	$(AF) prompt --target $(TARGET)

matrix:
	$(AF) matrix --seed 7 --runs 150

diff:
	$(AF) diff --target $(TARGET) --seed $(SEED) --runs 20

demo-offline:
	$(AF) demo-offline --seed $(SEED) --runs $(RUNS)

report:
	@set -a; [ -f .env ] && . ./.env; set +a; $(AF) report --seed $(SEED) --runs $(RUNS)
	@node scripts/update-readme-anchor.mjs || true

verify:
	@set -a; [ -f .env ] && . ./.env; set +a; $(AF) verify ../out/scorecard.json

replay:
	$(AF) replay $(REPRO)

sandbox-test:
	cargo test --manifest-path tests/sandbox/Cargo.toml -- --nocapture

web:
	node scripts/build-web.mjs

serve-web:
	node scripts/serve-web.mjs 8080

clean:
	rm -rf out target harness/node_modules web/playground.js web/playground-worker.js web/corpus.json web/wasm
