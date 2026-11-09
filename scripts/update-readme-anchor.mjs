#!/usr/bin/env node
// Refresh the "Live on NEAR testnet" table in README.md from web/scorecard.json.
// The table lives between <!-- anchor:start --> and <!-- anchor:end -->.
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const sc = JSON.parse(readFileSync(join(root, "web", "scorecard.json"), "utf8"));
const a = sc.anchors.find((x) => x.network === "testnet");
if (!a) {
  console.error("web/scorecard.json has no testnet anchor; run `make report` with .env credentials first");
  process.exit(1);
}
const table = [
  "<!-- anchor:start -->",
  "| What | Where |",
  "|------|-------|",
  `| Scoreboard contract | [\`${a.contractId}\`](https://testnet.nearblocks.io/address/${a.contractId}) |`,
  `| Published scorecard | [\`web/scorecard.json\`](web/scorecard.json) / [\`web/index.html\`](web/index.html): run \`${sc.runId}\` (commit \`${sc.meta.commit}\`) |`,
  `| Report SHA-256 | \`${sc.sha256}\` |`,
  `| Anchor transaction | [\`${a.txHash}\`](${a.explorerUrl}) |`,
  "<!-- anchor:end -->",
].join("\n");
const readmePath = join(root, "README.md");
const readme = readFileSync(readmePath, "utf8");
const re = /<!-- anchor:start -->[\s\S]*?<!-- anchor:end -->/;
if (!re.test(readme)) {
  console.error("README.md has no anchor markers");
  process.exit(1);
}
writeFileSync(readmePath, readme.replace(re, table));
console.log(`README.md updated: ${sc.runId} ${a.txHash}`);
