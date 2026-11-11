/**
 * The static site (web/index.html): the published scorecard plus the playground.
 *
 * The playground has no scripted results: playground.js (browser/page.ts) starts a Web Worker
 * (browser/worker.ts) that runs the real engine on the committed wasm builds and prompt corpus,
 * and every number it shows comes from that execution. Build with `make web`.
 */
import type { Scorecard, TargetScore } from "./scorecard.js";

const esc = (s: unknown) =>
  String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");

const ATTACK_CLASSES: Record<string, string> = {
  A1: "Prompt injection",
  A2: "Tool-output poisoning",
  A3: "Boundary amounts",
  A4: "Window rollover",
  A5: "Receiver look-alikes",
  A6: "Callback ordering",
  A7: "Key & allowance abuse",
  owner: "Owner actions (control)",
};

function badge(status: string): string {
  const cls = status === "held" ? "ok" : status === "broken" ? "bad" : status === "not-exercised" ? "warn" : "muted";
  return `<span class="badge ${cls}">${esc(status.replace("-", " "))}</span>`;
}

function outcomeBadge(o: string): string {
  const cls = o === "blocked" ? "ok" : o === "breach" ? "bad" : o === "resisted" ? "info" : "muted";
  return `<span class="badge ${cls}">${esc(o)}</span>`;
}

function targetCard(t: TargetScore): string {
  const clean = t.summary.broken === 0 && t.summary.promptBreaches === 0;
  const verdict = clean
    ? `<span class="verdict ok">${t.summary.held}/${t.summary.total} invariants held</span>`
    : `<span class="verdict bad">${t.summary.broken}/${t.summary.total} invariants broken</span>`;
  const rows = t.invariants
    .map(
      (i) => `<tr>
        <td class="mono">${esc(i.id)}</td>
        <td>${esc(i.title)}</td>
        <td>${badge(i.status)}</td>
        <td class="num">${i.runsExercised}/${i.runsChecked}</td>
        <td>${
          i.violation
            ? `<div class="violation">${esc(i.violation)}</div>${
                i.repro
                  ? `<details><summary>Minimised repro · ${i.repro.steps.length} step(s) · ${i.repro.numShrinks} shrinks · ${esc(i.repro.attackClasses.join(", ") || "no attack needed")}</summary><div class="repro-box"><ol>${
                      i.repro.steps.length ? i.repro.steps.map((s) => `<li><code>${esc(s)}</code></li>`).join("") : "<li><em>no steps: broken by the end-of-run owner check</em></li>"
                    }</ol></div></details>`
                  : ""
              }`
            : `<span class="muted">-</span>`
        }</td>
      </tr>`,
    )
    .join("");
  const total = Object.values(t.attacks.byClass).reduce((a, b) => a + b, 0) || 1;
  const bars = Object.entries(t.attacks.byClass)
    .map(
      ([k, v]) => `<div class="bar-row"><span class="bar-label">${esc(k)} <span class="muted">${esc(ATTACK_CLASSES[k] ?? "")}</span></span>
        <span class="bar"><span style="width:${Math.max(2, (v / total) * 100).toFixed(1)}%"></span></span><span class="num">${v}</span></div>`,
    )
    .join("");
  const prompt = t.prompt
    ? `<h4>Prompt layer <span class="muted">· planner ${esc(t.prompt.planner)}${t.prompt.planner === "compromised" ? " (worst case: every injected instruction is executed)" : t.prompt.model !== t.prompt.planner ? ` (${esc(t.prompt.model)})` : ""}</span></h4>
      <p class="stats"><b>${t.prompt.scenarios}</b> attacks · planner hijacked <b>${t.prompt.hijacked}</b> · guard blocked <b class="okc">${t.prompt.blocked}</b> · breaches <b class="${t.prompt.breaches ? "badc" : "okc"}">${t.prompt.breaches}</b>${t.prompt.resisted ? ` · resisted ${t.prompt.resisted}` : ""}</p>
      <details${t.prompt.breaches ? " open" : ""}><summary>Per-scenario results</summary>
      <table class="compact"><thead><tr><th>ID</th><th>Class</th><th>Attack</th><th>Outcome</th></tr></thead><tbody>${t.prompt.results
        .map(
          (r) => `<tr><td class="mono">${esc(r.id)}</td><td>${esc(r.class)}</td><td>${esc(r.title)}${
            r.violations.length ? `<div class="violation">${r.violations.map(esc).join("<br>")}</div>` : ""
          }</td><td>${outcomeBadge(r.outcome)}</td></tr>`,
        )
        .join("")}</tbody></table></details>`
    : "";
  return `<section class="card">
    <div class="card-head"><div><h3>${esc(t.name)}</h3><div class="muted small">${esc(t.source)}</div><div class="mono small muted">wasm sha256 ${esc(t.wasmSha256)}</div></div>${verdict}</div>
    <table><thead><tr><th>ID</th><th>Invariant</th><th>Status</th><th>Exercised</th><th>Evidence</th></tr></thead><tbody>${rows}</tbody></table>
    <div class="grid2"><div><h4>Contract-layer attacks <span class="muted">· ${t.attacks.sequences} sequences · ${t.attacks.steps} steps</span></h4>${bars}</div><div>${prompt}</div></div>
  </section>`;
}

const CSS = `
:root{--bg:#0b0e14;--panel:#121722;--panel-alt:#181f2e;--line:#232a38;--text:#e6e9ef;--muted:#8a93a6;--ok:#2ecc71;--bad:#ff5c5c;--warn:#f5b041;--info:#5dade2;--accent:#7aa2f7;--accent-glow:rgba(122,162,247,0.18)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:28px 20px 64px}a{color:var(--accent)}
header{margin-bottom:20px}header h1{margin:0;font-size:32px;letter-spacing:.3px}header h1 span{color:var(--accent)}
.tag{color:var(--muted);margin:6px 0 0;font-size:16px}
.tabs-nav{display:flex;gap:8px;border-bottom:1px solid var(--line);margin:24px 0 28px;padding-bottom:12px;overflow-x:auto}
.tab-btn{background:var(--panel);border:1px solid var(--line);color:var(--muted);padding:10px 18px;border-radius:10px;font-weight:600;font-size:14px;cursor:pointer;white-space:nowrap}
.tab-btn:hover{background:var(--panel-alt);color:var(--text);border-color:var(--accent)}
.tab-btn.active{background:var(--accent);color:#080c14;border-color:var(--accent);box-shadow:0 0 16px var(--accent-glow)}
.tab-content{display:none}.tab-content.active{display:block}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px;margin:0 0 24px}
.card-head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;margin-bottom:12px}.card h3{margin:0;font-size:22px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.small{font-size:12px}.muted{color:var(--muted)}.num{text-align:right;font-variant-numeric:tabular-nums}
.verdict{padding:8px 14px;border-radius:999px;font-weight:600;white-space:nowrap}.verdict.ok{background:#173a26;color:var(--ok)}.verdict.bad{background:#3d1b1b;color:var(--bad)}
table{width:100%;border-collapse:collapse;margin:8px 0}th,td{border-bottom:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}th{color:var(--muted);font-weight:500;font-size:12px;text-transform:uppercase}
table.compact td{padding:6px 8px;font-size:14px}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.4px}
.badge.ok{background:#173a26;color:var(--ok)}.badge.bad{background:#3d1b1b;color:var(--bad)}.badge.warn{background:#3d3117;color:var(--warn)}.badge.info{background:#17303d;color:var(--info)}.badge.muted{background:#222;color:var(--muted)}.badge.run{background:#1b2a45;color:var(--accent)}
.violation{color:#ffb3b3}.okc{color:var(--ok)}.badc{color:var(--bad)}
.repro-box{background:#090d14;border:1px solid var(--line);border-radius:8px;padding:8px 12px;margin-top:6px}
.repro-box ol{margin:4px 0 4px 18px;padding:0}.repro-box li{margin:3px 0;font-size:13px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-top:12px}@media(max-width:900px){.grid2{grid-template-columns:1fr}}
.bar-row{display:grid;grid-template-columns:200px 1fr 50px;gap:8px;align-items:center;font-size:13px;margin:4px 0}.bar{background:#1b2130;border-radius:4px;height:10px;overflow:hidden}.bar span{display:block;height:100%;background:var(--accent)}
.stats b{font-size:17px}code{background:#1b2130;padding:2px 6px;border-radius:5px}pre code{display:block;padding:10px 12px;overflow-x:auto;white-space:pre}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:10px 24px;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px 22px;margin-bottom:24px}
.meta b{display:block;color:var(--muted);font-size:12px;text-transform:uppercase;font-weight:500}
.controls{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:8px}
.field-box{background:var(--panel-alt);border:1px solid var(--line);border-radius:10px;padding:10px 14px}
.field-box label{display:block;font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}
.field-box.wide{grid-column:span 2}@media(max-width:600px){.field-box.wide{grid-column:auto}}
select,input[type=text],input[type=number],input[type=password],textarea{width:100%;background:#090d14;border:1px solid var(--line);color:var(--text);padding:8px 10px;border-radius:6px;font:inherit;font-size:14px;outline:none}
select:focus,input:focus,textarea:focus{border-color:var(--accent)}input[type=file]{font-size:13px;color:var(--muted);max-width:100%}
.btn-row{display:flex;gap:10px;align-items:center;margin:14px 0;flex-wrap:wrap}
.btn{background:var(--accent);color:#080c14;border:none;padding:9px 18px;border-radius:8px;font-weight:600;cursor:pointer}
.btn:disabled{opacity:.45;cursor:default}.btn.secondary{background:var(--panel-alt);border:1px solid var(--line);color:var(--text)}
.inv-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin:14px 0}
.inv{background:#090d14;border:1px solid var(--line);border-left:4px solid var(--line);border-radius:10px;padding:10px 12px;min-height:96px}
.inv.searching{border-left-color:var(--accent)}.inv.held{border-left-color:var(--ok)}.inv.broken{border-left-color:var(--bad);background:#1a0f12}.inv.not-exercised,.inv.n\\/a{border-left-color:var(--warn)}
.inv .id{font-weight:700}.inv .title{font-size:12px;color:var(--muted);margin:2px 0 6px;min-height:32px}.inv .count{font-size:12px;color:var(--muted)}
.console{background:#06080d;border:1px solid var(--line);border-radius:10px;padding:12px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;height:240px;overflow-y:auto;white-space:pre-wrap;line-height:1.55}
.console .bad{color:var(--bad)}.console .ok{color:var(--ok)}.console .dim{color:var(--muted)}
.repro{background:var(--panel-alt);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:12px 0}
.repro h4{margin:0 0 6px}.repro ol{margin:6px 0 6px 20px;padding:0}.repro li{margin:4px 0;font-size:13.5px}
.tx{font-size:12.5px;color:var(--muted);margin-left:14px}.tx.success{color:#9fd9b4}.tx.failure,.tx.rejected{color:#ffb3b3}
.scenario{background:var(--panel-alt);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:12px 0}
.scenario .doc{background:#090d14;border:1px solid var(--line);border-left:3px solid var(--warn);border-radius:6px;padding:8px 10px;font-size:13px;white-space:pre-wrap;margin:8px 0;max-height:160px;overflow:auto}
.grid2>div{min-width:0}.scenario code,.repro code{white-space:pre-wrap;word-break:break-word}
.notice{background:#3d3117;color:var(--warn);border-radius:10px;padding:12px 16px;margin:0 0 16px}
.summary-line{font-size:15px;margin:8px 0}
`;

export function renderScorecardHtml(sc: Scorecard): string {
  const s = sc.body.settings;
  const anchors = sc.anchors.length
    ? sc.anchors
        .map(
          (a) =>
            `<li><b>${esc(a.network)}</b>${a.contractId ? ` · ${esc(a.contractId)}` : ""}${a.txHash ? ` · tx ${a.explorerUrl ? `<a href="${esc(a.explorerUrl)}" target="_blank" rel="noopener">${esc(a.txHash)}</a>` : esc(a.txHash)}` : ""}${a.note ? ` <span class="muted">(${esc(a.note)})</span>` : ""}</li>`,
        )
        .join("")
    : `<li class="muted">not anchored</li>`;

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentFuzz · Red-team harness and playground for NEAR agent-wallet guards</title>
<style>${CSS}</style></head><body><main>
<header>
  <h1>Agent<span>Fuzz</span></h1>
  <p class="tag">“Your agent's spending guard says it's safe. AgentFuzz checks.” Fuzz NEAR agent-wallet guards and throw prompt injections at them, in your browser, with the same engine as the CLI.</p>
</header>

<div class="tabs-nav" role="tablist">
  <button class="tab-btn active" data-tab="fuzz">Fuzz a guard</button>
  <button class="tab-btn" data-tab="prompt">Prompt injection</button>
  <button class="tab-btn" data-tab="scorecard">Published scorecard</button>
  <button class="tab-btn" data-tab="cli">Run it yourself</button>
</div>

<div id="pg-missing" class="notice">The playground scripts are not loaded. On a local clone run <code>make web</code> and open the page through <code>make serve-web</code> (browsers block Web Workers on <code>file://</code>).</div>

<!-- TAB: FUZZ -->
<div id="tab-fuzz" class="tab-content active">
  <section class="card">
    <div class="card-head"><div>
      <h3>Fuzz a guard in your browser</h3>
      <p class="muted small">Runs the real fuzzer in a Web Worker: the compiled guard wasm is executed by nearsim (NEAR's host ABI, accounts, keys, receipts and callbacks), attacked with property-based sequences, checked against INV-1..6, and every break is shrunk to a minimal repro. Same seed, same result as <code>agentfuzz fuzz</code>.</p>
    </div></div>
    <div class="controls">
      <div class="field-box wide"><label for="fz-target">Guard</label><select id="fz-target" disabled><option>loading…</option></select></div>
      <div class="field-box wide"><label for="fz-upload">Or upload your guard (.wasm, agentfuzz-guard-v1 interface)</label><input type="file" id="fz-upload" accept=".wasm,application/wasm"></div>
      <div class="field-box"><label for="fz-seed">Seed</label><input type="number" id="fz-seed" value="42" min="0"></div>
      <div class="field-box"><label for="fz-runs">Runs per invariant</label><input type="number" id="fz-runs" value="100" min="1" max="2000"></div>
      <div class="field-box"><label for="fz-gen">Generator</label><select id="fz-gen"><option value="2">v2 (default)</option><option value="1">v1</option></select></div>
      <div class="field-box"><label for="fz-steps">Max steps</label><input type="number" id="fz-steps" value="20" min="1" max="40"></div>
    </div>
    <div class="btn-row">
      <button class="btn" id="fz-run" disabled>Run fuzz campaign</button>
      <button class="btn secondary" id="fz-stop" disabled>Stop</button>
      <span class="muted small" id="fz-status">Starting the engine…</span>
    </div>
    <div class="summary-line" id="fz-summary"></div>
    <div class="inv-grid" id="fz-grid"></div>
    <h4>Attack log</h4>
    <div class="console" id="fz-log"></div>
    <div id="fz-repros"></div>
  </section>
</div>

<!-- TAB: PROMPT -->
<div id="tab-prompt" class="tab-content">
  <section class="card">
    <div class="card-head"><div>
      <h3>Prompt injection against the reference agent</h3>
      <p class="muted small">Each corpus scenario is fed to the reference agent, which holds only a function-call key scoped to the guard. The <b>compromised</b> planner models a fully successful injection: it performs the legitimate work <em>and</em> every attacker instruction, so the guard is the last line of defence. The tool calls and transactions below are what actually executed on a fresh nearsim chain.</p>
    </div></div>
    <div class="controls">
      <div class="field-box wide"><label for="pr-target">Guard</label><select id="pr-target" disabled><option>loading…</option></select></div>
      <div class="field-box wide"><label for="pr-scenario">Scenario</label><select id="pr-scenario" disabled><option>loading…</option></select></div>
    </div>
    <div class="btn-row">
      <button class="btn" id="pr-run" disabled>Run scenario</button>
      <button class="btn secondary" id="pr-run-all" disabled>Run all corpus scenarios</button>
      <span class="muted small" id="pr-status"></span>
    </div>
    <div class="summary-line" id="pr-summary"></div>
    <div id="pr-results"></div>
  </section>
  <section class="card">
    <div class="card-head"><div>
      <h3>Your own injection, with a live model</h3>
      <p class="muted small">Write a poisoned document and let a real model on NEAR AI Cloud plan the agent's actions; the guard then executes them on a fresh chain. Your API key stays in this page's memory: it is never stored and is sent only to <code>cloud-api.near.ai</code>, directly from your browser. Without a key there is nothing honest to show for custom text, because the compromised planner only replays scripted attacker calls.</p>
    </div></div>
    <div class="controls">
      <div class="field-box wide"><label for="cu-key">NEAR AI API key</label><input type="password" id="cu-key" autocomplete="off" spellcheck="false" placeholder="sk-…"></div>
      <div class="field-box"><label for="cu-model">Model (optional)</label><input type="text" id="cu-model" placeholder="auto"></div>
      <div class="field-box"><label for="cu-target">Guard</label><select id="cu-target" disabled><option>loading…</option></select></div>
    </div>
    <div class="field-box" style="margin-bottom:10px"><label for="cu-task">Operator's task for the agent</label><input type="text" id="cu-task" value="Process the document below and pay it if it is legitimate."></div>
    <div class="field-box"><label for="cu-doc">Untrusted document</label><textarea id="cu-doc" rows="6" placeholder="Invoice #77 from bob.test.near, 1 NEAR. …"></textarea></div>
    <div class="btn-row"><button class="btn" id="cu-run" disabled>Ask the model and execute</button><span class="muted small" id="cu-status"></span></div>
    <div id="cu-results"></div>
  </section>
</div>

<!-- TAB: SCORECARD -->
<div id="tab-scorecard" class="tab-content">
  <div class="meta">
    <div><b>Run ID</b><span class="mono">${esc(sc.runId)}</span></div>
    <div><b>Report SHA-256</b><span class="mono small">${esc(sc.sha256)}</span></div>
    <div><b>Settings</b>seed ${s.seed} · ${s.runs} runs/invariant · ≤${s.maxSteps} steps · ${esc(s.backend)} · planner ${esc(s.planner)} · generator v${s.generator ?? 1}</div>
    <div><b>Generated</b>${esc(sc.meta.generatedAt)} · commit <span class="mono">${esc(sc.meta.commit)}</span> · agentfuzz ${esc(sc.body.tool.version)}</div>
    <div><b>On-chain anchors</b><ul style="margin:4px 0 0 16px;padding:0">${anchors}</ul></div>
    <div><b>Reproduce</b><code>agentfuzz verify scorecard.json</code> re-runs everything and recomputes this hash</div>
  </div>
  ${sc.body.targets.map(targetCard).join("\n")}
  <footer>
    <h4>Invariants</h4>
    <table>${Object.entries(sc.body.invariantDefinitions)
      .map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td>${esc(v)}</td></tr>`)
      .join("")}</table>
    <p>Attack classes: ${Object.entries(ATTACK_CLASSES)
      .filter(([k]) => k !== "owner")
      .map(([k, v]) => `<b>${k}</b> ${esc(v)}`)
      .join(" · ")}. All attacks run against freshly deployed contracts in an isolated local chain; only report hashes are written to a public network.</p>
  </footer>
</div>

<!-- TAB: CLI -->
<div id="tab-cli" class="tab-content">
  <section class="card">
    <div class="card-head"><div>
      <h3>Run it on your guard</h3>
      <p class="muted small">The same engine from the command line or in CI. Every field below maps to a real flag or action input.</p>
    </div></div>
    <div class="controls">
      <div class="field-box wide"><label for="cl-wasm">Guard wasm path</label><input type="text" id="cl-wasm" value="target/wasm32-unknown-unknown/release/guard.wasm"></div>
      <div class="field-box"><label for="cl-seed">Seed</label><input type="number" id="cl-seed" value="42"></div>
      <div class="field-box"><label for="cl-runs">Runs per invariant</label><input type="number" id="cl-runs" value="200"></div>
      <div class="field-box"><label for="cl-steps">Max steps</label><input type="number" id="cl-steps" value="20"></div>
      <div class="field-box"><label for="cl-fail">Fail on break</label><select id="cl-fail"><option value="true">yes</option><option value="false">no</option></select></div>
    </div>
    <h4>CLI <span class="muted small">(from a clone: <code>cd harness &amp;&amp; npm ci</code>)</span></h4>
    <pre><code id="cl-cmd" class="mono"></code></pre>
    <h4>GitHub Actions step</h4>
    <pre><code id="cl-yaml" class="mono"></code></pre>
  </section>
</div>

</main>
<script>
function afTab(name){document.querySelectorAll(".tab-btn").forEach(function(x){x.classList.toggle("active",x.dataset.tab===name)});document.querySelectorAll(".tab-content").forEach(function(x){x.classList.toggle("active",x.id==="tab-"+name)})}
document.querySelectorAll(".tab-btn").forEach(function(b){b.addEventListener("click",function(){afTab(b.dataset.tab)})});
</script>
<script src="playground.js" onerror="afTab('scorecard')"></script>
</body></html>
`;
}
