/**
 * The static site (web/index.html): the published scorecard plus the playground.
 *
 * The playground has no scripted results: playground.js (browser/page.ts) starts a Web Worker
 * (browser/worker.ts) that runs the real engine on the committed wasm builds and prompt corpus,
 * and every number it shows comes from that execution. Build with `make web`.
 */
import { demoGuardAccounts, PUBLISHED_SCOREBOARD, TESTNET_RPC } from "../anchor/audit-lookup.js";
import type { Scorecard, TargetScore } from "./scorecard.js";
import { contentSecurityPolicy, SITE_CONNECTIONS } from "./site-policy.js";

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
.hero{background:linear-gradient(135deg,#16233d,#121826);border:1px solid #2a3b5f;border-radius:16px;padding:24px;margin:8px 0 8px}.hero h2{margin:0 0 6px;font-size:26px}.hero p{margin:0 0 14px}.hero-row{display:flex;gap:10px;flex-wrap:wrap}.hero-row input{flex:1 1 220px;min-width:0;font-size:17px;padding:12px 14px}.hero-row .btn{font-size:16px;padding:12px 22px}.hero-try{margin-top:8px}.linkbtn{background:none;border:none;color:var(--accent);cursor:pointer;padding:0;font:inherit;text-decoration:underline}.hero-links{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}.hero-link{flex:1 1 260px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px;color:var(--text);text-decoration:none}.hero-link:hover{border-color:var(--accent)}.hero-link b{color:var(--accent)}.verdict-box{border-radius:12px;padding:16px 18px;margin-top:16px;border:1px solid var(--line);border-left:6px solid var(--line);background:#0c111b}.verdict-box.green{border-left-color:var(--ok)}.verdict-box.yellow{border-left-color:var(--warn)}.verdict-box.red{border-left-color:var(--bad);background:#1a0f12}.verdict-box.missing{border-left-color:var(--muted)}.verdict-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap;font-size:20px;font-weight:700}.light{width:16px;height:16px;border-radius:50%;flex:none}.light.green{background:var(--ok)}.light.yellow{background:var(--warn)}.light.red{background:var(--bad)}.light.missing{background:var(--muted)}.verdict-box ul{margin:10px 0 8px 20px;padding:0}.verdict-box li{margin:6px 0;line-height:1.45}.verdict-sub{font-size:13px;color:var(--muted);font-weight:400}
.finding{border-left:4px solid var(--line);background:#090d14;border-radius:8px;padding:9px 12px;margin:8px 0}.finding b{display:block;margin-bottom:2px}.finding.danger{border-left-color:var(--bad);background:#1a0f12}.finding.warn{border-left-color:var(--warn)}.finding.info{border-left-color:var(--info)}.finding.ok{border-left-color:var(--ok)}
.keys td{font-size:13px}.keys td.mono{word-break:break-all}
.sim-list{margin:6px 0 10px 18px;padding:0}.sim-list li{margin:4px 0;word-break:break-word}
.sim-log{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:var(--muted);white-space:pre-wrap;word-break:break-word}
`;

/**
 * Tab switching, deep links (#scan, #simulate…) and the fallback to the scorecard when the
 * playground bundle is missing. The only inline script: the CSP allows it by its hash, and no
 * inline event handlers are used.
 */
export const TAB_SCRIPT =
  'function afTab(name){document.querySelectorAll(".tab-btn").forEach(function(x){x.classList.toggle("active",x.dataset.tab===name)});document.querySelectorAll(".tab-content").forEach(function(x){x.classList.toggle("active",x.id==="tab-"+name)})}' +
  'document.querySelectorAll(".tab-btn").forEach(function(b){b.addEventListener("click",function(){afTab(b.dataset.tab);history.replaceState(null,"","#"+b.dataset.tab)})});' +
  'function afHash(e){var t=location.hash.slice(1);if(t&&document.getElementById("tab-"+t)){afTab(t);if(e)document.querySelector(".tabs-nav").scrollIntoView({behavior:"smooth"})}}' +
  'if(window.AF_PLAYGROUND){afHash();window.addEventListener("hashchange",afHash)}else afTab("scorecard");';

const REPO_URL = "https://github.com/Richard2606-hub/AgentFuzz";

function privacySection(): string {
  return `<section class="card" id="privacy">
  <h3>Privacy &amp; security</h3>
  <p class="small">This page is static files on GitHub Pages. It sets <b>no cookies</b>, uses <b>no browser storage</b>, and loads <b>no analytics or third-party scripts</b>. On load it contacts only this site. When you press a button, it may contact the hosts below and nothing else: a Content-Security-Policy makes your browser block every other destination, for the page and for its Web Worker. Tools that read the chain never ask for keys and never sign or send anything.</p>
  <table class="compact"><thead><tr><th>Host</th><th>Used by</th><th>What it receives</th></tr></thead><tbody>${SITE_CONNECTIONS.map(
    (c) => `<tr><td><span class="mono">${esc(new URL(c.origin).host)}</span><div class="small muted">${esc(c.operator)}</div></td><td class="small">${esc(c.usedBy)}</td><td class="small">${esc(c.sends)}</td></tr>`,
  ).join("")}</tbody></table>
  <p class="small muted">Every request also reveals your IP address to that host, under its own privacy policy. A NEAR AI key you type stays in this tab's memory only and is sent only to NEAR AI; use a separate key with a low limit, and revoke it afterwards. Account ids are public on-chain data. Details: <a href="${REPO_URL}/blob/main/PRIVACY.md" target="_blank" rel="noopener">PRIVACY.md</a> · <a href="${REPO_URL}/blob/main/SECURITY.md" target="_blank" rel="noopener">SECURITY.md</a> · found a security problem? Report it privately on the <a href="${REPO_URL}/security" target="_blank" rel="noopener">Security tab</a> (Report a vulnerability).</p>
</section>`;
}

export function renderScorecardHtml(sc: Scorecard): string {
  const s = sc.body.settings;
  const anchors = sc.anchors.length
    ? sc.anchors
        .map(
          (a) =>
            `<li><b>${esc(a.network)}</b>${a.contractId ? ` · ${esc(a.contractId)}` : ""}${a.txHash ? ` · tx ${a.explorerUrl ? `<a href="${esc(a.explorerUrl)}" target="_blank" rel="noopener">${esc(a.txHash)}</a>` : esc(a.txHash)}` : ""}${a.note ? ` <span class="muted">(${esc(a.note)})</span>` : ""}${
              a.audits?.length
                ? `<div class="small">guard audits${a.auditTxHash ? ` (tx ${a.network === "testnet" ? `<a href="https://testnet.nearblocks.io/txns/${esc(a.auditTxHash)}" target="_blank" rel="noopener">${esc(a.auditTxHash.slice(0, 12))}…</a>` : esc(a.auditTxHash)})` : ""}: ${a.audits
                    .map((x) => `${esc(x.target)} <span class="mono">${esc(x.codeHash.slice(0, 12))}…</span> ${x.broken ? `<span class="badc">${x.broken}/${x.total} broken</span>` : `<span class="okc">${x.held}/${x.total} held</span>`}`)
                    .join(" · ")}</div>`
                : ""
            }</li>`,
        )
        .join("")
    : `<li class="muted">not anchored</li>`;
  const testnet = sc.anchors.find((a) => a.network === "testnet" && a.contractId);
  const scoreboard = testnet?.contractId ?? PUBLISHED_SCOREBOARD;
  const examples = demoGuardAccounts(scoreboard);

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${esc(contentSecurityPolicy([TAB_SCRIPT]))}">
<meta name="referrer" content="no-referrer">
<title>AgentFuzz · Red-team harness and playground for NEAR agent-wallet guards</title>
<style>${CSS}</style></head><body><main>
<header>
  <h1>Agent<span>Fuzz</span></h1>
  <p class="tag">Free safety checks for every NEAR wallet, and a red-team harness for the guards that protect AI agents' money. “Your agent's spending guard says it's safe. AgentFuzz checks.”</p>
</header>

<section class="hero" id="hero">
  <h2>Is my NEAR wallet safe?</h2>
  <p class="muted">Type your account name. We read it from the NEAR blockchain and tell you, in plain words, who can move your money. No wallet connection, nothing to sign, nothing stored.</p>
  <div class="hero-row">
    <input type="text" id="hero-input" placeholder="yourname.near" spellcheck="false" autocapitalize="off" autocomplete="off" aria-label="NEAR account name">
    <button class="btn" id="hero-run" disabled>Check my wallet</button>
  </div>
  <div class="small muted hero-try">Try one: <button class="linkbtn hero-example" data-account="wrap-near.near">wrap-near.near</button> (a fake look-alike) · <button class="linkbtn hero-example" data-account="${esc(examples[1] ?? examples[0] ?? "")}">${esc((examples[1] ?? examples[0] ?? "").split(".")[0])}</button> (an AI-agent wallet that failed our tests)</div>
  <div id="hero-result" aria-live="polite"></div>
  <div class="hero-links">
    <a class="hero-link" href="#simulate">Got a transaction to sign? <b>Check what it really does first →</b></a>
    <a class="hero-link" href="#fuzz">Building AI agents? <b>Test your wallet guard →</b></a>
  </div>
</section>

<div class="tabs-nav" role="tablist">
  <button class="tab-btn active" data-tab="fuzz">Fuzz a guard</button>
  <button class="tab-btn" data-tab="prompt">Prompt injection</button>
  <button class="tab-btn" data-tab="check">Check a wallet</button>
  <button class="tab-btn" data-tab="scan">Account safety</button>
  <button class="tab-btn" data-tab="simulate">Simulate before you sign</button>
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
      <div class="field-box wide"><label for="fz-upload">Or upload your guard (.wasm, agentfuzz-guard-v1 interface)</label><input type="file" id="fz-upload" accept=".wasm,application/wasm"><div class="small muted">Audited as agentfuzz-guard-v1: the agent key may call only <code>pay</code>, so a wider key scope (like the naive builds' <code>rotate_key</code>) is reported under INV-3.</div></div>
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

<!-- TAB: CHECK -->
<div id="tab-check" class="tab-content">
  <section class="card" id="ck" data-scoreboard="${esc(scoreboard)}" data-rpc="${esc(TESTNET_RPC)}">
    <div class="card-head"><div>
      <h3>Before your agent trusts a wallet, check its guard</h3>
      <p class="muted small">Agents that pay or delegate budgets to other agents need to know the wallet guard on the other side holds up. Every NEAR account exposes the SHA-256 of the contract it runs (its code hash), and the AgentFuzz scoreboard on testnet records an audit for each guard build it tested: invariants held and broken, prompt-injection breaches, and the report hash anyone can re-run. This tab reads both straight from testnet, from your browser.</p>
    </div></div>
    <div class="controls">
      <div class="field-box wide"><label for="ck-input">Testnet account or code hash</label><input type="text" id="ck-input" placeholder="guard-reference.agentfuzz-28213.testnet" spellcheck="false"></div>
      <div class="field-box"><label>Scoreboard</label><div class="mono small" style="padding:8px 0">${esc(scoreboard)}</div></div>
    </div>
    <div class="btn-row">
      <button class="btn" id="ck-run" disabled>Check on-chain</button>
      ${examples.map((e) => `<button class="btn secondary ck-example" data-account="${esc(e)}">${esc(e.split(".")[0])}</button>`).join("\n      ")}
      <span class="muted small" id="ck-status"></span>
    </div>
    <div id="ck-result"></div>
    <h4>From an agent or CI</h4>
    <pre><code># exit code: 0 clean · 2 broken · 3 not audited · 4 no contract · 5 incomplete
node bin/agentfuzz.mjs check ${esc(examples[0] ?? "guard.your-account.testnet")}</code></pre>
    <p class="muted small">An audit is a claim by its submitter; it names a report that <code>agentfuzz verify</code> re-runs to the same hash. Pass <code>--trust account.testnet</code> to count only submitters you trust.</p>
  </section>
</div>

<!-- TAB: SIMULATE -->
<div id="tab-simulate" class="tab-content">
  <section class="card" id="sm">
    <div class="card-head"><div>
      <h3>Simulate before you sign</h3>
      <p class="muted small">Runs a transaction on a copy of mainnet or testnet before anyone signs it: the receiver's real contract code executes in nearsim (in your browser) on the network's current state, loaded on demand from public RPCs. You see what would really happen (NEAR and tokens in and out, keys added or removed, failures and fees), and what to worry about. Nothing is signed or sent; no wallet needed.</p>
    </div></div>
    <div class="controls">
      <div class="field-box"><label for="sm-mode">Transaction</label><select id="sm-mode"><option value="transfer">Send NEAR</option><option value="call">Call a contract</option><option value="json">Paste transaction JSON</option></select></div>
      <div class="field-box"><label for="sm-signer">Signer (who signs)</label><input type="text" id="sm-signer" placeholder="you.near" spellcheck="false" autocapitalize="off"></div>
      <div class="field-box"><label for="sm-to">Receiver / contract</label><input type="text" id="sm-to" placeholder="bob.near" spellcheck="false" autocapitalize="off"></div>
      <div class="field-box"><label for="sm-network">Network</label><select id="sm-network"><option value="">auto (.testnet = testnet)</option><option value="mainnet">mainnet</option><option value="testnet">testnet</option></select></div>
    </div>
    <div class="controls" id="sm-transfer-box">
      <div class="field-box"><label for="sm-amount">Amount (NEAR)</label><input type="text" id="sm-amount" placeholder="1.5"></div>
    </div>
    <div class="controls" id="sm-call-box" hidden>
      <div class="field-box"><label for="sm-method">Method</label><input type="text" id="sm-method" placeholder="ft_transfer" spellcheck="false"></div>
      <div class="field-box wide"><label for="sm-args">Arguments (JSON)</label><input type="text" id="sm-args" placeholder='{"receiver_id":"bob.near","amount":"1000000"}' spellcheck="false"></div>
      <div class="field-box"><label for="sm-deposit">Deposit (NEAR)</label><input type="text" id="sm-deposit" placeholder="0"></div>
      <div class="field-box"><label for="sm-gas">Gas (Tgas)</label><input type="text" id="sm-gas" placeholder="30"></div>
    </div>
    <div class="field-box" id="sm-json-box" hidden><label for="sm-json">Transaction JSON <span class="muted">(what a dApp passes to <code>signAndSendTransaction</code>, an explorer's or RPC's transaction, or a list of them)</span></label><textarea id="sm-json" rows="7" spellcheck="false" placeholder='{"receiverId":"wrap.near","actions":[{"type":"FunctionCall","params":{"methodName":"near_deposit","args":{},"gas":"30000000000000","deposit":"1000000000000000000000000"}}]}'></textarea></div>
    <div class="btn-row">
      <button class="btn" id="sm-run" disabled>Simulate</button>
      <span class="muted small" id="sm-status"></span>
    </div>
    <div class="btn-row small" style="margin-top:-4px">
      <span class="muted">Try:</span>
      <button class="btn secondary sm-example" data-ex="rotate">agent key installs a full-access key (naive guard)</button>
      <button class="btn secondary sm-example" data-ex="pay">agent pays 0.05 NEAR (reference guard)</button>
      <button class="btn secondary sm-example" data-ex="attacker">agent pays an attacker (reference guard)</button>
      <button class="btn secondary sm-example" data-ex="lookalike">1 NEAR to a look-alike (mainnet)</button>
      <button class="btn secondary sm-example" data-ex="wrap">wrap 1 NEAR (mainnet)</button>
      <button class="btn secondary sm-example" data-ex="addkey">dApp asks to add a full-access key</button>
    </div>
    <div id="sm-result"></div>
    <h4>From the command line</h4>
    <pre><code># exit code: 0 nothing risky · 2 danger · 3 review (fails, refused, or not fully simulated)
node bin/agentfuzz.mjs simulate --signer you.near --to wrap.near --call near_deposit --deposit 1
node bin/agentfuzz.mjs simulate --tx tx.json --signer you.near</code></pre>
    <p class="muted small">Limits: nearsim meters host calls, not every wasm instruction, so a call that would run out of gas on-chain can succeed here. Public RPCs refuse to serve the storage of contracts over 50 kB (wrap.near, USDt, Ref…); for those the page reads storage key by key from <code>rpc.intea.rs</code>, which is slower, and when it does not answer, the result is <em>decoded</em> from the transaction's arguments instead of executed, and says so.</p>
  </section>
</div>

<!-- TAB: SCAN -->
<div id="tab-scan" class="tab-content">
  <section class="card" id="sc">
    <div class="card-head"><div>
      <h3>Is this NEAR account safe?</h3>
      <p class="muted small">For any NEAR account, yours or one you are about to pay: who can move its money (its access keys and what each may do), what code runs on it and whether AgentFuzz audited that exact build, and whether its name imitates a well-known account. Read straight from a public NEAR RPC in your browser; nothing to sign or connect, no wallet needed.</p>
    </div></div>
    <div class="controls">
      <div class="field-box wide"><label for="sc-input">Account id</label><input type="text" id="sc-input" placeholder="you.near" spellcheck="false" autocapitalize="off"></div>
      <div class="field-box"><label for="sc-network">Network</label><select id="sc-network"><option value="">auto (.testnet = testnet)</option><option value="mainnet">mainnet</option><option value="testnet">testnet</option></select></div>
    </div>
    <div class="btn-row">
      <button class="btn" id="sc-run" disabled>Scan account</button>
      <button class="btn secondary sc-example" data-account="wrap-near.near" title="a real mainnet account named like wrap.near">look-alike</button>
      <button class="btn secondary sc-example" data-account="alice.near.attacker.near" title="a name that starts like alice.near">fake prefix</button>
      ${examples.map((e) => `<button class="btn secondary sc-example" data-account="${esc(e)}">${esc(e.split(".")[0])}</button>`).join("\n      ")}
      <span class="muted small" id="sc-status"></span>
    </div>
    <div id="sc-result"></div>
    <h4>From the command line</h4>
    <pre><code># exit code: 0 nothing risky · 2 danger · 3 review · 4 account does not exist
node bin/agentfuzz.mjs scan you.near</code></pre>
    <p class="muted small">What it can't see: whether a full-access key is <em>yours</em> (only you know), or what an app does with the key you gave it. A clean scan means no known risk pattern was found, not that an account is trustworthy.</p>
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

${privacySection()}
</main>
<script src="playground.js"></script>
<script>${TAB_SCRIPT}</script>
</body></html>
`;
}
