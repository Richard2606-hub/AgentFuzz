/** Static, self-contained HTML scorecard (no framework, no network requests). */
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

export function renderScorecardHtml(sc: Scorecard): string {
  const s = sc.body.settings;
  const anchors = sc.anchors.length
    ? sc.anchors
        .map(
          (a) =>
            `<li><b>${esc(a.network)}</b>${a.contractId ? ` · ${esc(a.contractId)}` : ""}${a.txHash ? ` · tx ${a.explorerUrl ? `<a href="${esc(a.explorerUrl)}">${esc(a.txHash)}</a>` : esc(a.txHash)}` : ""}${a.note ? ` <span class="muted">(${esc(a.note)})</span>` : ""}</li>`,
        )
        .join("")
    : `<li class="muted">not anchored</li>`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentFuzz scorecard · ${esc(sc.runId)}</title>
<style>
:root{--bg:#0b0e14;--panel:#121722;--line:#232a38;--text:#e6e9ef;--muted:#8a93a6;--ok:#2ecc71;--bad:#ff5c5c;--warn:#f5b041;--info:#5dade2;--accent:#7aa2f7}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:32px 20px 64px}a{color:var(--accent)}
header h1{margin:0;font-size:28px;letter-spacing:.3px}header h1 span{color:var(--accent)}
.tag{color:var(--muted);margin:4px 0 20px}.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-bottom:28px}
.meta div{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}.meta b{display:block;color:var(--muted);font-weight:500;font-size:12px;text-transform:uppercase;letter-spacing:.6px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.meta .mono,.meta a{word-break:break-all}td.mono{white-space:nowrap}.small{font-size:12px}.muted{color:var(--muted)}.num{text-align:right;font-variant-numeric:tabular-nums}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px;margin:0 0 24px}
.card-head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;margin-bottom:12px}.card h3{margin:0;font-size:22px}
.verdict{padding:8px 14px;border-radius:999px;font-weight:600;white-space:nowrap}.verdict.ok{background:#173a26;color:var(--ok)}.verdict.bad{background:#3d1b1b;color:var(--bad)}
table{width:100%;border-collapse:collapse;margin:8px 0}th,td{border-bottom:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}th{color:var(--muted);font-weight:500;font-size:12px;text-transform:uppercase}
table.compact td{padding:6px 8px;font-size:14px}.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.4px}
.badge.ok{background:#173a26;color:var(--ok)}.badge.bad{background:#3d1b1b;color:var(--bad)}.badge.warn{background:#3d3117;color:var(--warn)}.badge.info{background:#17303d;color:var(--info)}.badge.muted{background:#222;color:var(--muted)}
.violation{color:#ffb3b3}.okc{color:var(--ok)}.badc{color:var(--bad)}details summary{cursor:pointer;color:var(--accent);margin-top:4px}
.repro-box{background:#090d14;border:1px solid var(--line);border-radius:8px;padding:8px 12px;margin-top:6px}
.repro-box ol{margin:4px 0 4px 18px;padding:0}.repro-box li{margin:3px 0;font-size:13px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-top:12px}@media(max-width:900px){.grid2{grid-template-columns:1fr}}
h4{margin:12px 0 8px}.bar-row{display:grid;grid-template-columns:200px 1fr 50px;gap:8px;align-items:center;font-size:13px;margin:4px 0}.bar{background:#1b2130;border-radius:4px;height:10px;overflow:hidden}.bar span{display:block;height:100%;background:var(--accent)}
.stats b{font-size:17px}code{background:#1b2130;padding:2px 6px;border-radius:5px}footer{color:var(--muted);font-size:13px;margin-top:40px}footer table td{font-size:13px}
</style></head><body><main>
<header><h1>Agent<span>Fuzz</span> scorecard</h1><p class="tag">“Your agent's spending guard says it's safe. AgentFuzz checks.” · red-team results for NEAR agent-wallet guards</p></header>
<div class="meta">
  <div><b>Run ID</b><span class="mono">${esc(sc.runId)}</span></div>
  <div><b>Report SHA-256</b><span class="mono small">${esc(sc.sha256)}</span></div>
  <div><b>Settings</b>seed ${s.seed} · ${s.runs} runs/invariant · ≤${s.maxSteps} steps · ${esc(s.backend)} · planner ${esc(s.planner)}</div>
  <div><b>Generated</b>${esc(sc.meta.generatedAt)} · commit <span class="mono">${esc(sc.meta.commit)}</span> · agentfuzz ${esc(sc.body.tool.version)}</div>
  <div><b>On-chain anchors</b><ul style="margin:4px 0 0 16px;padding:0">${anchors}</ul></div>
  <div><b>Reproduce</b><code>agentfuzz verify scorecard.json</code> re-runs everything and recomputes this hash</div>
</div>
${sc.body.targets.map(targetCard).join("\n")}
<footer><h4>Invariants</h4><table>${Object.entries(sc.body.invariantDefinitions)
    .map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td>${esc(v)}</td></tr>`)
    .join("")}</table>
<p>Attack classes: ${Object.entries(ATTACK_CLASSES)
    .filter(([k]) => k !== "owner")
    .map(([k, v]) => `<b>${k}</b> ${esc(v)}`)
    .join(" · ")}. All attacks run against freshly deployed contracts in an isolated local chain; only report hashes are written to a public network.</p></footer>
</main></body></html>
`;
}
