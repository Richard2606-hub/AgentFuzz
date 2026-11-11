/**
 * Playground page controller (bundled to web/playground.js). It owns the DOM and renders only what
 * the worker reports from real executions; it holds no results of its own.
 */
import type { FromWorker, FuzzSummary, InvariantView, PromptView, ReproView, ScenarioInfo, TargetInfo, ToWorker } from "./protocol.js";

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const esc = (s: unknown) =>
  String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
const badge = (cls: string, text: string) => `<span class="badge ${cls}">${esc(text)}</span>`;
const statusBadge = (s: string) =>
  badge(s === "held" ? "ok" : s === "broken" ? "bad" : s === "searching" ? "run" : s === "not-exercised" ? "warn" : "muted", s.replace("-", " "));
const outcomeBadge = (o: string) => badge(o === "blocked" ? "ok" : o === "breach" ? "bad" : o === "resisted" ? "info" : "muted", o);

// Tab switching is a small inline script in index.html, so the scorecard works without this bundle.
$("pg-missing").hidden = true;

// ---------------------------------------------------------------- worker

let worker: Worker;
let targets: TargetInfo[] = [];
let scenarios: ScenarioInfo[] = [];
let job = 0;
let busy = false;
let upload: { name: string; bytes: ArrayBuffer } | undefined;

function startWorker() {
  worker = new Worker(new URL("playground-worker.js", location.href));
  worker.onmessage = (ev: MessageEvent<FromWorker>) => onMessage(ev.data);
  worker.onerror = (ev) => {
    $("fz-status").textContent = `Engine failed to start: ${ev.message || "see the browser console"}`;
  };
  send({ type: "init", base: new URL("./", location.href).href });
}
const send = (m: ToWorker, transfer: Transferable[] = []) => worker.postMessage(m, transfer);

function setBusy(b: boolean) {
  busy = b;
  for (const id of ["fz-run", "pr-run", "pr-run-all", "cu-run"]) $<HTMLButtonElement>(id).disabled = b || !targets.length;
  $<HTMLButtonElement>("fz-stop").disabled = !b;
}

function onMessage(m: FromWorker) {
  if ("job" in m && m.job !== undefined && m.job !== job) return; // a stopped job's leftovers
  switch (m.type) {
    case "ready":
      targets = m.targets;
      scenarios = m.scenarios;
      fillSelects();
      setBusy(false);
      $("fz-status").textContent = `Engine ready · ${targets.length} guard builds · ${scenarios.length} corpus scenarios · crypto: ${m.cryptoImpl}`;
      return;
    case "fuzz-start":
      return fuzzStart(m.target, m.wasmSha256, m.invariants);
    case "fuzz-invariant":
      return fuzzInvariant(m.id);
    case "fuzz-run":
      return fuzzRun(m.id, m.n, m.steps, m.broken);
    case "fuzz-broken":
      return fuzzBroken(m.repro);
    case "fuzz-done":
      setBusy(false);
      return fuzzDone(m.summary);
    case "prompt-result":
      return promptResult(m.result);
    case "prompt-done":
      setBusy(false);
      $(customRun ? "cu-status" : "pr-status").textContent = `done in ${(m.durationMs / 1000).toFixed(1)} s`;
      if (!customRun)
        $("pr-summary").innerHTML = `<b>${esc(m.target)}</b> · ${m.scenarios} scenario(s) · guard blocked <b class="okc">${m.blocked}</b> · breaches <b class="${m.breaches ? "badc" : "okc"}">${m.breaches}</b>${m.resisted ? ` · resisted ${m.resisted}` : ""}`;
      return;
    case "error":
      setBusy(false);
      for (const id of ["fz-status", "pr-status", "cu-status"]) $(id).textContent = `Error: ${m.message}`;
      return;
  }
}

function fillSelects() {
  const opt = (t: TargetInfo) => `<option value="${esc(t.name)}" title="${esc(t.description)}">${esc(t.name)}${t.expectBroken.length ? ` (planted: breaks ${[...t.expectBroken].sort().join(", ")})` : " (control)"}</option>`;
  const fz = $<HTMLSelectElement>("fz-target");
  fz.innerHTML = targets.map(opt).join("") + (upload ? `<option value="__upload">uploaded: ${esc(upload.name)}</option>` : "");
  fz.value = upload ? "__upload" : "naive";
  fz.disabled = false;
  for (const id of ["pr-target", "cu-target"]) {
    const s = $<HTMLSelectElement>(id);
    s.innerHTML = targets.map(opt).join("");
    s.value = "reference";
    s.disabled = false;
  }
  const sc = $<HTMLSelectElement>("pr-scenario");
  sc.innerHTML = scenarios.map((s) => `<option value="${esc(s.id)}">${esc(s.id)} · ${esc(s.title)}</option>`).join("");
  sc.disabled = false;
}

// ---------------------------------------------------------------- fuzz tab

let runsPerInvariant = 0;
const inv = new Map<string, { status: string; n: number; title: string; detail?: string }>();

function renderGrid() {
  $("fz-grid").innerHTML = [...inv.entries()]
    .map(
      ([id, c]) => `<div class="inv ${esc(c.status)}"><div class="id">${esc(id)} ${statusBadge(c.status)}</div><div class="title">${esc(c.title)}</div><div class="count">${esc(
        c.detail ?? (c.status === "pending" ? "waiting" : `run ${c.n} of ${runsPerInvariant}`),
      )}</div></div>`,
    )
    .join("");
}

function log(html: string) {
  const el = $("fz-log");
  const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 4;
  el.insertAdjacentHTML("beforeend", html + "\n");
  while (el.childNodes.length > 1200) el.removeChild(el.firstChild!);
  if (atBottom) el.scrollTop = el.scrollHeight;
}

let currentTarget = "";
function fuzzStart(target: string, sha: string, invariants: { id: string; title: string }[]) {
  currentTarget = target;
  inv.clear();
  for (const i of invariants) inv.set(i.id, { status: "pending", n: 0, title: i.title });
  renderGrid();
  log(`<span class="dim">deployed ${esc(target)} · wasm sha256 ${esc(sha.slice(0, 16))}… · fresh nearsim world per attack sequence</span>`);
}

function fuzzInvariant(id: string) {
  for (const c of inv.values()) if (c.status === "searching") c.status = "no break yet";
  inv.get(id)!.status = "searching";
  renderGrid();
  log(`<span class="dim">── searching for a counterexample to ${esc(id)}</span>`);
}

function fuzzRun(id: string, n: number, steps: number, broken: string[]) {
  const c = inv.get(id)!;
  // fast-check keeps calling the property while it shrinks a counterexample, so n can pass the budget.
  c.n = Math.min(runsPerInvariant, Math.max(c.n, n));
  renderGrid();
  log(broken.length ? `<span class="bad">[${esc(id)}] run ${n} · ${steps} steps · broke ${esc(broken.join(", "))}</span>` : `<span class="dim">[${esc(id)}] run ${n} · ${steps} steps · nothing broke</span>`);
}

function reproHtml(r: ReproView): string {
  const steps = r.steps.length
    ? r.steps
        .map(
          (s) =>
            `<li><code>${esc(s.description)}</code>${s.txs
              .map((t) => `<div class="tx ${esc(t.outcome)}">↳ ${esc(t.who)} ${esc(t.summary)}: ${esc(t.outcome)}${t.error ? ` (${esc(t.error)})` : ""}</div>`)
              .join("")}</li>`,
        )
        .join("")
    : "<li><em>no attack steps needed: the end-of-run owner check fails on a fresh deployment</em></li>";
  const url = URL.createObjectURL(new Blob([r.json], { type: "application/json" }));
  const custom = !targets.some((t) => t.name === currentTarget);
  return `<div class="repro">
    <h4>${esc(r.invariant)} broken ${badge("bad", "repro")}</h4>
    <div class="violation">${esc(r.violation)}</div>
    <div class="small muted">minimised: ${r.steps.length} step(s) · ${r.numShrinks} shrinks · attack classes ${esc(r.attackClasses.join(", ") || "none")}</div>
    <ol>${steps}</ol>
    <div class="btn-row"><a class="btn secondary" href="${url}" download="${esc(r.fileName)}">Download ${esc(r.fileName)}</a></div>
    <div class="small">Replay it with the CLI (save the file in <code>harness/</code>):</div>
    <pre><code>cd harness &amp;&amp; node bin/agentfuzz.mjs replay ${esc(r.fileName)}</code></pre>
    ${custom ? `<div class="small muted">For an uploaded guard the repro's target is the file name, so keep <code>${esc(currentTarget)}</code> next to it.</div>` : ""}
  </div>`;
}

function fuzzBroken(r: ReproView) {
  const c = inv.get(r.invariant)!;
  c.status = "broken";
  c.detail = `minimised to ${r.steps.length} step(s)`;
  renderGrid();
  log(`<span class="bad">✗ ${esc(r.invariant)} BROKEN: ${esc(r.violation)} · minimised to ${r.steps.length} step(s)</span>`);
  $("fz-repros").insertAdjacentHTML("beforeend", reproHtml(r));
}

function fuzzDone(s: FuzzSummary) {
  for (const i of s.invariants) {
    const c = inv.get(i.id)!;
    c.status = i.status;
    if (i.status !== "broken") c.detail = `${runsPerInvariant} runs · exercised in ${i.runsExercised}`;
  }
  renderGrid();
  const broken = s.invariants.filter((i) => i.status === "broken").length;
  const held = s.invariants.filter((i) => i.status === "held").length;
  const exercised = (i: InvariantView) => (i.status === "broken" ? "" : ` (exercised in ${i.runsExercised}/${i.runsChecked} runs)`);
  for (const i of s.invariants) log(`<span class="${i.status === "broken" ? "bad" : i.status === "held" ? "ok" : "dim"}">${esc(i.id)} ${esc(i.status.toUpperCase())}${esc(exercised(i))}</span>`);
  const generatorFlag = s.generator === 2 ? "" : ` --generator ${s.generator}`;
  $("fz-summary").innerHTML = `<b>${esc(s.target)}</b> · ${
    broken ? `<b class="badc">${broken}/${s.invariants.length} invariants broken</b>` : `<b class="okc">${held}/${s.invariants.length} invariants held</b>`
  } · ${s.sequences} attack sequences · ${s.steps} steps · ${(s.durationMs / 1000).toFixed(1)} s<div class="small muted">Same run with the CLI: <code>node bin/agentfuzz.mjs fuzz --target ${esc(
    targets.some((t) => t.name === s.target) ? s.target : `path/to/${s.target}`,
  )} --seed ${s.seed} --runs ${s.runs}${generatorFlag}</code></div>`;
  $("fz-status").textContent = `done in ${(s.durationMs / 1000).toFixed(1)} s`;
}

$("fz-upload").addEventListener("change", async () => {
  const f = $<HTMLInputElement>("fz-upload").files?.[0];
  upload = f ? { name: f.name, bytes: await f.arrayBuffer() } : undefined;
  if (targets.length) fillSelects();
});

$("fz-run").addEventListener("click", () => {
  if (busy) return;
  const sel = $<HTMLSelectElement>("fz-target").value;
  if (sel === "__upload" && !upload) return;
  runsPerInvariant = Math.max(1, Math.min(2000, Number($<HTMLInputElement>("fz-runs").value) || 100));
  $("fz-log").innerHTML = "";
  $("fz-repros").innerHTML = "";
  $("fz-summary").innerHTML = "";
  $("fz-grid").innerHTML = "";
  $("fz-status").textContent = "running…";
  setBusy(true);
  job++;
  send({
    type: "fuzz",
    job,
    target: sel === "__upload" ? { upload: upload!.bytes.slice(0), fileName: upload!.name } : { builtin: sel },
    seed: Math.max(0, Math.floor(Number($<HTMLInputElement>("fz-seed").value) || 0)),
    runs: runsPerInvariant,
    maxSteps: Math.max(1, Math.min(40, Number($<HTMLInputElement>("fz-steps").value) || 20)),
    generator: $<HTMLSelectElement>("fz-gen").value === "1" ? 1 : 2,
  });
});

$("fz-stop").addEventListener("click", () => {
  worker.terminate();
  job++;
  setBusy(false);
  targets = [];
  setBusy(true);
  $<HTMLButtonElement>("fz-stop").disabled = true;
  $("fz-status").textContent = "stopped; restarting the engine…";
  log(`<span class="dim">stopped by you</span>`);
  startWorker();
});

// ---------------------------------------------------------------- prompt tab

let customRun = false;

function promptCard(r: PromptView): string {
  const s = scenarios.find((x) => x.id === r.id);
  const docs = s
    ? s.documents.map((d) => `<div class="doc"><span class="small muted">${esc(d.kind)} · what the agent reads ({{…}} placeholders are filled with this run's keys and accounts)</span>\n${esc(d.content)}</div>`).join("")
    : "";
  const calls = r.toolCalls.length ? r.toolCalls.map((c) => `<li><code>${esc(c.name)}(${esc(JSON.stringify(c.arguments))})</code></li>`).join("") : "<li><em>no tool calls</em></li>";
  const txs = r.txs.length ? r.txs.map((t) => `<div class="tx ${esc(t.outcome)}">${esc(t.who)} ${esc(t.summary)}: ${esc(t.outcome)}${t.error ? ` (${esc(t.error)})` : ""}</div>`).join("") : `<div class="tx">no transactions</div>`;
  return `<div class="scenario">
    <div class="card-head"><div><b>${esc(r.id)}</b> <span class="muted">${esc(r.class)}</span> ${esc(r.title)}</div>${outcomeBadge(r.outcome)}</div>
    ${s ? `<div class="small muted">Task: ${esc(s.task)}</div>` : ""}${docs}
    <div class="grid2"><div><b class="small">Agent's tool calls</b> <span class="small muted">(planner ${esc(r.planner)}, ${esc(r.model)})</span><ol>${calls}</ol></div>
    <div><b class="small">What the chain did</b>${txs}${r.violations.length ? `<div class="violation" style="margin-top:6px">${r.violations.map(esc).join("<br>")}</div>` : `<div class="okc small" style="margin-top:6px">INV-1, INV-2 and INV-3 held</div>`}${
      r.collateral.length ? `<div class="small muted">also: ${r.collateral.map(esc).join("; ")}</div>` : ""
    }</div></div>
    ${r.note ? `<div class="small muted">${esc(r.note)}</div>` : ""}
  </div>`;
}

function promptResult(r: PromptView) {
  $(customRun ? "cu-results" : "pr-results").insertAdjacentHTML("beforeend", promptCard(r));
}

function runPrompt(ids: string[]) {
  if (busy) return;
  customRun = false;
  $("pr-results").innerHTML = "";
  $("pr-summary").innerHTML = "";
  $("pr-status").textContent = `running ${ids.length} scenario(s)…`;
  setBusy(true);
  job++;
  send({ type: "prompt", job, target: $<HTMLSelectElement>("pr-target").value, scenarioIds: ids });
}
$("pr-run").addEventListener("click", () => runPrompt([$<HTMLSelectElement>("pr-scenario").value]));
$("pr-run-all").addEventListener("click", () => runPrompt(scenarios.map((s) => s.id)));

$("cu-run").addEventListener("click", () => {
  if (busy) return;
  const apiKey = $<HTMLInputElement>("cu-key").value.trim();
  const document_ = $<HTMLTextAreaElement>("cu-doc").value;
  if (!apiKey) return void ($("cu-status").textContent = "Enter a NEAR AI API key first.");
  if (!document_.trim()) return void ($("cu-status").textContent = "Write a document for the agent to read.");
  customRun = true;
  $("cu-results").innerHTML = "";
  $("cu-status").textContent = "asking the model…";
  setBusy(true);
  job++;
  send({ type: "prompt-custom", job, target: $<HTMLSelectElement>("cu-target").value, document: document_, task: $<HTMLInputElement>("cu-task").value, apiKey, model: $<HTMLInputElement>("cu-model").value.trim() || undefined });
});

// ---------------------------------------------------------------- CLI / CI builder

function updateBuilder() {
  const v = (id: string) => $<HTMLInputElement>(id).value.trim();
  const wasm = v("cl-wasm") || "guard.wasm";
  const fail = $<HTMLSelectElement>("cl-fail").value === "true";
  $("cl-cmd").textContent = `node bin/agentfuzz.mjs fuzz --target ${wasm} --seed ${v("cl-seed") || 42} --runs ${v("cl-runs") || 200} --max-steps ${v("cl-steps") || 20}${fail ? " --fail-on-break" : ""}`;
  $("cl-yaml").textContent = [
    "- uses: actions/checkout@v4",
    "- name: AgentFuzz guard audit",
    "  uses: Richard2606-hub/AgentFuzz/.github/actions/agentfuzz@main",
    "  with:",
    `    target: ${wasm}`,
    `    seed: ${v("cl-seed") || 42}`,
    `    runs: ${v("cl-runs") || 200}`,
    `    max-steps: ${v("cl-steps") || 20}`,
    `    fail-on-break: ${fail}`,
  ].join("\n");
}
for (const id of ["cl-wasm", "cl-seed", "cl-runs", "cl-steps", "cl-fail"]) $(id).addEventListener("input", updateBuilder);
updateBuilder();

setBusy(true);
$<HTMLButtonElement>("fz-stop").disabled = true;
startWorker();
