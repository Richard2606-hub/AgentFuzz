/**
 * Playground page controller (bundled to web/playground.js). It owns the DOM and renders only what
 * the worker reports from real executions (or, on the Check tab, reads from testnet); it holds no
 * results of its own.
 */
import { checkGuard, type CheckResult } from "../anchor/audit-lookup.js";
import { scanAccount, type Network, type ScanResult, type Severity } from "../account/scan.js";
import { everydaySummary } from "../account/everyday.js";
import { fmtNear } from "../near/keys.js";
import type { SimulationResult } from "../simulate/simulate.js";
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

// Tab switching is a small inline script in index.html, so the scorecard works without this bundle;
// it runs after this file and falls back to the scorecard tab unless this flag is set.
$("pg-missing").hidden = true;
(window as unknown as { AF_PLAYGROUND: boolean }).AF_PLAYGROUND = true;

// ---------------------------------------------------------------- worker

let worker: Worker;
let targets: TargetInfo[] = [];
let scenarios: ScenarioInfo[] = [];
let job = 0;
let busy = false;
let upload: { name: string; bytes: ArrayBuffer } | undefined;
/** Status line of the tab whose job is running, for errors. */
let statusId = "fz-status";

/**
 * The worker runs from a blob: URL so it inherits this page's Content-Security-Policy (a worker
 * loaded from its own URL takes the policy of that response's headers, and GitHub Pages sends none).
 * That is what limits the worker's fetches, including the NEAR AI key, to the allowed hosts.
 */
let workerUrl: string | undefined;
async function loadWorkerSource(): Promise<void> {
  const res = await fetch(new URL("playground-worker.js", location.href));
  if (!res.ok) throw new Error(`playground-worker.js: HTTP ${res.status}`);
  workerUrl = URL.createObjectURL(new Blob([await res.text()], { type: "text/javascript" }));
}

function startWorker() {
  if (!workerUrl) throw new Error("worker source not loaded");
  worker = new Worker(workerUrl);
  worker.onmessage = (ev: MessageEvent<FromWorker>) => onMessage(ev.data);
  worker.onerror = (ev) => {
    $("fz-status").textContent = `Engine failed to start: ${ev.message || "see the browser console"}`;
  };
  send({ type: "init", base: new URL("./", location.href).href });
}
const send = (m: ToWorker, transfer: Transferable[] = []) => worker.postMessage(m, transfer);

function setBusy(b: boolean) {
  busy = b;
  for (const id of ["fz-run", "pr-run", "pr-run-all", "cu-run", "sm-run"]) $<HTMLButtonElement>(id).disabled = b || !targets.length;
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
    case "sim-log":
      return simLogLine(m.line);
    case "sim-done":
      setBusy(false);
      return simDone(m.result);
    case "prompt-done":
      setBusy(false);
      $(customRun ? "cu-status" : "pr-status").textContent = `done in ${(m.durationMs / 1000).toFixed(1)} s`;
      if (!customRun)
        $("pr-summary").innerHTML = `<b>${esc(m.target)}</b> · ${m.scenarios} scenario(s) · guard blocked <b class="okc">${m.blocked}</b> · breaches <b class="${m.breaches ? "badc" : "okc"}">${m.breaches}</b>${m.resisted ? ` · resisted ${m.resisted}` : ""}`;
      return;
    case "error":
      setBusy(false);
      $(statusId).textContent = `Error: ${m.message}`;
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
    : "<li><em>no attack steps needed: the invariant already fails on a freshly deployed guard</em></li>";
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
  statusId = "fz-status";
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
  statusId = "pr-status";
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
  statusId = "cu-status";
  setBusy(true);
  job++;
  send({ type: "prompt-custom", job, target: $<HTMLSelectElement>("cu-target").value, document: document_, task: $<HTMLInputElement>("cu-task").value, apiKey, model: $<HTMLInputElement>("cu-model").value.trim() || undefined });
});

// ---------------------------------------------------------------- check tab (reads testnet)

const VERDICTS: Record<CheckResult["verdict"], [string, string, string]> = {
  clean: ["ok", "audited · held", "Every invariant held and no prompt attack breached it. Safe to trust with a budget, per this audit."],
  broken: ["bad", "audited · broken", "Do not trust this guard with funds."],
  incomplete: ["warn", "audited · incomplete", "Nothing broke, but not every invariant was exercised. Run a longer campaign."],
  "not-audited": ["muted", "not audited", "No AgentFuzz report on this scoreboard covers this exact build. Fuzz it first."],
  "no-contract": ["muted", "no contract", "This account has no contract deployed, so there is no guard to check."],
};

async function runCheck() {
  const box = $("ck");
  const input = $<HTMLInputElement>("ck-input").value.trim();
  if (!input) return void ($("ck-status").textContent = "Enter a testnet account id or a 64-character code hash.");
  const ref = /^[0-9a-f]{64}$/.test(input) ? { codeHash: input } : { accountId: input.toLowerCase() };
  $("ck-status").textContent = "reading testnet…";
  $("ck-result").innerHTML = "";
  $<HTMLButtonElement>("ck-run").disabled = true;
  try {
    const r = await checkGuard(ref, { scoreboard: box.dataset.scoreboard, rpcUrl: box.dataset.rpc });
    const [cls, label, text] = VERDICTS[r.verdict];
    const a = r.latest;
    $("ck-result").innerHTML = `<div class="repro">
      <h4>${esc(r.accountId ?? "code hash")} ${badge(cls, label)}</h4>
      ${r.verdict === "no-contract" ? "" : `<div class="small">code hash <span class="mono">${esc(r.codeHash)}</span> <span class="muted">(SHA-256 of the deployed wasm)</span></div>`}
      ${
        a
          ? `<div style="margin:8px 0">${a.broken ? `<b class="badc">${a.broken}/${a.total} invariants broken</b> (${esc(a.broken_invariants.join(", "))})` : `<b class="okc">${a.held}/${a.total} invariants held</b>`} · prompt-injection breaches <b class="${a.prompt_breaches ? "badc" : "okc"}">${a.prompt_breaches}</b></div>
             <div class="small muted">audited as <b>${esc(a.target)}</b> in report <span class="mono">${esc(a.run_id)}</span> (sha256 <span class="mono">${esc(a.report_sha256.slice(0, 16))}…</span>), submitted by ${esc(a.submitter)} at block ${esc(a.block_height)}${r.audits.length > 1 ? ` · ${r.audits.length} audits of this build on record, showing the latest` : ""}</div>`
          : ""
      }
      <p>${esc(text)}</p>
    </div>`;
    $("ck-status").textContent = "read from testnet just now";
  } catch (e) {
    $("ck-status").textContent = `Error: ${e instanceof Error ? e.message : String(e)}`;
  } finally {
    $<HTMLButtonElement>("ck-run").disabled = false;
  }
}

$<HTMLButtonElement>("ck-run").disabled = false;
$("ck-run").addEventListener("click", runCheck);
$("ck-input").addEventListener("keydown", (e) => {
  if ((e as KeyboardEvent).key === "Enter") void runCheck();
});
document.querySelectorAll<HTMLButtonElement>(".ck-example").forEach((b) =>
  b.addEventListener("click", () => {
    $<HTMLInputElement>("ck-input").value = b.dataset.account ?? "";
    void runCheck();
  }),
);

// ---------------------------------------------------------------- account safety tab (reads mainnet or testnet)

const SEVERITY_BADGE: Record<Severity, [string, string]> = { danger: ["bad", "danger"], warn: ["warn", "review"], info: ["info", "info"], ok: ["ok", "ok"] };
const SCAN_VERDICT: Record<ScanResult["verdict"], [string, string, string]> = {
  danger: ["bad", "danger", "Act on the red items before you send money to this account or trust it with a budget."],
  warn: ["warn", "review", "Nothing alarming, but review the yellow items."],
  ok: ["ok", "nothing risky found", "No known risk pattern on this account."],
};
const nearAmount = (yocto: string) => fmtNear(BigInt(yocto));

async function runScan() {
  const input = $<HTMLInputElement>("sc-input").value.trim();
  if (!input) return void ($("sc-status").textContent = "Enter a NEAR account id, e.g. you.near or you.testnet.");
  const network = ($<HTMLSelectElement>("sc-network").value || undefined) as Network | undefined;
  $("sc-status").textContent = "reading the chain…";
  $("sc-result").innerHTML = "";
  $<HTMLButtonElement>("sc-run").disabled = true;
  try {
    const r = await scanAccount(input, { network });
    const [cls, label, text] = r.exists ? SCAN_VERDICT[r.verdict] : ["warn", "not found", `This account does not exist on ${r.network}.`];
    const b = r.balance;
    $("sc-result").innerHTML = `<div class="repro">
      <h4>${esc(r.accountId)} <span class="muted small">${esc(r.network)}</span> ${badge(cls, label)}</h4>
      ${b ? `<div class="small">balance <b>${esc(nearAmount(b.total))}</b>${BigInt(b.staked) ? ` · staked ${esc(nearAmount(b.staked))}` : ""} · storage ${b.storageBytes.toLocaleString()} bytes${r.codeHash ? ` · contract <span class="mono">${esc(r.codeHash.slice(0, 16))}…</span>` : ""}</div>` : ""}
      <p>${esc(text)}</p>
      ${r.findings
        .map((f) => `<div class="finding ${f.severity}"><b>${badge(...SEVERITY_BADGE[f.severity])} ${esc(f.title)}</b><span class="small">${esc(f.detail)}</span></div>`)
        .join("")}
      ${
        r.keys.length
          ? `<h4 style="margin-top:14px">Access keys (${r.keys.length})</h4>
             <table class="compact keys"><thead><tr><th></th><th>Kind</th><th>Public key</th><th>What it can do</th></tr></thead><tbody>${r.keys
               .map((k) => `<tr><td>${badge(...SEVERITY_BADGE[k.severity])}</td><td>${esc(k.kind)}</td><td class="mono">${esc(k.publicKey)}</td><td>${esc(k.note)}</td></tr>`)
               .join("")}</tbody></table>`
          : ""
      }
    </div>`;
    $("sc-status").textContent = `read from ${r.network} just now`;
  } catch (e) {
    $("sc-status").textContent = `Error: ${e instanceof Error ? e.message : String(e)}`;
  } finally {
    $<HTMLButtonElement>("sc-run").disabled = false;
  }
}

$<HTMLButtonElement>("sc-run").disabled = false;
$("sc-run").addEventListener("click", runScan);
$("sc-input").addEventListener("keydown", (e) => {
  if ((e as KeyboardEvent).key === "Enter") void runScan();
});
document.querySelectorAll<HTMLButtonElement>(".sc-example").forEach((b) =>
  b.addEventListener("click", () => {
    $<HTMLInputElement>("sc-input").value = b.dataset.account ?? "";
    $<HTMLSelectElement>("sc-network").value = "";
    void runScan();
  }),
);

// ---------------------------------------------------------------- front box: "Is my NEAR wallet safe?" (everyday words)

let heroLast: string | undefined;
async function runHero() {
  const input = $<HTMLInputElement>("hero-input").value.trim();
  const out = $("hero-result");
  if (!input) {
    out.innerHTML = `<p class="small">Type your NEAR account name, for example <b>yourname.near</b>.</p>`;
    return;
  }
  $<HTMLButtonElement>("hero-run").disabled = true;
  out.innerHTML = `<p class="small muted">Reading ${esc(input)} from the NEAR blockchain…</p>`;
  try {
    const r = await scanAccount(input);
    const e = everydaySummary(r);
    heroLast = r.accountId;
    out.innerHTML = `<div class="verdict-box ${e.light}">
      <div class="verdict-head"><span class="light ${e.light}" aria-hidden="true"></span><span>${esc(e.headline)}</span><span class="verdict-sub">${esc(r.accountId)} · ${esc(r.network)}${e.balance ? ` · balance ${esc(e.balance)}` : ""}</span></div>
      ${e.points.length ? `<ul>${e.points.map((p) => `<li>${esc(p)}</li>`).join("")}</ul>` : ""}
      <p class="small muted">${esc(e.limits)}</p>
      ${r.exists ? `<button class="linkbtn small" id="hero-details">See the full technical details →</button>` : ""}
    </div>`;
    $("hero-details")?.addEventListener("click", () => {
      $<HTMLInputElement>("sc-input").value = heroLast ?? "";
      $<HTMLSelectElement>("sc-network").value = "";
      void runScan();
      openTab("scan");
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    out.innerHTML = `<div class="verdict-box missing"><div class="verdict-head"><span class="light missing"></span><span>${/not a valid NEAR account id/.test(msg) ? "That is not a NEAR account name" : "Could not check right now"}</span></div><p class="small">${esc(/not a valid NEAR account id/.test(msg) ? "NEAR account names use lowercase letters, numbers, - _ and dots, like yourname.near." : `${msg}. Please try again in a moment.`)}</p></div>`;
  } finally {
    $<HTMLButtonElement>("hero-run").disabled = false;
  }
}

/** Switch to a tab and bring it into view (also when its #hash is already in the address bar). */
function openTab(name: string) {
  document.querySelector<HTMLButtonElement>(`.tab-btn[data-tab="${name}"]`)?.click();
  document.querySelector(".tabs-nav")?.scrollIntoView({ behavior: "smooth" });
}

$<HTMLButtonElement>("hero-run").disabled = false;
$("hero-run").addEventListener("click", () => void runHero());
$("hero-input").addEventListener("keydown", (e) => {
  if ((e as KeyboardEvent).key === "Enter") void runHero();
});
document.querySelectorAll<HTMLButtonElement>(".hero-example").forEach((b) =>
  b.addEventListener("click", () => {
    $<HTMLInputElement>("hero-input").value = b.dataset.account ?? "";
    void runHero();
  }),
);
document.querySelectorAll<HTMLAnchorElement>(".hero-link").forEach((a) =>
  a.addEventListener("click", (e) => {
    e.preventDefault();
    openTab(a.hash.slice(1));
  }),
);

// ---------------------------------------------------------------- simulate before you sign (runs in the worker)

const GUARD_REF = "guard-reference.agentfuzz-28213.testnet";
const GUARD_NAIVE = "guard-naive.agentfuzz-28213.testnet";
type SimExample = { mode: "transfer" | "call" | "json"; signer: string; to?: string; amount?: string; method?: string; args?: string; deposit?: string; gas?: string; json?: string };
const SIM_EXAMPLES: Record<string, SimExample> = {
  rotate: { mode: "call", signer: GUARD_NAIVE, to: GUARD_NAIVE, method: "rotate_key", args: '{"new_public_key":"ed25519:8az9oB8mcn3DBYDCg6v32JhSsktcWdGwp8D5x9mU1aLo"}', gas: "60" },
  pay: { mode: "call", signer: GUARD_REF, to: GUARD_REF, method: "pay", args: '{"receiver_id":"agentfuzz-28213.testnet","amount":"50000000000000000000000"}', gas: "60" },
  attacker: { mode: "call", signer: GUARD_REF, to: GUARD_REF, method: "pay", args: '{"receiver_id":"attacker.testnet","amount":"50000000000000000000000"}', gas: "60" },
  lookalike: { mode: "transfer", signer: "root.near", to: "wrap-near.near", amount: "1" },
  wrap: { mode: "call", signer: "root.near", to: "wrap.near", method: "near_deposit", args: "{}", deposit: "1", gas: "30" },
  addkey: {
    mode: "json",
    signer: "root.near",
    json: JSON.stringify({ receiverId: "root.near", actions: [{ type: "AddKey", params: { publicKey: "ed25519:8az9oB8mcn3DBYDCg6v32JhSsktcWdGwp8D5x9mU1aLo", accessKey: { permission: "FullAccess" } } }] }, null, 1),
  },
};

function smMode() {
  const m = $<HTMLSelectElement>("sm-mode").value;
  $("sm-transfer-box").hidden = m !== "transfer";
  $("sm-call-box").hidden = m !== "call";
  $("sm-json-box").hidden = m !== "json";
  $("sm-to").parentElement!.hidden = m === "json";
}
$("sm-mode").addEventListener("change", smMode);

let simLog: string[] = [];
function runSimulate() {
  if (busy) return void ($("sm-status").textContent = "The engine is busy with a fuzz or prompt run; wait for it or press Stop on that tab.");
  const v = (id: string) => $<HTMLInputElement>(id).value.trim();
  const mode = $<HTMLSelectElement>("sm-mode").value;
  const signerId = v("sm-signer").toLowerCase();
  if (!signerId && mode !== "json") return void ($("sm-status").textContent = "Enter the signer: the account that would sign.");
  const network = ($<HTMLSelectElement>("sm-network").value || undefined) as Network | undefined;
  job++;
  statusId = "sm-status";
  simLog = [];
  $("sm-result").innerHTML = "";
  $("sm-status").textContent = "forking the network…";
  setBusy(true);
  if (mode === "json") send({ type: "simulate", job, network, txJson: v("sm-json"), signerId: signerId || undefined });
  else
    send({
      type: "simulate",
      job,
      network,
      fields:
        mode === "transfer"
          ? { signerId, receiverId: v("sm-to"), transferNear: v("sm-amount") || "0" }
          : { signerId, receiverId: v("sm-to"), method: v("sm-method"), args: v("sm-args"), depositNear: v("sm-deposit"), gasTgas: v("sm-gas") },
    });
}
$("sm-run").addEventListener("click", runSimulate);
document.querySelectorAll<HTMLButtonElement>(".sm-example").forEach((b) =>
  b.addEventListener("click", () => {
    const ex = SIM_EXAMPLES[b.dataset.ex ?? ""];
    if (!ex) return;
    const set = (id: string, val = "") => ($<HTMLInputElement>(id).value = val);
    $<HTMLSelectElement>("sm-mode").value = ex.mode;
    $<HTMLSelectElement>("sm-network").value = "";
    set("sm-signer", ex.signer);
    set("sm-to", ex.to);
    set("sm-amount", ex.amount);
    set("sm-method", ex.method);
    set("sm-args", ex.args);
    set("sm-deposit", ex.deposit);
    set("sm-gas", ex.gas);
    set("sm-json", ex.json);
    smMode();
    runSimulate();
  }),
);

function simLogLine(line: string) {
  simLog.push(line);
  $("sm-status").textContent = line;
}

function simDone(r: SimulationResult) {
  const nearDelta = (n: SimulationResult["near"][number]) => `${nearAmount(n.before)} → ${n.after === null ? "deleted" : nearAmount(n.after)}`;
  const [cls, label] = r.verdict === "danger" ? ["bad", "danger"] : r.verdict === "warn" ? ["warn", "review"] : ["ok", "nothing risky found"];
  const list = (items: string[]) => `<ul class="sim-list">${items.map((i) => `<li>${esc(i)}</li>`).join("")}</ul>`;
  const changed = r.tokenBalances.filter((b) => b.delta !== "0");
  $("sm-result").innerHTML = `<div class="repro">
    <h4>${badge(cls, label)} ${r.mode === "decoded" ? badge("warn", "decoded only, not executed") : badge("info", `simulated on ${r.network} at block ${r.block.height}`)}</h4>
    <b>What it asks for</b>${list(r.intent)}
    <b>${r.mode === "executed" ? "What would happen" : "What it would do, if it succeeds"}</b>${list(r.summary)}
    ${r.findings.map((f) => `<div class="finding ${f.severity}"><b>${badge(...SEVERITY_BADGE[f.severity])} ${esc(f.title)}</b><span class="small">${esc(f.detail)}</span></div>`).join("")}
    ${
      r.near.length || changed.length
        ? `<h4 style="margin-top:14px">Balances before → after</h4><table class="compact"><tbody>${r.near.map((n) => `<tr><td class="mono">${esc(n.accountId)}</td><td>NEAR</td><td>${esc(nearDelta(n))}</td></tr>`).join("")}${changed
            .map((b) => `<tr><td class="mono">${esc(b.accountId)}</td><td>${esc(b.symbol ?? b.contract)}</td><td>${esc(tokenAmount(b.before, b.decimals))} → ${esc(tokenAmount(b.after, b.decimals))}</td></tr>`)
            .join("")}</tbody></table>`
        : ""
    }
    ${
      r.txs.length
        ? `<details><summary class="small">Receipts (${r.txs.reduce((n, t) => n + t.receipts.length, 0)}), as nearsim executed them</summary><ol class="small">${r.txs
            .flatMap((t) =>
              t.rejected
                ? [`<li class="badc">refused: ${esc(t.rejected)}</li>`]
                : t.receipts.map((x) => `<li><span class="${x.status === "success" ? "okc" : "badc"}">${x.status === "success" ? "ok" : "failed"}</span> <span class="mono">${esc(x.predecessorId)} → ${esc(x.receiverId)}</span>: ${esc(x.actions.join("; "))}${x.error ? ` <span class="badc">(${esc(x.error)})</span>` : ""}${x.logs.length ? `<div class="sim-log">${esc(x.logs.join("\n"))}</div>` : ""}</li>`),
            )
            .join("")}</ol></details>`
        : ""
    }
    <div class="small muted" style="margin-top:8px">${r.stats.rounds + 1} round(s) · ${r.stats.accounts} account(s) and ${r.stats.wholeStates + r.stats.storageKeys} state read(s) from the network · ${r.stats.rpcCalls} RPC calls · ${(r.stats.ms / 1000).toFixed(1)} s${r.fees !== "0" ? ` · fee ≈ ${esc(nearAmount(r.fees))}` : ""}</div>
  </div>`;
  $("sm-status").textContent = r.mode === "executed" ? "simulated just now; nothing was signed or sent" : "decoded only; see the note";
}
const tokenAmount = (raw: string, decimals?: number) => {
  if (!decimals) return raw;
  const v = BigInt(raw);
  const base = 10n ** BigInt(decimals);
  const frac = (v % base).toString().padStart(decimals, "0").replace(/0+$/, "").slice(0, 6);
  return `${v / base}${frac ? `.${frac}` : ""}`;
};

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
loadWorkerSource().then(startWorker, (e: unknown) => {
  $("fz-status").textContent = `Engine failed to load: ${e instanceof Error ? e.message : String(e)}`;
});
