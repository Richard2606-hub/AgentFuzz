/**
 * Launch a local nearcore sandbox (the same binary near-workspaces uses) for the sandbox backend.
 *
 * Binary lookup: $NEAR_SANDBOX_BIN, else the one near-workspaces-rs downloaded for
 * `make sandbox-test` (tests/sandbox/target/<profile>/build/near-sandbox-*\/out/.near/near-sandbox-*\/near-sandbox).
 * Linux and macOS only (nearcore publishes no Windows sandbox build).
 */
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { REPO_ROOT } from "../targets/registry.js";

export function findSandboxBinary(): string | undefined {
  if (process.env.NEAR_SANDBOX_BIN && existsSync(process.env.NEAR_SANDBOX_BIN)) return process.env.NEAR_SANDBOX_BIN;
  const target = join(REPO_ROOT, "tests", "sandbox", "target");
  if (!existsSync(target)) return undefined;
  for (const profile of readdirSync(target)) {
    const build = join(target, profile, "build");
    if (!existsSync(build)) continue;
    for (const d of readdirSync(build).filter((x) => x.startsWith("near-sandbox-"))) {
      const nearDir = join(build, d, "out", ".near");
      if (!existsSync(nearDir)) continue;
      for (const v of readdirSync(nearDir).filter((x) => x.startsWith("near-sandbox-")).sort().reverse()) {
        const bin = join(nearDir, v, "near-sandbox");
        if (existsSync(bin)) return bin;
      }
    }
  }
  return undefined;
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const port = (srv.address() as { port: number }).port;
      srv.close(() => resolve(port));
    });
  });
}

export interface SandboxHandle {
  rpcUrl: string;
  rootAccountId: string;
  rootSecretKey: string;
  home: string;
  stop(): Promise<void>;
}

export async function startSandbox(opts: { bin?: string; log?: (s: string) => void } = {}): Promise<SandboxHandle> {
  if (process.platform === "win32") throw new Error("the nearcore sandbox has no Windows build; use WSL, Linux or macOS (nearsim works everywhere)");
  const bin = opts.bin ?? findSandboxBinary();
  if (!bin) throw new Error("near-sandbox binary not found: run `make sandbox-test` once (downloads it) or set NEAR_SANDBOX_BIN");
  const home = mkdtempSync(join(tmpdir(), "agentfuzz-sandbox-"));
  execFileSync(bin, ["--home", home, "init"], { stdio: "ignore" });

  // Fast blocks, like near-workspaces' sandbox defaults.
  const cfgPath = join(home, "config.json");
  const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
  cfg.consensus = { ...cfg.consensus, min_block_production_delay: { secs: 0, nanos: 100_000_000 }, max_block_production_delay: { secs: 0, nanos: 300_000_000 } };
  writeFileSync(cfgPath, JSON.stringify(cfg, null, 2));

  const rpcPort = await freePort();
  const netPort = await freePort();
  const child: ChildProcess = spawn(bin, ["--home", home, "run", "--rpc-addr", `127.0.0.1:${rpcPort}`, "--network-addr", `127.0.0.1:${netPort}`], {
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr?.on("data", (d) => (stderr = (stderr + d.toString()).slice(-4000)));
  const rpcUrl = `http://127.0.0.1:${rpcPort}`;

  const deadline = Date.now() + 60_000;
  for (;;) {
    if (child.exitCode !== null) throw new Error(`near-sandbox exited early:\n${stderr}`);
    try {
      const r = await fetch(rpcUrl, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "status", params: [] }) });
      if (r.ok) {
        const s = (await r.json()) as { result?: { sync_info?: { latest_block_height?: number } } };
        if ((s.result?.sync_info?.latest_block_height ?? 0) > 1) break;
      }
    } catch {
      /* not up yet */
    }
    if (Date.now() > deadline) throw new Error(`near-sandbox did not start within 60 s:\n${stderr}`);
    await new Promise((r) => setTimeout(r, 200));
  }
  const key = JSON.parse(readFileSync(join(home, "validator_key.json"), "utf8")) as { account_id: string; secret_key: string };
  opts.log?.(`near-sandbox ${bin} at ${rpcUrl}`);
  return {
    rpcUrl,
    rootAccountId: key.account_id,
    rootSecretKey: key.secret_key,
    home,
    stop: async () => {
      child.kill("SIGTERM");
      await new Promise((r) => setTimeout(r, 200));
      rmSync(home, { recursive: true, force: true });
    },
  };
}
