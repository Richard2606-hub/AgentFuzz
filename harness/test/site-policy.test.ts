/**
 * The web playground's data policy is enforced, not just documented: the CSP allows exactly the
 * hosts in site-policy.ts, the page and worker code mention no other host and use no browser
 * storage, and PRIVACY.md lists the same hosts.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";
import { renderScorecardHtml, TAB_SCRIPT } from "../src/report/html.js";
import { CONNECT_ORIGINS, contentSecurityPolicy, cspHash, SITE_CONNECTIONS } from "../src/report/site-policy.js";
import { loadScorecard } from "../src/report.js";
import { REPO_ROOT } from "../src/targets/registry.js";

type BuildWeb = { browserBundleOptions: (entry: string, extra?: object) => object };
const esbuild = createRequire(join(REPO_ROOT, "harness", "package.json"))("esbuild") as { build: (o: object) => Promise<{ outputFiles: { text: string }[] }> };

/** Hosts that only appear as links the visitor can click (navigation, not connections). */
const LINK_ONLY_HOSTS = new Set(["github.com", "testnet.nearblocks.io", "nearblocks.io", "docs.github.com"]);

describe("web playground data policy", () => {
  const html = renderScorecardHtml(loadScorecard(join(REPO_ROOT, "web", "scorecard.json")));
  const csp = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html)?.[1].replaceAll("&amp;", "&") ?? "";
  const directive = (name: string) => csp.split("; ").find((d) => d.startsWith(`${name} `))?.slice(name.length + 1).split(" ") ?? [];

  it("the page carries a strict CSP and no-referrer", () => {
    expect(csp).toBe(contentSecurityPolicy([TAB_SCRIPT]));
    expect(directive("default-src")).toEqual(["'none'"]);
    expect(directive("connect-src")).toEqual(["'self'", ...CONNECT_ORIGINS]);
    expect(directive("script-src")).toEqual(["'self'", cspHash(TAB_SCRIPT), "'wasm-unsafe-eval'"]);
    expect(directive("worker-src")).toEqual(["blob:"]);
    for (const d of ["object-src", "base-uri", "form-action"]) expect(directive(d)).toEqual(["'none'"]);
    expect(csp).not.toContain("'unsafe-eval'");
    expect(csp).not.toContain("*");
    expect(html).toContain('<meta name="referrer" content="no-referrer">');
  });

  it("the only inline script is the hashed one, and there are no inline event handlers", () => {
    const inline = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
    expect(inline).toEqual([TAB_SCRIPT]);
    expect(html).not.toMatch(/\son[a-z]+=["']/i);
    expect([...html.matchAll(/<script src="([^"]+)"/g)].map((m) => m[1])).toEqual(["playground.js"]);
  });

  it("every allowed host is https, listed once, and shown in the page's privacy notice", () => {
    expect(new Set(CONNECT_ORIGINS).size).toBe(CONNECT_ORIGINS.length);
    for (const c of SITE_CONNECTIONS) {
      expect(c.origin).toMatch(/^https:\/\/[a-z0-9.-]+$/);
      expect(html).toContain(new URL(c.origin).host);
    }
    expect(html).toContain('id="privacy"');
  });

  it("PRIVACY.md lists exactly the hosts the site may contact", () => {
    const privacy = readFileSync(join(REPO_ROOT, "PRIVACY.md"), "utf8");
    const listed = [...privacy.matchAll(/^\| `([a-z0-9.-]+)` \|/gm)].map((m) => m[1]);
    expect(listed.sort()).toEqual(CONNECT_ORIGINS.map((o) => new URL(o).host).sort());
  });

  it("the page and worker bundles, built exactly as the site ships them, contact no other host and use no browser storage or eval", async () => {
    const web = (await import(pathToFileURL(join(REPO_ROOT, "scripts", "build-web.mjs")).href)) as BuildWeb;
    const allowed = new Set(CONNECT_ORIGINS.map((o) => new URL(o).host));
    for (const entry of ["page.ts", "worker.ts"]) {
      const r = await esbuild.build(web.browserBundleOptions(join(REPO_ROOT, "harness", "src", "browser", entry), { format: "iife", minify: true, write: false }));
      const code = r.outputFiles[0].text;
      const hosts = new Set([...code.matchAll(/https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/gi)].map((m) => m[1].toLowerCase()));
      const unexpected = [...hosts].filter((h) => !allowed.has(h) && !LINK_ONLY_HOSTS.has(h));
      expect(unexpected, `${entry} mentions hosts outside site-policy.ts`).toEqual([]);
      expect(code, entry).not.toMatch(/\blocalStorage\b|\bsessionStorage\b|\bindexedDB\b|document\.cookie/);
      expect(code, entry).not.toMatch(/\beval\(|new Function\(/);
    }
  }, 60_000);
});
