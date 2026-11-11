/**
 * The web playground's data policy, in one place: every host the page or its worker may contact,
 * why, and what it receives. The Content-Security-Policy, the page's privacy notice and PRIVACY.md
 * are all derived from (or checked against) this list, and a test bundles the page and worker and
 * fails if their code mentions any other host. Add a host here, or the browser blocks it.
 */
import { TESTNET_RPC } from "../anchor/audit-lookup.js";
import { MAINNET_RPC } from "../account/scan.js";
import { LARGE_STATE_RPC } from "../simulate/fork.js";
import { DEFAULT_LLM_BASE_URL } from "../agent/planners.js";
import { sha256 } from "../platform/crypto.js";
import { toBase64 } from "../util/bytes.js";

export interface SiteConnection {
  origin: string;
  operator: string;
  /** Which features contact it. */
  usedBy: string;
  /** What leaves the visitor's browser (besides their IP address, which every request reveals). */
  sends: string;
  /** Only when the visitor acts (clicks a button); nothing is contacted on page load except the site itself. */
  onlyOnRequest: true;
}

const origin = (u: string) => new URL(u).origin;

export const SITE_CONNECTIONS: SiteConnection[] = [
  {
    origin: origin(TESTNET_RPC),
    operator: "FastNEAR (NEAR testnet RPC)",
    usedBy: "Check a wallet, Account safety and Simulate on testnet",
    sends: "the testnet account ids you enter; read-only queries (accounts, keys, contract code and state)",
    onlyOnRequest: true,
  },
  {
    origin: origin(MAINNET_RPC),
    operator: "FastNEAR (NEAR mainnet RPC)",
    usedBy: "Account safety and Simulate on mainnet",
    sends: "the mainnet account ids you enter; read-only queries (accounts, keys, contract code and state, token metadata)",
    onlyOnRequest: true,
  },
  {
    origin: origin(LARGE_STATE_RPC),
    operator: "Intear (NEAR RPC that serves large contract state)",
    usedBy: "Simulate, only for contracts over 50 kB of state",
    sends: "the contract account id and the storage keys the simulation reads",
    onlyOnRequest: true,
  },
  {
    origin: origin(DEFAULT_LLM_BASE_URL),
    operator: "NEAR AI Cloud",
    usedBy: "Prompt injection → Your own injection, with a live model (optional)",
    sends: "your NEAR AI API key (Authorization header), the task and document you typed, and the agent's tool definitions",
    onlyOnRequest: true,
  },
];

export const CONNECT_ORIGINS = SITE_CONNECTIONS.map((c) => c.origin);

/** Base64 SHA-256 of an inline script, as CSP `'sha256-…'` expects. */
export function cspHash(inlineScript: string): string {
  return `'sha256-${toBase64(sha256(new TextEncoder().encode(inlineScript)))}'`;
}

/**
 * The page's Content-Security-Policy (delivered as a <meta> tag: GitHub Pages cannot set headers).
 * The worker is started from a blob: URL so it inherits this policy, including connect-src.
 */
export function contentSecurityPolicy(inlineScripts: string[]): string {
  return [
    "default-src 'none'",
    `script-src 'self' ${inlineScripts.map(cspHash).join(" ")} 'wasm-unsafe-eval'`,
    "worker-src blob:",
    `connect-src 'self' ${CONNECT_ORIGINS.join(" ")}`,
    "style-src 'unsafe-inline'",
    "img-src 'self' data:",
    "base-uri 'none'",
    "form-action 'none'",
    "object-src 'none'",
    "upgrade-insecure-requests",
  ].join("; ");
}
