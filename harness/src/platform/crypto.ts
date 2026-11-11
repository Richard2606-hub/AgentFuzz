/**
 * Platform crypto. Everything imports from here; browser bundles alias crypto.node.js to
 * crypto.browser.ts at build time (scripts/build-web.mjs).
 */
export { CRYPTO_IMPL, ed25519FromSeed, ed25519Verify, sha256 } from "./crypto.node.js";
