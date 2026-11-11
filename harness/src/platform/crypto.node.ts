/**
 * Crypto for Node: native node:crypto (fast; the CLI hashes every deployed wasm).
 * Browser bundles swap this file for crypto.browser.ts (see scripts/build-web.mjs). Both must
 * return identical bytes; harness/test/browser.test.ts checks it.
 */
import { createHash, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";

export const CRYPTO_IMPL = "node";

export function sha256(data: Uint8Array | string): Uint8Array {
  return new Uint8Array(createHash("sha256").update(data).digest());
}

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** Ed25519 from a 32-byte seed: the public key and a signer. */
export function ed25519FromSeed(seed: Uint8Array): { publicKey: Uint8Array; sign(message: Uint8Array): Uint8Array } {
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: "der", type: "pkcs8" });
  const spki = createPublicKey(priv).export({ format: "der", type: "spki" });
  return {
    publicKey: new Uint8Array(spki.subarray(spki.length - 32)),
    sign: (message) => new Uint8Array(edSign(null, message, priv)),
  };
}

export function ed25519Verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, publicKey]), format: "der", type: "spki" });
    return edVerify(null, message, key, signature);
  } catch {
    return false;
  }
}
