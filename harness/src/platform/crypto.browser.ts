/**
 * Crypto for browsers: @noble/hashes and @noble/curves (audited, pure JS). Same signatures and
 * byte-identical results as crypto.node.ts, which browser bundles replace with this file.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";

export const CRYPTO_IMPL = "browser";

export function sha256(data: Uint8Array | string): Uint8Array {
  return nobleSha256(typeof data === "string" ? new TextEncoder().encode(data) : data);
}

export function ed25519FromSeed(seed: Uint8Array): { publicKey: Uint8Array; sign(message: Uint8Array): Uint8Array } {
  return {
    publicKey: ed25519.getPublicKey(seed),
    sign: (message) => ed25519.sign(message, seed),
  };
}

export function ed25519Verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}
