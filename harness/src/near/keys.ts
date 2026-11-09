/**
 * Key material and encodings shared by every backend.
 *
 * Keys are real ed25519 keys derived deterministically from a seed label, so the same
 * fuzz seed produces the same accounts and keys in nearsim *and* in a near-workspaces
 * sandbox (where transactions are actually signed).
 */
import { createHash, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ALPHABET_MAP = new Map([...ALPHABET].map((c, i) => [c, i]));

export function base58Encode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = "";
  while (n > 0n) {
    out = ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  return "1".repeat(zeros) + out;
}

export function base58Decode(s: string): Uint8Array {
  let zeros = 0;
  while (zeros < s.length && s[zeros] === "1") zeros++;
  let n = 0n;
  for (const c of s) {
    const v = ALPHABET_MAP.get(c);
    if (v === undefined) throw new Error(`invalid base58 character '${c}'`);
    n = n * 58n + BigInt(v);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n % 256n));
    n /= 256n;
  }
  return Uint8Array.from([...new Array(zeros).fill(0), ...bytes]);
}

export function sha256(data: Uint8Array | string): Uint8Array {
  return new Uint8Array(createHash("sha256").update(data).digest());
}

export function sha256Hex(data: Uint8Array | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/** "ed25519:<base58>" -> borsh bytes (1-byte curve tag + raw key). */
export function publicKeyToBorsh(pk: string): Uint8Array {
  const [curve, data] = splitKey(pk);
  const raw = base58Decode(data);
  if (curve === "ed25519") {
    if (raw.length !== 32) throw new Error(`ed25519 key must be 32 bytes, got ${raw.length}`);
    return Uint8Array.from([0, ...raw]);
  }
  if (curve === "secp256k1") {
    if (raw.length !== 64) throw new Error(`secp256k1 key must be 64 bytes, got ${raw.length}`);
    return Uint8Array.from([1, ...raw]);
  }
  throw new Error(`unknown key curve '${curve}'`);
}

export function publicKeyFromBorsh(bytes: Uint8Array): string {
  if (bytes[0] === 0 && bytes.length === 33) return `ed25519:${base58Encode(bytes.subarray(1))}`;
  if (bytes[0] === 1 && bytes.length === 65) return `secp256k1:${base58Encode(bytes.subarray(1))}`;
  throw new Error("invalid borsh public key");
}

export function isValidPublicKey(pk: string): boolean {
  try {
    publicKeyToBorsh(pk);
    return true;
  } catch {
    return false;
  }
}

function splitKey(pk: string): [string, string] {
  const i = pk.indexOf(":");
  if (i < 0) return ["ed25519", pk];
  return [pk.slice(0, i), pk.slice(i + 1)];
}

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export interface KeyPair {
  /** "ed25519:<base58 32-byte public key>" */
  publicKey: string;
  /** near-api-js style "ed25519:<base58 64-byte seed||public>" */
  secretKey: string;
  sign(message: Uint8Array): Uint8Array;
}

/** Deterministic ed25519 key pair from an arbitrary label (e.g. `${seed}/agent/0`). */
export function deriveKeyPair(label: string): KeyPair {
  const seed = sha256(`agentfuzz-key:${label}`);
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: "der", type: "pkcs8" });
  const spki = createPublicKey(priv).export({ format: "der", type: "spki" });
  const pub = new Uint8Array(spki.subarray(spki.length - 32));
  return {
    publicKey: `ed25519:${base58Encode(pub)}`,
    secretKey: `ed25519:${base58Encode(Uint8Array.from([...seed, ...pub]))}`,
    sign: (message) => new Uint8Array(edSign(null, message, priv)),
  };
}

export function ed25519Verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  if (signature.length !== 64 || publicKey.length !== 32) return false;
  try {
    const key = createPublicKey({
      key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), publicKey]),
      format: "der",
      type: "spki",
    });
    return edVerify(null, message, key, signature);
  } catch {
    return false;
  }
}

/** NEAR account-id validation (nearcore rules). */
export function isValidAccountId(id: string): boolean {
  if (id.length < 2 || id.length > 64) return false;
  return /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/.test(id);
}

export function isImplicitAccount(id: string): boolean {
  return /^[0-9a-f]{64}$/.test(id);
}

export function u128ToLeBytes(v: bigint): Uint8Array {
  if (v < 0n || v >= 1n << 128n) throw new Error(`u128 out of range: ${v}`);
  const out = new Uint8Array(16);
  let x = v;
  for (let i = 0; i < 16; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

export function u128FromLeBytes(b: Uint8Array): bigint {
  let v = 0n;
  for (let i = 15; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
  return v;
}

export const ONE_NEAR = 10n ** 24n;
export const TGAS = 10n ** 12n;

export function near(amount: number | string): bigint {
  const [whole, frac = ""] = String(amount).split(".");
  return BigInt(whole) * ONE_NEAR + BigInt((frac + "0".repeat(24)).slice(0, 24));
}

export function formatNear(yocto: bigint, digits = 4): string {
  const neg = yocto < 0n;
  const v = neg ? -yocto : yocto;
  const whole = v / ONE_NEAR;
  const frac = (v % ONE_NEAR).toString().padStart(24, "0").slice(0, digits);
  return `${neg ? "-" : ""}${whole}.${frac}`;
}

/** Human-friendly amount: "3 NEAR", "0.0301 NEAR", or raw yocto for dust and huge values. */
export function fmtNear(yocto: bigint): string {
  const v = yocto < 0n ? -yocto : yocto;
  if (v === 0n) return "0 NEAR";
  if (v < 10n ** 20n || v > 10n ** 33n) return `${yocto} yocto`;
  const s = formatNear(yocto, 4).replace(/\.?0+$/, "");
  return `${s} NEAR`;
}
