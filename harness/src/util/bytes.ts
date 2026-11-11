/** Byte encodings without Node's Buffer, so the engine also runs in browsers. Output matches Buffer's. */

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));

export function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += HEX[b];
  return s;
}

export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2) throw new Error("odd-length hex string");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const b = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
    if (Number.isNaN(b)) throw new Error("invalid hex string");
    out[i] = b;
  }
  return out;
}

/** Like Buffer.toString("utf16le"): little-endian code units, a trailing odd byte is dropped. */
export function utf16leDecode(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i + 1 < bytes.length; i += 2) s += String.fromCharCode(bytes[i] | (bytes[i + 1] << 8));
  return s;
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Standard padded base64, like Buffer.toString("base64"). */
export function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    s += B64[(n >> 18) & 63] + B64[(n >> 12) & 63];
    s += i + 1 < bytes.length ? B64[(n >> 6) & 63] : "=";
    s += i + 2 < bytes.length ? B64[n & 63] : "=";
  }
  return s;
}
