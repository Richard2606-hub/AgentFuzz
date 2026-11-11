/** JSON helpers: bigint-safe, canonical (sorted keys) serialisation for hashing. */
import { toBase64 } from "./bytes.js";

export function toJSONSafe(v: unknown): unknown {
  if (typeof v === "bigint") return v.toString();
  if (v instanceof Uint8Array) return toBase64(v);
  if (v instanceof Set) return [...v].map(toJSONSafe);
  if (v instanceof Map) return Object.fromEntries([...v].map(([k, x]) => [String(k), toJSONSafe(x)]));
  if (Array.isArray(v)) return v.map(toJSONSafe);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) if (x !== undefined) out[k] = toJSONSafe(x);
    return out;
  }
  return v;
}

/** Canonical JSON: sorted object keys, no whitespace. Used for report hashing. */
export function canonicalJSON(v: unknown): string {
  const norm = (x: unknown): unknown => {
    if (Array.isArray(x)) return x.map(norm);
    if (x && typeof x === "object") {
      return Object.fromEntries(
        Object.keys(x as object)
          .sort()
          .map((k) => [k, norm((x as Record<string, unknown>)[k])]),
      );
    }
    return x;
  };
  return JSON.stringify(norm(toJSONSafe(v)));
}

export function prettyJSON(v: unknown): string {
  return JSON.stringify(toJSONSafe(v), null, 2) + "\n";
}
