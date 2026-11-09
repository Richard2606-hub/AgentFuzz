/** Minimal .env loader (no dependency): KEY=VALUE lines, never overrides existing variables. */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

export function loadDotEnv(dir: string, env: NodeJS.ProcessEnv = process.env): string[] {
  const file = join(dir, ".env");
  if (!existsSync(file)) return [];
  const set: string[] = [];
  for (const line of readFileSync(file, "utf8").split(/\r?\n/)) {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(line);
    if (!m || line.trimStart().startsWith("#")) continue;
    const [, key, raw] = m;
    const value = raw.replace(/^(['"])(.*)\1$/, "$2");
    if (value === "" || env[key] !== undefined) continue;
    env[key] = value;
    set.push(key);
  }
  return set;
}
