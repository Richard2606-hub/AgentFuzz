#!/usr/bin/env node
// Serve web/ on http://localhost:8080 (make serve-web). Browsers refuse Web Workers and fetch()
// on file://, so the playground needs a real HTTP origin even locally. No dependencies.
//   node scripts/serve-web.mjs [port]
import { createReadStream, statSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

const WEB = join(dirname(fileURLToPath(import.meta.url)), "..", "web");
const PORT = Number(process.argv[2] ?? process.env.PORT ?? 8080);
const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".wasm": "application/wasm",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
};

createServer((req, res) => {
  const path = decodeURIComponent(new URL(req.url ?? "/", "http://x").pathname);
  const file = normalize(join(WEB, path.endsWith("/") ? path + "index.html" : path));
  if (file !== WEB && !file.startsWith(WEB + sep)) {
    res.writeHead(403).end("forbidden");
    return;
  }
  let size;
  try {
    const st = statSync(file);
    if (!st.isFile()) throw new Error("not a file");
    size = st.size;
  } catch {
    res.writeHead(404, { "content-type": "text/plain" }).end("not found");
    return;
  }
  res.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream", "content-length": size, "cache-control": "no-store" });
  createReadStream(file).pipe(res);
}).listen(PORT, "127.0.0.1", () => console.log(`AgentFuzz site: http://localhost:${PORT}/  (serving ${WEB})`));
