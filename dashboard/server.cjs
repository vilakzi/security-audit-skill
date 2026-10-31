#!/usr/bin/env node
// Read-only live dashboard for security-audit run directories. Zero dependencies.
// Usage: node dashboard/server.cjs [run-dir] [--port 4777]
const http = require("http");
const fs = require("fs");
const path = require("path");
const os = require("os");

const args = process.argv.slice(2);
const pi = args.indexOf("--port");
const PORT = pi >= 0 ? Number(args[pi + 1]) : 4777;
const explicit = args.find((a, i) => !a.startsWith("--") && args[i - 1] !== "--port");
const ROOT = path.join(os.homedir(), "security-audit-skill");
const FILES = ["findings.json", "coverage-ledger.json", "architecture.md", "REPORT.md", "FINDINGS-DETAIL.md", "NEEDS-VALIDATION.md"];

function newestRun() {
  let best = null;
  try {
    for (const repo of fs.readdirSync(ROOT, { withFileTypes: true })) {
      if (!repo.isDirectory()) continue;
      const rp = path.join(ROOT, repo.name);
      for (const run of fs.readdirSync(rp, { withFileTypes: true })) {
        if (!run.isDirectory() || !/^run-\d+$/.test(run.name)) continue;
        const dir = path.join(rp, run.name);
        const m = fs.statSync(dir).mtimeMs;
        if (!best || m > best.m) best = { dir, m };
      }
    }
  } catch {}
  return best && best.dir;
}

const runDir = () => (explicit ? path.resolve(explicit) : newestRun());

function readJson(p) {
  try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return null; }
}
function readText(p) {
  try { return fs.readFileSync(p, "utf8"); } catch { return null; }
}
function snapshot() {
  const dir = runDir();
  if (!dir || !fs.existsSync(dir)) return { dir: dir || null, exists: false, root: ROOT };
  const mtimes = {};
  for (const f of FILES) { try { mtimes[f] = fs.statSync(path.join(dir, f)).mtimeMs; } catch {} }
  const findings = readJson(path.join(dir, "findings.json"));
  const ledger = readJson(path.join(dir, "coverage-ledger.json"));
  return {
    dir, exists: true, mtimes, updated: Date.now(),
    findings: Array.isArray(findings) ? findings : [],
    ledger: Array.isArray(ledger) ? ledger : [],
    docs: {
      architecture: readText(path.join(dir, "architecture.md")),
      report: readText(path.join(dir, "REPORT.md")),
      detail: readText(path.join(dir, "FINDINGS-DETAIL.md")),
      needs: readText(path.join(dir, "NEEDS-VALIDATION.md")),
    },
  };
}

const clients = new Set();
let lastSig = "";
setInterval(() => {
  const dir = runDir();
  let sig = String(dir);
  if (dir) for (const f of FILES) { try { sig += f + fs.statSync(path.join(dir, f)).mtimeMs; } catch {} }
  if (sig !== lastSig) {
    lastSig = sig;
    for (const c of clients) c.write("data: change\n\n");
  }
}, 1000);

const html = fs.readFileSync(path.join(__dirname, "index.html"));
http.createServer((req, res) => {
  if (req.method !== "GET") { res.writeHead(405).end(); return; }
  if (req.url === "/api/state") {
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(JSON.stringify(snapshot()));
  } else if (req.url === "/api/events") {
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store", connection: "keep-alive" });
    res.write("retry: 2000\n\n");
    clients.add(res);
    req.on("close", () => clients.delete(res));
  } else if (req.url === "/" || req.url === "/index.html") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(html);
  } else res.writeHead(404).end("not found");
}).listen(PORT, "127.0.0.1", () => {
  console.log(`Audit dashboard: http://localhost:${PORT}`);
  console.log(`Watching: ${runDir() || `(no run yet under ${ROOT})`}`);
});
