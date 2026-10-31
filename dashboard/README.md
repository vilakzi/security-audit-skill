# Audit Console

Read-only live dashboard for `security-audit` runs. Zero dependencies (Node 18+).
It never runs the agent or target code. It only watches the run directory and
renders `findings.json`, `coverage-ledger.json`, `architecture.md` and the reports.

```
# terminal 1: your agent runs the audit as normal
# terminal 2:
node dashboard/server.cjs                  # newest ~/security-audit-skill/*/run-N
node dashboard/server.cjs <run-dir> --port 4777
```

Open http://127.0.0.1:4777 (or http://localhost:4777). The page updates within ~1s of any file change.
Binds to 127.0.0.1 only and rejects any request whose `Host` is not `localhost`/`127.0.0.1`/`[::1]` on the
server port (421) or whose `Origin` is foreign (403), which blocks DNS-rebinding reads. Responses carry a strict CSP,
`nosniff` and `X-Frame-Options: DENY`; run-dir files are read only if regular (no symlinks) and under 8 MB. All finding text is HTML-escaped (it comes from the audited repo).
