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

Open http://localhost:4777. The page updates within ~1s of any file change.
Binds to 127.0.0.1 only. All finding text is HTML-escaped (it comes from the audited repo).
