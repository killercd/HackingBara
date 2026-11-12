# Implementation verification

Verified on 2026-11-12 with Python 3.12, Node 22 and Docker Compose on Linux.

| Milestone | Implemented | Verification |
| --- | --- | --- |
| A — Foundation | Compose stack, PostgreSQL migration, account bootstrap, Argon2id/cookie/CSRF authentication, Vue shell | Clean database migration exits 0; container health checks pass; authentication/session/CSRF tests and browser login/logout pass |
| B — Management | Scan and encrypted credential CRUD, IP/CIDR/URL/port validation, server pagination/search/sorting | Backend CRUD/validation/pagination tests and browser create/search/delete workflows pass |
| C — Execution | Durable outbox, Celery worker, separate scheduler, leases, queue limits, run controls, checkpoints, process guardian | State-conflict, checkpoint resume, cancellation, orphan reconciliation and capacity tests pass |
| D — Discovery | RustScan TCP discovery and Nmap XML service identification on discovered ports; progressive persisted results | Parser/scope tests and real operator-owned Docker lab run record one host/open port/service |
| E — Optional modules | Explicit web endpoints, bounded HTTP Basic validation, private EyeWitness images/thumbnails and scope proxy | Opt-in defaults, password-first ordering, account/service budgets, lockout/unknown handling, secret redaction and authenticated media tests pass; local lab run verifies one approved credential and two screenshots |
| F — Hardening | Historical observations/diffs, missing observations, follow-up candidates, input/output/process limits, deployment and security documentation | History, DNS pinning/rebinding, redirect refusal, subprocess timeout/output/cancellation and full suite pass; Alembic check reports no pending schema changes |

Commands to reproduce checks and the local smoke are in [README](../README.md) and [smoke tests](smoke-tests.md). The automated suite now includes 77 Pytest tests, 4 Vitest tests and 3 Playwright browser smoke scenarios. The URL-only update passed the full Pytest/Vitest suites, two browser scenarios (IP-target CRUD and URL-only CRUD), and a real URL-only local lab run with 1 host, 1 identified service, 2 endpoints and 0 errors. URL-derived IPs were frozen in the run snapshot while the definition kept an empty explicit target list. Frontend production build and npm audit pass with no reported npm vulnerabilities.

The actual local optional-module smoke completed with 1 host, 1 open TCP port, 1 identified service, 2 endpoints, 1 successful credential validation, 2 screenshots and 0 errors. It assessed only the bundled Docker lab's dynamically assigned address on port 8000. Authentication was required to fetch captured PNGs.

Deliberate MVP limits: HTTP Basic is the only credential adapter; the live transport is polling; off-origin screenshot resources are denied; a stale lease fails closed instead of automatically restarting uncertain work; retention is operator-managed through deliberate scan deletion; inventory persists after deleting run history. No CVE feeds, exploitation, credential generation, RBAC or distributed multi-node orchestration were added. Host egress firewall configuration remains an administrator responsibility; application-level checks do not sandbox a browser exploit.

Future work can add credential adapters, retention scheduling, cached CVE enrichment and approved follow-up execution without changing the split between persistent assets and run observations. None of those future capabilities are represented as implemented.

DNS diagnostics update: API containers now have external DNS connectivity through the edge network without publishing an API host port. Mixed URL lists preserve individual DNS failures as endpoint errors, events and findings while proceeding with resolvable targets. All-unresolvable lists return HTTP 422 with individual URL explanations. DNS failures remain distinct from explicit-scope violations, which still reject launch. Coverage includes both cases and exclusion of failed endpoints from optional credential/screenshot work.
