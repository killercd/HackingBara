<p align="center">
  <img src="imgs/capbar.png" alt="HackingBara cyberpunk capybara mascot" width="140" />
  <br />
  <img src="imgs/hackingbara-wordmark.svg" alt="HackingBara" width="420" />
</p>
<p align="center">
  <strong>Discover. Enumerate. Observe.</strong><br />
  <a href="imgs/hackingbara-logo.svg">Full project logo</a>
</p>

# HackingBara

Self-hosted network assessment workspace built with FastAPI, Celery, PostgreSQL and Vue 3. Use only on systems and accounts you own or are explicitly authorized to assess. Every run requires approval of its exact scope. All users have the same capabilities.

## Start

Prerequisites: Docker Engine and Compose v2, approximately 4 GB RAM, internet access for the first build. RustScan is compiled in a build stage; the initial worker build takes several minutes. Linux containers are required.

```sh
python3 scripts/setup.py --local-http

docker compose up --build -d
docker compose exec api hackingbara create-user operator
```

The setup command creates `.env` and generates missing secrets without printing them. Re-running it preserves existing passwords and the credential key; if `.env` lost its password while PostgreSQL still has a container, setup recovers that container configuration. Never regenerate `secrets/credential_key` after storing credentials.

No account or default password is shipped. The bootstrap command prompts twice and requires at least 12 characters. Run it again with another username to add an equally capable account. Alembic runs once before API, worker and scheduler start. Database/Redis ports are never published. The frontend listens only on `127.0.0.1:8080` by default.

For local HTTP development, set `PUBLIC_ORIGIN=http://127.0.0.1:8080` and `SECURE_COOKIES=false` before starting, then open that exact origin. For deployment, run `python3 scripts/setup.py` without `--local-http`, configure `PUBLIC_ORIGIN` and `SECURE_COOKIES=true` in `.env`, terminate TLS at your reverse proxy, forward traffic to the loopback listener, and set `PUBLIC_ORIGIN` to the exact HTTPS origin (no trailing slash). Configure HSTS at the TLS proxy. Do not trust arbitrary forwarded client-IP headers. The encryption key must be backed up separately from PostgreSQL; losing it makes stored secrets unreadable.

## Features and defaults

- Cookie authentication, Argon2id passwords, expiring database sessions, CSRF and login throttling; authenticated API docs at `/api/v1/docs`.
- Scan and encrypted credential CRUD; every collection uses server-side pagination, deterministic sorting and search. Default page size 25, maximum 100.
- Immutable run snapshots and credential references; one active run per definition. Durable database outbox, Celery jobs, independent scheduler, bounded queue and concurrent runs, worker leases.
- Scan modes: **Network** (default) and **Subdomain**. Subdomain scans use Gobuster DNS against a base domain and an editable common/custom wordlist, including multipart `.txt` uploads (up to 3 MiB, with no limit on the number of relative names; file contents stay out of the textarea). Discovered names and IPv4/IPv6 addresses appear in the Subdomains results tab. DNS scans do not launch port scans or optional HTTP modules.
- RustScan TCP discovery, then Nmap XML service identification on **only discovered ports**. Connect scans need no raw socket capability. IPv4/IPv6 supported by adapters. No UDP, NSE or exploits.
- Configurable per-request timeout and maximum concurrency for DNS and Network scans; Network also supports Nmap timing T0–T5. No total scanner duration limit; DNS results contain only successfully resolved names and appear during execution, with progress counted against the wordlist size.
- Cooperative pause finishes the active tool, persists its results and pauses before the next item. Stop terminates the entire process group, waits, then confirms `stopped`. A guardian kills scanner/browser descendants after worker death. Partial results remain available.
- Live results refresh by polling every 2.5–5 seconds. Hosts, ports, services, endpoints, credential attempts, screenshots, findings, events, targets, checkpoints and follow-up candidates have paginated APIs. No SSE is required for the polling implementation.
- Credential validation and EyeWitness are off by default. Only explicitly approved HTTP Basic endpoints are supported. Approved pairs are grouped by password, then username; no unapproved combinations are generated. Default delay is 30 seconds; maximum 2 attempts per username per run and 10 per service. Defensive responses and uncertain outcomes abort further attempts against that service. An attempt is durably marked `unknown` before network I/O and never automatically retried.
- EyeWitness is installed in the worker image; enable administrator setting `EYEWITNESS_ENABLED=true` as well as the scan toggle. A patched browser uses a local proxy that pins checked IPs and restricts traffic to the approved origin; off-origin resources and redirects are denied. Screenshots are private, with generated thumbnails.
- The default empty port selection means TCP `1-1024`. Maximum 256 addresses and 10,000 ports per run. All CIDR addresses count toward the limit, including IPv4 network/broadcast addresses. Duplicate/overlapping networks and ports are rejected; normalized duplicate URLs are deduplicated. Supply IP/CIDR targets, bare hostnames, HTTP(S) URLs, or a combination; at least one entry is required. Starting a run immediately queues it and returns its ID. The worker resolves and deduplicates hostname/URL IPv4/IPv6 addresses during the scope stage, enforces the target limit, and finalizes the effective snapshot before any port scan. Discovery uses those IPs and the configured port selection; explicit URLs also reach endpoint processing. When IP targets are provided, every URL DNS answer must remain in that explicit scope. Later DNS changes and redirects never expand a run scope. Individual DNS failures are skipped and appear as endpoint errors, events and findings; the other resolvable targets continue. If no hostname/URL resolves and no explicit IP target is supplied, the run fails in the scope stage with DNS diagnostics. Scope violations and resolved-address limits also fail this stage before any scanner starts.
- Deleting a scan deletes all its runs, observations and private evidence; active/paused runs must be stopped first. Persistent host/service/endpoint inventory remains for cross-run identity. Credentials referenced by a definition or run cannot be changed or deleted; create a new entry for rotated secrets. Secrets are never revealed through the UI or API.
- Reruns retain observations and identify new/changed/unchanged/no-longer-observed services. The latter is an observation, not proof of disappearance. Follow-up candidates remain pending; they never launch work. CVE fields are reserved, without feed ingestion or fabricated matches.

## Development and tests

Python 3.12+ and Node 22.19+:

```sh
python3 -m venv .venv
.venv/bin/pip install -c backend/requirements.lock './backend[test]'
.venv/bin/pytest backend/tests -q
.venv/bin/ruff check backend
.venv/bin/ruff format --check backend
npm --prefix frontend ci
npm --prefix frontend test
npm --prefix frontend run build
npm --prefix frontend audit
```

Tests use SQLite for fast portable coverage and mock external scanners. They cover authentication, CSRF, secret redaction, CRUD, scope validation, DNS rebinding checks, pagination, state conflicts, subprocess bounds, checkpoint resume, orphan recovery, history, optional-module defaults, credential ordering, attempt budgets and defensive aborts. Deployment exercises the actual PostgreSQL migration and foreign keys. See [smoke tests](docs/smoke-tests.md) for browser and operator-owned local lab verification. CI runs backend checks and frontend tests/build/audit.

For local API development, configure `DATABASE_URL`, `REDIS_URL`, `SECRET_KEY_FILE`, `PUBLIC_ORIGIN` and `SECURE_COOKIES`, then run `alembic upgrade head` from `backend`, `uvicorn app.main:app`, `celery -A app.tasks:celery worker --concurrency=2`, and `python -m app.scheduler`. Vite proxies `/api` to port 8000. Set origin to the Vite origin when using this arrangement.

## Operations and limitations

See [architecture](docs/architecture.md), [security and threat model](docs/security.md), and [scanner adapters](docs/scanner-adapters.md).

Run `docker compose logs api worker scheduler` for process health and use run events for sanitized scanner activity. `docker compose down` retains the database and evidence volumes; avoid `down -v` unless intentionally removing all data. Back up PostgreSQL and evidence together, with the credential key stored separately. There is no automated retention job: deliberately delete completed definitions through the UI/API to remove their history/evidence, and monitor database/evidence disk usage. Only PNG screenshots are retained from EyeWitness; raw HTML reports are deleted with the per-item temporary directory.

Keep one scheduler and one worker service with two child processes in the default deployment. `MAX_CONCURRENT_RUNS` must not exceed actual worker capacity. Multi-node orchestration and automatic CVE re-evaluation are outside the MVP. A stale lease fails the run conservatively instead of automatically repeating uncertain work. Start another explicitly approved run to retry failed items. Redis is ephemeral: the independent scheduler republishes queued database rows after broker recovery. Application scope checks do not replace a worker firewall when assessing hostile servers or browser content. See the security document before enabling screenshots.


Network scans accept entries such as `web.example.com` without a scheme in the Hostnames or HTTP(S) URLs field. Bare hostnames authorize DNS resolution and scanning, without creating an assumed HTTP endpoint. Nmap selects the HTTP/HTTPS ports; with screenshots enabled, EyeWitness attempts a separate capture for every identified web port, retaining the original hostname for Host/SNI and pinning the address where the service was observed. For example, selecting TCP ports `80,443,8080` and discovering HTTP, TLS HTTP, and HTTP on those ports generates `http://web.example.com/`, `https://web.example.com/`, and `http://web.example.com:8080/`. The default TCP range is still `1-1024`; add `8080` explicitly. Explicit URLs and paths remain supported; scheme-less entries with a port/path are normalized to HTTP (HTTPS for explicit port 443).


From a DNS run's results, **Create Network scan** opens a new Network configuration with all discovered subdomain names prefilled, regardless of table filters or pagination. This also works with partial results from running/stopped scans. Review ports, timing and optional screenshots, then save the new definition and launch it separately. The draft link survives page reloads. DNS names remain hostnames, preserving HTTP virtual hosting and TLS SNI; IP scope is resolved and authorized when the new Network run starts.
