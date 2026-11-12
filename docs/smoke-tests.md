# Local smoke verification

These tests target the local HackingBara instance and a bundled operator-owned fixture. They do not scan external targets. Backend automated tests mock scanner binaries and include local HTTP fixtures for proof of authentication, redirect refusal and proxy checks.

## Browser smoke

Start the platform with local HTTP settings and create a dedicated local test account with `hackingbara create-user`. Then:

```sh
cd frontend
npm ci
npx playwright install chromium
export SMOKE_URL=http://127.0.0.1:8080
export SMOKE_USERNAME=your-test-account
read -rs SMOKE_PASSWORD
export SMOKE_PASSWORD
npm run smoke
unset SMOKE_PASSWORD
```

The main test confirms login gating, scan creation, searchable pagination, deletion confirmation, masked credential CRUD and logout. Set `SMOKE_RUN_PATH=/scans/<scan-id>/runs/<run-id>` to enable the second browser test against a completed local lab run with screenshots; it checks the services table and authenticated image thumbnails. It deliberately does not launch a network scan. Failure traces are written under `frontend/test-results` and can contain assessment data; do not publish them.

## Complete local scanner pipeline

Start the explicitly owned fixture, which has no published host port:

```sh
docker compose -f compose.yaml -f compose.lab.yaml up -d lab
.venv/bin/python scripts/smoke_lab.py --username your-test-account
```

The script obtains the fixture's numeric address from Docker, approves exactly that IP and port 8000, creates a definition and run, waits for Celery execution, and asserts that a service is recorded. It prints the results URL. It does not accept arbitrary target addresses.

For optional modules, set `EYEWITNESS_ENABLED=true` in your local `.env`, recreate the worker, then run:

```sh
docker compose up -d worker
.venv/bin/python scripts/smoke_lab.py --username your-test-account --screenshots --credentials
```

This uses only the fixture's `lab` / `local-fixture-only` Basic account. These are fixture credentials, never platform credentials. The adapter must see the Basic challenge, obey the default 30-second delay, and record one verified credential reference. EyeWitness captures the fixture through its scope proxy. The script verifies authenticated PNG access and rejects unauthenticated access. Definitions and evidence remain for inspection; delete those completed definitions from Scans when finished, then remove their unreferenced fixture credential entries. Stop the lab with `docker compose -f compose.yaml -f compose.lab.yaml stop lab`.

To inspect redirect policy, the fixture exposes `/redirect`, which points to the documentation address `203.0.113.1` outside its approved scope. Credential validation refuses to follow it. Screenshot proxy requests to that origin are denied. Unit tests exercise this policy without contacting that address.

## Deployment checks

```sh
docker compose ps --all
docker compose logs migrate
docker compose exec worker rustscan --version
docker compose exec worker nmap --version
```

The migration job should exit 0, API/frontend/PostgreSQL/Redis health checks should pass, and worker/scheduler should remain running. Do not use `docker compose down -v` against a deployment with data to retain.

## API address changes behind Nginx

The frontend resolves the `api` service through Docker DNS every five seconds instead of retaining its startup IP. Its health check also traverses the proxy and API database health endpoint.

To reproduce the DNS recovery regression after building the default Compose project:

```sh
docker compose build frontend
python3 scripts/test_proxy_dns.py --image hackingbara-frontend
```

The test creates an isolated temporary Docker network with two owned HTTP fixtures on distinct IPs. It starts the proxy against the first fixture, replaces the DNS target with the second, and verifies recovery without restarting Nginx. It also checks that the API path and query string survive proxying. All temporary containers and the network are removed afterwards. No application data or user credentials are accessed. The `python:3.12-alpine` fixture image is downloaded if absent. Use your project's frontend image name if overriding the default Compose project name.
