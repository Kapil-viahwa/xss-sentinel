# Installation and setup guide

This guide covers a local Python installation, the Docker Compose stack, optional practice labs, and running the test suite. Use XSS Sentinel only against applications you are explicitly authorized to assess. The dashboard has no built-in user authentication; keep it on your own machine or place it behind suitable access controls before any network exposure.

## Prerequisites

For a local Python setup:

- Python 3.11 or newer and `pip`.
- Git, if you are cloning the repository.
- A supported operating system for Playwright Chromium. On Linux, system browser dependencies may need installation with `playwright install --with-deps chromium`.

For the containerized setup:

- Docker Engine and Docker Compose v2 (`docker compose`).

The web dashboard uses port 8000 by default. Optional labs use ports 3000, 8081, 8082, 8084, and 9090; the optional OWASP benchmark uses 8443. Compose binds these ports to `127.0.0.1`.

## Option 1: Run locally with Python

From the repository root, create and activate a virtual environment.

macOS/Linux:

```sh
python3 -m venv .venv
source .venv/bin/activate
```

Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the Python dependencies and Chromium:

```sh
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
playwright install chromium
```

If Chromium reports missing Linux system packages, install them with `playwright install --with-deps chromium` (this may require administrator privileges).

### Configure the persistent frontier key

The crawl frontier is encrypted at rest. Generate a Fernet key once:

```sh
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Set the generated value as `XSS_SENTINEL_FRONTIER_KEY` in both the app and worker environments. For example, in macOS/Linux:

```sh
export XSS_SENTINEL_FRONTIER_KEY='paste-the-generated-key-here'
```

In Windows PowerShell:

```powershell
$env:XSS_SENTINEL_FRONTIER_KEY = 'paste-the-generated-key-here'
```

Use the same stable key for every app and worker using the same database. Save it in a secret manager or other protected location; do not commit it. Do not rotate it while jobs or frontier records remain in the database, because they will no longer be decryptable with a different key.

### Optional authentication and WAF configuration

Authentication profiles are supplied through the `XSS_SENTINEL_AUTH_PROFILES` environment variable as JSON. The selected profile must allowlist the exact target origin. Keep passwords, tokens, TOTP seeds, and virtual-passkey private keys in protected environment configuration, never in source control or the assessment database. The profile formats and browser-login examples are documented in the [README](README.md#authentication-profiles).

Optional literal WAF signatures are supplied as JSON through `XSS_SENTINEL_WAF_SIGNATURES`. See the WAF example in the README. Do not put secrets in WAF signatures.

### Start the app and worker

The default database is a SQLite file named `xss_sentinel.db` in the repository directory. Stop any older app/worker processes first. For the simplest local setup, activate the virtual environment, set the saved frontier key and any required profile variables once in the current shell, then run `python run_local.py`. It starts the app, waits for its health endpoint, and only then starts the worker; both inherit the same working directory, database URL, key, and profile settings. Press Ctrl+C to stop both. The launcher refuses to start if port 8000 is already occupied, and requires an activated `.venv` plus a valid `XSS_SENTINEL_FRONTIER_KEY`.

For manual operation, open two terminals in the repository, activate the same virtual environment, and set the same database URL, frontier key, and any required auth-profile environment variables in both.

Terminal 1 — start the web app:

```sh
uvicorn xss_sentinel.main:app --reload
```

Terminal 2 — start a crawl worker:

```sh
python -m xss_sentinel.worker
```

Open <http://127.0.0.1:8000>. Create an assessment only for an authorized target, confirm authorization, set sensible crawl limits, and select a server-configured auth profile if needed. Start the crawl from the assessment row. The worker must remain running to process queued jobs. A failed assessment stays failed until you explicitly start a new crawl.

If a crawl fails, inspect the worker terminal for its exception traceback, then check the assessment API with `curl -sS http://127.0.0.1:8000/api/assessments`. `scope_error` means the saved target failed URL-scope validation; `setup_error` means another setup/configuration value was rejected; `frontier_key_error` means the saved frontier cannot be decrypted with the current key. Do not share logs or screenshots containing keys, cookies, tokens, or sensitive target data.

To use a non-default database, set `XSS_SENTINEL_DATABASE_URL` identically for the app and worker. For example, a PostgreSQL URL is `postgresql+psycopg://USER:PASSWORD@HOST:5432/DATABASE`; configure its credentials securely rather than copying real passwords into shell history.

## Option 2: Run the app stack with Docker Compose

The `stack` profile starts PostgreSQL, the web app, and one worker. Generate a frontier key as above, then export it in the shell that runs Compose:

```sh
export XSS_SENTINEL_FRONTIER_KEY='paste-the-generated-key-here'
docker compose --profile stack up --build -d
```

On Windows PowerShell, set it with `$env:XSS_SENTINEL_FRONTIER_KEY = 'paste-the-generated-key-here'` before running Compose. To scale to three workers:

```sh
docker compose --profile stack up --build -d --scale worker=3
```

Check service state and logs with:

```sh
docker compose --profile stack ps
docker compose --profile stack logs -f app worker
```

The dashboard is at <http://127.0.0.1:8000>. Compose passes `XSS_SENTINEL_AUTH_PROFILES` and `XSS_SENTINEL_WAF_SIGNATURES` through from the host environment as well. For repeatable local configuration, Compose can read a root `.env` file; it is ignored by Git. Restrict its permissions and never commit it. The Compose database password is a development-only default and must not be reused in production.

Stop the stack with:

```sh
docker compose --profile stack down
```

The named PostgreSQL volume is retained by this command. Adding `-v` removes the database volume and its data; use that only when you intend to delete it.

## Optional practice labs

Start the intentionally vulnerable, loopback-only labs with:

```sh
docker compose --profile lab up --build -d
```

The Juice Shop, DVWA, WebGoat, and custom lab are available at `http://127.0.0.1:3000`, `http://127.0.0.1:8081`, `http://127.0.0.1:8082`, and `http://127.0.0.1:8084`. The custom lab includes reflected, DOM, stored-message, and local callback examples. Do not expose these lab ports to a network.

To practice stored-XSS checks with the custom lab, configure an auth profile allowing `http://127.0.0.1:8084` as both the target origin and callback origin, create and crawl an authorized assessment for `http://127.0.0.1:8084/`, then use the stored-XSS action on its POST `message` input. Use `/wall` as the verification page and the lab's `/callback` endpoint when prompted. Stored-XSS checks submit state-changing data and require confirmation; they do not automatically remove submitted data.

Stop the labs with:

```sh
docker compose --profile lab down
```

## Optional OWASP BenchmarkJava service

Start the benchmark container, which is bound to loopback on port 8443:

```sh
docker compose --profile benchmark up -d
```

For a host-run app, target `https://127.0.0.1:8443/benchmark/`, allowlist the matching origin, and set `verify_tls:false` only in the profile used for this local self-signed-TLS benchmark. To run the benchmark with the Compose app stack, enable both profiles together:

```sh
docker compose --profile stack --profile benchmark up --build -d
```

The app can then target `https://owasp-benchmark:8443/benchmark/` on the shared Compose network; allowlist that exact origin in its auth profile. Download expected-results CSVs from the official OWASP BenchmarkJava repository for the exact version being tested; do not commit or mix versioned expected results. Scoring instructions are in the README.

Stop the benchmark service with:

```sh
docker compose --profile benchmark down
```

## Run the tests

With the virtual environment active and dependencies installed, run:

```sh
python -m compileall -q xss_sentinel tests
python -m unittest discover -s tests
```

The same checks run in GitHub Actions on pushes and pull requests. Browser-specific behavior may additionally require installing Chromium with Playwright.

## Security and operating notes

- Keep the dashboard private. This project is an assessment tool, not a production-hardened, multi-user service.
- Assess only explicitly authorized targets. Crawling stays within the configured origin; review scope and rate limits before starting.
- Use disposable accounts and test environments. State-changing stored-XSS submissions can persist on the target and require explicit confirmation.
- Keep environment profiles, API credentials, TOTP seeds, passkey private keys, and the frontier encryption key out of source control.
- App and worker must use the same database, auth-profile configuration, and stable frontier key.
- Back up the database and protect screenshots and reports as potentially sensitive assessment data.
