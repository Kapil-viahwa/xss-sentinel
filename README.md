# XSS Sentinel

XSS Sentinel is an authorized web-application assessment platform focused on mapping attack surface and validating XSS with browser evidence. It is an evolving assessment tool, not a production-complete enterprise scanner; reflection alone is never reported as XSS.

For step-by-step local, Docker, lab, and test setup, see the [installation and setup guide](INSTALLATION.md).

## Current capabilities

- Create assessments only after explicit authorization; crawl the exact target origin with bounded depth, request count, and concurrency.
- Queue crawl jobs and a durable encrypted URL frontier in a shared database for separate worker processes, with leases, heartbeats, retries, pause/resume, and cancellation.
- Configure origin-scoped HTTP form/API login, cookie sessions, bearer/custom headers, and access-token refresh through server environment profiles. Secret values are not stored in the assessment database or returned by APIs.
- Inventory first-party JavaScript routes and JSON inputs, plus low-confidence bounded static taint traces; discovered routes are not requested.
- Discover same-origin pages, redirects, forms, GET parameters, and POST/JSON fields without submitting forms during crawling.
- Run inert reflection probes and explicitly confirmed browser checks for supported reflected and DOM contexts. The isolated browser blocks writes and out-of-scope requests and retains execution screenshots.
- Explicitly submit a POST form/JSON canary for stored-XSS checks, then visit only user-selected same-origin verification pages. A configured callback origin may receive only the exact marker-specific image GET; callback receipt or local execution is recorded as evidence. Submitted field values are not persisted.
- Attribute common WAF/edge fingerprints from headers, cookies, challenge pages, and baseline-to-test status changes; distinguish explicit blocks from generic denials. Add vendor-specific signatures with `XSS_SENTINEL_WAF_SIGNATURES`; fingerprints alone never prove a request was blocked.
- Export findings, evidence, resources, WAF signals, and CVSS estimates as JSON, CSV, HTML, or PDF.
- Score CWE-79 results against version-matched OWASP BenchmarkJava expected results, including coverage and untested cases.

## Run locally

Use Python 3.11 or newer:

1. `python -m venv .venv`
2. Activate the environment.
3. `pip install -r requirements.txt`
4. `playwright install chromium`
5. Generate a frontier-encryption key once, save it securely, and export the same value whenever you start the app: `export XSS_SENTINEL_FRONTIER_KEY='paste-your-saved-key-here'`.
6. Run `python run_local.py` to start the dashboard and worker together with the same environment and database.
7. Open `http://127.0.0.1:8000`. Use only targets you are authorized to assess.

The local default database is SQLite. Run one or more workers against the same database. For multi-host workers, use a shared PostgreSQL database; the included Compose stack supplies one. Frontier URLs and discovery sources are encrypted at rest and require the same stable `XSS_SENTINEL_FRONTIER_KEY` across app and worker instances. Do not rotate this key while jobs are active or pending. Pending and completed frontier items are checkpointed; a crashed worker retries in-flight URLs at least once.

## Authentication profiles

Profiles are JSON in `XSS_SENTINEL_AUTH_PROFILES`. HTTP login and refresh URLs are same-origin paths; credentials remain in the server environment. `format` is `json` or `form`; token paths are dotted JSON paths. A cookie-only login may omit token paths. `{{refresh_token}}` and `{{access_token}}` in refresh fields are replaced from the prior response. For same-origin HTML logins, `browser_flow` supports bounded CSS-selector `fill`, `click`, `wait_for`, dynamic CSRF-header extraction, and RFC 6238 TOTP steps; POST paths must be explicitly listed. Browser login is replayed after a 401 to renew cookies/tokens.

```json
{"staging":{"origins":["https://staging.example.com"],"login":{"url":"/api/login","format":"json","fields":{"username":"<user>","password":"<secret>"},"token_path":"access_token","refresh_token_path":"refresh_token"},"refresh":{"url":"/api/refresh","format":"json","fields":{"refresh_token":"{{refresh_token}}"},"token_path":"access_token","refresh_token_path":"refresh_token"},"callback_origins":["https://oast.example.net"]}}
```

Only configured callback origins can be used. A per-test callback URL must be an absolute endpoint on one of those origins; the browser allows only that exact URL and marker query. For browser-flow MFA, keep TOTP seeds in the server environment profile. Virtual WebAuthn passkeys are supported for authorized test accounts: export a test credential through an authorized Playwright virtual-authenticator enrollment flow and keep its ID, user handle, private key, and public key only in the server environment. The virtual authenticator requires Playwright 1.64 or newer; only a hash of its credential ID and its signature counter are persisted. Physical OS security-key prompts, cross-origin identity providers, CAPTCHA, and arbitrary JavaScript steps are not available in the headless flow. `verify_tls:false` is available only as an explicit profile setting, for example for a local self-signed benchmark; do not use it for normal targets.

Optional custom WAF signatures are a JSON list configured through `XSS_SENTINEL_WAF_SIGNATURES`. Header presence and server/body substrings identify fingerprints; block attribution requires a configured matching block-header value or a strong vendor-specific challenge signature. Example: `[{"vendor":"Example WAF","headers":["x-example-id"],"server_contains":["example-edge"],"body_contains":["blocked by example"],"block_headers":{"x-example-action":["block","challenge"]}}]`. These signatures use literal matches, not regular expressions.

A browser-flow profile uses simple, declarative steps. CSRF meta/header tokens can be captured before submitting; hidden form tokens are submitted by the browser with the form. Only listed same-origin POST paths are allowed during login. Add a `webauthn` object to seed an exported test credential; for example, its `credentials` entry contains `id`, `user_handle`, `private_key`, `public_key`, and optional `sign_count`. See the [Playwright Credentials API](https://playwright.dev/python/docs/api/class-credentials) for virtual-authenticator enrollment/export examples. The private key stays in the server profile and is never returned by the app.

```json
{"ui":{"origins":["https://app.example.com"],"browser_flow":{"url":"/login","post_paths":["/login","/mfa"],"steps":[{"action":"fill","selector":"#username","value":"<user>"},{"action":"fill","selector":"#password","value":"<secret>"},{"action":"csrf_header","selector":"meta[name=csrf-token]","header":"X-CSRF-Token"},{"action":"click","selector":"button[type=submit]"},{"action":"wait_for","selector":"#otp"},{"action":"totp","selector":"#otp","secret":"<base32-seed>"},{"action":"click","selector":"#verify"},{"action":"wait_for","selector":"#account"}],"success_selector":"#account","webauthn":{"rp_id":"app.example.com","credentials":[{"id":"<base64url-id>","user_handle":"<base64url-user-handle>","private_key":"<base64url-pkcs8>","public_key":"<base64url-spki>","sign_count":0}]}}}}
```

## Local vulnerable labs

Start the loopback-only practice targets with `docker compose --profile lab up --build -d`. Juice Shop, DVWA, and WebGoat are on ports 3000, 8081, and 8082. The custom lab on port 8084 covers reflected, DOM, stored XSS, and a local marker callback. Its stored entries are in memory; clear them from the lab wall or restart the container.

For the custom stored/blind workflow, configure a profile allowing both origins, for example `{"local-lab":{"origins":["http://127.0.0.1:8084"],"callback_origins":["http://127.0.0.1:8084"]}}`. Create an authorized assessment for `http://127.0.0.1:8084/`, crawl it, then use “Test stored XSS” on the POST `message` input. Supply required form fields, `/wall` as a verification URL, and `http://127.0.0.1:8084/callback` as the callback endpoint. The workflow submits state-changing data only after two confirmations; it does not automatically clean up target data.

These intentionally vulnerable services are bound to loopback. Do not expose their ports to a network. Stop them with `docker compose --profile lab down`.

## Distributed worker stack

Generate and export `XSS_SENTINEL_FRONTIER_KEY` as shown above, then start the PostgreSQL-backed app and one worker with `docker compose --profile stack up --build -d`; scale workers with `docker compose --profile stack up --scale worker=3 -d`. The database is not published to the host. The Compose database password is for local development only. For production, replace development credentials, protect the web console, and use a separately managed database and secrets service.

## OWASP BenchmarkJava

The optional official OWASP image is large, mutable (`latest`), and self-signed-TLS enabled. Start it loopback-only with `docker compose --profile benchmark up -d`. The Java v1.2 benchmark contains 455 CWE-79 cases among 2,740 total. For a full Compose stack, start `stack` and `benchmark` profiles together and target `https://owasp-benchmark:8443/benchmark/`; for a host-run app, use `https://127.0.0.1:8443/benchmark/`. Configure the matching origin and `verify_tls:false` only for this local benchmark. Set the assessment request limit high enough for the intended coverage (maximum 5,000).

Download the expected-results CSV for the exact BenchmarkJava release/revision from the [official repository](https://github.com/OWASP-Benchmark/BenchmarkJava) (for v1.2, [expectedresults-1.2.csv](https://raw.githubusercontent.com/OWASP-Benchmark/BenchmarkJava/master/expectedresults-1.2.csv)). Do not mix expected results with a different benchmark version. The scoring tool uses successfully crawled test pages, reports unvisited cases separately, and calculates the OWASP score as TPR minus FPR:

`python -m xss_sentinel.benchmark --expected benchmarks/expectedresults-1.2.csv --report xss-sentinel-1.json --output benchmark-score.json`

The OWASP BenchmarkJava project is GPL-2.0; XSS Sentinel does not vendor its fixtures or expected-results CSV. OWASP notes that its cases are simpler than many real applications; use this as a reproducible benchmark, not as a guarantee of real-world accuracy. Stop the optional service with `docker compose --profile benchmark down`.

## Tests and limitations

Run unit and benchmark-scoring tests with `python -m unittest discover -s tests`. CI compiles and runs this suite. This environment cannot run the build or tests, so the latest changes still need verification.

WAF detection is based on known header/body signatures and explicit status changes, not complete vendor coverage or bypass testing. Static JavaScript flow and runtime sink instrumentation remain bounded heuristics. Stored-XSS checks require the operator to know where content will render; blind callbacks only cover pages actually visited by the verifier. There is no automatic cleanup for arbitrary applications. Whole-program JavaScript analysis, broad URL-attribute payload coverage, and production-grade durable crawl-frontier checkpointing remain out of scope.

## Authorization and scope

Only assess applications for which you have explicit permission. Crawling and ordinary browser verification remain same-origin. State-changing XSS tests require explicit per-test confirmation, a user-supplied field set and verification URLs, plus callback confirmation. Callback traffic is limited to the endpoint origin allowlisted in the selected server profile and the exact marker URL. Use disposable accounts and test environments; review scope and cleanup requirements before starting.