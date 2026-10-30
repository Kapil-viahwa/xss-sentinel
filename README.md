# XSS Sentinel

XSS Sentinel is an authorized web-application assessment platform focused on mapping application attack surface and validating XSS findings with browser evidence. It is being built incrementally; this first working slice provides a database-backed assessment dashboard and a scope-restricted, read-only crawler. It does not yet send XSS test cases or claim vulnerabilities based on reflection.

## Current capabilities

- Create assessments only after explicitly confirming authorization.
- Persist assessments, discovered resources, and potential input locations in SQLite.
- Crawl same-origin pages within configurable request, depth, and concurrency limits.
- Discover same-origin links, redirects, forms, query parameters, and form fields without submitting forms.
- Avoid duplicate requests to equivalent paths/query-key sets.
- Keep discovered URLs in scope, avoid following external redirects, and redact parameter values in stored URLs.
- Show dashboard metrics from the actual assessment database.

Authentication workflows, JavaScript/AST analysis, active context-aware XSS tests, Playwright execution verification, WAF analysis, and reporting are planned next phases. No scan result is represented as a confirmed vulnerability until browser-based verification is implemented.

## Run locally

Use Python 3.11 or newer:

1. `python -m venv .venv`
2. Activate the virtual environment.
3. `pip install -r requirements.txt`
4. `playwright install chromium` (needed by the browser verification phase).
5. `uvicorn xss_sentinel.main:app --reload`
6. Open `http://127.0.0.1:8000`.

The SQLite database path can be changed with `XSS_SENTINEL_DATABASE_URL`, for example `sqlite:///./sentinel.db`.

## Authorization and scope

Only assess applications for which you have explicit permission. Each assessment is restricted to the exact origin entered at creation; the crawler does not submit forms, execute generated test cases, follow cross-origin redirects, or attempt to bypass WAF controls. Use a dedicated test environment and review the target scope before starting a crawl.
