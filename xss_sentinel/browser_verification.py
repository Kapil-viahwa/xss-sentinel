import asyncio
import secrets
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright

from .auth_profiles import browser_auth_profile, callback_url_allowed
from .models import InjectionPoint


SUPPORTED_CONTEXTS = {"html_text", "html_attribute", "javascript_text", "html_comment", "css_text", "dom_source"}


def _origin(url: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        return parsed.scheme.lower(), parsed.hostname.lower(), parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError:
        return None


def _parameter_url(url: str, name: str, value: str) -> str:
    parsed = urlsplit(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    result = []
    replaced = False
    for key, old_value in query:
        if key == name:
            result.append((key, value))
            replaced = True
        else:
            result.append((key, old_value))
    if not replaced:
        result.append((name, value))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(result), ""))


def _payloads(context: str, marker: str, callback_url: str | None = None) -> list[str]:
    callback = f"window.__xssSentinel('{marker}')"
    if callback_url:
        callback += f";(new Image()).src='{quote(callback_url, safe=':/?&=%')}'"
    if context in {"html_text", "dom_source"}:
        return [f'<svg onload="{callback}"></svg>']
    if context == "html_attribute":
        return [
            f'"><svg onload="{callback}"></svg>',
            f"'><svg onload=\"{callback}\"></svg>",
        ]
    if context == "javascript_text":
        return [
            f'";{callback};//',
            f"';{callback};//",
        ]
    if context == "html_comment":
        return [f"--><svg onload=\"{callback}\"></svg><!--"]
    if context == "css_text":
        return [f"</style><svg onload=\"{callback}\"></svg><style>"]
    return []


async def _attempt(browser, url: str, allowed_origin: tuple[str, str, int], marker: str,
                   auth_profile: dict, cookie_url: str, callback_url: str | None = None) -> dict:
    context_options = {"service_workers": "block", "ignore_https_errors": not auth_profile.get("verify_tls", True)}
    if auth_profile.get("headers"):
        context_options["extra_http_headers"] = auth_profile["headers"]
    context = await browser.new_context(**context_options)
    if auth_profile.get("cookies"):
        await context.add_cookies([{"name": name, "value": value, "url": cookie_url}
                                   for name, value in auth_profile["cookies"].items()])
    console_errors = 0
    page_errors = 0
    blocked_requests = 0
    callback_request_count = 0
    callback_response_statuses = []
    main_navigation_seen = False
    page = None

    async def restrict_requests(route):
        nonlocal blocked_requests, callback_request_count, main_navigation_seen
        request = route.request
        if (callback_url and request.url == callback_url and request.method == "GET"
                and request.resource_type == "image"):
            callback_request_count += 1
            await route.continue_()
            return
        allowed_resource_types = {"document", "script", "stylesheet", "font"}
        if (_origin(request.url) != allowed_origin or request.method != "GET"
                or request.resource_type not in allowed_resource_types):
            blocked_requests += 1
            await route.abort()
            return
        if request.is_navigation_request():
            if page is None or request.frame != page.main_frame:
                blocked_requests += 1
                await route.abort()
                return
            if request.redirected_from is None:
                if main_navigation_seen:
                    blocked_requests += 1
                    await route.abort()
                    return
                main_navigation_seen = True
        await route.continue_()

    await context.route("**/*", restrict_requests)
    await context.add_init_script(script="""
        Object.defineProperty(window, "__xssSentinelExecutions", {value: [], configurable: false});
        Object.defineProperty(window, "__xssSentinelSinkHits", {value: [], configurable: false});
        Object.defineProperty(window, "__xssSentinel", {
            value: function(marker) { window.__xssSentinelExecutions.push(String(marker)); },
            configurable: false,
            writable: false
        });
        const recordSentinelSink = (name, value) => {
            if (String(value).includes("XSSSENTINEL")) window.__xssSentinelSinkHits.push(name);
        };
        for (const property of ["innerHTML", "outerHTML"]) {
            try {
                const descriptor = Object.getOwnPropertyDescriptor(Element.prototype, property);
                if (!descriptor || !descriptor.set || !descriptor.get || !descriptor.configurable) continue;
                Object.defineProperty(Element.prototype, property, {
                    configurable: descriptor.configurable,
                    enumerable: descriptor.enumerable,
                    get: descriptor.get,
                    set(value) { recordSentinelSink(property, value); return descriptor.set.call(this, value); }
                });
            } catch (_error) {}
        }
        try {
            const insertAdjacentHTML = Element.prototype.insertAdjacentHTML;
            Element.prototype.insertAdjacentHTML = function(position, value) {
                recordSentinelSink("insertAdjacentHTML", value);
                return insertAdjacentHTML.call(this, position, value);
            };
        } catch (_error) {}
        for (const method of ["write", "writeln"]) {
            try {
                const original = Document.prototype[method];
                Document.prototype[method] = function(...values) {
                    values.forEach((value) => recordSentinelSink(`document.${method}`, value));
                    return original.apply(this, values);
                };
            } catch (_error) {}
        }
    """)
    page = await context.new_page()

    def on_console(message):
        nonlocal console_errors
        if message.type == "error":
            console_errors += 1

    def on_page_error(_error):
        nonlocal page_errors
        page_errors += 1

    page.on("console", on_console)
    page.on("pageerror", on_page_error)
    if callback_url:
        page.on("response", lambda response: callback_response_statuses.append(response.status)
               if response.url == callback_url else None)
    page.on("dialog", lambda dialog: asyncio.create_task(dialog.dismiss()))
    response_status = None
    executions = []
    dom_evidence = "marker_not_executed"
    screenshot_data = None
    try:
        response = await page.goto(url, wait_until="domcontentloaded", timeout=15000)
        response_status = response.status if response else None
        await page.wait_for_timeout(350)
        executions = await page.evaluate("window.__xssSentinelExecutions || []")
        sink_hits = await page.evaluate("Array.from(new Set(window.__xssSentinelSinkHits || []))")
        if marker in executions:
            dom_evidence = await page.evaluate("""(marker) => {
                const nodes = document.querySelectorAll("svg[onload], script");
                for (const node of nodes) {
                    if ((node.outerHTML || "").includes(marker) || (node.textContent || "").includes(marker)) {
                        return `${node.tagName.toLowerCase()} execution marker observed`;
                    }
                }
                return "instrumented execution marker observed";
            }""", marker)
            screenshot_data = await page.screenshot(type="png", full_page=False, timeout=5000)
    except (PlaywrightTimeoutError, PlaywrightError):
        pass
    finally:
        await context.close()

    return {
        "response_status": response_status,
        "executed": marker in executions,
        "dom_evidence": dom_evidence if dom_evidence != "marker_not_executed" else (
            "marker_reached_sink:" + ",".join(sink_hits[:5]) if "sink_hits" in locals() and sink_hits else dom_evidence
        ),
        "console_error_count": console_errors,
        "page_error_count": page_errors,
        "blocked_request_count": blocked_requests,
        "callback_request_count": callback_request_count,
        "callback_response_status": callback_response_statuses[-1] if callback_response_statuses else None,
        "screenshot_data": screenshot_data,
    }


async def verify_browser_execution(point: InjectionPoint, target_url: str, auth_profile: dict | None = None,
                                   mode: str = "reflected") -> dict:
    if point.method.upper() != "GET" or point.location != "query" or point.input_type:
        raise ValueError("Browser execution checks are currently limited to URL-based GET query inputs.")
    if point.original_value == "<redacted>":
        raise ValueError("This input is redacted and cannot be safely replayed.")
    if mode not in {"reflected", "dom"}:
        raise ValueError("Unsupported browser verification mode.")
    if mode == "reflected" and point.context not in SUPPORTED_CONTEXTS - {"dom_source"}:
        raise ValueError("Run a reflection check first; no supported browser context was identified.")
    test_context = point.context if mode == "reflected" else "dom_source"
    allowed_origin = _origin(target_url)
    if _origin(point.url) is None or _origin(point.url) != allowed_origin:
        raise ValueError("Input URL is outside the assessment origin.")

    marker = f"XSSSENTINEL{point.assessment_id}{point.id}{secrets.token_hex(6)}"
    payloads = _payloads(test_context, marker)
    if not payloads:
        raise ValueError("No safe execution marker is available for this context.")
    baseline_url = _parameter_url(point.url, point.parameter_name, "")
    profile = await browser_auth_profile(auth_profile, target_url)
    parsed_target = urlsplit(target_url)
    cookie_url = urlunsplit((parsed_target.scheme, parsed_target.netloc, "/", "", ""))
    timeout_result = {
        "marker": marker,
        "result": "inconclusive",
        "context": test_context,
        "baseline_status": None,
        "response_status": None,
        "dom_evidence": "browser_unavailable",
        "evidence": "Browser verification could not start; no vulnerability conclusion was made.",
        "console_error_count": 0,
        "page_error_count": 0,
        "screenshot_data": None,
    }
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            try:
                baseline = await _attempt(browser, baseline_url, allowed_origin, marker, profile, cookie_url)
                timeout_result["baseline_status"] = baseline["response_status"]
                if baseline["response_status"] is None or baseline["response_status"] >= 400 or 300 <= baseline["response_status"] < 400:
                    timeout_result["evidence"] = f"Baseline browser navigation returned HTTP {baseline['response_status']}; execution test was not run."
                    return timeout_result
                for payload in payloads:
                    test_url = _parameter_url(point.url, point.parameter_name, payload)
                    attempt = await _attempt(browser, test_url, allowed_origin, marker, profile, cookie_url)
                    timeout_result["response_status"] = attempt["response_status"]
                    timeout_result["console_error_count"] += attempt["console_error_count"]
                    timeout_result["page_error_count"] += attempt["page_error_count"]
                    if attempt["dom_evidence"].startswith("marker_reached_sink:"):
                        timeout_result["dom_evidence"] = attempt["dom_evidence"]
                    if attempt["executed"]:
                        timeout_result.update({
                            "result": "confirmed",
                            "dom_evidence": attempt["dom_evidence"],
                            "evidence": "The unique in-page execution marker ran in an isolated browser context; network writes and out-of-scope requests were blocked.",
                            "screenshot_data": attempt["screenshot_data"],
                        })
                        return timeout_result
                    if attempt["response_status"] is None or attempt["response_status"] < 200 or attempt["response_status"] >= 400:
                        timeout_result["evidence"] = f"Controlled browser request returned HTTP {attempt['response_status']}; security-control or application interference is inconclusive."
                        return timeout_result
            finally:
                await browser.close()
    except PlaywrightError as exc:
        timeout_result["evidence"] = f"Browser verification unavailable ({type(exc).__name__}); no vulnerability conclusion was made."
        return timeout_result

    timeout_result["result"] = "not_confirmed"
    if not timeout_result["dom_evidence"].startswith("marker_reached_sink:"):
        timeout_result["dom_evidence"] = "execution_marker_not_observed"
    timeout_result["evidence"] = "No execution marker was observed for the supported context-specific checks; this does not establish that the input is safe."
    return timeout_result



async def verify_stored_execution(verification_urls: list[str], target_url: str, marker: str,
                                  auth_profile: dict | None, callback_url: str) -> dict:
    allowed_origin = _origin(target_url)
    if allowed_origin is None or any(_origin(url) != allowed_origin for url in verification_urls):
        raise ValueError("Stored-XSS verification URLs must remain within the assessment origin.")
    profile = await browser_auth_profile(auth_profile, target_url)
    parsed_target = urlsplit(target_url)
    cookie_url = urlunsplit((parsed_target.scheme, parsed_target.netloc, "/", "", ""))
    result = {
        "result": "not_confirmed",
        "response_status": None,
        "callback_request_count": 0,
        "callback_response_status": None,
        "screenshot_data": None,
        "evidence": "The stored marker was not observed executing on the selected same-origin verification pages.",
    }
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            try:
                for url in verification_urls:
                    attempt = await _attempt(browser, url, allowed_origin, marker, profile, cookie_url, callback_url)
                    result["response_status"] = attempt["response_status"]
                    result["callback_request_count"] += attempt["callback_request_count"]
                    if attempt["callback_response_status"] is not None:
                        result["callback_response_status"] = attempt["callback_response_status"]
                    callback_confirmed = attempt["callback_response_status"] is not None and 200 <= attempt["callback_response_status"] < 300
                    if attempt["executed"] or callback_confirmed:
                        result.update({
                            "result": "blind_confirmed" if callback_confirmed else "stored_confirmed",
                            "screenshot_data": attempt["screenshot_data"],
                            "evidence": "A unique stored canary executed on a user-specified same-origin page. The configured callback endpoint was permitted as a single GET image beacon; unrelated external requests remained blocked."
                            if callback_confirmed else "The unique in-page execution marker ran on a user-specified same-origin page; unrelated external requests remained blocked.",
                        })
                        return result
            finally:
                await browser.close()
    except PlaywrightError as exc:
        result["result"] = "inconclusive"
        result["evidence"] = f"Stored-XSS browser check unavailable ({type(exc).__name__}); no vulnerability conclusion was made."
    return result
