import secrets
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

import httpx

from .auth_profiles import AuthFlow, callback_url_allowed
from .browser_verification import _payloads, _origin, verify_stored_execution
from .models import InjectionPoint


SENSITIVE_FIELD_PARTS = ("password", "passwd", "token", "secret", "authorization", "auth", "csrf", "xsrf", "api_key", "apikey")
SUPPORTED_CONTEXTS = {"html_text", "html_attribute", "javascript_text", "html_comment", "css_text"}


def _set_nested_value(target: dict, name: str, value: str) -> None:
    parts = name.split(".")
    if any(not part or len(part) > 120 for part in parts):
        raise ValueError("The selected JSON input path is invalid.")
    current = target
    for part in parts[:-1]:
        next_value = current.get(part)
        if not isinstance(next_value, dict):
            next_value = {}
            current[part] = next_value
        current = next_value
    current[parts[-1]] = value


def _same_origin_urls(urls: list[str], target_url: str) -> list[str]:
    if not isinstance(urls, list) or not 1 <= len(urls) <= 5:
        raise ValueError("Select between one and five same-origin pages to check for stored output.")
    allowed = _origin(target_url)
    checked = []
    for url in urls:
        if not isinstance(url, str) or len(url) > 2048 or _origin(url) != allowed:
            raise ValueError("Every stored-XSS verification URL must be an absolute URL within the assessment origin.")
        checked.append(url)
    return list(dict.fromkeys(checked))


def _callback_endpoint(callback_url: str, marker: str, profile: dict) -> tuple[str, str]:
    if (not isinstance(callback_url, str) or len(callback_url) > 2048
            or not callback_url_allowed(profile, callback_url)):
        raise ValueError("Callback URL origin is not allowlisted by the selected server profile.")
    parsed = urlsplit(callback_url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment):
        raise ValueError("Callback URL must be an absolute HTTP(S) endpoint without credentials, query, or fragment.")
    endpoint = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode({"xs": marker}), ""))
    safe_endpoint = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    return endpoint, safe_endpoint


async def run_stored_xss_test(point: InjectionPoint, target_url: str, auth_profile: dict | None,
                              fields: dict[str, str], verification_urls: list[str], callback_url: str,
                              body_format: str = "form", context: str = "html_text") -> dict:
    if point.method.upper() != "POST" or point.location not in {"body", "json"}:
        raise ValueError("State-changing stored-XSS checks are limited to discovered POST body/JSON inputs.")
    if any(part in point.parameter_name.lower() for part in SENSITIVE_FIELD_PARTS):
        raise ValueError("Credential and security-token fields cannot be used for stored-XSS tests.")
    if body_format not in {"form", "json"} or context not in SUPPORTED_CONTEXTS:
        raise ValueError("Unsupported body format or output context.")
    if point.location == "json" and body_format != "json":
        raise ValueError("JSON request inputs require the JSON body format.")
    if point.location == "body" and body_format != "form":
        raise ValueError("HTML form body inputs require form encoding.")
    if not isinstance(fields, dict) or len(fields) > 32:
        raise ValueError("Provide at most 32 form or JSON fields.")
    safe_fields = {}
    for name, value in fields.items():
        if not isinstance(name, str) or not name or len(name) > 500 or not isinstance(value, str) or len(value) > 4096:
            raise ValueError("Form and JSON values must be bounded strings.")
        safe_fields[name] = value
    if point.parameter_name not in safe_fields:
        raise ValueError("The supplied fields must include the selected injection-point parameter.")
    if "<value>" in point.url or "<redacted>" in point.url:
        raise ValueError("This form action contains redacted query values and cannot be safely replayed.")
    verify_urls = _same_origin_urls(verification_urls, target_url)
    profile = auth_profile or {"headers": {}, "cookies": {}, "callback_origins": [], "verify_tls": True}
    marker = f"XSSSENTINEL{point.assessment_id}{point.id}{secrets.token_hex(6)}"
    callback_endpoint, safe_callback_endpoint = _callback_endpoint(callback_url, marker, profile)
    payload = _payloads(context, marker, callback_endpoint)[0]
    if body_format == "form":
        safe_fields[point.parameter_name] = payload
    else:
        nested_fields = {}
        for name, value in safe_fields.items():
            _set_nested_value(nested_fields, name, value)
        _set_nested_value(nested_fields, point.parameter_name, payload)
        safe_fields = nested_fields

    headers = {"user-agent": "XSS-Sentinel/0.1 (explicitly authorized stored-XSS test)"}
    headers.update(profile.get("headers", {}))
    timeout = httpx.Timeout(15.0, connect=8.0)
    flow = AuthFlow(profile, target_url)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, headers=headers,
                                 cookies=profile.get("cookies") or None,
                                 verify=profile.get("verify_tls", True)) as client:
        try:
            await flow.initialize(client)
        except httpx.HTTPError as exc:
            raise ValueError(f"Configured authentication step failed ({type(exc).__name__}); no stored test was submitted.") from exc
        try:
            if body_format == "form":
                response = await flow.request(client, "POST", point.url, data=safe_fields)
            else:
                response = await flow.request(client, "POST", point.url, json=safe_fields)
        except httpx.HTTPError as exc:
            return {
                "marker": marker, "result": "submission_inconclusive", "submission_status": None,
                "verification_url_count": 0, "callback_request_count": 0, "callback_response_status": None,
                "callback_endpoint": safe_callback_endpoint, "screenshot_data": None,
                "evidence": f"POST delivery outcome is unknown ({type(exc).__name__}); the target may have accepted the state-changing request.",
            }
        submission_status = response.status_code
        if submission_status >= 400:
            return {
                "marker": marker, "result": "submission_failed", "submission_status": submission_status,
                "verification_url_count": 0, "callback_request_count": 0, "callback_response_status": None,
                "callback_endpoint": safe_callback_endpoint, "screenshot_data": None,
                "evidence": f"The explicitly confirmed test submission returned HTTP {submission_status}; no verification pages were visited.",
            }
        location = response.headers.get("location")
        if location:
            resolved = urljoin(point.url, location)
            if _origin(resolved) == _origin(target_url) and resolved not in verify_urls:
                verify_urls.append(resolved)

    try:
        verification = await verify_stored_execution(verify_urls, target_url, marker, profile, callback_endpoint)
    except (ValueError, httpx.HTTPError) as exc:
        return {
            "marker": marker, "result": "inconclusive", "submission_status": submission_status,
            "verification_url_count": len(verify_urls), "callback_request_count": 0,
            "callback_response_status": None, "callback_endpoint": safe_callback_endpoint,
            "screenshot_data": None,
            "evidence": f"POST returned HTTP {submission_status}, but follow-up verification could not complete ({type(exc).__name__}); submitted data may remain in the target.",
        }
    return {
        "marker": marker,
        "result": verification["result"],
        "submission_status": submission_status,
        "verification_url_count": len(verify_urls),
        "callback_request_count": verification["callback_request_count"],
        "callback_response_status": verification["callback_response_status"],
        "callback_endpoint": safe_callback_endpoint,
        "screenshot_data": verification["screenshot_data"],
        "evidence": f"Submission HTTP {submission_status}; {verification['evidence']}",
    }
