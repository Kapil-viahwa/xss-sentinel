import json
import os
import re
import secrets
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from .auth_profiles import AuthFlow
from .models import InjectionPoint


MAX_RESPONSE_BYTES = 2_000_000
SENSITIVE_MARKER = "<redacted>"
WAF_SIGNATURES_ENV = "XSS_SENTINEL_WAF_SIGNATURES"
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class _MarkerContextParser(HTMLParser):
    URL_ATTRIBUTES = {"href", "src", "action", "formaction", "xlink:href"}
    VOID_ELEMENTS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self, marker: str):
        super().__init__(convert_charrefs=True)
        self.marker = marker
        self.contexts: set[str] = set()
        self.stack: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if value and self.marker in value:
                self.contexts.add("url_attribute" if name.lower() in self.URL_ATTRIBUTES else "html_attribute")
        if tag not in self.VOID_ELEMENTS:
            self.stack.append(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in self.VOID_ELEMENTS and self.stack and self.stack[-1] == tag:
            self.stack.pop()

    def handle_endtag(self, tag: str) -> None:
        if tag in self.stack:
            index = len(self.stack) - 1 - self.stack[::-1].index(tag)
            del self.stack[index:]

    def handle_data(self, data: str) -> None:
        if self.marker not in data:
            return
        if self.stack and self.stack[-1] == "script":
            self.contexts.add("javascript_text")
        elif self.stack and self.stack[-1] == "style":
            self.contexts.add("css_text")
        else:
            self.contexts.add("html_text")

    def handle_comment(self, data: str) -> None:
        if self.marker in data:
            self.contexts.add("html_comment")


def _parameter_url(url: str, name: str, value: str) -> str:
    parsed = urlsplit(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    updated = []
    for key, old_value in query:
        if key == name:
            updated.append((key, value))
            replaced = True
        else:
            updated.append((key, old_value))
    if not replaced:
        updated.append((name, value))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(updated), ""))


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


async def _fetch(client: httpx.AsyncClient, url: str, auth_flow: AuthFlow | None = None,
                 retried_after_refresh: bool = False) -> tuple[int, str, str, bool, dict[str, str]]:
    body = bytearray()
    retry_after_refresh = False
    async with client.stream("GET", url) as response:
        if response.status_code == 401 and auth_flow is not None and not retried_after_refresh:
            await response.aread()
            retry_after_refresh = True
        else:
            status = response.status_code
            content_type = response.headers.get("content-type", "").lower()
            response_headers = dict(response.headers)
            async for chunk in response.aiter_bytes():
                remaining = MAX_RESPONSE_BYTES + 1 - len(body)
                body.extend(chunk[:remaining])
                if len(body) > MAX_RESPONSE_BYTES:
                    break
            truncated = len(body) > MAX_RESPONSE_BYTES
            response_text = bytes(body[:MAX_RESPONSE_BYTES]).decode(response.encoding or "utf-8", errors="replace")
    if retry_after_refresh:
        await auth_flow.refresh(client)
        return await _fetch(client, url, auth_flow, retried_after_refresh=True)
    return status, content_type, response_text, truncated, response_headers


def _custom_waf_signatures() -> list[dict]:
    raw = os.getenv(WAF_SIGNATURES_ENV, "")
    if not raw:
        return []
    if len(raw) > 32_000:
        raise ValueError("Custom WAF signature configuration is too large.")
    try:
        configured = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Custom WAF signatures must be valid JSON.") from exc
    if not isinstance(configured, list) or len(configured) > 50:
        raise ValueError("Custom WAF signatures must be a list of at most 50 entries.")
    result = []
    for item in configured:
        if not isinstance(item, dict) or not isinstance(item.get("vendor"), str) or not 1 <= len(item["vendor"]) <= 80:
            raise ValueError("Each custom WAF signature needs a short vendor name.")
        headers = item.get("headers", [])
        server_contains = item.get("server_contains", [])
        body_contains = item.get("body_contains", [])
        block_headers = item.get("block_headers", {})
        if (not isinstance(headers, list) or len(headers) > 20
                or not isinstance(server_contains, list) or len(server_contains) > 20
                or not isinstance(body_contains, list) or len(body_contains) > 20
                or not isinstance(block_headers, dict) or len(block_headers) > 10):
            raise ValueError("Custom WAF signature fields exceed their limits.")
        safe_headers = []
        for header in headers:
            if not isinstance(header, str) or not _HEADER_NAME.fullmatch(header):
                raise ValueError("Custom WAF signature header names must be valid HTTP tokens.")
            safe_headers.append(header.lower())
        safe_server = []
        safe_body = []
        for source, target in ((server_contains, safe_server), (body_contains, safe_body)):
            for phrase in source:
                if not isinstance(phrase, str) or not phrase or len(phrase) > 160 or any(ord(char) < 32 for char in phrase):
                    raise ValueError("Custom WAF signature phrases must be bounded printable strings.")
                target.append(phrase.lower())
        safe_blocks = {}
        for header, values in block_headers.items():
            if (not isinstance(header, str) or not _HEADER_NAME.fullmatch(header)
                    or not isinstance(values, list) or not values or len(values) > 20):
                raise ValueError("Custom WAF block indicators need valid headers and value lists.")
            safe_values = []
            for value in values:
                if not isinstance(value, str) or not value or len(value) > 120 or any(ord(char) < 32 for char in value):
                    raise ValueError("Custom WAF block indicator values must be bounded printable strings.")
                safe_values.append(value.lower())
            safe_blocks[header.lower()] = safe_values
        result.append({"vendor": item["vendor"], "headers": safe_headers,
                       "server_contains": safe_server, "body_contains": safe_body,
                       "block_headers": safe_blocks})
    return result


def _waf_observation(status: int | None, baseline_headers: dict[str, str], response_headers: dict[str, str],
                     baseline_body: str = "", response_body: str = "", baseline_status: int | None = None) -> dict:
    header_signatures = {
        "cf-ray": "Cloudflare", "cf-mitigated": "Cloudflare", "akamai-grn": "Akamai",
        "x-akamai-transformed": "Akamai", "x-iinfo": "Imperva", "x-sucuri-id": "Sucuri",
        "x-amzn-waf-action": "AWS WAF", "x-azure-ref": "Azure Front Door",
        "x-sucuri-block": "Sucuri", "x-fortiweb-action": "FortiWeb",
        "x-fd-int-roxy-purgeid": "Azure Front Door", "x-fortiweb": "FortiWeb",
        "x-fortiweb-": "FortiWeb", "x-wf-blocked": "Wordfence", "x-rdwr-": "Radware",
        "x-sl-compstate": "Radware", "x-wa-info": "F5 BIG-IP ASM", "x-cdn": "Imperva",
        "x-sucuri-cache": "Sucuri", "x-fastly-request-id": "Fastly",
        "x-barracuda-url": "Barracuda", "x-barracuda-encrypted": "Barracuda",
        "x-ns-cf-open": "Citrix ADC", "ns_af": "Citrix ADC", "nsid": "Citrix ADC",
        "x-sp-waf": "StackPath", "x-reblaze": "Reblaze", "x-wallarm-": "Wallarm",
    }
    baseline_normalized = {key.lower(): value.lower() for key, value in baseline_headers.items()}
    response_normalized = {key.lower(): value.lower() for key, value in response_headers.items()}
    headers = {**baseline_normalized, **response_normalized}
    vendors = set()
    signals = []
    explicit_vendor_headers = set()
    for header, vendor in header_signatures.items():
        if header.endswith("-"):
            matches = [key for key in headers if key.startswith(header)]
            if matches:
                vendors.add(vendor)
                signals.extend(f"header:{key}" for key in matches)
                explicit_vendor_headers.update(matches)
        elif header in headers:
            vendors.add(vendor)
            signals.append(f"header:{header}")
            explicit_vendor_headers.add(header)

    set_cookie = headers.get("set-cookie", "")
    for cookie_signature, vendor in (("__cf_bm", "Cloudflare"), ("cf_clearance", "Cloudflare"),
                                     ("incap_ses_", "Imperva"), ("visid_incap_", "Imperva"),
                                     ("barra_counter_session", "Barracuda"),
                                     ("sucuri_cloudproxy_uuid", "Sucuri")):
        if cookie_signature in set_cookie:
            vendors.add(vendor)
            signals.append("cookie_signature:" + cookie_signature)

    server = headers.get("server", "")
    for signature, vendor in (("cloudflare", "Cloudflare"), ("akamai", "Akamai"), ("imperva", "Imperva"),
                              ("sucuri", "Sucuri"), ("fortiweb", "FortiWeb"), ("mod_security", "ModSecurity"),
                              ("modsecurity", "ModSecurity"), ("barracuda", "Barracuda"), ("big-ip", "F5 BIG-IP ASM")):
        if signature in server:
            vendors.add(vendor)
            signals.append("server_signature:" + signature)

    body = (response_body or "").lower()
    body_signatures = {
        "cloudflare_challenge": ("cloudflare", "checking your browser"),
        "akamai_reference": ("reference #", "akamai"),
        "imperva_incident": ("incapsula incident id",),
        "sucuri_denied": ("sucuri website firewall", "access denied"),
        "f5_rejected": ("the requested url was rejected", "support id"),
        "modsecurity_denied": ("mod_security",),
        "fortiweb_denied": ("fortiweb", "access denied"),
        "generic_access_denied": ("access denied", "request blocked"),
    }
    for signature, phrases in body_signatures.items():
        if all(phrase in body for phrase in phrases):
            signals.append("body_signature:" + signature)
            if signature.startswith("cloudflare"):
                vendors.add("Cloudflare")
            elif signature.startswith("akamai"):
                vendors.add("Akamai")
            elif signature.startswith("imperva"):
                vendors.add("Imperva")
            elif signature.startswith("sucuri"):
                vendors.add("Sucuri")
            elif signature.startswith("f5"):
                vendors.add("F5 BIG-IP ASM")
            elif signature.startswith("modsecurity"):
                vendors.add("ModSecurity")
            elif signature.startswith("fortiweb"):
                vendors.add("FortiWeb")

    custom_block = False
    for signature in _custom_waf_signatures():
        vendor = signature["vendor"]
        for header in signature["headers"]:
            if header in headers:
                vendors.add(vendor)
                signals.append(f"custom_header:{vendor}:{header}")
                explicit_vendor_headers.add(header)
        for phrase in signature["server_contains"]:
            if phrase in server:
                vendors.add(vendor)
                signals.append(f"custom_server:{vendor}:{phrase}")
        if any(phrase in body for phrase in signature["body_contains"]):
            vendors.add(vendor)
            signals.append(f"body_signature:custom:{vendor}")
        for header, values in signature["block_headers"].items():
            if response_normalized.get(header, "").strip() in values:
                vendors.add(vendor)
                signals.append(f"custom_block_header:{vendor}:{header}")
                custom_block = True

    explicit_block = custom_block or (
        response_normalized.get("cf-mitigated", "").strip() == "challenge"
        or response_normalized.get("x-amzn-waf-action", "").strip() in {"block", "captcha", "challenge"}
        or response_normalized.get("x-wf-blocked", "").strip() in {"1", "true", "yes"}
        or response_normalized.get("x-sucuri-block", "").strip() in {"1", "true", "yes"}
        or response_normalized.get("x-fortiweb-action", "").strip() in {"block", "deny", "challenge"}
        or response_normalized.get("x-barracuda-url", "").strip() in {"blocked", "deny"}
    )
    blocked_status = status in {403, 406, 429}
    if baseline_status is not None and status is not None and baseline_status < 400 <= status:
        signals.append(f"status_delta:{baseline_status}->{status}")
    if blocked_status and response_body and response_body != baseline_body:
        signals.append("block_response_body_changed_from_baseline")
    body_block_signals = any(
        signal.startswith("body_signature:") and signal != "body_signature:generic_access_denied"
        for signal in signals
    )
    if explicit_block or (blocked_status and body_block_signals):
        result = "waf_blocked" if blocked_status else "waf_challenge"
        confidence = "high" if explicit_block else "medium"
        source = "explicit vendor header" if explicit_block else "vendor-specific block-page signature"
        evidence = f"A {source} was observed on the controlled inert-marker request. This does not prove the application is safe."
    elif body_block_signals:
        result = "waf_challenge"
        confidence = "medium"
        evidence = "A vendor-specific challenge or block-page signature was observed; status alone was not a block response. This does not prove the application is safe."
    elif blocked_status:
        result = "block_response"
        confidence = "low"
        evidence = f"HTTP {status} followed a controlled inert-marker request; application versus WAF attribution is not conclusive."
    elif signals:
        result = "fingerprint"
        confidence = "medium" if explicit_vendor_headers else "low"
        evidence = "Security-control fingerprints were observed; presence alone does not establish that a WAF blocked this request."
    else:
        return {"waf_result": None, "waf_vendor": None, "waf_vendors": [], "waf_confidence": None,
                "waf_evidence": None, "waf_signals": []}
    return {"waf_result": result, "waf_vendor": sorted(vendors)[0] if vendors else None,
            "waf_vendors": sorted(vendors), "waf_confidence": confidence, "waf_evidence": evidence,
            "waf_signals": sorted(set(signals))}


def _locate_marker(body: str, content_type: str, marker: str) -> tuple[bool, str]:
    if marker not in body:
        return False, "unknown"
    if "html" in content_type:
        parser = _MarkerContextParser(marker)
        parser.feed(body)
        if parser.contexts:
            return True, ", ".join(sorted(parser.contexts))[:80]
        return True, "html_parser"
    if "json" in content_type:
        return True, "json_value"
    return True, "response_text"


async def run_reflection_probe(point: InjectionPoint, target_url: str, auth_profile: dict | None = None) -> dict:
    if point.method.upper() != "GET" or point.location != "query" or point.input_type:
        raise ValueError("Only URL-based GET query inputs are supported; form fields are not replayed.")
    if point.original_value == SENSITIVE_MARKER:
        raise ValueError("This input is redacted and cannot be safely replayed.")
    if _origin(point.url) is None or _origin(point.url) != _origin(target_url):
        raise ValueError("Input URL is outside the assessment origin.")

    marker = f"XSSSENTINEL{point.assessment_id}{point.id}{secrets.token_hex(6)}"
    original_value = point.original_value or ""
    baseline_url = _parameter_url(point.url, point.parameter_name, original_value)
    marker_url = _parameter_url(point.url, point.parameter_name, marker)
    timeout = httpx.Timeout(12.0, connect=5.0)
    headers = {"user-agent": "XSS-Sentinel/0.1 (authorized inert reflection check)"}
    headers.update((auth_profile or {}).get("headers", {}))
    cookies = (auth_profile or {}).get("cookies") or None
    auth_flow = AuthFlow(auth_profile, target_url)

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, headers=headers, cookies=cookies,
                                     verify=(auth_profile or {}).get("verify_tls", True)) as client:
            await auth_flow.initialize(client)
            baseline_status, _, baseline_body, baseline_truncated, baseline_headers = await _fetch(client, baseline_url, auth_flow)
            if 300 <= baseline_status < 400 or baseline_status >= 400:
                return {
                    "marker": marker,
                    "result": "inconclusive",
                    "context": "unknown",
                    "baseline_status": baseline_status,
                    "response_status": None,
                    "evidence": f"Baseline request returned HTTP {baseline_status}; marker comparison was not attempted.",
                    **_waf_observation(baseline_status, {}, baseline_headers, baseline_body, baseline_body, baseline_status),
                }
            if marker in baseline_body or baseline_truncated:
                return {
                    "marker": marker,
                    "result": "inconclusive",
                    "context": "unknown",
                    "baseline_status": baseline_status,
                    "response_status": None,
                    "evidence": "Baseline response could not provide a complete clean comparison.",
                }
            response_status, content_type, body, truncated, response_headers = await _fetch(client, marker_url, auth_flow)
    except httpx.HTTPError as exc:
        return {
            "marker": marker,
            "result": "inconclusive",
            "context": "unknown",
            "baseline_status": None,
            "response_status": None,
            "evidence": f"Request failed ({type(exc).__name__}); no vulnerability conclusion was made.",
        }

    reflected, context = _locate_marker(body, content_type, marker)
    if 300 <= response_status < 400 or response_status >= 400:
        result = "inconclusive"
        evidence = f"Controlled request returned HTTP {response_status}; this is not evidence that the application is safe."
    elif reflected:
        result = "reflected"
        evidence = f"Harmless marker appeared in the response ({context}); reflection alone does not confirm XSS."
    elif truncated:
        result = "inconclusive"
        evidence = "Response exceeded the inspection limit before a marker match was found."
    else:
        result = "not_reflected"
        evidence = "Harmless marker was not found in the inspected response; this does not rule out DOM or stored XSS."
    return {
        "marker": marker,
        "result": result,
        "context": context,
        "baseline_status": baseline_status,
        "response_status": response_status,
        "evidence": evidence,
        **_waf_observation(response_status, baseline_headers, response_headers, baseline_body, body, baseline_status),
    }
