import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import struct
import time
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import async_playwright


AUTH_PROFILES_ENV = "XSS_SENTINEL_AUTH_PROFILES"
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_COOKIE_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_FORBIDDEN_HEADERS = {"host", "content-length", "transfer-encoding", "connection", "proxy-authorization", "cookie", "set-cookie"}
_SELECTOR = re.compile(r"^[^\r\n\x00]{1,300}$")


def _origin_key(value: str) -> str | None:
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        port = parsed.port or (443 if scheme == "https" else 80)
        return f"{scheme}|{parsed.hostname.lower()}|{port}"
    except ValueError:
        return None


def _safe_path(value: Any, description: str) -> str:
    parsed = urlsplit(value) if isinstance(value, str) else None
    if (parsed is None or not parsed.path.startswith("/") or parsed.path.startswith("//")
            or parsed.scheme or parsed.netloc or parsed.query or parsed.fragment):
        raise ValueError(f"{description} must be a same-origin absolute path without a query or fragment.")
    return parsed.path


def _validate_token_header(value: Any) -> str:
    if not isinstance(value, str) or not _HEADER_NAME.fullmatch(value) or value.lower() in _FORBIDDEN_HEADERS:
        raise ValueError("The configured token header is invalid or unsafe.")
    return value.lower()


def _validate_exchange(config: Any) -> dict[str, Any]:
    if not isinstance(config, dict):
        raise ValueError("Login and refresh steps must be JSON objects.")
    path = _safe_path(config.get("url"), "Login and refresh URLs")
    request_format = config.get("format", "json")
    fields = config.get("fields", {})
    if request_format not in {"json", "form"} or not isinstance(fields, dict) or len(fields) > 32:
        raise ValueError("Login fields must be a small JSON or form object.")
    safe_fields = {}
    for key, value in fields.items():
        if (not isinstance(key, str) or not key or len(key) > 120 or not isinstance(value, str)
                or len(value) > 4096 or any(ord(char) == 0 for char in value)):
            raise ValueError("Login field names and values must be bounded strings.")
        safe_fields[key] = value
    token_path = config.get("token_path")
    refresh_token_path = config.get("refresh_token_path")
    for value in (token_path, refresh_token_path):
        if value is not None and (not isinstance(value, str) or not value or len(value) > 200):
            raise ValueError("Token response paths must be short dotted JSON paths.")
    token_header = _validate_token_header(config.get("token_header", "Authorization"))
    token_prefix = config.get("token_prefix", "Bearer ")
    if not isinstance(token_prefix, str) or len(token_prefix) > 40 or any(ord(char) < 32 for char in token_prefix):
        raise ValueError("The configured token prefix is invalid.")
    return {
        "url": path,
        "format": request_format,
        "fields": safe_fields,
        "token_path": token_path,
        "refresh_token_path": refresh_token_path,
        "token_header": token_header,
        "token_prefix": token_prefix,
    }


def _validate_webauthn(config: Any) -> dict[str, Any] | None:
    if config is None:
        return None
    if not isinstance(config, dict):
        raise ValueError("WebAuthn settings must be a JSON object.")
    rp_id = config.get("rp_id")
    credentials = config.get("credentials")
    if (not isinstance(rp_id, str) or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", rp_id)
            or rp_id.startswith(".") or rp_id.endswith(".") or ".." in rp_id
            or not isinstance(credentials, list) or not 1 <= len(credentials) <= 10):
        raise ValueError("WebAuthn settings need a valid relying-party ID and 1–10 seeded test credentials.")
    safe_credentials = []
    for credential in credentials:
        if not isinstance(credential, dict):
            raise ValueError("Each WebAuthn credential must be a JSON object.")
        safe_credential = {}
        for key in ("id", "user_handle", "private_key", "public_key"):
            value = credential.get(key)
            if (not isinstance(value, str) or not 1 <= len(value) <= 4096
                    or not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", value)):
                raise ValueError("WebAuthn credential fields must be bounded base64url strings.")
            try:
                decoded = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
            except (ValueError, binascii.Error) as exc:
                raise ValueError("WebAuthn credential fields must be valid base64url strings.") from exc
            if not decoded:
                raise ValueError("WebAuthn credential fields must not be empty.")
            safe_credential[key] = value
        sign_count = credential.get("sign_count", 0)
        if not isinstance(sign_count, int) or isinstance(sign_count, bool) or sign_count < 0:
            raise ValueError("WebAuthn sign_count must be a non-negative integer.")
        safe_credential["sign_count"] = sign_count
        safe_credentials.append(safe_credential)
    return {"rp_id": rp_id.lower(), "credentials": safe_credentials}


def _validate_browser_flow(config: Any) -> dict[str, Any]:
    if not isinstance(config, dict):
        raise ValueError("Browser login flow must be a JSON object.")
    path = _safe_path(config.get("url"), "Browser login URL")
    steps = config.get("steps")
    post_paths = config.get("post_paths", [])
    if not isinstance(steps, list) or not 1 <= len(steps) <= 20 or not isinstance(post_paths, list) or len(post_paths) > 10:
        raise ValueError("Browser login needs 1–20 steps and at most 10 explicitly allowed POST paths.")
    safe_posts = sorted({_safe_path(value, "Allowed browser login POST paths") for value in post_paths})
    safe_steps = []
    for step in steps:
        if not isinstance(step, dict) or step.get("action") not in {"fill", "click", "wait_for", "csrf_header", "totp"}:
            raise ValueError("Browser login steps must use a supported action.")
        action = step["action"]
        selector = step.get("selector")
        if not isinstance(selector, str) or not _SELECTOR.fullmatch(selector):
            raise ValueError("Browser login selectors must be bounded, non-empty strings.")
        safe_step = {"action": action, "selector": selector}
        if action == "fill":
            value = step.get("value")
            if not isinstance(value, str) or len(value) > 4096:
                raise ValueError("Browser login fill values must be bounded strings.")
            safe_step["value"] = value
        elif action == "csrf_header":
            attribute = step.get("attribute", "content")
            if not isinstance(attribute, str) or not _HEADER_NAME.fullmatch(attribute):
                raise ValueError("CSRF token attributes must be valid short names.")
            safe_step["attribute"] = attribute
            safe_step["header"] = _validate_token_header(step.get("header"))
        elif action == "totp":
            secret = step.get("secret")
            digits = step.get("digits", 6)
            period = step.get("period", 30)
            normalized_secret = re.sub(r"[\s=-]", "", secret).upper() if isinstance(secret, str) else ""
            if (not normalized_secret or not re.fullmatch(r"[A-Z2-7]+", normalized_secret)
                    or digits not in {6, 8} or not isinstance(period, int) or not 15 <= period <= 120):
                raise ValueError("TOTP steps need a Base32 secret, 6/8 digits, and a valid time period.")
            safe_step.update({"secret": normalized_secret, "digits": digits, "period": period})
        safe_steps.append(safe_step)

    success_selector = config.get("success_selector")
    if success_selector is not None and (not isinstance(success_selector, str) or not _SELECTOR.fullmatch(success_selector)):
        raise ValueError("The browser login success selector is invalid.")
    token_storage_key = config.get("token_storage_key")
    if token_storage_key is not None and (not isinstance(token_storage_key, str) or not token_storage_key or len(token_storage_key) > 200):
        raise ValueError("The browser login token storage key is invalid.")
    token_header = _validate_token_header(config.get("token_header", "Authorization"))
    token_prefix = config.get("token_prefix", "Bearer ")
    if not isinstance(token_prefix, str) or len(token_prefix) > 40 or any(ord(char) < 32 for char in token_prefix):
        raise ValueError("The configured token prefix is invalid.")
    return {
        "url": path,
        "steps": safe_steps,
        "post_paths": safe_posts,
        "success_selector": success_selector,
        "token_storage_key": token_storage_key,
        "token_header": token_header,
        "token_prefix": token_prefix,
        "webauthn": _validate_webauthn(config.get("webauthn")),
    }


def _totp_code(secret: str, timestamp: int | None = None, digits: int = 6, period: int = 30) -> str:
    normalized = re.sub(r"[\s=-]", "", secret).upper()
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    key = base64.b32decode(normalized + padding, casefold=True)
    counter = int((time.time() if timestamp is None else timestamp) // period)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return str(binary % (10 ** digits)).zfill(digits)


def _credential_fingerprint(rp_id: str, credential_id: str) -> str:
    return hashlib.sha256(f"{rp_id.lower()}\\0{credential_id}".encode("utf-8")).hexdigest()


def _load_webauthn_sign_count(rp_id: str, credential_id: str, default: int) -> int:
    from .database import SessionLocal
    from .models import WebAuthnCredentialState

    fingerprint = _credential_fingerprint(rp_id, credential_id)
    with SessionLocal() as session:
        state = session.get(WebAuthnCredentialState, fingerprint)
        return max(default, state.sign_count) if state is not None else default


def _save_webauthn_sign_count(rp_id: str, credential_id: str, sign_count: int) -> None:
    from sqlalchemy.exc import IntegrityError

    from .database import SessionLocal
    from .models import WebAuthnCredentialState, utc_now

    fingerprint = _credential_fingerprint(rp_id, credential_id)
    try:
        with SessionLocal() as session:
            state = session.get(WebAuthnCredentialState, fingerprint)
            if state is None:
                session.add(WebAuthnCredentialState(
                    credential_fingerprint=fingerprint, rp_id=rp_id.lower(),
                    sign_count=sign_count, updated_at=utc_now(),
                ))
            else:
                state.sign_count = max(state.sign_count, sign_count)
                state.updated_at = utc_now()
            session.commit()
    except IntegrityError:
        with SessionLocal() as session:
            state = session.get(WebAuthnCredentialState, fingerprint)
            if state is None:
                raise
            state.sign_count = max(state.sign_count, sign_count)
            state.updated_at = utc_now()
            session.commit()


def parse_auth_profiles(raw: str | None = None) -> dict[str, dict[str, Any]]:
    source = os.getenv(AUTH_PROFILES_ENV, "") if raw is None else raw
    if not source.strip():
        return {}
    if len(source) > 64_000:
        raise ValueError("Authentication profile configuration is too large.")
    try:
        decoded = json.loads(source)
    except json.JSONDecodeError as exc:
        raise ValueError("Authentication profiles must be valid JSON.") from exc
    if not isinstance(decoded, dict):
        raise ValueError("Authentication profiles must be a JSON object.")

    profiles: dict[str, dict[str, Any]] = {}
    for name, config in decoded.items():
        if not isinstance(name, str) or not name.strip() or len(name) > 120 or not isinstance(config, dict):
            raise ValueError("Each authentication profile needs a short name and an object configuration.")
        headers = config.get("headers", {})
        cookies = config.get("cookies", {})
        origins = config.get("origins")
        callback_origins = config.get("callback_origins", [])
        verify_tls = config.get("verify_tls", True)
        if (not isinstance(headers, dict) or not isinstance(cookies, dict) or not isinstance(origins, list) or not origins
                or not isinstance(callback_origins, list) or not isinstance(verify_tls, bool)):
            raise ValueError("Each profile needs origin allowlists and valid header, cookie, callback, and TLS settings.")
        if len(headers) > 32 or len(cookies) > 64 or len(origins) > 50 or len(callback_origins) > 50:
            raise ValueError("An authentication profile has too many origins, headers, or cookies.")

        safe_headers = {}
        for key, value in headers.items():
            if (not isinstance(key, str) or not _HEADER_NAME.fullmatch(key)
                    or key.lower() in _FORBIDDEN_HEADERS or not isinstance(value, str)
                    or len(value) > 8192 or any(ord(char) < 32 or ord(char) == 127 for char in value)):
                raise ValueError("Profile contains an invalid or unsafe HTTP header.")
            safe_headers[key.lower()] = value

        safe_cookies = {}
        for key, value in cookies.items():
            if (not isinstance(key, str) or not _COOKIE_NAME.fullmatch(key) or not isinstance(value, str)
                    or len(value) > 4096 or ";" in value
                    or any(ord(char) < 32 or ord(char) == 127 for char in value)):
                raise ValueError("Profile contains an invalid cookie.")
            safe_cookies[key] = value

        safe_origins = set()
        for origin in origins:
            if not isinstance(origin, str):
                raise ValueError("Profile origins must be HTTP(S) origins.")
            parsed_origin = urlsplit(origin)
            if parsed_origin.path not in {"", "/"} or parsed_origin.query or parsed_origin.fragment:
                raise ValueError("Profile origins must not include paths, queries, or fragments.")
            key = _origin_key(origin)
            if key is None:
                raise ValueError("Profile origins must be absolute HTTP(S) origins without embedded credentials.")
            safe_origins.add(key)

        safe_callbacks = set()
        for origin in callback_origins:
            if not isinstance(origin, str):
                raise ValueError("Callback allowlists must contain HTTP(S) origins.")
            parsed_origin = urlsplit(origin)
            if parsed_origin.path not in {"", "/"} or parsed_origin.query or parsed_origin.fragment:
                raise ValueError("Callback allowlist entries must be origins without paths, queries, or fragments.")
            key = _origin_key(origin)
            if key is None:
                raise ValueError("Callback allowlist entries must be absolute HTTP(S) origins without credentials.")
            safe_callbacks.add(key)

        login = config.get("login")
        browser_flow = config.get("browser_flow")
        if login is not None and browser_flow is not None:
            raise ValueError("Choose either HTTP login or browser_flow for one profile, not both.")
        refresh = config.get("refresh")
        if login is not None:
            login = _validate_exchange(login)
            if refresh is not None:
                login["refresh"] = _validate_exchange(refresh)
        elif browser_flow is not None:
            if refresh is not None:
                raise ValueError("Browser-flow refresh is performed by replaying the configured browser steps.")
            browser_flow = _validate_browser_flow(browser_flow)
        elif refresh is not None:
            raise ValueError("A refresh step requires a configured login step.")
        profiles[name.strip()] = {
            "headers": safe_headers,
            "cookies": safe_cookies,
            "origins": sorted(safe_origins),
            "callback_origins": sorted(safe_callbacks),
            "verify_tls": verify_tls,
            "login": login,
            "browser_flow": browser_flow,
        }
    return profiles


def auth_profile_names() -> list[str]:
    return sorted(parse_auth_profiles())


def get_auth_profile(name: str | None, target_url: str | None = None) -> dict[str, Any]:
    if not name:
        return {"headers": {}, "cookies": {}, "origins": [], "callback_origins": [], "verify_tls": True,
                "login": None, "browser_flow": None}
    profiles = parse_auth_profiles()
    if name not in profiles:
        raise ValueError("The selected authentication profile is not configured on this server.")
    profile = profiles[name]
    if target_url is not None and _origin_key(target_url) not in profile["origins"]:
        raise ValueError("The target origin is not allowlisted for the selected authentication profile.")
    webauthn = (profile.get("browser_flow") or {}).get("webauthn")
    if target_url is not None and webauthn:
        hostname = (urlsplit(target_url).hostname or "").lower()
        rp_id = webauthn["rp_id"]
        if hostname != rp_id and not hostname.endswith("." + rp_id):
            raise ValueError("The WebAuthn relying-party ID must match or be a parent domain of the target host.")
    return profile


def callback_url_allowed(profile: dict[str, Any] | None, callback_url: str) -> bool:
    return bool(profile and _origin_key(callback_url) in profile.get("callback_origins", []))


def _json_path(value: Any, path: str | None) -> str | None:
    if not path:
        return None
    current = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current if isinstance(current, str) and current else None


class AuthFlow:
    """Origin-scoped HTTP and browser login, cookie capture, and token refresh."""

    def __init__(self, profile: dict[str, Any] | None, target_url: str):
        self.profile = profile or {"headers": {}, "cookies": {}, "login": None, "browser_flow": None, "verify_tls": True}
        self.target_url = target_url
        self.login_config = self.profile.get("login")
        self.browser_flow = self.profile.get("browser_flow")
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.token_header: str | None = None
        self.dynamic_headers: dict[str, str] = {}
        self.generation = 0
        self._lock = asyncio.Lock()

    async def initialize(self, client: httpx.AsyncClient) -> None:
        if self.browser_flow:
            await self._browser_exchange(client)
        elif self.login_config:
            await self._exchange(client, self.login_config)

    async def _exchange(self, client: httpx.AsyncClient, config: dict[str, Any], refresh: bool = False) -> None:
        url = urljoin(self.target_url, config["url"])
        if _origin_key(url) != _origin_key(self.target_url):
            raise ValueError("Authentication endpoints must remain within the allowlisted target origin.")
        fields = {}
        for key, value in config["fields"].items():
            fields[key] = value.replace("{{access_token}}", self.access_token or "").replace(
                "{{refresh_token}}", self.refresh_token or ""
            )
        if config["format"] == "form":
            response = await client.post(url, data=fields)
        else:
            response = await client.post(url, json=fields)
        if 300 <= response.status_code < 400 and not refresh:
            location = response.headers.get("location")
            redirected = urljoin(url, location or "")
            if not location or _origin_key(redirected) != _origin_key(self.target_url):
                raise ValueError("Authentication redirect left the allowlisted target origin.")
            response = await client.get(redirected)
        if response.status_code < 200 or response.status_code >= 300:
            raise ValueError(f"Configured authentication step failed with HTTP {response.status_code}.")
        try:
            result = response.json()
        except (ValueError, json.JSONDecodeError):
            result = None
        new_access = _json_path(result, config.get("token_path"))
        new_refresh = _json_path(result, config.get("refresh_token_path"))
        if new_access:
            header_name = config["token_header"]
            client.headers[header_name] = f"{config['token_prefix']}{new_access}"
            self.access_token = new_access
            self.token_header = header_name
            self.dynamic_headers[header_name] = client.headers[header_name]
        if new_refresh:
            self.refresh_token = new_refresh
        self.generation += 1

    async def _browser_exchange(self, client: httpx.AsyncClient) -> None:
        config = self.browser_flow
        if config is None:
            return
        login_url = urljoin(self.target_url, config["url"])
        origin = _origin_key(self.target_url)
        if _origin_key(login_url) != origin:
            raise ValueError("Browser login must remain within the allowlisted target origin.")
        webauthn = config.get("webauthn")
        if webauthn:
            hostname = (urlsplit(self.target_url).hostname or "").lower()
            rp_id = webauthn["rp_id"]
            if hostname != rp_id and not hostname.endswith("." + rp_id):
                raise ValueError("The WebAuthn relying-party ID must match or be a parent domain of the target host.")
        browser_headers = dict(self.profile.get("headers", {}))
        context_options = {"service_workers": "block", "ignore_https_errors": not self.profile.get("verify_tls", True)}
        if browser_headers:
            context_options["extra_http_headers"] = browser_headers
        post_paths = set(config["post_paths"])
        try:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(headless=True)
                try:
                    context = await browser.new_context(**context_options)
                    webauthn = config.get("webauthn")
                    if webauthn:
                        authenticator = context.credentials
                        for credential in webauthn["credentials"]:
                            credential["sign_count"] = _load_webauthn_sign_count(
                                webauthn["rp_id"], credential["id"], credential["sign_count"]
                            )
                            await authenticator.create(
                                webauthn["rp_id"],
                                id=credential["id"],
                                user_handle=credential["user_handle"],
                                private_key=credential["private_key"],
                                public_key=credential["public_key"],
                                sign_count=credential["sign_count"],
                            )
                        await authenticator.install()
                    if self.profile.get("cookies"):
                        parsed = urlsplit(self.target_url)
                        cookie_url = urljoin(self.target_url, "/")
                        await context.add_cookies([{"name": name, "value": value, "url": cookie_url}
                                                   for name, value in self.profile["cookies"].items()])
                    page = await context.new_page()

                    async def restrict_login_requests(route):
                        request = route.request
                        parsed_request = urlsplit(request.url)
                        allowed_types = {"document", "script", "stylesheet", "font", "image", "fetch", "xhr"}
                        if (_origin_key(request.url) != origin or request.resource_type not in allowed_types
                                or request.method not in {"GET", "POST"}
                                or (request.method == "POST" and parsed_request.path not in post_paths)):
                            await route.abort()
                            return
                        await route.continue_()

                    await context.route("**/*", restrict_login_requests)
                    response = await page.goto(login_url, wait_until="domcontentloaded", timeout=15000)
                    if response is None or response.status >= 400:
                        raise ValueError(f"Configured browser login page returned HTTP {response.status if response else 'no response'}.")
                    for step in config["steps"]:
                        action = step["action"]
                        locator = page.locator(step["selector"]).first
                        if action == "fill":
                            await locator.fill(step["value"])
                        elif action == "click":
                            await locator.click()
                        elif action == "wait_for":
                            await locator.wait_for(state="visible", timeout=15000)
                        elif action == "csrf_header":
                            token = await locator.get_attribute(step["attribute"])
                            if not token or any(ord(char) < 32 or ord(char) == 127 for char in token):
                                raise ValueError("Configured CSRF token selector did not return a safe value.")
                            self.dynamic_headers[step["header"]] = token
                            browser_headers[step["header"]] = token
                            await page.set_extra_http_headers(browser_headers)
                            client.headers[step["header"]] = token
                        elif action == "totp":
                            await locator.fill(_totp_code(step["secret"], digits=step["digits"], period=step["period"]))
                    if webauthn:
                        for credential in await authenticator.get(rp_id=webauthn["rp_id"]):
                            _save_webauthn_sign_count(webauthn["rp_id"], credential["id"], credential["signCount"])
                            for configured in webauthn["credentials"]:
                                if configured["id"] == credential["id"]:
                                    configured["sign_count"] = credential["signCount"]
                    if config["success_selector"]:
                        await page.locator(config["success_selector"]).wait_for(state="visible", timeout=15000)
                    if config["token_storage_key"]:
                        token = await page.evaluate("key => window.localStorage.getItem(key)", config["token_storage_key"])
                        if token:
                            self.access_token = token
                            self.token_header = config["token_header"]
                            token_value = f"{config['token_prefix']}{token}"
                            self.dynamic_headers[self.token_header] = token_value
                            client.headers[self.token_header] = token_value
                    cookies = await context.cookies()
                    client.cookies.clear()
                    for cookie in cookies:
                        client.cookies.set(cookie["name"], cookie["value"],
                                           domain=cookie.get("domain"), path=cookie.get("path", "/"))
                    self.generation += 1
                    await context.close()
                finally:
                    await browser.close()
        except PlaywrightError as exc:
            raise ValueError(f"Configured browser login failed ({type(exc).__name__}).") from exc

    async def refresh(self, client: httpx.AsyncClient) -> None:
        async with self._lock:
            if self.browser_flow:
                await self._browser_exchange(client)
                return
            if not self.login_config:
                return
            refresh_config = self.login_config.get("refresh")
            if refresh_config and self.refresh_token:
                await self._exchange(client, refresh_config, refresh=True)
            else:
                await self._exchange(client, self.login_config)

    async def request(self, client: httpx.AsyncClient, method: str, url: str, **kwargs):
        generation = self.generation
        response = await client.request(method, url, **kwargs)
        if response.status_code != 401 or not (self.login_config or self.browser_flow) or method.upper() not in {"GET", "HEAD"}:
            return response
        await response.aread()
        async with self._lock:
            if self.generation == generation:
                if self.browser_flow:
                    await self._browser_exchange(client)
                else:
                    refresh_config = self.login_config.get("refresh")
                    if refresh_config and self.refresh_token:
                        await self._exchange(client, refresh_config, refresh=True)
                    else:
                        await self._exchange(client, self.login_config)
        return await client.request(method, url, **kwargs)


async def browser_auth_profile(profile: dict[str, Any] | None, target_url: str) -> dict[str, Any]:
    resolved = profile or {"headers": {}, "cookies": {}, "login": None, "browser_flow": None, "verify_tls": True}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(12.0, connect=5.0), follow_redirects=False,
                                     headers=resolved.get("headers", {}), cookies=resolved.get("cookies", {}),
                                     verify=resolved.get("verify_tls", True)) as client:
            flow = AuthFlow(resolved, target_url)
            await flow.initialize(client)
            headers = {key: value for key, value in client.headers.items() if key in resolved.get("headers", {})}
            headers.update(flow.dynamic_headers)
            cookies = dict(resolved.get("cookies", {}))
            cookies.update({cookie.name: cookie.value for cookie in client.cookies.jar})
            return {"headers": headers, "cookies": cookies, "verify_tls": resolved.get("verify_tls", True)}
    except httpx.HTTPError as exc:
        raise ValueError(f"Configured authentication endpoint could not be reached ({type(exc).__name__}).") from exc
