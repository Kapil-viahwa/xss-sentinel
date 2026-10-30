import asyncio
from collections import deque
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx
from bs4 import BeautifulSoup
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth_profiles import AuthFlow
from .database import SessionLocal
from .frontier import decrypt_frontier_value, encrypt_frontier_value, frontier_cipher, request_fingerprint
from .javascript_analysis import analyze_javascript
from .models import Assessment, CrawlFrontier, CrawlJob, InjectionPoint, JavaScriptObservation, Resource, utc_now


SENSITIVE_FIELD_PARTS = ("password", "passwd", "token", "secret", "authorization", "auth", "csrf", "xsrf", "api_key", "apikey")
MAX_HTML_BYTES = 2_000_000


def _origin(url: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        return parsed.scheme.lower(), parsed.hostname.lower(), port
    except ValueError:
        return None


def _safe_url(url: str) -> str:
    parsed = urlsplit(url)
    safe_query = []
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        lowered = name.lower()
        is_sensitive = any(part in lowered for part in SENSITIVE_FIELD_PARTS)
        safe_query.append((name, "<redacted>" if is_sensitive else "<value>"))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(safe_query), ""))


def _request_key(url: str) -> str:
    parsed = urlsplit(url)
    names = sorted(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True))
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", urlencode([(name, "") for name in names]), ""))


def _stored_value(name: str, value: str | None) -> str | None:
    if value is None:
        return None
    if any(part in name.lower() for part in SENSITIVE_FIELD_PARTS):
        return "<redacted>"
    return value[:500]


def _ensure_resource(session: Session, assessment_id: int, url: str, method: str, kind: str, depth: int,
                     status_code: int | None = None, content_type: str | None = None, title: str | None = None,
                     discovered_from: str | None = None) -> Resource:
    stored_url = _safe_url(url)
    resource = session.scalar(select(Resource).where(
        Resource.assessment_id == assessment_id,
        Resource.method == method,
        Resource.url == stored_url,
        Resource.kind == kind,
    ))
    if resource is None:
        resource = Resource(assessment_id=assessment_id, url=stored_url, method=method, kind=kind,
                            depth=depth, status_code=status_code, content_type=content_type, title=title,
                            discovered_from=_safe_url(discovered_from) if discovered_from else None)
        session.add(resource)
        session.flush()
    else:
        resource.status_code = status_code if status_code is not None else resource.status_code
        resource.content_type = content_type or resource.content_type
        resource.title = title or resource.title
        resource.depth = min(resource.depth, depth)
    return resource


def _save_javascript_observation(session: Session, assessment_id: int, resource_id: int, observation: dict) -> None:
    source = observation.get("source") or ""
    sink = observation.get("sink") or ""
    existing = session.scalar(select(JavaScriptObservation.id).where(
        JavaScriptObservation.assessment_id == assessment_id,
        JavaScriptObservation.resource_id == resource_id,
        JavaScriptObservation.kind == observation["kind"],
        JavaScriptObservation.identifier == observation["identifier"][:2048],
        JavaScriptObservation.source == source[:120],
        JavaScriptObservation.sink == sink[:120],
        JavaScriptObservation.line == observation.get("line", 0),
    ))
    if existing is not None:
        return
    session.add(JavaScriptObservation(
        assessment_id=assessment_id,
        resource_id=resource_id,
        kind=observation["kind"],
        identifier=observation["identifier"][:2048],
        source=source[:120],
        sink=sink[:120],
        line=observation.get("line", 0),
        confidence=observation.get("confidence", "low"),
        evidence=observation["evidence"],
    ))
    session.flush()


def _add_input(session: Session, assessment_id: int, resource: Resource, url: str, method: str,
               name: str, location: str, input_type: str | None, value: str | None) -> None:
    if not name.strip():
        return
    input_type = input_type or ""
    existing = session.scalar(select(InjectionPoint.id).where(
        InjectionPoint.assessment_id == assessment_id,
        InjectionPoint.url == _safe_url(url),
        InjectionPoint.method == method.upper(),
        InjectionPoint.parameter_name == name[:500],
        InjectionPoint.location == location,
        InjectionPoint.input_type == input_type[:80],
    ))
    if existing is not None:
        return
    session.add(InjectionPoint(
        assessment_id=assessment_id,
        resource_id=resource.id,
        url=_safe_url(url),
        method=method.upper(),
        parameter_name=name[:500],
        location=location,
        input_type=input_type[:80],
        original_value=_stored_value(name, value),
        context="unassessed",
        status="untested",
    ))
    session.flush()


async def _wait_for_job_control(session: Session, assessment_id: int, job_id: int, worker_id: str | None) -> bool:
    while True:
        session.expire_all()
        assessment = session.get(Assessment, assessment_id)
        job = session.get(CrawlJob, job_id)
        if assessment is None or job is None:
            return False
        if assessment.status == "cancelled" or job.status == "cancelled":
            raise asyncio.CancelledError
        if worker_id is not None and job.lease_owner != worker_id:
            raise asyncio.CancelledError
        if assessment.status == "paused" or job.status == "paused":
            await asyncio.sleep(0.5)
            continue
        return job.status == "running" and assessment.status == "running"


async def crawl_assessment(assessment_id: int, auth_profile: dict | None = None,
                           resume_event: asyncio.Event | None = None, job_id: int | None = None,
                           worker_id: str | None = None) -> None:
    session = SessionLocal()
    try:
        assessment = session.get(Assessment, assessment_id)
        if assessment is None:
            return
        if assessment.status != "paused":
            assessment.status = "running"
        assessment.error_type = None
        assessment.completed_at = None
        session.commit()

        start_url = assessment.target_url
        allowed_origin = _origin(start_url)
        if allowed_origin is None:
            raise ValueError("invalid_scope")

        queue = deque()
        seen_keys: set[str] = set()
        queued_keys: set[str] = set()
        if job_id is None:
            _enqueue(queue, queued_keys, seen_keys, start_url, 0, None, session, None)
        else:
            frontier_cipher()
            frontier_rows = session.scalars(
                select(CrawlFrontier).where(CrawlFrontier.job_id == job_id).order_by(CrawlFrontier.id)
            ).all()
            if not frontier_rows:
                _enqueue(queue, queued_keys, seen_keys, start_url, 0, None, session, job_id)
            else:
                for frontier in frontier_rows:
                    seen_keys.add(frontier.request_key)
                    if frontier.status == "processing":
                        frontier.status = "pending"
                    if frontier.status == "pending":
                        url = decrypt_frontier_value(frontier.url_ciphertext)
                        source = decrypt_frontier_value(frontier.source_ciphertext) if frontier.source_ciphertext else None
                        queue.append((url, frontier.depth, source, frontier.id))
                        queued_keys.add(frontier.request_key)
            session.commit()
        timeout = httpx.Timeout(15.0, connect=8.0)
        limits = httpx.Limits(max_connections=assessment.concurrency, max_keepalive_connections=assessment.concurrency)
        headers = {"user-agent": "XSS-Sentinel/0.1 (authorized security assessment)"}
        headers.update((auth_profile or {}).get("headers", {}))
        cookies = (auth_profile or {}).get("cookies") or None
        auth_flow = AuthFlow(auth_profile, start_url)

        async with httpx.AsyncClient(timeout=timeout, limits=limits, follow_redirects=False, headers=headers, cookies=cookies,
                                     verify=(auth_profile or {}).get("verify_tls", True)) as client:
            await auth_flow.initialize(client)
            while queue and assessment.requests_made < assessment.max_requests:
                if job_id is not None:
                    if not await _wait_for_job_control(session, assessment_id, job_id, worker_id):
                        break
                elif resume_event is not None:
                    await resume_event.wait()
                    session.refresh(assessment)
                    if assessment.status == "paused":
                        assessment.status = "running"
                        session.commit()
                batch = []
                while queue and len(batch) < assessment.concurrency and assessment.requests_made + len(batch) < assessment.max_requests:
                    item = queue.popleft()
                    queued_keys.discard(_frontier_request_key(item[0]))
                    batch.append(item)
                if not batch:
                    continue
                if job_id is not None:
                    for item in batch:
                        frontier = session.get(CrawlFrontier, item[3])
                        if frontier is not None:
                            frontier.status = "processing"
                    session.commit()
                    session.refresh(assessment)

                async def fetch(item: tuple[str, int, str | None, int | None]):
                    url, depth, source = item
                    try:
                        response = await auth_flow.request(client, "GET", url)
                        return item, response, None
                    except (httpx.HTTPError, ValueError) as exc:
                        return item, None, type(exc).__name__

                results = await asyncio.gather(*(fetch(item) for item in batch))
                assessment.requests_made += len(batch)
                for (url, depth, source, frontier_id), response, _ in results:
                    if frontier_id is not None:
                        frontier = session.get(CrawlFrontier, frontier_id)
                        if frontier is not None:
                            frontier.status = "done"
                    response_content_type = response.headers.get("content-type", "").lower() if response else ""
                    path_lower = urlsplit(url).path.lower()
                    is_javascript = bool(response and response.status_code < 400 and (
                        "javascript" in response_content_type or "ecmascript" in response_content_type
                        or (path_lower.endswith((".js", ".mjs", ".cjs")) and "html" not in response_content_type)))
                    resource = _ensure_resource(session, assessment_id, url, "GET", "script" if is_javascript else "page", depth,
                                                status_code=response.status_code if response else None,
                                                content_type=response.headers.get("content-type", "")[:200] if response else None,
                                                discovered_from=source)
                    parsed_url = urlsplit(url)
                    for name, value in parse_qsl(parsed_url.query, keep_blank_values=True):
                        _add_input(session, assessment_id, resource, url, "GET", name, "query", None, value)
                    if parsed_url.fragment:
                        _add_input(session, assessment_id, resource, url, "GET", "<fragment>", "fragment", None, parsed_url.fragment)

                    if response is None:
                        continue
                    location = response.headers.get("location")
                    if response.is_redirect and location:
                        next_url = urljoin(url, location)
                        if _origin(next_url) == allowed_origin:
                            _enqueue(queue, queued_keys, seen_keys, next_url, depth, url, session, job_id)
                        continue
                    if is_javascript:
                        if len(response.content) <= MAX_HTML_BYTES:
                            analysis = analyze_javascript(response.text)
                            for endpoint in analysis["endpoints"]:
                                endpoint_url = urljoin(url, endpoint["path"])
                                if endpoint["method"] == "WS":
                                    parts = urlsplit(endpoint_url)
                                    if parts.scheme in {"http", "https"}:
                                        websocket_scheme = "wss" if parts.scheme == "https" else "ws"
                                        endpoint_url = urlunsplit((websocket_scheme, parts.netloc, parts.path, parts.query, ""))
                                    parts = urlsplit(endpoint_url)
                                    scope_scheme = {"ws": "http", "wss": "https"}.get(parts.scheme, parts.scheme)
                                    scope_url = urlunsplit((scope_scheme, parts.netloc, parts.path, parts.query, ""))
                                else:
                                    scope_url = endpoint_url
                                if _origin(scope_url) != allowed_origin:
                                    continue
                                endpoint_resource = _ensure_resource(
                                    session, assessment_id, endpoint_url, endpoint["method"], "javascript_endpoint", depth + 1,
                                    discovered_from=url,
                                )
                                endpoint_identifier = endpoint_resource.url
                                _save_javascript_observation(session, assessment_id, resource.id, {
                                    "kind": "endpoint",
                                    "identifier": endpoint_identifier,
                                    "source": endpoint["call"],
                                    "sink": "",
                                    "line": endpoint["line"],
                                    "confidence": endpoint["confidence"],
                                    "evidence": f"AST extracted a same-origin endpoint from {endpoint['call']} at line {endpoint['line']}; the endpoint was inventoried but not requested.",
                                })
                                if endpoint["method"] in {"GET", "POST", "WS", "SSE"}:
                                    for name, value in parse_qsl(urlsplit(endpoint_url).query, keep_blank_values=True):
                                        _add_input(session, assessment_id, endpoint_resource, endpoint_url, endpoint["method"],
                                                   name, "query", None, value)
                                for body_input in endpoint.get("inputs", []):
                                    _add_input(session, assessment_id, endpoint_resource, endpoint_url, endpoint["method"],
                                               body_input["name"], body_input["location"], body_input["input_type"], None)
                            for observation in analysis["observations"]:
                                _save_javascript_observation(session, assessment_id, resource.id, observation)
                            if analysis["parse_error"]:
                                _save_javascript_observation(session, assessment_id, resource.id, {
                                    "kind": "parse_status", "identifier": resource.url, "source": "", "sink": "",
                                    "line": 0, "confidence": "low",
                                    "evidence": "Tree-sitter reported syntax errors; extracted JavaScript indicators may be incomplete.",
                                })
                        continue
                    if depth >= assessment.max_depth:
                        continue
                    content_type = response_content_type
                    if "html" not in content_type or len(response.content) > MAX_HTML_BYTES:
                        continue
                    soup = BeautifulSoup(response.content, "html.parser")
                    title_tag = soup.title
                    if title_tag and title_tag.get_text(strip=True):
                        resource.title = title_tag.get_text(" ", strip=True)[:500]

                    for anchor in soup.select("a[href], area[href]"):
                        linked_url = urljoin(url, anchor.get("href", ""))
                        if _origin(linked_url) == allowed_origin:
                            linked_parts = urlsplit(linked_url)
                            if linked_parts.fragment:
                                _add_input(session, assessment_id, resource, linked_url, "GET", "<fragment>",
                                           "fragment", None, linked_parts.fragment)
                            request_url = urlunsplit((linked_parts.scheme, linked_parts.netloc, linked_parts.path or "/", linked_parts.query, ""))
                            _enqueue(queue, queued_keys, seen_keys, request_url, depth + 1, url, session, job_id)
                    for tag in soup.select("iframe[src], script[src], link[href]"):
                        attr = "src" if tag.has_attr("src") else "href"
                        next_url = urljoin(url, tag.get(attr, ""))
                        if _origin(next_url) == allowed_origin:
                            _enqueue(queue, queued_keys, seen_keys, next_url, depth + 1, url, session, job_id)

                    for form in soup.find_all("form"):
                        action = urljoin(url, form.get("action") or url)
                        if _origin(action) != allowed_origin:
                            continue
                        method = (form.get("method") or "GET").upper()
                        if method not in {"GET", "POST"}:
                            method = "POST"
                        form_resource = _ensure_resource(session, assessment_id, action, method, "form", depth + 1,
                                                         discovered_from=url)
                        for field in form.select("input[name], textarea[name], select[name], button[name]"):
                            name = field.get("name", "")
                            field_type = field.get("type", field.name)
                            value = field.get("value")
                            if field.name == "textarea":
                                value = field.get_text()
                            _add_input(session, assessment_id, form_resource, action, method, name, "body" if method == "POST" else "query",
                                       str(field_type), value)

                session.commit()
                session.refresh(assessment)

        if job_id is not None and not await _wait_for_job_control(session, assessment_id, job_id, worker_id):
            raise asyncio.CancelledError
        assessment.status = "completed"
        assessment.completed_at = utc_now()
        if job_id is not None:
            job = session.get(CrawlJob, job_id)
            if job is not None:
                job.status = "completed"
                job.lease_owner = None
                job.lease_expires_at = None
                job.updated_at = utc_now()
        session.commit()
    except asyncio.CancelledError:
        session.rollback()
        job = session.get(CrawlJob, job_id) if job_id is not None else None
        owns_job = job_id is None or (job is not None and (worker_id is None or job.lease_owner == worker_id))
        assessment = session.get(Assessment, assessment_id)
        if owns_job and assessment is not None:
            assessment.status = "cancelled"
            assessment.completed_at = utc_now()
        if owns_job and job is not None:
            job.status = "cancelled"
            job.lease_owner = None
            job.lease_expires_at = None
            job.updated_at = utc_now()
        session.commit()
        raise
    except Exception as exc:
        session.rollback()
        job = session.get(CrawlJob, job_id) if job_id is not None else None
        owns_job = job_id is None or (job is not None and (worker_id is None or job.lease_owner == worker_id))
        assessment = session.get(Assessment, assessment_id)
        if owns_job and assessment is not None:
            assessment.status = "failed"
            error_text = str(exc).lower()
            assessment.error_type = ("frontier_key_error" if "frontier" in error_text or "xss_sentinel_frontier_key" in error_text
                                     else "scope_error" if isinstance(exc, ValueError) else type(exc).__name__)
            assessment.completed_at = utc_now()
        if owns_job and job is not None:
            job.status = "failed"
            job.lease_owner = None
            job.lease_expires_at = None
            job.updated_at = utc_now()
        if owns_job:
            session.commit()
        else:
            session.rollback()
    finally:
        session.close()


def _frontier_request_key(url: str) -> str:
    return request_fingerprint(_request_key(url))


def _persist_frontier_item(session: Session, job_id: int, url: str, depth: int, source: str | None) -> int | None:
    request_key = _frontier_request_key(url)
    existing = session.scalar(select(CrawlFrontier.id).where(
        CrawlFrontier.job_id == job_id,
        CrawlFrontier.request_key == request_key,
    ))
    if existing is not None:
        return None
    row = CrawlFrontier(
        job_id=job_id,
        request_key=request_key,
        url_ciphertext=encrypt_frontier_value(url),
        source_ciphertext=encrypt_frontier_value(source) if source else None,
        depth=depth,
        status="pending",
    )
    session.add(row)
    session.flush()
    return row.id


def _enqueue(queue: deque, queued_keys: set[str], seen_keys: set[str], url: str, depth: int,
             source: str | None, session: Session, job_id: int | None) -> None:
    parsed = urlsplit(url)
    normalized = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
    key = _frontier_request_key(normalized)
    if key in seen_keys or key in queued_keys:
        return
    frontier_id = _persist_frontier_item(session, job_id, normalized, depth, source) if job_id is not None else None
    if job_id is not None and frontier_id is None:
        seen_keys.add(key)
        return
    queue.append((normalized, depth, source, frontier_id))
    seen_keys.add(key)
    queued_keys.add(key)
