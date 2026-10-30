import asyncio
from collections import deque
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx
from bs4 import BeautifulSoup
from sqlalchemy import select
from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import Assessment, InjectionPoint, Resource, utc_now


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
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", urlencode((name, "") for name in names), ""))


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


async def crawl_assessment(assessment_id: int) -> None:
    session = SessionLocal()
    try:
        assessment = session.get(Assessment, assessment_id)
        if assessment is None:
            return
        assessment.status = "running"
        assessment.error_type = None
        assessment.completed_at = None
        assessment.requests_made = 0
        session.commit()

        start_url = assessment.target_url
        allowed_origin = _origin(start_url)
        if allowed_origin is None:
            raise ValueError("invalid_scope")

        queue = deque([(start_url, 0, None)])
        seen_keys: set[str] = set()
        queued_keys: set[str] = {_request_key(start_url)}
        timeout = httpx.Timeout(15.0, connect=8.0)
        limits = httpx.Limits(max_connections=assessment.concurrency, max_keepalive_connections=assessment.concurrency)
        headers = {"User-Agent": "XSS-Sentinel/0.1 (authorized security assessment)"}

        async with httpx.AsyncClient(timeout=timeout, limits=limits, follow_redirects=False, headers=headers) as client:
            while queue and assessment.requests_made < assessment.max_requests:
                batch = []
                while queue and len(batch) < assessment.concurrency and assessment.requests_made + len(batch) < assessment.max_requests:
                    item = queue.popleft()
                    key = _request_key(item[0])
                    queued_keys.discard(key)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    batch.append(item)
                if not batch:
                    continue

                async def fetch(item: tuple[str, int, str | None]):
                    url, depth, source = item
                    try:
                        response = await client.get(url)
                        return item, response, None
                    except (httpx.HTTPError, ValueError) as exc:
                        return item, None, type(exc).__name__

                results = await asyncio.gather(*(fetch(item) for item in batch))
                assessment.requests_made += len(batch)
                for (url, depth, source), response, _ in results:
                    resource = _ensure_resource(session, assessment_id, url, "GET", "page", depth,
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
                            _enqueue(queue, queued_keys, seen_keys, next_url, depth, url)
                        continue
                    if depth >= assessment.max_depth:
                        continue
                    content_type = response.headers.get("content-type", "").lower()
                    if "html" not in content_type or len(response.content) > MAX_HTML_BYTES:
                        continue
                    soup = BeautifulSoup(response.content, "html.parser")
                    title_tag = soup.title
                    if title_tag and title_tag.get_text(strip=True):
                        resource.title = title_tag.get_text(" ", strip=True)[:500]

                    for anchor in soup.select("a[href], area[href]"):
                        next_url = urljoin(url, anchor.get("href", ""))
                        if _origin(next_url) == allowed_origin:
                            _enqueue(queue, queued_keys, seen_keys, next_url, depth + 1, url)
                    for tag in soup.select("iframe[src], script[src], link[href]"):
                        attr = "src" if tag.has_attr("src") else "href"
                        next_url = urljoin(url, tag.get(attr, ""))
                        if _origin(next_url) == allowed_origin:
                            _enqueue(queue, queued_keys, seen_keys, next_url, depth + 1, url)

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

        assessment.status = "completed"
        assessment.completed_at = utc_now()
        session.commit()
    except Exception as exc:
        session.rollback()
        assessment = session.get(Assessment, assessment_id)
        if assessment is not None:
            assessment.status = "failed"
            assessment.error_type = "scope_error" if isinstance(exc, ValueError) else type(exc).__name__
            assessment.completed_at = utc_now()
            session.commit()
    finally:
        session.close()


def _enqueue(queue: deque, queued_keys: set[str], seen_keys: set[str], url: str, depth: int, source: str) -> None:
    parsed = urlsplit(url)
    normalized = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
    key = _request_key(normalized)
    if key not in seen_keys and key not in queued_keys:
        queue.append((normalized, depth, source))
        queued_keys.add(key)
