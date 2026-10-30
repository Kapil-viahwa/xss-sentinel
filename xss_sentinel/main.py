from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from .crawler import crawl_assessment
from .database import Base, SessionLocal, engine
from .models import Assessment, Finding, InjectionPoint, Resource, WafObservation


BASE_DIR = Path(__file__).resolve().parent.parent
Base.metadata.create_all(bind=engine)
app = FastAPI(title="XSS Sentinel", version="0.1.0", description="Authorized web application assessment and XSS validation platform")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


class AssessmentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    target_url: str = Field(min_length=8, max_length=2048)
    authorization_confirmed: bool
    max_depth: int = Field(default=3, ge=0, le=10)
    max_requests: int = Field(default=100, ge=1, le=1000)
    concurrency: int = Field(default=4, ge=1, le=10)


def _display_target(value: str) -> str:
    parsed = urlsplit(value)
    safe_query = urlencode((name, "<redacted>") for name, _ in parse_qsl(parsed.query, keep_blank_values=True))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, safe_query, ""))


def _normalize_target(value: str) -> str:
    parsed = urlsplit(value.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=422, detail="Target must be an absolute HTTP or HTTPS URL.")
    if parsed.username is not None or parsed.password is not None:
        raise HTTPException(status_code=422, detail="Credentials must not be embedded in the target URL.")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Target URL has an invalid port.") from exc
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, ""))


def _assessment_dict(item: Assessment, session) -> dict:
    return {
        "id": item.id,
        "name": item.name,
        "target_url": _display_target(item.target_url),
        "status": item.status,
        "error_type": item.error_type,
        "max_depth": item.max_depth,
        "max_requests": item.max_requests,
        "concurrency": item.concurrency,
        "requests_made": item.requests_made,
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "completed_at": item.completed_at.isoformat() if item.completed_at else None,
        "resources": session.scalar(select(func.count(Resource.id)).where(Resource.assessment_id == item.id)) or 0,
        "injection_points": session.scalar(select(func.count(InjectionPoint.id)).where(InjectionPoint.assessment_id == item.id)) or 0,
        "findings": session.scalar(select(func.count(Finding.id)).where(Finding.assessment_id == item.id)) or 0,
    }


@app.get("/")
def dashboard():
    return FileResponse(BASE_DIR / "templates" / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "xss-sentinel"}


@app.get("/api/overview")
def overview():
    with SessionLocal() as session:
        return {
            "assessments": session.scalar(select(func.count(Assessment.id))) or 0,
            "urls_discovered": session.scalar(select(func.count(Resource.id)).where(Resource.kind == "page")) or 0,
            "endpoints_discovered": session.scalar(select(func.count(Resource.id)).where(Resource.kind == "form")) or 0,
            "injection_points": session.scalar(select(func.count(InjectionPoint.id))) or 0,
            "confirmed_vulnerabilities": session.scalar(select(func.count(Finding.id)).where(Finding.state == "confirmed")) or 0,
            "potential_vulnerabilities": session.scalar(select(func.count(Finding.id)).where(Finding.state == "potential")) or 0,
            "active_assessments": session.scalar(select(func.count(Assessment.id)).where(Assessment.status.in_(["queued", "running"]))) or 0,
            "waf_blocked": session.scalar(select(func.count(WafObservation.id)).where(WafObservation.result == "waf_blocked")) or 0,
        }


@app.get("/api/assessments")
def list_assessments():
    with SessionLocal() as session:
        items = session.scalars(select(Assessment).order_by(Assessment.created_at.desc())).all()
        return [_assessment_dict(item, session) for item in items]


@app.post("/api/assessments", status_code=201)
def create_assessment(payload: AssessmentCreate):
    if not payload.authorization_confirmed:
        raise HTTPException(status_code=400, detail="Explicit authorization confirmation is required.")
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Assessment name must not be empty.")
    target = _normalize_target(payload.target_url)
    with SessionLocal() as session:
        item = Assessment(
            name=name,
            target_url=target,
            status="created",
            max_depth=payload.max_depth,
            max_requests=payload.max_requests,
            concurrency=payload.concurrency,
        )
        session.add(item)
        session.commit()
        session.refresh(item)
        return _assessment_dict(item, session)


@app.post("/api/assessments/{assessment_id}/crawl")
async def start_crawl(assessment_id: int):
    with SessionLocal() as session:
        item = session.get(Assessment, assessment_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Assessment not found.")
        if item.status == "running":
            raise HTTPException(status_code=409, detail="Assessment is already running.")
        item.status = "queued"
        session.commit()
    await crawl_assessment(assessment_id)
    with SessionLocal() as session:
        item = session.get(Assessment, assessment_id)
        return _assessment_dict(item, session)


@app.get("/api/assessments/{assessment_id}/resources")
def assessment_resources(assessment_id: int):
    with SessionLocal() as session:
        if session.get(Assessment, assessment_id) is None:
            raise HTTPException(status_code=404, detail="Assessment not found.")
        rows = session.scalars(select(Resource).where(Resource.assessment_id == assessment_id).order_by(Resource.url)).all()
        return [{"id": row.id, "url": row.url, "method": row.method, "kind": row.kind, "depth": row.depth,
                 "status_code": row.status_code, "content_type": row.content_type, "title": row.title} for row in rows]


@app.get("/api/assessments/{assessment_id}/injection-points")
def assessment_injection_points(assessment_id: int):
    with SessionLocal() as session:
        if session.get(Assessment, assessment_id) is None:
            raise HTTPException(status_code=404, detail="Assessment not found.")
        rows = session.scalars(select(InjectionPoint).where(InjectionPoint.assessment_id == assessment_id)
                               .order_by(InjectionPoint.url, InjectionPoint.parameter_name)).all()
        return [{"id": row.id, "url": row.url, "method": row.method, "parameter": row.parameter_name,
                 "location": row.location, "input_type": row.input_type, "context": row.context,
                 "status": row.status, "original_value": row.original_value} for row in rows]
