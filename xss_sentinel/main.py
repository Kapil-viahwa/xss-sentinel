import base64
import csv
import html
import io
import json
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Image as PdfImage, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .auth_profiles import auth_profile_names, get_auth_profile
from .database import Base, SessionLocal, engine, ensure_additive_schema
from .models import Assessment, AssessmentAuthProfileBinding, BrowserVerification, CrawlJob, Finding, InjectionPoint, JavaScriptObservation, ReflectionProbe, Resource, StoredXssTest, WafObservation, utc_now
from .reflection import run_reflection_probe
from .browser_verification import verify_browser_execution
from .stored_xss import run_stored_xss_test
from .frontier import frontier_cipher


BASE_DIR = Path(__file__).resolve().parent.parent
Base.metadata.create_all(bind=engine)
ensure_additive_schema()
app = FastAPI(title="XSS Sentinel", version="0.1.0", description="Authorized web application assessment and XSS validation platform")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.on_event("startup")
def reconcile_legacy_crawls():
    with SessionLocal() as session:
        active = session.scalars(select(Assessment).where(Assessment.status.in_(["queued", "running", "paused"]))).all()
        for assessment in active:
            job_id = session.scalar(select(CrawlJob.id).where(
                CrawlJob.assessment_id == assessment.id,
                CrawlJob.status.in_(["queued", "running", "paused"]),
            ).limit(1))
            if job_id is None:
                assessment.status = "interrupted"
                assessment.error_type = "missing_worker_job"
                assessment.completed_at = utc_now()
        if active:
            session.commit()


class BrowserVerifyRequest(BaseModel):
    execution_confirmed: bool
    mode: Literal["reflected", "dom"] = "reflected"


class StoredXssRequest(BaseModel):
    submission_confirmed: bool
    callback_confirmed: bool
    fields: dict[str, str]
    verification_urls: list[str] = Field(min_length=1, max_length=5)
    callback_url: str = Field(min_length=8, max_length=2048)
    body_format: Literal["form", "json"] = "form"
    context: Literal["html_text", "html_attribute", "javascript_text", "html_comment", "css_text"] = "html_text"


class AssessmentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    target_url: str = Field(min_length=8, max_length=2048)
    authorization_confirmed: bool
    max_depth: int = Field(default=3, ge=0, le=10)
    max_requests: int = Field(default=100, ge=1, le=5000)
    concurrency: int = Field(default=4, ge=1, le=10)
    auth_profile: str | None = Field(default=None, max_length=120)


def _display_target(value: str) -> str:
    parsed = urlsplit(value)
    safe_query = urlencode([(name, "<redacted>") for name, _ in parse_qsl(parsed.query, keep_blank_values=True)])
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
        "auth_profile": session.scalar(select(AssessmentAuthProfileBinding.profile_name).where(AssessmentAuthProfileBinding.assessment_id == item.id)),
        "status": item.status,
        "error_type": item.error_type,
        "max_depth": item.max_depth,
        "max_requests": item.max_requests,
        "concurrency": item.concurrency,
        "requests_made": item.requests_made,
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "completed_at": item.completed_at.isoformat() if item.completed_at else None,
        "resources": session.scalar(select(func.count(Resource.id)).where(Resource.assessment_id == item.id, Resource.kind == "page")) or 0,
        "endpoints": session.scalar(select(func.count(Resource.id)).where(Resource.assessment_id == item.id, Resource.kind.in_(["form", "javascript_endpoint"]))) or 0,
        "injection_points": session.scalar(select(func.count(InjectionPoint.id)).where(InjectionPoint.assessment_id == item.id)) or 0,
        "findings": session.scalar(select(func.count(Finding.id)).where(Finding.assessment_id == item.id)) or 0,
    }


@app.get("/")
def dashboard():
    return FileResponse(BASE_DIR / "templates" / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "xss-sentinel"}


@app.get("/api/auth-profiles")
def list_auth_profiles():
    try:
        return {"profiles": auth_profile_names()}
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="Server authentication profile configuration is invalid.") from exc


@app.get("/api/overview")
def overview():
    with SessionLocal() as session:
        return {
            "assessments": session.scalar(select(func.count(Assessment.id))) or 0,
            "urls_discovered": session.scalar(select(func.count(Resource.id)).where(Resource.kind == "page")) or 0,
            "endpoints_discovered": session.scalar(select(func.count(Resource.id)).where(Resource.kind.in_(["form", "javascript_endpoint"]))) or 0,
            "injection_points": session.scalar(select(func.count(InjectionPoint.id))) or 0,
            "confirmed_vulnerabilities": session.scalar(select(func.count(Finding.id)).where(Finding.state == "confirmed")) or 0,
            "potential_vulnerabilities": session.scalar(select(func.count(Finding.id)).where(Finding.state == "potential")) or 0,
            "active_assessments": session.scalar(select(func.count(Assessment.id)).where(Assessment.status.in_(["queued", "running", "paused"]))) or 0,
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
    auth_profile = payload.auth_profile.strip() if payload.auth_profile else None
    if auth_profile:
        try:
            get_auth_profile(auth_profile, target)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
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
        session.flush()
        if auth_profile:
            session.add(AssessmentAuthProfileBinding(assessment_id=item.id, profile_name=auth_profile))
        session.commit()
        session.refresh(item)
        return _assessment_dict(item, session)


@app.post("/api/assessments/{assessment_id}/crawl", status_code=202)
async def start_crawl(assessment_id: int):
    try:
        frontier_cipher()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    with SessionLocal() as session:
        item = session.get(Assessment, assessment_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Assessment not found.")
        profile_name = session.scalar(select(AssessmentAuthProfileBinding.profile_name).where(AssessmentAuthProfileBinding.assessment_id == assessment_id))
        try:
            get_auth_profile(profile_name, item.target_url)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        active_statuses = ["queued", "running", "paused"]
        claimed = session.execute(
            update(Assessment).where(Assessment.id == assessment_id, Assessment.status.notin_(active_statuses))
            .values(status="queued", error_type=None, completed_at=None, requests_made=0)
        )
        if claimed.rowcount != 1:
            raise HTTPException(status_code=409, detail="Assessment already has an active crawl.")
        session.add(CrawlJob(assessment_id=assessment_id, status="queued"))
        session.commit()
        session.refresh(item)
        return _assessment_dict(item, session)


@app.post("/api/assessments/{assessment_id}/pause")
async def pause_crawl(assessment_id: int):
    with SessionLocal() as session:
        item = session.get(Assessment, assessment_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Assessment not found.")
        job = session.scalar(select(CrawlJob).where(
            CrawlJob.assessment_id == assessment_id,
            CrawlJob.status.in_(["queued", "running"]),
        ).order_by(CrawlJob.created_at.desc(), CrawlJob.id.desc()).limit(1))
        if job is None:
            raise HTTPException(status_code=409, detail="No active crawl can be paused.")
        job.status = "paused"
        item.status = "paused"
        session.commit()
        return _assessment_dict(item, session)


@app.post("/api/assessments/{assessment_id}/resume")
async def resume_crawl(assessment_id: int):
    with SessionLocal() as session:
        item = session.get(Assessment, assessment_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Assessment not found.")
        if item.status != "paused":
            raise HTTPException(status_code=409, detail="Assessment is not paused.")
        job = session.scalar(select(CrawlJob).where(
            CrawlJob.assessment_id == assessment_id, CrawlJob.status == "paused",
        ).order_by(CrawlJob.created_at.desc(), CrawlJob.id.desc()).limit(1))
        if job is None:
            raise HTTPException(status_code=409, detail="No paused crawl can be resumed.")
        lease_expires_at = job.lease_expires_at
        if lease_expires_at is not None and lease_expires_at.tzinfo is None:
            lease_expires_at = lease_expires_at.replace(tzinfo=utc_now().tzinfo)
        if job.lease_owner and lease_expires_at and lease_expires_at > utc_now():
            job.status = "running"
            item.status = "running"
        else:
            job.status = "queued"
            job.lease_owner = None
            job.lease_expires_at = None
            item.status = "queued"
        session.commit()
        return _assessment_dict(item, session)


@app.post("/api/assessments/{assessment_id}/cancel")
async def cancel_crawl(assessment_id: int):
    with SessionLocal() as session:
        item = session.get(Assessment, assessment_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Assessment not found.")
        job = session.scalar(select(CrawlJob).where(
            CrawlJob.assessment_id == assessment_id,
            CrawlJob.status.in_(["queued", "running", "paused"]),
        ).order_by(CrawlJob.created_at.desc(), CrawlJob.id.desc()).limit(1))
        if job is None:
            raise HTTPException(status_code=409, detail="No active crawl can be cancelled.")
        job.status = "cancelled"
        job.lease_owner = None
        job.lease_expires_at = None
        job.updated_at = utc_now()
        item.status = "cancelled"
        item.completed_at = utc_now()
        session.commit()
        return _assessment_dict(item, session)


@app.get("/api/assessments/{assessment_id}/status")
def assessment_status(assessment_id: int):
    with SessionLocal() as session:
        item = session.get(Assessment, assessment_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Assessment not found.")
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
        probes = session.scalars(select(ReflectionProbe).join(InjectionPoint)
                                 .where(InjectionPoint.assessment_id == assessment_id)
                                 .order_by(ReflectionProbe.created_at.desc(), ReflectionProbe.id.desc())).all()
        latest_by_input = {}
        for probe in probes:
            latest_by_input.setdefault(probe.injection_point_id, probe)
        stored_tests = session.scalars(select(StoredXssTest).where(
            StoredXssTest.assessment_id == assessment_id
        ).order_by(StoredXssTest.created_at.desc(), StoredXssTest.id.desc())).all()
        latest_stored_by_input = {}
        for test in stored_tests:
            latest_stored_by_input.setdefault(test.injection_point_id, test)
        verifications = session.scalars(select(BrowserVerification).join(InjectionPoint)
                                        .where(InjectionPoint.assessment_id == assessment_id)
                                        .order_by(BrowserVerification.created_at.desc(), BrowserVerification.id.desc())).all()
        latest_verification_by_input = {}
        for verification in verifications:
            latest_verification_by_input.setdefault(verification.injection_point_id, verification)
        return [{"id": row.id, "url": row.url, "method": row.method, "parameter": row.parameter_name,
                 "location": row.location, "input_type": row.input_type, "context": row.context,
                 "status": row.status, "original_value": row.original_value,
                 "reflection_status": latest_by_input[row.id].result if row.id in latest_by_input else "not_checked",
                 "reflection_context": latest_by_input[row.id].context if row.id in latest_by_input else None,
                 "reflection_marker": latest_by_input[row.id].marker if row.id in latest_by_input else None,
                 "reflection_evidence": latest_by_input[row.id].evidence if row.id in latest_by_input else None,
                 "baseline_status": latest_by_input[row.id].baseline_status if row.id in latest_by_input else None,
                 "response_status": latest_by_input[row.id].response_status if row.id in latest_by_input else None,
                 "browser_result": latest_verification_by_input[row.id].result if row.id in latest_verification_by_input else "not_tested",
                 "browser_verification_id": latest_verification_by_input[row.id].id if row.id in latest_verification_by_input else None,
                 "browser_marker": latest_verification_by_input[row.id].marker if row.id in latest_verification_by_input else None,
                 "browser_console_error_count": latest_verification_by_input[row.id].console_error_count if row.id in latest_verification_by_input else 0,
                 "browser_page_error_count": latest_verification_by_input[row.id].page_error_count if row.id in latest_verification_by_input else 0,
                 "browser_evidence": latest_verification_by_input[row.id].evidence if row.id in latest_verification_by_input else None,
                 "browser_dom_evidence": latest_verification_by_input[row.id].dom_evidence if row.id in latest_verification_by_input else None,
                 "browser_baseline_status": latest_verification_by_input[row.id].baseline_status if row.id in latest_verification_by_input else None,
                 "browser_response_status": latest_verification_by_input[row.id].response_status if row.id in latest_verification_by_input else None,
                 "browser_screenshot_available": bool(latest_verification_by_input[row.id].screenshot_data) if row.id in latest_verification_by_input else False,
                 "stored_test_result": latest_stored_by_input[row.id].result if row.id in latest_stored_by_input else "not_tested",
                 "stored_test_id": latest_stored_by_input[row.id].id if row.id in latest_stored_by_input else None,
                 "stored_screenshot_available": bool(latest_stored_by_input[row.id].screenshot_data) if row.id in latest_stored_by_input else False,
                 "stored_callback_requests": latest_stored_by_input[row.id].callback_request_count if row.id in latest_stored_by_input else 0,
                 "stored_callback_response_status": latest_stored_by_input[row.id].callback_response_status if row.id in latest_stored_by_input else None}
                for row in rows]


@app.post("/api/assessments/{assessment_id}/injection-points/{point_id}/reflection-probe")
async def create_reflection_probe(assessment_id: int, point_id: int):
    with SessionLocal() as session:
        assessment = session.get(Assessment, assessment_id)
        point = session.get(InjectionPoint, point_id)
        if assessment is None or point is None or point.assessment_id != assessment_id:
            raise HTTPException(status_code=404, detail="Injection point not found.")
        target_url = assessment.target_url
        profile_name = session.scalar(select(AssessmentAuthProfileBinding.profile_name).where(AssessmentAuthProfileBinding.assessment_id == assessment_id))
        try:
            auth_profile = get_auth_profile(profile_name, target_url)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    try:
        result = await run_reflection_probe(point, target_url, auth_profile)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    with SessionLocal() as session:
        point = session.get(InjectionPoint, point_id)
        record = ReflectionProbe(
            injection_point_id=point_id,
            marker=result["marker"],
            result=result["result"],
            context=result["context"],
            baseline_status=result["baseline_status"],
            response_status=result["response_status"],
            evidence=result["evidence"],
        )
        point.context = result["context"]
        session.add(record)
        if result.get("waf_result"):
            session.add(WafObservation(
                assessment_id=assessment_id,
                result=result["waf_result"],
                confidence=result["waf_confidence"] or "low",
                evidence=result["waf_evidence"],
                vendor=result.get("waf_vendor"),
                vendors=json.dumps(result.get("waf_vendors", [])),
                signals=json.dumps(result.get("waf_signals", [])),
            ))
        session.commit()
        session.refresh(record)
        return {"id": record.id, "marker": record.marker, "result": record.result, "context": record.context,
                "baseline_status": record.baseline_status, "response_status": record.response_status,
                "evidence": record.evidence, "waf_result": result.get("waf_result"),
                "waf_vendor": result.get("waf_vendor"), "waf_vendors": result.get("waf_vendors", []),
                "waf_signals": result.get("waf_signals", []), "waf_evidence": result.get("waf_evidence"),
                "created_at": record.created_at.isoformat()}



@app.post("/api/assessments/{assessment_id}/injection-points/{point_id}/stored-test")
async def create_stored_xss_test(assessment_id: int, point_id: int, payload: StoredXssRequest):
    if not payload.submission_confirmed or not payload.callback_confirmed:
        raise HTTPException(status_code=400, detail="Explicit confirmation is required before submitting a stored-XSS test or sending a callback beacon.")
    with SessionLocal() as session:
        assessment = session.get(Assessment, assessment_id)
        point = session.get(InjectionPoint, point_id)
        if assessment is None or point is None or point.assessment_id != assessment_id:
            raise HTTPException(status_code=404, detail="Injection point not found.")
        target_url = assessment.target_url
        profile_name = session.scalar(select(AssessmentAuthProfileBinding.profile_name).where(AssessmentAuthProfileBinding.assessment_id == assessment_id))
        try:
            auth_profile = get_auth_profile(profile_name, target_url)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    try:
        result = await run_stored_xss_test(
            point, target_url, auth_profile, payload.fields, payload.verification_urls,
            payload.callback_url, payload.body_format, payload.context,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    with SessionLocal() as session:
        point = session.get(InjectionPoint, point_id)
        record = StoredXssTest(
            assessment_id=assessment_id,
            injection_point_id=point_id,
            marker=result["marker"],
            callback_endpoint=result["callback_endpoint"],
            result=result["result"],
            submission_status=result["submission_status"],
            verification_url_count=result["verification_url_count"],
            callback_request_count=result["callback_request_count"],
            callback_response_status=result["callback_response_status"],
            evidence=result["evidence"],
            screenshot_data=result["screenshot_data"],
        )
        session.add(record)
        session.flush()
        if result["result"] in {"stored_confirmed", "blind_confirmed"}:
            point.status = "confirmed"
            category = "blind_xss" if result["result"] == "blind_confirmed" else "stored_xss"
            existing = session.scalar(select(Finding.id).where(
                Finding.injection_point_id == point_id,
                Finding.category == category,
                Finding.state == "confirmed",
            ))
            if existing is None:
                session.add(Finding(
                    assessment_id=assessment_id,
                    injection_point_id=point_id,
                    title="Blind stored XSS confirmed by callback" if category == "blind_xss" else "Stored XSS confirmed by browser execution",
                    category=category,
                    severity="medium",
                    confidence="high",
                    state="confirmed",
                    evidence=f"Stored verification {record.id}: {result['evidence']}",
                ))
        else:
            point.status = "inconclusive" if result["result"] in {"inconclusive", "submission_inconclusive"} else "tested"
        session.commit()
        session.refresh(record)
        return {"id": record.id, "marker": record.marker, "result": record.result,
                "submission_status": record.submission_status,
                "verification_url_count": record.verification_url_count,
                "callback_request_count": record.callback_request_count,
                "callback_response_status": record.callback_response_status,
                "evidence": record.evidence, "screenshot_available": bool(record.screenshot_data)}


@app.post("/api/assessments/{assessment_id}/injection-points/{point_id}/browser-verify")
async def create_browser_verification(assessment_id: int, point_id: int, payload: BrowserVerifyRequest):
    if not payload.execution_confirmed:
        raise HTTPException(status_code=400, detail="Explicit confirmation is required before browser execution checks.")
    with SessionLocal() as session:
        assessment = session.get(Assessment, assessment_id)
        point = session.get(InjectionPoint, point_id)
        if assessment is None or point is None or point.assessment_id != assessment_id:
            raise HTTPException(status_code=404, detail="Injection point not found.")
        target_url = assessment.target_url
        if payload.mode == "dom":
            latest_probe = session.scalar(select(ReflectionProbe).where(ReflectionProbe.injection_point_id == point_id)
                                          .order_by(ReflectionProbe.created_at.desc(), ReflectionProbe.id.desc()).limit(1))
            if latest_probe is not None and latest_probe.result == "reflected":
                raise HTTPException(status_code=409, detail="The input reflects in the HTTP response; use reflected-context browser verification instead.")
        profile_name = session.scalar(select(AssessmentAuthProfileBinding.profile_name).where(AssessmentAuthProfileBinding.assessment_id == assessment_id))
        try:
            auth_profile = get_auth_profile(profile_name, target_url)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    try:
        result = await verify_browser_execution(point, target_url, auth_profile, payload.mode)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    with SessionLocal() as session:
        point = session.get(InjectionPoint, point_id)
        record = BrowserVerification(
            injection_point_id=point_id,
            marker=result["marker"],
            result=result["result"],
            context=result["context"],
            baseline_status=result["baseline_status"],
            response_status=result["response_status"],
            dom_evidence=result["dom_evidence"],
            evidence=result["evidence"],
            console_error_count=result["console_error_count"],
            page_error_count=result["page_error_count"],
            screenshot_data=result["screenshot_data"],
        )
        point.status = "confirmed" if result["result"] == "confirmed" else ("inconclusive" if result["result"] == "inconclusive" else "tested")
        session.add(record)
        session.flush()
        if result["result"] == "confirmed":
            category = "dom_xss" if payload.mode == "dom" else "reflected_xss"
            title = "DOM-based XSS confirmed by browser execution" if payload.mode == "dom" else "Reflected XSS confirmed by browser execution"
            existing = session.scalar(select(Finding.id).where(
                Finding.injection_point_id == point_id,
                Finding.category == category,
                Finding.state == "confirmed",
            ))
            if existing is None:
                session.add(Finding(
                    assessment_id=assessment_id,
                    injection_point_id=point_id,
                    title=title,
                    category=category,
                    severity="medium",
                    confidence="high",
                    state="confirmed",
                    evidence=f"Verification {record.id}: {result['evidence']} {result['dom_evidence']}",
                ))
        session.commit()
        session.refresh(record)
        return {"id": record.id, "result": record.result, "context": record.context,
                "baseline_status": record.baseline_status, "response_status": record.response_status,
                "evidence": record.evidence, "screenshot_available": bool(record.screenshot_data)}


@app.get("/api/browser-verifications/{verification_id}/screenshot")
def browser_verification_screenshot(verification_id: int):
    with SessionLocal() as session:
        record = session.get(BrowserVerification, verification_id)
        if record is None or record.screenshot_data is None:
            raise HTTPException(status_code=404, detail="Verification screenshot not found.")
        return Response(content=record.screenshot_data, media_type="image/png")


@app.get("/api/stored-xss-tests/{test_id}/screenshot")
def stored_xss_test_screenshot(test_id: int):
    with SessionLocal() as session:
        record = session.get(StoredXssTest, test_id)
        if record is None or record.screenshot_data is None:
            raise HTTPException(status_code=404, detail="Stored-XSS screenshot not found.")
        return Response(content=record.screenshot_data, media_type="image/png")




def _cvss_estimate(category: str) -> dict | None:
    if category not in {"reflected_xss", "dom_xss", "stored_xss", "blind_xss"}:
        return None
    return {
        "version": "3.1",
        "score": 6.1,
        "severity": "Medium",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "assumptions": "Unauthenticated network-reachable XSS requiring victim interaction; context-specific impact may differ.",
    }


def _assessment_report_data(session, assessment_id: int) -> dict:
    assessment = session.get(Assessment, assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    rows = session.execute(
        select(Finding, InjectionPoint)
        .outerjoin(InjectionPoint, Finding.injection_point_id == InjectionPoint.id)
        .where(Finding.assessment_id == assessment_id)
        .order_by(Finding.created_at.desc(), Finding.id.desc())
    ).all()
    point_ids = [point.id for _, point in rows if point is not None]
    verified_rows = session.scalars(select(BrowserVerification)
                                    .where(BrowserVerification.injection_point_id.in_(point_ids), BrowserVerification.result == "confirmed")
                                    .order_by(BrowserVerification.created_at.desc(), BrowserVerification.id.desc())).all() if point_ids else []
    latest_verified_by_input = {}
    for verification in verified_rows:
        latest_verified_by_input.setdefault(verification.injection_point_id, verification)
    stored_rows = session.scalars(select(StoredXssTest)
                                  .where(StoredXssTest.injection_point_id.in_(point_ids), StoredXssTest.result.in_(["stored_confirmed", "blind_confirmed"]))
                                  .order_by(StoredXssTest.created_at.desc(), StoredXssTest.id.desc())).all() if point_ids else []
    latest_stored_by_input = {}
    for stored_test in stored_rows:
        latest_stored_by_input.setdefault(stored_test.injection_point_id, stored_test)
    findings = []
    for finding, point in rows:
        verification = latest_verified_by_input.get(point.id) if point else None
        stored_test = latest_stored_by_input.get(point.id) if point else None
        findings.append({
            "id": finding.id,
            "title": finding.title,
            "url": point.url if point else None,
            "method": point.method if point else None,
            "parameter": point.parameter_name if point else None,
            "category": finding.category,
            "severity": finding.severity,
            "cvss": _cvss_estimate(finding.category) if finding.state == "confirmed" else None,
            "confidence": finding.confidence,
            "state": finding.state,
            "evidence": finding.evidence or "",
            "browser_marker": verification.marker if verification else (stored_test.marker if stored_test else None),
            "browser_evidence": verification.evidence if verification else (stored_test.evidence if stored_test else None),
            "dom_evidence": verification.dom_evidence if verification else (stored_test.result if stored_test else None),
            "stored_callback_requests": stored_test.callback_request_count if stored_test else 0,
            "stored_callback_response_status": stored_test.callback_response_status if stored_test else None,
            "screenshot_base64": base64.b64encode(
                verification.screenshot_data if verification and verification.screenshot_data else stored_test.screenshot_data
            ).decode("ascii") if (verification and verification.screenshot_data) or (stored_test and stored_test.screenshot_data) else None,
            "created_at": finding.created_at.isoformat() if finding.created_at else None,
            "remediation": "Review context-appropriate output encoding and remove unsafe HTML/JavaScript sinks. Retest after remediation.",
        })
    waf_rows = session.scalars(select(WafObservation).where(WafObservation.assessment_id == assessment_id)
                               .order_by(WafObservation.created_at.desc(), WafObservation.id.desc())).all()
    waf_observations = [{
        "result": row.result,
        "confidence": row.confidence,
        "vendor": row.vendor,
        "vendors": json.loads(row.vendors or "[]"),
        "signals": json.loads(row.signals or "[]"),
        "evidence": row.evidence or "",
        "created_at": row.created_at.isoformat() if row.created_at else None,
    } for row in waf_rows]
    resource_rows = session.scalars(
        select(Resource).where(Resource.assessment_id == assessment_id).order_by(Resource.url)
    ).all()
    return {
        "assessment": {
            "id": assessment.id,
            "name": assessment.name,
            "target_url": _display_target(assessment.target_url),
            "status": assessment.status,
            "auth_profile": session.scalar(select(AssessmentAuthProfileBinding.profile_name).where(AssessmentAuthProfileBinding.assessment_id == assessment_id)),
            "created_at": assessment.created_at.isoformat() if assessment.created_at else None,
            "completed_at": assessment.completed_at.isoformat() if assessment.completed_at else None,
            "requests_made": assessment.requests_made,
        },
        "summary": {
            "urls_discovered": session.scalar(select(func.count(Resource.id)).where(Resource.assessment_id == assessment_id, Resource.kind == "page")) or 0,
            "endpoints_discovered": session.scalar(select(func.count(Resource.id)).where(Resource.assessment_id == assessment_id, Resource.kind.in_(["form", "javascript_endpoint"]))) or 0,
            "injection_points": session.scalar(select(func.count(InjectionPoint.id)).where(InjectionPoint.assessment_id == assessment_id)) or 0,
            "findings": len(findings),
            "confirmed": sum(1 for finding in findings if finding["state"] == "confirmed"),
            "waf_observations": len(waf_observations),
            "waf_blocked": sum(1 for observation in waf_observations if observation["result"] == "waf_blocked"),
        },
        "findings": findings,
        "resources": [{"url": row.url, "kind": row.kind, "status_code": row.status_code} for row in resource_rows],
        "waf_observations": waf_observations,
    }


def _csv_safe(value) -> str:
    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


def _pdf_text(value: str) -> str:
    printable = str(value).encode("cp1252", errors="replace").decode("cp1252")
    return html.escape(printable).replace("\n", "<br/>")


def _report_pdf(payload: dict) -> bytes:
    output = io.BytesIO()
    document = SimpleDocTemplate(output, pagesize=letter, rightMargin=42, leftMargin=42, topMargin=42, bottomMargin=42)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("XSS Sentinel Assessment Report", styles["Title"]),
        Spacer(1, 10),
        Paragraph(_pdf_text(payload["assessment"]["name"]), styles["Heading2"]),
        Paragraph(_pdf_text(payload["assessment"]["target_url"]), styles["BodyText"]),
        Spacer(1, 10),
    ]
    summary = payload["summary"]
    summary_table = Table([
        ["URLs", "Endpoints", "Inputs", "Findings", "Confirmed", "WAF blocks"],
        [str(summary["urls_discovered"]), str(summary["endpoints_discovered"]), str(summary["injection_points"]),
         str(summary["findings"]), str(summary["confirmed"]), str(summary["waf_blocked"])],
    ], colWidths=[85, 85, 85, 85, 85, 85])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#24364f")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#aab6c5")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([summary_table, Spacer(1, 14)])
    if not payload["findings"]:
        story.append(Paragraph("No findings have been confirmed or recorded for this assessment.", styles["BodyText"]))
    if payload["waf_observations"]:
        story.extend([Paragraph("Security-control observations", styles["Heading2"]), Spacer(1, 6)])
        for observation in payload["waf_observations"]:
            vendors = ", ".join(observation["vendors"]) or observation["vendor"] or "Unattributed"
            signals = ", ".join(observation["signals"]) or "no distinctive signals"
            story.append(Paragraph(f"{_pdf_text(vendors)} · {_pdf_text(observation['result'])} · {_pdf_text(observation['confidence'])}: {_pdf_text(observation['evidence'])} Signals: {_pdf_text(signals)}", styles["BodyText"]))
            story.append(Spacer(1, 4))
    for finding in payload["findings"]:
        story.append(Paragraph(_pdf_text(finding["title"]), styles["Heading3"]))
        details = [
            f"Severity: {_pdf_text(finding['severity'])} · Confidence: {_pdf_text(finding['confidence'])} · State: {_pdf_text(finding['state'])}",
            f"CVSS estimate: {_pdf_text(str(finding['cvss']['score']) + ' (' + finding['cvss']['vector'] + ')') if finding['cvss'] else 'Not scored'}",
            f"CVSS assumptions: {_pdf_text(finding['cvss']['assumptions']) if finding['cvss'] else 'Not scored'}",
            f"Location: {_pdf_text(finding['method'] or '—')} {_pdf_text(finding['url'] or '—')}",
            f"Parameter: {_pdf_text(finding['parameter'] or '—')} · Category: {_pdf_text(finding['category'])}",
            f"Evidence: {_pdf_text(finding['evidence'][:1800])}",
            f"Remediation: {_pdf_text(finding['remediation'])}",
        ]
        story.append(Paragraph("<br/>".join(details), styles["BodyText"]))
        if finding["screenshot_base64"]:
            image_data = base64.b64decode(finding["screenshot_base64"], validate=True)
            story.append(PdfImage(io.BytesIO(image_data), width=430, height=242, kind="proportional"))
        story.append(Spacer(1, 10))
    document.build(story)
    return output.getvalue()


@app.get("/api/assessments/{assessment_id}/report.json")
def assessment_report_json(assessment_id: int):
    with SessionLocal() as session:
        payload = _assessment_report_data(session, assessment_id)
    return Response(content=json.dumps(payload, ensure_ascii=False, indent=2), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="xss-sentinel-{assessment_id}.json"'})


@app.get("/api/assessments/{assessment_id}/report.csv")
def assessment_report_csv(assessment_id: int):
    with SessionLocal() as session:
        payload = _assessment_report_data(session, assessment_id)
    output = io.StringIO(newline="")
    columns = ["id", "title", "url", "method", "parameter", "category", "severity", "confidence", "state", "cvss", "cvss_assumptions", "evidence", "browser_marker", "browser_evidence", "remediation", "created_at"]
    writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for finding in payload["findings"]:
        row = dict(finding)
        cvss = finding.get("cvss")
        row["cvss"] = f"{cvss['score']} {cvss['vector']}" if cvss else ""
        row["cvss_assumptions"] = cvss["assumptions"] if cvss else ""
        writer.writerow({key: _csv_safe(row.get(key)) for key in columns})
    return Response(content=output.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="xss-sentinel-{assessment_id}.csv"'})


@app.get("/api/assessments/{assessment_id}/report.html")
def assessment_report_html(assessment_id: int):
    with SessionLocal() as session:
        payload = _assessment_report_data(session, assessment_id)
    summary = payload["summary"]
    cards = "".join(f"<li><strong>{label}:</strong> {summary[key]}</li>" for label, key in (
        ("URLs", "urls_discovered"), ("Endpoints", "endpoints_discovered"), ("Input points", "injection_points"),
        ("Findings", "findings"), ("Confirmed", "confirmed")))
    findings_html = []
    for finding in payload["findings"]:
        screenshot = (f'<img alt="Execution evidence" style="max-width:700px" src="data:image/png;base64,{finding["screenshot_base64"]}">' 
                      if finding["screenshot_base64"] else "")
        findings_html.append(
            "<article><h2>{}</h2><p><strong>{}</strong> · {} confidence · {}</p><p>{} {} · parameter {}</p>"
            "<p><strong>CVSS estimate:</strong> {}</p><p><strong>Evidence:</strong> {}</p><p><strong>Browser:</strong> {}</p><p><strong>Remediation:</strong> {}</p>{}</article>".format(
                html.escape(finding["title"]), html.escape(finding["severity"]), html.escape(finding["confidence"]),
                html.escape(finding["state"]), html.escape(finding["method"] or "—"), html.escape(finding["url"] or "—"),
                html.escape(finding["parameter"] or "—"),
                html.escape(
                    f"{finding['cvss']['score']} {finding['cvss']['vector']} — {finding['cvss']['assumptions']}"
                    if finding["cvss"] else "Not scored"
                ),
                html.escape(finding["evidence"]), html.escape(finding["browser_evidence"] or "Not available"),
                html.escape(finding["remediation"]), screenshot))
    content = "".join(findings_html) or "<p>No findings have been recorded.</p>"
    waf_html = "".join(f"<li>{html.escape(', '.join(item['vendors']) or item['vendor'] or 'Unattributed')} · {html.escape(item['result'])} ({html.escape(item['confidence'])}): {html.escape(item['evidence'])} Signals: {html.escape(', '.join(item['signals']))}</li>" for item in payload["waf_observations"])
    waf_section = f"<section><h2>Security-control observations</h2><ul>{waf_html}</ul></section>" if waf_html else ""
    document = ("<!doctype html><html lang='en'><meta charset='utf-8'><title>XSS Sentinel Report</title>"
                "<style>body{font:15px system-ui;max-width:900px;margin:40px auto;color:#182335}h1{color:#2457a6}article{border-top:1px solid #ccd5e0;padding:12px 0}li{margin:5px 0}</style>"
                f"<h1>XSS Sentinel Assessment Report</h1><h2>{html.escape(payload['assessment']['name'])}</h2>"
                f"<p>Target: {html.escape(payload['assessment']['target_url'])}</p><ul>{cards}</ul>{content}{waf_section}</html>")
    return Response(content=document, media_type="text/html; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="xss-sentinel-{assessment_id}.html"'})


@app.get("/api/assessments/{assessment_id}/report.pdf")
def assessment_report_pdf(assessment_id: int):
    with SessionLocal() as session:
        payload = _assessment_report_data(session, assessment_id)
    return Response(content=_report_pdf(payload), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="xss-sentinel-{assessment_id}.pdf"'})



@app.get("/api/assessments/{assessment_id}/waf-observations")
def assessment_waf_observations(assessment_id: int):
    with SessionLocal() as session:
        if session.get(Assessment, assessment_id) is None:
            raise HTTPException(status_code=404, detail="Assessment not found.")
        rows = session.scalars(select(WafObservation).where(WafObservation.assessment_id == assessment_id)
                               .order_by(WafObservation.created_at.desc(), WafObservation.id.desc())).all()
        return [{"id": row.id, "result": row.result, "confidence": row.confidence,
                 "vendor": row.vendor, "vendors": json.loads(row.vendors or "[]"),
                 "signals": json.loads(row.signals or "[]"),
                 "evidence": row.evidence, "created_at": row.created_at.isoformat()} for row in rows]



@app.get("/api/assessments/{assessment_id}/javascript-analysis")
def assessment_javascript_analysis(assessment_id: int):
    with SessionLocal() as session:
        if session.get(Assessment, assessment_id) is None:
            raise HTTPException(status_code=404, detail="Assessment not found.")
        rows = session.execute(
            select(JavaScriptObservation, Resource.url)
            .join(Resource, JavaScriptObservation.resource_id == Resource.id)
            .where(JavaScriptObservation.assessment_id == assessment_id)
            .order_by(JavaScriptObservation.created_at.desc(), JavaScriptObservation.id.desc())
        ).all()
        return [{"id": observation.id, "kind": observation.kind, "script_url": script_url,
                 "identifier": observation.identifier, "source": observation.source, "sink": observation.sink,
                 "line": observation.line, "confidence": observation.confidence, "evidence": observation.evidence}
                for observation, script_url in rows]
