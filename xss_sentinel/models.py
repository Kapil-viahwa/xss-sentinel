from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index, Integer, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Assessment(Base):
    __tablename__ = "assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="created")
    max_depth: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    max_requests: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    concurrency: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    requests_made: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_type: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Resource(Base):
    __tablename__ = "resources"
    __table_args__ = (
        UniqueConstraint("assessment_id", "method", "url", "kind", name="uq_resource_assessment_method_url_kind"),
        Index("ix_resources_assessment", "assessment_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    method: Mapped[str] = mapped_column(String(12), nullable=False, default="GET")
    kind: Mapped[str] = mapped_column(String(24), nullable=False, default="page")
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(200), nullable=True)
    title: Mapped[str | None] = mapped_column(String(500), nullable=True)
    discovered_from: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class InjectionPoint(Base):
    __tablename__ = "injection_points"
    __table_args__ = (
        UniqueConstraint("assessment_id", "url", "method", "parameter_name", "location", "input_type",
                         name="uq_injection_point_assessment_location"),
        Index("ix_injection_points_assessment", "assessment_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    resource_id: Mapped[int | None] = mapped_column(ForeignKey("resources.id", ondelete="SET NULL"), nullable=True)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    method: Mapped[str] = mapped_column(String(12), nullable=False)
    parameter_name: Mapped[str] = mapped_column(String(500), nullable=False)
    location: Mapped[str] = mapped_column(String(40), nullable=False)
    input_type: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    original_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    context: Mapped[str] = mapped_column(String(80), nullable=False, default="unassessed")
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="untested")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_assessment", "assessment_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    injection_point_id: Mapped[int | None] = mapped_column(ForeignKey("injection_points.id", ondelete="SET NULL"), nullable=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    severity: Mapped[str] = mapped_column(String(24), nullable=False)
    confidence: Mapped[str] = mapped_column(String(24), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="potential")
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)



class WafObservation(Base):
    __tablename__ = "waf_observations"
    __table_args__ = (Index("ix_waf_observations_assessment", "assessment_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    result: Mapped[str] = mapped_column(String(40), nullable=False)
    confidence: Mapped[str] = mapped_column(String(24), nullable=False, default="low")
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(120), nullable=True)
    vendors: Mapped[str | None] = mapped_column(Text, nullable=True)
    signals: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class ReflectionProbe(Base):
    __tablename__ = "reflection_probes"
    __table_args__ = (Index("ix_reflection_probes_input", "injection_point_id", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    injection_point_id: Mapped[int] = mapped_column(ForeignKey("injection_points.id", ondelete="CASCADE"), nullable=False)
    marker: Mapped[str] = mapped_column(String(80), nullable=False)
    result: Mapped[str] = mapped_column(String(24), nullable=False)
    context: Mapped[str] = mapped_column(String(80), nullable=False, default="unknown")
    baseline_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)



class BrowserVerification(Base):
    __tablename__ = "browser_verifications"
    __table_args__ = (Index("ix_browser_verifications_input", "injection_point_id", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    injection_point_id: Mapped[int] = mapped_column(ForeignKey("injection_points.id", ondelete="CASCADE"), nullable=False)
    marker: Mapped[str] = mapped_column(String(80), nullable=False)
    result: Mapped[str] = mapped_column(String(24), nullable=False)
    context: Mapped[str] = mapped_column(String(80), nullable=False)
    baseline_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dom_evidence: Mapped[str] = mapped_column(String(200), nullable=False)
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    console_error_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    page_error_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    screenshot_data: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)



class JavaScriptObservation(Base):
    __tablename__ = "javascript_observations"
    __table_args__ = (Index("ix_javascript_observations_assessment", "assessment_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    resource_id: Mapped[int] = mapped_column(ForeignKey("resources.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    identifier: Mapped[str] = mapped_column(String(2048), nullable=False)
    source: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    sink: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    line: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    confidence: Mapped[str] = mapped_column(String(24), nullable=False, default="low")
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)



class AssessmentAuthProfileBinding(Base):
    __tablename__ = "assessment_auth_profiles"
    __table_args__ = (UniqueConstraint("assessment_id", name="uq_assessment_auth_profile"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    profile_name: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)



class CrawlJob(Base):
    __tablename__ = "crawl_jobs"
    __table_args__ = (
        Index("ix_crawl_jobs_status_created", "status", "created_at"),
        Index("ix_crawl_jobs_lease", "status", "lease_expires_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="queued")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lease_owner: Mapped[str | None] = mapped_column(String(120), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)



class StoredXssTest(Base):
    __tablename__ = "stored_xss_tests"
    __table_args__ = (Index("ix_stored_xss_tests_input", "injection_point_id", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    injection_point_id: Mapped[int] = mapped_column(ForeignKey("injection_points.id", ondelete="CASCADE"), nullable=False)
    marker: Mapped[str] = mapped_column(String(80), nullable=False)
    callback_endpoint: Mapped[str] = mapped_column(String(2048), nullable=False)
    result: Mapped[str] = mapped_column(String(32), nullable=False)
    submission_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    verification_url_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    callback_request_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    callback_response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    screenshot_data: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)



class CrawlFrontier(Base):
    __tablename__ = "crawl_frontier"
    __table_args__ = (
        UniqueConstraint("job_id", "request_key", name="uq_crawl_frontier_job_request_key"),
        Index("ix_crawl_frontier_job_status", "job_id", "status", "id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("crawl_jobs.id", ondelete="CASCADE"), nullable=False)
    request_key: Mapped[str] = mapped_column(String(64), nullable=False)
    url_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    source_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)



class WebAuthnCredentialState(Base):
    __tablename__ = "webauthn_credential_state"

    credential_fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    rp_id: Mapped[str] = mapped_column(String(253), nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
