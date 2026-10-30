from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
