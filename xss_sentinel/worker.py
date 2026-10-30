import argparse
import asyncio
import os
import socket
import uuid
from datetime import timedelta

from sqlalchemy import select, update

from .auth_profiles import get_auth_profile
from .database import SessionLocal
from .models import Assessment, AssessmentAuthProfileBinding, CrawlFrontier, CrawlJob, utc_now
from .crawler import crawl_assessment


LEASE_SECONDS = 90
HEARTBEAT_SECONDS = 20
MAX_JOB_ATTEMPTS = 3


def _claim_job(worker_id: str) -> tuple[int, int] | None:
    now = utc_now()
    with SessionLocal() as session:
        expired_jobs = select(CrawlJob.id).where(
            CrawlJob.status == "running", CrawlJob.lease_expires_at < now,
        )
        session.execute(
            update(CrawlFrontier)
            .where(CrawlFrontier.job_id.in_(expired_jobs), CrawlFrontier.status == "processing")
            .values(status="pending")
        )
        session.execute(
            update(CrawlJob)
            .where(CrawlJob.id.in_(expired_jobs))
            .values(status="queued", lease_owner=None, lease_expires_at=None, updated_at=now)
        )
        candidate_id = session.scalar(
            select(CrawlJob.id).where(CrawlJob.status == "queued")
            .order_by(CrawlJob.created_at, CrawlJob.id).limit(1)
        )
        if candidate_id is None:
            session.commit()
            return None
        claimed = session.execute(
            update(CrawlJob)
            .where(CrawlJob.id == candidate_id, CrawlJob.status == "queued")
            .values(status="running", attempts=CrawlJob.attempts + 1, lease_owner=worker_id,
                    lease_expires_at=now + timedelta(seconds=LEASE_SECONDS), updated_at=now)
        )
        if claimed.rowcount != 1:
            session.rollback()
            return None
        job = session.get(CrawlJob, candidate_id)
        assessment = session.get(Assessment, job.assessment_id)
        if assessment is None or assessment.status in {"cancelled", "completed"}:
            job.status = "cancelled"
            job.lease_owner = None
            job.lease_expires_at = None
            session.commit()
            return None
        if job.attempts > MAX_JOB_ATTEMPTS:
            job.status = "failed"
            job.lease_owner = None
            job.lease_expires_at = None
            assessment.status = "failed"
            assessment.error_type = "worker_attempts_exhausted"
            assessment.completed_at = now
            session.commit()
            return None
        assessment.status = "running"
        assessment.error_type = None
        session.commit()
        return job.id, assessment.id


async def _heartbeat(job_id: int, worker_id: str, stopped: asyncio.Event) -> None:
    while not stopped.is_set():
        try:
            await asyncio.wait_for(stopped.wait(), timeout=HEARTBEAT_SECONDS)
            return
        except asyncio.TimeoutError:
            pass
        now = utc_now()
        try:
            with SessionLocal() as session:
                updated = session.execute(
                    update(CrawlJob)
                    .where(CrawlJob.id == job_id, CrawlJob.lease_owner == worker_id,
                           CrawlJob.status.in_(["running", "paused"]))
                    .values(lease_expires_at=now + timedelta(seconds=LEASE_SECONDS), updated_at=now)
                )
                rowcount = updated.rowcount
                session.commit()
            if rowcount != 1:
                return
        except Exception:
            return


async def _execute_job(job_id: int, assessment_id: int, worker_id: str) -> None:
    with SessionLocal() as session:
        assessment = session.get(Assessment, assessment_id)
        profile_name = session.scalar(
            select(AssessmentAuthProfileBinding.profile_name)
            .where(AssessmentAuthProfileBinding.assessment_id == assessment_id)
        )
        if assessment is None:
            return
        target_url = assessment.target_url
    try:
        auth_profile = get_auth_profile(profile_name, target_url)
    except ValueError as exc:
        with SessionLocal() as session:
            job = session.get(CrawlJob, job_id)
            assessment = session.get(Assessment, assessment_id)
            if job is not None:
                job.status = "failed"
                job.lease_owner = None
                job.lease_expires_at = None
            if assessment is not None:
                assessment.status = "failed"
                assessment.error_type = "auth_profile_error"
                assessment.completed_at = utc_now()
            session.commit()
        return

    stopped = asyncio.Event()
    heartbeat = asyncio.create_task(_heartbeat(job_id, worker_id, stopped))
    try:
        await crawl_assessment(assessment_id, auth_profile, job_id=job_id, worker_id=worker_id)
    except asyncio.CancelledError:
        pass
    finally:
        stopped.set()
        await heartbeat


async def run_worker(poll_interval: float = 1.0, once: bool = False) -> None:
    worker_id = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    while True:
        claimed = _claim_job(worker_id)
        if claimed is None:
            if once:
                return
            await asyncio.sleep(poll_interval)
            continue
        await _execute_job(*claimed, worker_id)
        if once:
            return


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a database-backed XSS Sentinel crawl worker.")
    parser.add_argument("--once", action="store_true", help="claim at most one job and exit")
    parser.add_argument("--poll-interval", type=float, default=1.0)
    args = parser.parse_args()
    asyncio.run(run_worker(max(0.1, args.poll_interval), args.once))


if __name__ == "__main__":
    main()
