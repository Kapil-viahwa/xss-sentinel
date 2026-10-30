import os
import tempfile
import unittest
from datetime import timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from xss_sentinel.database import Base
from xss_sentinel.models import Assessment, CrawlFrontier, CrawlJob, utc_now
from xss_sentinel import worker


class WorkerQueueTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        path = os.path.join(self.temp_dir.name, "queue.db")
        self.engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
        Base.metadata.create_all(self.engine)
        self.session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.previous_session_factory = worker.SessionLocal
        worker.SessionLocal = self.session_factory

    def tearDown(self):
        worker.SessionLocal = self.previous_session_factory
        self.engine.dispose()
        self.temp_dir.cleanup()

    def test_claim_is_atomic_and_expired_lease_can_be_reclaimed(self):
        with self.session_factory() as session:
            assessment = Assessment(name="queue test", target_url="http://127.0.0.1:8084/", status="queued")
            session.add(assessment)
            session.flush()
            job = CrawlJob(assessment_id=assessment.id, status="queued")
            session.add(job)
            session.flush()
            frontier = CrawlFrontier(job_id=job.id, request_key="f" * 64, url_ciphertext="encrypted", status="pending")
            session.add(frontier)
            session.commit()
            job_id = job.id
            frontier_id = frontier.id

        first = worker._claim_job("worker-a")
        self.assertIsNotNone(first)
        self.assertEqual(worker._claim_job("worker-b"), None)
        with self.session_factory() as session:
            job = session.get(CrawlJob, job_id)
            job.lease_expires_at = utc_now() - timedelta(seconds=1)
            frontier = session.get(CrawlFrontier, frontier_id)
            frontier.status = "processing"
            session.commit()

        second = worker._claim_job("worker-b")
        self.assertEqual(second, first)
        with self.session_factory() as session:
            job = session.get(CrawlJob, job_id)
            self.assertEqual(job.attempts, 2)
            self.assertEqual(job.lease_owner, "worker-b")
            frontier = session.get(CrawlFrontier, frontier_id)
            self.assertEqual(frontier.status, "pending")


if __name__ == "__main__":
    unittest.main()
