import asyncio
import os
import tempfile
import unittest
from unittest.mock import patch

import httpx
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from xss_sentinel import crawler
from xss_sentinel.database import Base
from xss_sentinel.models import Assessment, CrawlFrontier, CrawlJob, Resource


class CrawlWorkerIntegrationTest(unittest.TestCase):
    def test_worker_crawl_persists_frontier_and_completes_for_valid_https_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = create_engine(
                f"sqlite:///{os.path.join(directory, 'crawl.db')}",
                connect_args={"check_same_thread": False},
            )
            Base.metadata.create_all(engine)
            factory = sessionmaker(bind=engine, expire_on_commit=False)
            previous_session_factory = crawler.SessionLocal
            crawler.SessionLocal = factory
            key = Fernet.generate_key().decode("ascii")
            real_async_client = httpx.AsyncClient

            def handler(request):
                body = (
                    b"<html><title>Root</title><a href='/next'>Next</a></html>"
                    if request.url.path == "/"
                    else b"<html><title>Next</title></html>"
                )
                return httpx.Response(
                    200, request=request, headers={"content-type": "text/html"}, content=body,
                )

            def mocked_async_client(*args, **kwargs):
                kwargs["transport"] = httpx.MockTransport(handler)
                return real_async_client(*args, **kwargs)

            with patch.dict(os.environ, {"XSS_SENTINEL_FRONTIER_KEY": key}):
                try:
                    with factory() as session:
                        assessment = Assessment(
                            name="valid origin integration",
                            target_url="https://fruituncle.in/",
                            status="running",
                            max_depth=1,
                            max_requests=5,
                            concurrency=1,
                        )
                        session.add(assessment)
                        session.flush()
                        job = CrawlJob(
                            assessment_id=assessment.id,
                            status="running",
                            lease_owner="worker-test",
                        )
                        session.add(job)
                        session.commit()
                        assessment_id = assessment.id
                        job_id = job.id

                    with patch.object(crawler.httpx, "AsyncClient", mocked_async_client):
                        asyncio.run(crawler.crawl_assessment(
                            assessment_id,
                            auth_profile={"headers": {}, "cookies": {}, "verify_tls": True},
                            job_id=job_id,
                            worker_id="worker-test",
                        ))

                    with factory() as session:
                        assessment = session.get(Assessment, assessment_id)
                        job = session.get(CrawlJob, job_id)
                        self.assertEqual(assessment.status, "completed")
                        self.assertEqual(assessment.requests_made, 2)
                        self.assertEqual(job.status, "completed")
                        self.assertEqual(session.query(Resource).filter_by(assessment_id=assessment_id).count(), 2)
                        frontier_rows = session.query(CrawlFrontier).filter_by(job_id=job_id).all()
                        self.assertEqual(len(frontier_rows), 2)
                        self.assertTrue(all(row.status == "done" for row in frontier_rows))
                finally:
                    crawler.SessionLocal = previous_session_factory
                    engine.dispose()


if __name__ == "__main__":
    unittest.main()
