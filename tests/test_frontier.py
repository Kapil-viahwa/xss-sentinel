import os
import tempfile
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from xss_sentinel.database import Base
from xss_sentinel.frontier import decrypt_frontier_value, encrypt_frontier_value, frontier_cipher
from xss_sentinel.models import Assessment, CrawlFrontier, CrawlJob
from xss_sentinel.crawler import _persist_frontier_item


class CrawlFrontierEncryptionTest(unittest.TestCase):
    def test_frontier_url_values_are_encrypted_and_recoverable(self):
        key = Fernet.generate_key().decode("ascii")
        with patch.dict(os.environ, {"XSS_SENTINEL_FRONTIER_KEY": key}):
            url = "https://app.example.test/search?token=private-value"
            encrypted = encrypt_frontier_value(url)
            self.assertNotIn("private-value", encrypted)
            self.assertEqual(decrypt_frontier_value(encrypted), url)

    def test_database_frontier_persists_encrypted_urls_and_deduplicates(self):
        key = Fernet.generate_key().decode("ascii")
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"XSS_SENTINEL_FRONTIER_KEY": key}):
            engine = create_engine(f"sqlite:///{os.path.join(directory, 'frontier.db')}")
            Base.metadata.create_all(engine)
            factory = sessionmaker(bind=engine, expire_on_commit=False)
            with factory() as session:
                assessment = Assessment(name="frontier", target_url="https://app.example.test/", status="queued")
                session.add(assessment)
                session.flush()
                job = CrawlJob(assessment_id=assessment.id, status="running")
                session.add(job)
                session.flush()
                url = "https://app.example.test/search?token=private-value&lang=en"
                row_id = _persist_frontier_item(session, job.id, url, 2, "https://app.example.test/source?secret=hidden")
                self.assertIsNotNone(row_id)
                self.assertIsNone(_persist_frontier_item(session, job.id, "https://app.example.test/search?lang=fr&token=other", 3, None))
                session.commit()
                row = session.get(CrawlFrontier, row_id)
                self.assertNotIn("private-value", row.url_ciphertext)
                self.assertNotIn("hidden", row.source_ciphertext)
                self.assertEqual(decrypt_frontier_value(row.url_ciphertext), url)
                self.assertEqual(decrypt_frontier_value(row.source_ciphertext), "https://app.example.test/source?secret=hidden")
            engine.dispose()

    def test_missing_or_changed_key_fails_closed(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                frontier_cipher()
        key_a = Fernet.generate_key().decode("ascii")
        key_b = Fernet.generate_key().decode("ascii")
        with patch.dict(os.environ, {"XSS_SENTINEL_FRONTIER_KEY": key_a}):
            encrypted = encrypt_frontier_value("https://app.example.test/")
        with patch.dict(os.environ, {"XSS_SENTINEL_FRONTIER_KEY": key_b}):
            with self.assertRaises(ValueError):
                decrypt_frontier_value(encrypted)


if __name__ == "__main__":
    unittest.main()
