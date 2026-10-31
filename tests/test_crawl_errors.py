import unittest

from xss_sentinel.crawler import ScopeValidationError, _crawl_error_type, _origin


class CrawlErrorClassificationTest(unittest.TestCase):
    def test_valid_https_target_has_a_stable_origin(self):
        self.assertEqual(_origin("https://fruituncle.in/"), ("https", "fruituncle.in", 443))

    def test_only_explicit_scope_validation_errors_are_scope_errors(self):
        self.assertEqual(_crawl_error_type(ScopeValidationError("invalid scope")), "scope_error")
        self.assertEqual(_crawl_error_type(ValueError("unexpected setup error")), "setup_error")

    def test_frontier_key_errors_are_reported_separately(self):
        self.assertEqual(
            _crawl_error_type(ValueError("Unable to decrypt a saved crawl frontier item")),
            "frontier_key_error",
        )

    def test_other_failures_keep_their_exception_type(self):
        self.assertEqual(_crawl_error_type(RuntimeError("unexpected")), "RuntimeError")


if __name__ == "__main__":
    unittest.main()
