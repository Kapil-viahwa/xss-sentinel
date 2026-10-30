import unittest

from xss_sentinel.main import _cvss_estimate, _csv_safe, _display_target, _pdf_text, _report_pdf


class ReportHelpersTest(unittest.TestCase):
    def test_csv_formula_prefix_is_neutralized(self):
        self.assertEqual(_csv_safe("=1+1"), "'=1+1")
        self.assertEqual(_csv_safe("ordinary"), "ordinary")

    def test_display_target_redacts_query_values(self):
        self.assertEqual(
            _display_target("https://example.test/path?token=secret&name=Alice"),
            "https://example.test/path?token=%3Credacted%3E&name=%3Credacted%3E",
        )

    def test_xss_cvss_estimate_discloses_its_vector_and_assumptions(self):
        estimate = _cvss_estimate("reflected_xss")
        self.assertEqual(estimate["score"], 6.1)
        self.assertEqual(estimate["severity"], "Medium")
        self.assertIn("UI:R", estimate["vector"])
        self.assertIn("assumptions", estimate)
        self.assertIsNone(_cvss_estimate("other"))

    def test_pdf_text_escapes_markup_and_normalizes_newlines(self):
        self.assertEqual(_pdf_text("<tag>\nvalue"), "&lt;tag&gt;<br/>value")

    def test_pdf_report_has_a_valid_header(self):
        payload = {
            "assessment": {"name": "Example", "target_url": "https://example.test/"},
            "summary": {"urls_discovered": 1, "endpoints_discovered": 0, "injection_points": 1, "findings": 0, "confirmed": 0, "waf_blocked": 0},
            "findings": [],
            "waf_observations": [],
        }
        self.assertTrue(_report_pdf(payload).startswith(b"%PDF-"))


if __name__ == "__main__":
    unittest.main()
