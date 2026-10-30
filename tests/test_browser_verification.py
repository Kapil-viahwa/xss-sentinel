import unittest

from xss_sentinel.browser_verification import SUPPORTED_CONTEXTS, _origin, _parameter_url, _payloads


class BrowserVerificationHelpersTest(unittest.TestCase):
    def test_html_text_payload_uses_only_the_local_execution_marker(self):
        payload = _payloads("html_text", "TESTMARKER")[0]
        self.assertIn("window.__xssSentinel('TESTMARKER')", payload)
        self.assertNotIn("alert(", payload)
        self.assertNotIn("fetch(", payload)

    def test_attribute_and_javascript_contexts_have_quote_variants(self):
        for context in ("html_attribute", "javascript_text"):
            with self.subTest(context=context):
                payloads = _payloads(context, "TESTMARKER")
                self.assertEqual(len(payloads), 2)
                self.assertTrue(all("TESTMARKER" in payload for payload in payloads))
                self.assertTrue(all("window.__xssSentinel" in payload for payload in payloads))

    def test_dom_source_payload_uses_the_local_execution_marker(self):
        payload = _payloads("dom_source", "TESTMARKER")[0]
        self.assertIn("window.__xssSentinel('TESTMARKER')", payload)

    def test_configured_callback_is_added_only_to_the_context_payload(self):
        payload = _payloads("html_text", "TESTMARKER", "https://oast.test/hit?xs=TESTMARKER")[0]
        self.assertIn("new Image()).src='https://oast.test/hit?xs=TESTMARKER'", payload)
        self.assertNotIn("fetch(", payload)

    def test_comment_and_style_contexts_have_local_execution_markers(self):
        for context in ("html_comment", "css_text"):
            with self.subTest(context=context):
                payloads = _payloads(context, "TESTMARKER")
                self.assertIn(context, SUPPORTED_CONTEXTS)
                self.assertTrue(payloads)
                self.assertTrue(all("window.__xssSentinel('TESTMARKER')" in payload for payload in payloads))
                self.assertTrue(all("fetch(" not in payload and "alert(" not in payload for payload in payloads))

    def test_unsupported_context_has_no_payloads(self):
        self.assertEqual(_payloads("url_attribute", "TESTMARKER"), [])
        self.assertEqual(_payloads("unknown", "TESTMARKER"), [])

    def test_parameter_url_preserves_other_parameters(self):
        self.assertEqual(
            _parameter_url("https://example.test/search?q=old&lang=en", "q", "new value"),
            "https://example.test/search?q=new+value&lang=en",
        )

    def test_origin_normalizes_default_port_and_rejects_credentials(self):
        self.assertEqual(_origin("https://example.test/"), _origin("https://EXAMPLE.test:443/path"))
        self.assertIsNone(_origin("https://user:pass@example.test/"))


if __name__ == "__main__":
    unittest.main()
