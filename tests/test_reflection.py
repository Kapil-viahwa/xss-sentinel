import os
import unittest

from xss_sentinel.reflection import _MarkerContextParser, _locate_marker, _origin, _parameter_url, _waf_observation


class ReflectionHelpersTest(unittest.TestCase):
    def test_parameter_url_replaces_only_the_selected_input(self):
        result = _parameter_url("https://example.test/search?q=old&lang=en", "q", "sentinel")
        self.assertEqual(result, "https://example.test/search?q=sentinel&lang=en")

    def test_parameter_url_adds_missing_input(self):
        result = _parameter_url("https://example.test/search", "q", "sentinel")
        self.assertEqual(result, "https://example.test/search?q=sentinel")

    def test_context_parser_identifies_html_text(self):
        parser = _MarkerContextParser("SENTINEL")
        parser.feed("<p>SENTINEL</p>")
        self.assertEqual(parser.contexts, {"html_text"})

    def test_context_parser_identifies_attributes_and_script_text(self):
        cases = {
            '<div title="SENTINEL">x</div>': "html_attribute",
            '<a href="SENTINEL">x</a>': "url_attribute",
            '<script>const value = "SENTINEL";</script>': "javascript_text",
        }
        for source, expected in cases.items():
            with self.subTest(expected=expected):
                parser = _MarkerContextParser("SENTINEL")
                parser.feed(source)
                self.assertIn(expected, parser.contexts)

    def test_marker_location_requires_actual_marker(self):
        self.assertEqual(_locate_marker("<p>SENTINEL</p>", "text/html", "SENTINEL"), (True, "html_text"))
        self.assertEqual(_locate_marker("<p>ordinary</p>", "text/html", "SENTINEL"), (False, "unknown"))

    def test_origin_comparison_uses_scheme_host_and_effective_port(self):
        self.assertEqual(_origin("https://example.test/path"), _origin("https://EXAMPLE.test:443/other"))
        self.assertNotEqual(_origin("https://example.test/"), _origin("http://example.test/"))
        self.assertIsNone(_origin("https://user:pass@example.test/"))

    def test_block_status_is_not_attributed_to_waf_without_explicit_signal(self):
        observation = _waf_observation(403, {}, {"server": "cloudflare", "cf-ray": "abc"})
        self.assertEqual(observation["waf_result"], "block_response")

    def test_explicit_challenge_header_records_waf_block(self):
        observation = _waf_observation(403, {}, {"cf-ray": "abc", "cf-mitigated": "challenge"})
        self.assertEqual(observation["waf_result"], "waf_blocked")
        self.assertEqual(observation["waf_vendor"], "Cloudflare")
        self.assertEqual(observation["waf_confidence"], "high")

    def test_detects_vendor_fingerprints_without_claiming_a_block(self):
        observation = _waf_observation(200, {}, {"x-amzn-waf-action": "", "x-fortiweb-id": "abc"})
        self.assertEqual(observation["waf_result"], "fingerprint")
        self.assertIn("FortiWeb", observation["waf_vendors"])

    def test_recognizes_common_vendor_headers_without_calling_them_blocks(self):
        cases = {
            "akamai-grn": "Akamai",
            "x-iinfo": "Imperva",
            "x-sucuri-id": "Sucuri",
            "x-azure-ref": "Azure Front Door",
            "x-fortiweb-id": "FortiWeb",
            "x-wf-blocked": "Wordfence",
            "x-rdwr-session": "Radware",
            "x-fastly-request-id": "Fastly",
            "x-barracuda-url": "Barracuda",
            "x-ns-cf-open": "Citrix ADC",
            "x-sp-waf": "StackPath",
            "x-reblaze": "Reblaze",
            "x-wallarm-mode": "Wallarm",
        }
        for header, vendor in cases.items():
            with self.subTest(vendor=vendor):
                observation = _waf_observation(200, {}, {header: "signature"})
                self.assertEqual(observation["waf_result"], "fingerprint")
                self.assertIn(vendor, observation["waf_vendors"])

    def test_vendor_challenge_body_is_reported_without_assuming_http_block_status(self):
        observation = _waf_observation(200, {}, {}, response_body="Cloudflare checking your browser before accessing the site")
        self.assertEqual(observation["waf_result"], "waf_challenge")
        self.assertEqual(observation["waf_confidence"], "medium")

    def test_vendor_block_page_signature_improves_attribution_confidence(self):
        observation = _waf_observation(403, {}, {}, response_body="The requested URL was rejected. Support ID: 1")
        self.assertEqual(observation["waf_result"], "waf_blocked")
        self.assertEqual(observation["waf_vendor"], "F5 BIG-IP ASM")
        self.assertEqual(observation["waf_confidence"], "medium")

    def test_probe_status_change_is_retained_as_a_low_confidence_signal(self):
        observation = _waf_observation(403, {}, {}, baseline_status=200)
        self.assertEqual(observation["waf_result"], "block_response")
        self.assertIn("status_delta:200->403", observation["waf_signals"])

    def test_custom_waf_signatures_can_add_explicit_vendor_and_block_indicators(self):
        raw = '[{"vendor":"Example Edge","headers":["x-example-edge"],"block_headers":{"x-example-action":["deny"]},"body_contains":["example firewall"]}]'
        previous = os.environ.get("XSS_SENTINEL_WAF_SIGNATURES")
        os.environ["XSS_SENTINEL_WAF_SIGNATURES"] = raw
        try:
            observation = _waf_observation(403, {}, {"x-example-edge": "present", "x-example-action": "deny"})
            self.assertEqual(observation["waf_result"], "waf_blocked")
            self.assertIn("Example Edge", observation["waf_vendors"])
        finally:
            if previous is None:
                os.environ.pop("XSS_SENTINEL_WAF_SIGNATURES", None)
            else:
                os.environ["XSS_SENTINEL_WAF_SIGNATURES"] = previous

    def test_generic_access_denied_body_is_not_attributed_to_a_vendor(self):
        observation = _waf_observation(403, {}, {}, response_body="Access denied")
        self.assertEqual(observation["waf_result"], "block_response")
        self.assertIsNone(observation["waf_vendor"])


if __name__ == "__main__":
    unittest.main()
