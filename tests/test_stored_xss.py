import unittest

from xss_sentinel.auth_profiles import parse_auth_profiles
from xss_sentinel.stored_xss import _callback_endpoint, _same_origin_urls, _set_nested_value


class StoredXssHelpersTest(unittest.TestCase):
    def test_json_fields_support_nested_parameter_paths(self):
        value = {}
        _set_nested_value(value, "profile.display.name", "canary")
        self.assertEqual(value, {"profile": {"display": {"name": "canary"}}})

    def test_callback_is_origin_allowlisted_and_marker_is_per_request(self):
        profile = parse_auth_profiles('{"staging":{"origins":["https://app.test"],"callback_origins":["https://oast.test"]}}')["staging"]
        endpoint, safe_endpoint = _callback_endpoint("https://oast.test/collector", "UNIQUE123", profile)
        self.assertEqual(endpoint, "https://oast.test/collector?xs=UNIQUE123")
        self.assertEqual(safe_endpoint, "https://oast.test")
        with self.assertRaises(ValueError):
            _callback_endpoint("https://other.test/collector", "UNIQUE123", profile)

    def test_verification_urls_cannot_escape_assessment_origin(self):
        self.assertEqual(
            _same_origin_urls(["https://app.test/a", "https://app.test/a"], "https://app.test/"),
            ["https://app.test/a"],
        )
        with self.assertRaises(ValueError):
            _same_origin_urls(["https://other.test/page"], "https://app.test/")


if __name__ == "__main__":
    unittest.main()
