import os
import tempfile
import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from xss_sentinel import database
from xss_sentinel.auth_profiles import AuthFlow, _load_webauthn_sign_count, _save_webauthn_sign_count, _totp_code, callback_url_allowed, get_auth_profile, parse_auth_profiles
from xss_sentinel.database import Base
from xss_sentinel.models import WebAuthnCredentialState


class AuthProfileTest(unittest.TestCase):
    def test_parses_headers_and_cookies_without_storing_secrets_in_names(self):
        profiles = parse_auth_profiles('{"staging":{"origins":["https://staging.example.test"],"headers":{"Authorization":"Bearer hidden"},"cookies":{"session":"cookie-value"}}}')
        self.assertEqual(profiles["staging"]["headers"]["authorization"], "Bearer hidden")
        self.assertEqual(profiles["staging"]["cookies"]["session"], "cookie-value")

    def test_rejects_host_header_override(self):
        with self.assertRaises(ValueError):
            parse_auth_profiles('{"unsafe":{"origins":["https://example.test"],"headers":{"Host":"other.example"}}}')

    def test_missing_profile_has_safe_defaults(self):
        profile = get_auth_profile(None)
        self.assertEqual(profile["headers"], {})
        self.assertEqual(profile["cookies"], {})
        self.assertTrue(profile["verify_tls"])
        self.assertIsNone(profile["login"])

    def test_login_and_refresh_profiles_are_origin_scoped(self):
        raw = '{"staging":{"origins":["https://staging.example.test"],"login":{"url":"/api/login","format":"json","fields":{"username":"user","password":"secret"},"token_path":"access.token","refresh_token_path":"refresh"},"refresh":{"url":"/api/refresh","format":"json","fields":{"refresh_token":"{{refresh_token}}"},"token_path":"access","refresh_token_path":"refresh"}}}'
        profile = parse_auth_profiles(raw)["staging"]
        self.assertEqual(profile["login"]["url"], "/api/login")
        self.assertEqual(profile["login"]["refresh"]["url"], "/api/refresh")
        with self.assertRaises(ValueError):
            parse_auth_profiles('{"unsafe":{"origins":["https://example.test"],"login":{"url":"https://other.test/login","fields":{"u":"x"}}}}')

    def test_browser_login_profile_validates_csrf_mfa_passkeys_and_post_scope(self):
        raw = '{"ui":{"origins":["https://app.example.test"],"browser_flow":{"url":"/login","post_paths":["/login","/mfa"],"steps":[{"action":"fill","selector":"#username","value":"user"},{"action":"csrf_header","selector":"meta[name=csrf-token]","header":"X-CSRF-Token"},{"action":"click","selector":"button[type=submit]"},{"action":"totp","selector":"#otp","secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"},{"action":"click","selector":"#verify"},{"action":"wait_for","selector":"#account"}],"success_selector":"#account","webauthn":{"rp_id":"app.example.test","credentials":[{"id":"Y3JlZA","user_handle":"dXNlcg","private_key":"cHJpdmF0ZQ","public_key":"cHVibGlj","sign_count":0}]}}}}'
        profile = parse_auth_profiles(raw)["ui"]
        flow = profile["browser_flow"]
        self.assertEqual(flow["post_paths"], ["/login", "/mfa"])
        self.assertEqual(flow["steps"][3]["action"], "totp")
        self.assertEqual(flow["webauthn"]["rp_id"], "app.example.test")
        previous = os.environ.get("XSS_SENTINEL_AUTH_PROFILES")
        os.environ["XSS_SENTINEL_AUTH_PROFILES"] = raw
        try:
            get_auth_profile("ui", "https://app.example.test/login")
            with self.assertRaises(ValueError):
                get_auth_profile("ui", "https://other.example.test/login")
        finally:
            if previous is None:
                os.environ.pop("XSS_SENTINEL_AUTH_PROFILES", None)
            else:
                os.environ["XSS_SENTINEL_AUTH_PROFILES"] = previous
        with self.assertRaises(ValueError):
            parse_auth_profiles('{"ui":{"origins":["https://app.example.test"],"browser_flow":{"url":"/login","post_paths":["https://other.test/submit"],"steps":[{"action":"click","selector":"#submit"}]}}}')

    def test_browser_flow_can_seed_a_virtual_passkey_for_the_target_rp_id(self):
        raw = '{"passkey":{"origins":["https://app.example.test"],"browser_flow":{"url":"/login","post_paths":["/login"],"steps":[{"action":"click","selector":"#passkey"}],"webauthn":{"rp_id":"app.example.test","credentials":[{"id":"Y3JlZA","user_handle":"dXNlcg","private_key":"cHJpdmF0ZQ","public_key":"cHVibGlj","sign_count":0}]}}}}'
        profile = parse_auth_profiles(raw)["passkey"]
        self.assertEqual(profile["browser_flow"]["webauthn"]["rp_id"], "app.example.test")
        previous = os.environ.get("XSS_SENTINEL_AUTH_PROFILES")
        os.environ["XSS_SENTINEL_AUTH_PROFILES"] = raw
        try:
            get_auth_profile("passkey", "https://app.example.test/login")
            with self.assertRaises(ValueError):
                get_auth_profile("passkey", "https://other.example.test/login")
        finally:
            if previous is None:
                os.environ.pop("XSS_SENTINEL_AUTH_PROFILES", None)
            else:
                os.environ["XSS_SENTINEL_AUTH_PROFILES"] = previous

    def test_virtual_passkey_signature_counters_are_persisted_without_credential_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = create_engine(f"sqlite:///{os.path.join(directory, 'auth.db')}")
            Base.metadata.create_all(engine)
            previous_session_factory = database.SessionLocal
            database.SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
            try:
                _save_webauthn_sign_count("app.example.test", "credential-id", 4)
                _save_webauthn_sign_count("app.example.test", "credential-id", 2)
                self.assertEqual(_load_webauthn_sign_count("app.example.test", "credential-id", 0), 4)
                with database.SessionLocal() as session:
                    saved = session.query(WebAuthnCredentialState).one()
                    self.assertNotIn("credential-id", saved.credential_fingerprint)
                    self.assertEqual(saved.sign_count, 4)
            finally:
                database.SessionLocal = previous_session_factory
                engine.dispose()

    def test_totp_matches_rfc6238_sha1_test_vector(self):
        self.assertEqual(_totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59, digits=8, period=30), "94287082")

    def test_callback_allowlist_uses_exact_origin(self):
        profile = parse_auth_profiles('{"staging":{"origins":["https://staging.example.test"],"callback_origins":["https://oast.example.test"]}}')["staging"]
        self.assertTrue(callback_url_allowed(profile, "https://oast.example.test/hit?id=123"))
        self.assertFalse(callback_url_allowed(profile, "https://other.example.test/hit"))

    def test_login_and_refresh_exchange_with_mock_transport(self):
        import asyncio
        import httpx

        profile = parse_auth_profiles('{"staging":{"origins":["https://staging.example.test"],"login":{"url":"/api/login","format":"json","fields":{"username":"user","password":"secret"},"token_path":"access","refresh_token_path":"refresh"},"refresh":{"url":"/api/refresh","format":"json","fields":{"refresh":"{{refresh_token}}"},"token_path":"access"}}}')['staging']
        seen = []

        def handler(request):
            if request.url.path == "/api/login":
                return httpx.Response(200, json={"access": "first", "refresh": "renewal"})
            if request.url.path == "/api/refresh":
                seen.append(request.content.decode())
                return httpx.Response(200, json={"access": "second"})
            if request.headers.get("authorization") == "Bearer second":
                return httpx.Response(200, text="ok")
            return httpx.Response(401)

        async def exercise():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler), headers=profile["headers"]) as client:
                flow = AuthFlow(profile, "https://staging.example.test/")
                await flow.initialize(client)
                response = await flow.request(client, "GET", "https://staging.example.test/private")
                self.assertEqual(response.status_code, 200)
                self.assertIn("renewal", seen[0])

        asyncio.run(exercise())

    def test_profile_credentials_are_origin_scoped(self):
        raw = '{"staging":{"origins":["https://staging.example.test"],"headers":{"Authorization":"Bearer hidden"}}}'
        profiles = parse_auth_profiles(raw)
        self.assertEqual(profiles["staging"]["headers"]["authorization"], "Bearer hidden")
        previous_value = os.environ.get("XSS_SENTINEL_AUTH_PROFILES")
        os.environ["XSS_SENTINEL_AUTH_PROFILES"] = raw
        try:
            self.assertEqual(get_auth_profile("staging", "https://staging.example.test/login")["headers"]["authorization"], "Bearer hidden")
            with self.assertRaises(ValueError):
                get_auth_profile("staging", "https://other.example.test/")
        finally:
            if previous_value is None:
                os.environ.pop("XSS_SENTINEL_AUTH_PROFILES", None)
            else:
                os.environ["XSS_SENTINEL_AUTH_PROFILES"] = previous_value


if __name__ == "__main__":
    unittest.main()
