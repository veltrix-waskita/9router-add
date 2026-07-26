#!/usr/bin/env python3
"""Unit tests for multi-source principal_id / userId extraction."""
import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from signup import (  # noqa: E402
    extract_user_id_from_cookies,
    extract_user_id_from_set_cookie_urls,
    extract_user_id_from_text,
    resolve_principal_id,
)

UID = "63237ca9-d606-48e7-ba54-5f8a747f9808"
UID2 = "1b3ef973-9e94-40d0-96be-35a341d25a50"


def _fake_set_cookie_url(payload: dict) -> str:
    """Build a set-cookie?q=JWT URL whose middle segment is payload."""
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(b"sig").decode().rstrip("=")
    return f"https://auth.grokusercontent.com/set-cookie?q={header}.{body}.{sig}"


class ExtractUserIdFromText(unittest.TestCase):
    def test_plain_json(self):
        self.assertEqual(
            extract_user_id_from_text(f'{{"userId":"{UID}"}}'),
            UID,
        )

    def test_escaped_rsc_flight(self):
        # Consent page style: \\"userId\\":\\"uuid\\"
        html = r'some flight \\"userId\\":\\"' + UID + r'\\" tail'
        self.assertEqual(extract_user_id_from_text(html), UID)

    def test_principal_id_form_field(self):
        html = f'<input type="hidden" name="principal_id" value="{UID}" />'
        self.assertEqual(extract_user_id_from_text(html), UID)

    def test_principal_id_json_key(self):
        self.assertEqual(
            extract_user_id_from_text(f'{{"principal_id":"{UID}"}}'),
            UID,
        )

    def test_no_match(self):
        self.assertIsNone(extract_user_id_from_text("<html>no id here</html>"))

    def test_empty(self):
        self.assertIsNone(extract_user_id_from_text(None))
        self.assertIsNone(extract_user_id_from_text(""))


class ExtractUserIdFromCookies(unittest.TestCase):
    def test_x_userid_dict(self):
        self.assertEqual(
            extract_user_id_from_cookies({"x-userid": UID2, "sso": "jwt"}),
            UID2,
        )

    def test_rejects_non_uuid(self):
        self.assertIsNone(
            extract_user_id_from_cookies({"x-userid": "not-a-uuid", "sso": "x"})
        )

    def test_case_insensitive_name(self):
        # Mapping iteration path
        class Jar:
            def items(self):
                return [("X-UserId", UID2)]

            def get(self, name):
                return None

        self.assertEqual(extract_user_id_from_cookies(Jar()), UID2)

    def test_empty(self):
        self.assertIsNone(extract_user_id_from_cookies(None))
        self.assertIsNone(extract_user_id_from_cookies({}))


class ExtractUserIdFromSetCookieJwt(unittest.TestCase):
    def test_user_id_in_config(self):
        url = _fake_set_cookie_url(
            {"config": {"success_url": "https://accounts.x.ai/account", "userId": UID}}
        )
        body = f'redirect to {url} now'
        self.assertEqual(extract_user_id_from_set_cookie_urls(body), UID)

    def test_no_user_id(self):
        url = _fake_set_cookie_url(
            {"config": {"success_url": "https://accounts.x.ai/account"}}
        )
        self.assertIsNone(extract_user_id_from_set_cookie_urls(f"go {url}"))


class ResolvePrincipalId(unittest.TestCase):
    def test_prefers_consent_html(self):
        uid, src = resolve_principal_id(
            consent_html=f'{{"userId":"{UID}"}}',
            cookies={"x-userid": UID2},
        )
        self.assertEqual(uid, UID)
        self.assertEqual(src, "consent_html")

    def test_falls_back_to_cookie(self):
        uid, src = resolve_principal_id(
            consent_html="<html>nope</html>",
            cookies={"x-userid": UID2},
        )
        self.assertEqual(uid, UID2)
        self.assertEqual(src, "cookie")

    def test_falls_back_to_create_user_body(self):
        uid, src = resolve_principal_id(
            consent_html="<html/>",
            cookies={},
            create_user_body=f'action result userId\\":\\"{UID}\\"',
        )
        self.assertEqual(uid, UID)
        self.assertEqual(src, "create_user_body")

    def test_uses_cached_known(self):
        uid, src = resolve_principal_id(
            known=UID,
            consent_html="<html/>",
            cookies={},
        )
        self.assertEqual(uid, UID)
        self.assertEqual(src, "cached")

    def test_set_cookie_jwt_fallback(self):
        url = _fake_set_cookie_url({"principal_id": UID})
        uid, src = resolve_principal_id(
            consent_html="<html/>",
            cookies={},
            create_user_body=f"see {url}",
        )
        self.assertEqual(uid, UID)
        self.assertEqual(src, "set_cookie_jwt")

    def test_all_miss(self):
        uid, src = resolve_principal_id(
            consent_html="<html/>",
            cookies={"sso": "jwt-only"},
            create_user_body="no id",
        )
        self.assertIsNone(uid)
        self.assertIsNone(src)


if __name__ == "__main__":
    unittest.main()
