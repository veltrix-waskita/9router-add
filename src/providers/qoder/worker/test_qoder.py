import io
import json
import unittest
from contextlib import redirect_stdout
from unittest import mock

from signup import (
    encode_bx_ua,
    TMD_IN_URL,
    is_tmd_punish,
    _body_json,
    _mask6,
    create_pat,
    login_me,
    poll_otp,
    register,
    run,
)
import imap_otp


class FakeResp:
    """Minimal curl_cffi-like response for hermetic tests."""

    def __init__(self, status_code=200, text="", json_data=None):
        self.status_code = status_code
        self._text = text
        self._json = json_data

    @property
    def text(self):
        return self._text

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


class TestHelpers(unittest.TestCase):
    def test_bx_ua_nonempty(self):
        self.assertGreater(len(encode_bx_ua()), 10)

    def test_tmd_detect(self):
        self.assertTrue(is_tmd_punish({"x5secdata": "xx"}))
        self.assertFalse(is_tmd_punish({"errorCode": "BadRequest"}))
        self.assertFalse(is_tmd_punish({"errorMessage": "Code required"}))

    def test_tmd_detect_html_str(self):
        # Live punish is HTTP 200 HTML; _body_json cannot parse it, so
        # detection must also work on the raw text (r.text).
        self.assertTrue(
            is_tmd_punish('<script>window.__tmd__; x5secdata="a1b2"</script>')
        )
        self.assertTrue(is_tmd_punish("_____tmd_____ blocked"))
        self.assertFalse(is_tmd_punish('{"errorMessage":"Code required"}'))
        self.assertFalse(is_tmd_punish("Code required"))
        self.assertFalse(is_tmd_punish(None))
        self.assertFalse(is_tmd_punish(123))

    def test_mask6(self):
        self.assertEqual(_mask6("code 123456 sent"), "code ****** sent")
        self.assertNotIn("707124", _mask6("707124"))
        self.assertEqual(_mask6(None), "")

    def test_body_json(self):
        self.assertEqual(_body_json(FakeResp(200, json_data={"a": 1})), {"a": 1})
        self.assertIsNone(_body_json(FakeResp(200, text="not json")))


class TestImapExtract(unittest.TestCase):
    def test_labeled_digit6(self):
        self.assertEqual(
            imap_otp.extract_otp("Your verification code is 482913"),
            "482913",
        )

    def test_bare_digit6_with_qoder_context(self):
        self.assertEqual(
            imap_otp.extract_otp("qoder code: 482913"),
            "482913",
        )

    def test_noise_skipped(self):
        self.assertNotEqual(imap_otp.extract_otp("code 123456"), "123456")
        self.assertIsNone(imap_otp.extract_otp("no code here 123456"))

    def test_message_extract(self):
        raw = (
            b"Subject: [Qoder] Your verification code\r\n"
            b"To: someone@example.com\r\n"
            b"\r\n"
            b"Your verification code is 482913.\r\n"
        )
        self.assertEqual(imap_otp.extract_otp_from_message(raw), "482913")


class TestApiFns(unittest.TestCase):
    def test_login_me_ok(self):
        s = mock.Mock()
        s.get.return_value = FakeResp(200, json_data={"id": "u1", "name": "Alex"})
        self.assertEqual(login_me(s), {"id": "u1", "name": "Alex"})

    def test_login_me_error(self):
        s = mock.Mock()
        s.get.return_value = FakeResp(401, text="no")
        self.assertIsNone(login_me(s))

    def test_create_pat_returns_token_text(self):
        s = mock.Mock()
        s.post.return_value = FakeResp(
            201,
            json_data={
                "token_id": "t1",
                "token": "pt-secret-abc",
                "expires_at": 2534023007999,
            },
        )
        self.assertEqual(create_pat(s, "Alex Rivera"), "pt-secret-abc")

    def test_create_pat_none_on_error(self):
        s = mock.Mock()
        s.post.return_value = FakeResp(500, text="boom")
        self.assertIsNone(create_pat(s))

    def test_register_sends_payload_with_proxy(self):
        s = mock.Mock()
        s.post.return_value = FakeResp(200, text="")
        register(s, "a@b.c", "pw123", "Alex", code="482913", proxy="http://p:8080")
        args, kw = s.post.call_args
        self.assertTrue(args[0].endswith("/api/v1/users"))
        self.assertEqual(kw["proxy"], "http://p:8080")
        body = kw["json"]
        self.assertEqual(body["code"], "482913")
        self.assertEqual(body["type"], "email_pwd")
        self.assertTrue(body["bx-ua"])


class TestRunFlow(unittest.TestCase):
    def _emit_lines(self, fn, env):
        buf = io.StringIO()
        with mock.patch.dict("os.environ", env, clear=False):
            with redirect_stdout(buf):
                rc = fn()
        lines = [json.loads(l) for l in buf.getvalue().splitlines() if l.strip()]
        return rc, lines

    def test_run_success_masked_output(self):
        box = mock.Mock()
        box.address = "swift_core1234@ncaori.my.id"
        box.create_account.return_value = box.address
        box.wait_code.return_value = "482913"

        s = mock.Mock()
        s.get.side_effect = [
            FakeResp(200, text="signup page"),            # signup_page
            FakeResp(200, json_data={"id": "u1"}),         # login_me
        ]
        s.post.side_effect = [
            FakeResp(200, text="{}"),                      # check_login_type
            FakeResp(200, text=""),                        # verificationCodes (OTP sent)
            FakeResp(200, text=""),                        # register with code
            FakeResp(201, json_data={"token": "pt-secret-abc"}),  # PAT
        ]

        with mock.patch("signup._session", return_value=s), \
             mock.patch("tempmail.EmailBox", return_value=box):
            rc, lines = self._emit_lines(
                run,
                {
                    "QODER_EMAIL": "",
                    "QODER_PASSWORD": "Sup3rSecret!",
                    "QODER_EMAIL_SOURCE": "tempmail",
                    "QODER_NAME": "Alex Rivera",
                },
            )

        self.assertEqual(rc, 0)
        results = [l for l in lines if l.get("kind") == "result"]
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["ok"])
        self.assertEqual(results[0]["pat"], "pt-secret-abc")
        self.assertTrue(results[0]["me"])
        blob = json.dumps(lines)
        self.assertNotIn("Sup3rSecret", blob)
        self.assertNotIn("482913", blob)
        # password never emitted; 6-digit runs never emitted in steps
        self.assertNotIn("password", blob)

    def test_run_missing_env(self):
        # No network: missing password short-circuits at the env guard before
        # any tempmail box is created. EmailBox is still mocked so the test
        # stays offline even if the guard order changes.
        box = mock.Mock()
        box.address = "x@ncaori.my.id"
        box.create_account.return_value = box.address
        with mock.patch("tempmail.EmailBox", return_value=box):
            rc, lines = self._emit_lines(
                run, {"QODER_EMAIL": "", "QODER_PASSWORD": ""}
            )
        self.assertEqual(rc, 1)
        self.assertEqual(lines[-1]["error"], "missing-email-or-password")
        box.create_account.assert_not_called()

    def test_run_pat_missing_fails(self):
        box = mock.Mock()
        box.address = "x@ncaori.my.id"
        box.create_account.return_value = box.address
        box.wait_code.return_value = "482913"

        s = mock.Mock()
        s.get.return_value = FakeResp(200, text="page")  # signup_page only
        s.post.side_effect = [
            FakeResp(200, text="{}"),                      # check_login_type
            FakeResp(200, text=""),                        # verificationCodes (OTP sent)
            FakeResp(200, text=""),                        # register with code
            FakeResp(500, text="boom"),                    # PAT fails
        ]

        with mock.patch("signup._session", return_value=s), \
             mock.patch("tempmail.EmailBox", return_value=box):
            rc, lines = self._emit_lines(
                run,
                {
                    "QODER_EMAIL": "",
                    "QODER_PASSWORD": "pw",
                    "QODER_EMAIL_SOURCE": "tempmail",
                },
            )
        self.assertEqual(rc, 1)
        self.assertEqual(lines[-1]["error"], "pat-missing")
        self.assertEqual(lines[-1]["step"], "pat")

    def test_run_tmd_persistent(self):
        box = mock.Mock()
        box.address = "x@ncaori.my.id"
        box.create_account.return_value = box.address
        s = mock.Mock()
        s.get.return_value = FakeResp(200, text="page")
        s.post.return_value = FakeResp(403, json_data={"x5secdata": "block"})
        with mock.patch("signup._session", return_value=s), \
             mock.patch("tempmail.EmailBox", return_value=box):
            rc, lines = self._emit_lines(
                run,
                {
                    "QODER_EMAIL": "",
                    "QODER_PASSWORD": "pw",
                    "QODER_EMAIL_SOURCE": "tempmail",
                },
            )
        self.assertEqual(rc, 1)
        self.assertEqual(lines[-1]["error"], "tmd-persistent")
        # check_login_type + verificationCodes step1 + 3 retries
        self.assertEqual(s.post.call_count, 5)

    def test_run_tmd_html_then_otp_recovers(self):
        # Live punish is HTTP 200 HTML (x5secdata page). A later retry returns
        # the normal 400 "Code required" -> must break to the OTP poll and NOT
        # burn 3 retries or emit a false tmd-persistent. Also proves HTML-text
        # detection is what routes this through the tmd branch.
        box = mock.Mock()
        box.address = "x@ncaori.my.id"
        box.create_account.return_value = box.address
        box.wait_code.return_value = "482913"

        s = mock.Mock()
        s.get.side_effect = [
            FakeResp(200, text="signup page"),            # signup_page
            FakeResp(200, json_data={"id": "u1"}),         # login_me
        ]
        s.post.side_effect = [
            FakeResp(200, text="{}"),                                  # check_login_type
            FakeResp(200, text='<script>x5secdata="a1"</script>'),     # verificationCodes HTML punish
            FakeResp(200, text=""),                                    # retry -> OTP sent
            FakeResp(200, text=""),                                    # register with code
            FakeResp(201, json_data={"token": "pt-secret-abc"}),       # PAT
        ]

        with mock.patch("signup._session", return_value=s), \
             mock.patch("tempmail.EmailBox", return_value=box):
            rc, lines = self._emit_lines(
                run,
                {
                    "QODER_EMAIL": "",
                    "QODER_PASSWORD": "pw",
                    "QODER_EMAIL_SOURCE": "tempmail",
                },
            )

        self.assertEqual(rc, 0)
        tmd_warn = [l for l in lines if l.get("step") == "tmd"]
        self.assertEqual(tmd_warn, [{"event": "step", "step": "tmd", "status": "warn"}])
        results = [l for l in lines if l.get("kind") == "result"]
        self.assertTrue(results[0]["ok"])
        blob = json.dumps(lines)
        self.assertNotIn("tmd-persistent", blob)

    def test_poll_otp_imap_path(self):
        with mock.patch("imap_otp.read_otp", return_value="482913") as read:
            code = poll_otp("a@b.c", "imap", proxy=None, box=None, timeout=10, interval=1)
        self.assertEqual(code, "482913")
        read.assert_called_once()
        self.assertEqual(read.call_args[0][0], "a@b.c")


if __name__ == "__main__":
    unittest.main()
