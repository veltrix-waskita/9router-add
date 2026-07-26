#!/usr/bin/env python3
"""OTP extraction unit tests for grok-cli pure-HTTP worker."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from signup import (  # noqa: E402
    extract_otp,
    extract_otp_from_message,
    _mailbox_for,
    _mailboxes_for,
    _select_mailbox,
)


class OtpTests(unittest.TestCase):
    def test_subject_primary_pattern(self):
        self.assertEqual(extract_otp("", "DW5-FQW xAI confirmation code"), "DW5-FQW")

    def test_confirmation_prefix(self):
        self.assertEqual(extract_otp("", "xAI confirmation code: ABC-123"), "ABC-123")

    def test_spacexai_subject(self):
        self.assertEqual(
            extract_otp("", "SpaceXAI confirmation code: HPN-7Z9"),
            "HPN-7Z9",
        )

    def test_noise_rejected(self):
        self.assertIsNone(extract_otp("noise per-100 rgb-255 max-age text", ""))

    def test_body_fallback(self):
        self.assertEqual(extract_otp("Your code is ZZZ-999", ""), "ZZZ-999")

    def test_case_insensitive(self):
        self.assertEqual(extract_otp("code abc-def here", ""), "ABC-DEF")

    def test_no_code(self):
        self.assertIsNone(extract_otp("hello world no code here", ""))

    def test_message_bytes_subject(self):
        raw = b"Subject: ABC-123 xAI\r\nFrom: noreply@x.ai\r\n\r\nbody"
        self.assertEqual(extract_otp_from_message(raw), "ABC-123")

    def test_message_bytes_html_body(self):
        raw = (
            b"Subject: hi\r\nFrom: noreply@x.ai\r\nContent-Type: text/html\r\n\r\n"
            b"<p>Your code is <b>QQ1-2W3</b></p>"
        )
        self.assertEqual(extract_otp_from_message(raw), "QQ1-2W3")

    def test_known_sample_subject(self):
        self.assertEqual(
            extract_otp("", "Your xAI confirmation code is XYZ-789"),
            "XYZ-789",
        )


class MailboxTests(unittest.TestCase):
    def test_gmail_primary_is_inbox(self):
        # All Mail is locale-dependent and often fails SELECT; INBOX first.
        self.assertEqual(_mailbox_for("imap.gmail.com"), "INBOX")

    def test_gmail_mailboxes_include_spam(self):
        boxes = _mailboxes_for("imap.gmail.com")
        self.assertEqual(boxes[0], "INBOX")
        self.assertIn('"[Gmail]/Spam"', boxes)
        self.assertIn('"[Gmail]/All Mail"', boxes)

    def test_non_gmail_inbox(self):
        self.assertEqual(_mailbox_for("mail.example.com"), "INBOX")
        self.assertEqual(_mailboxes_for("mail.example.com"), ["INBOX"])

    def test_empty_host_inbox(self):
        self.assertEqual(_mailbox_for(""), "INBOX")


class FakeImap:
    """Minimal stand-in for imaplib.IMAP4 used by _select_mailbox tests."""

    def __init__(self, typ="OK", state_after="SELECTED", dat=None, raise_on_select=None):
        self._typ = typ
        self._state_after = state_after
        self._dat = dat if dat is not None else [b"1"]
        self._raise = raise_on_select
        self.state = "AUTH"

    def select(self, mailbox):
        if self._raise is not None:
            raise self._raise
        if self._typ == "OK":
            self.state = self._state_after
        else:
            self.state = "AUTH"
        return self._typ, self._dat


class SelectMailboxTests(unittest.TestCase):
    def test_ok_selected(self):
        m = FakeImap(typ="OK", state_after="SELECTED")
        self.assertTrue(_select_mailbox(m, "INBOX"))
        self.assertEqual(m.state, "SELECTED")

    def test_no_keeps_auth(self):
        # Root-cause regression: select() returning NO must not look selected.
        m = FakeImap(typ="NO", dat=[b"Mailbox does not exist"])
        self.assertFalse(_select_mailbox(m, '"[Gmail]/All Mail"'))
        self.assertEqual(m.state, "AUTH")

    def test_exception_returns_false(self):
        m = FakeImap(raise_on_select=OSError("socket closed"))
        self.assertFalse(_select_mailbox(m, "INBOX"))


# ── Temp-mail EmailBox tests (ported from Node tempmail.test.js) ──────────────


class TempmailCodeTests(unittest.TestCase):
    """Test extract_code() from tempmail.py — mirrors Node extractTempmailOtp."""

    def setUp(self):
        # Lazy import; tempmail.py has zero deps beyond stdlib + curl_cffi
        from tempmail import extract_code
        self.extract = extract_code

    # -- hyphen codes ----------------------------------------------------------
    def test_hyphen_labeled_confirmation_prefix(self):
        self.assertEqual(self.extract("xAI confirmation code: HPN-7Z9"), "HPN-7Z9")

    def test_hyphen_labeled_lowercase(self):
        self.assertEqual(self.extract("code: abc-def"), "ABC-DEF")

    def test_hyphen_bare_with_xai_context(self):
        self.assertEqual(self.extract("xai verification: ABC-DEF is your code"), "ABC-DEF")

    def test_hyphen_bare_no_xai_context(self):
        self.assertIsNone(self.extract("Your code is abc-def for the thing"))

    def test_hyphen_skip_known_tokens(self):
        self.assertIsNone(self.extract("xai per-100 max-100 moz-osx"))

    # -- legacy 6-char alnum ---------------------------------------------------
    def test_legacy_6char_with_label(self):
        self.assertEqual(self.extract("xai confirmation code: AX3BBY expires soon"), "AX3BBY")

    def test_legacy_6digit_with_label(self):
        self.assertEqual(self.extract("xai verification code: 123456 is your otp"), "123456")

    def test_legacy_6digit_no_xai(self):
        self.assertIsNone(self.extract("tracking id: 123456, please ignore"))

    def test_legacy_skip_known_tokens(self):
        self.assertIsNone(self.extract("xai signup verify please gmail"))

    # -- 6-digit OTP (xAI only) ------------------------------------------------
    def test_digit6_with_xai(self):
        self.assertEqual(self.extract("xai otp: 987654"), "987654")
        self.assertEqual(self.extract("grok one-time passcode: 555666"), "555666")

    def test_digit6_no_xai(self):
        self.assertIsNone(self.extract("Your otp: 123456 for login"))

    # -- ad / noise rejection --------------------------------------------------
    def test_ad_only_rejected(self):
        self.assertIsNone(self.extract("ai tools to unleash the power of your workflow"))

    def test_ad_with_xai_rescued(self):
        self.assertEqual(
            self.extract("ai tools from xai — confirmation code: ABC-DEF"),
            "ABC-DEF",
        )

    def test_empty_or_none(self):
        self.assertIsNone(self.extract(""))
        self.assertIsNone(self.extract(None))

    def test_noise_only(self):
        self.assertIsNone(self.extract("Hello from the team at ExampleCorp"))

    # -- QP decoding -----------------------------------------------------------
    def test_qp_soft_break(self):
        self.assertEqual(self.extract("confirmation=\n code: ABC-DEF"), "ABC-DEF")

    # -- real-world xAI samples ------------------------------------------------
    def test_real_xai_body(self):
        body = "Dear user,\n\nYour xAI confirmation code: 8D8448\n\nIt expires in 30 minutes."
        self.assertEqual(self.extract(body), "8D8448")

    def test_real_xai_hyphen_subject(self):
        self.assertEqual(self.extract("Your xAI confirmation code is HPN-7Z9"), "HPN-7Z9")


class TempmailHelpersTests(unittest.TestCase):
    """Test helper functions from tempmail.py."""

    def setUp(self):
        from tempmail import _decode_qpish, _looks_like_ad, _has_xai_context
        self._decode_qpish = _decode_qpish
        self._looks_like_ad = _looks_like_ad
        self._has_xai_context = _has_xai_context

    def test_decode_qpish_removes_soft_breaks(self):
        self.assertEqual(self._decode_qpish("hello=\nworld"), "helloworld")
        self.assertEqual(self._decode_qpish("hello=\r\nworld"), "helloworld")

    def test_looks_like_ad_detects_ads(self):
        self.assertTrue(self._looks_like_ad("unleash the power of ai tools"))

    def test_looks_like_ad_not_xai(self):
        self.assertFalse(self._looks_like_ad("xai confirmation code: ABC-DEF"))

    def test_has_xai_context_detects(self):
        self.assertTrue(self._has_xai_context("xai confirmation code"))
        self.assertTrue(self._has_xai_context("accounts.x.ai verification"))

    def test_has_xai_context_no_match(self):
        self.assertFalse(self._has_xai_context("hello world"))


class EmailBoxUnitTests(unittest.TestCase):
    """Test EmailBox class with mocked providers (no network)."""

    def test_default_prefer(self):
        from tempmail import EmailBox
        box = EmailBox(prefer=["ncaori", "zoromail"])
        self.assertEqual(box.prefer, ["ncaori", "zoromail"])

    def test_env_var_overrides_default(self):
        from tempmail import EmailBox
        import os
        os.environ["GROK_TEMPMAIL_PROVIDERS"] = "zoromail"
        try:
            box = EmailBox()
            self.assertEqual(box.prefer, ["zoromail"])
        finally:
            del os.environ["GROK_TEMPMAIL_PROVIDERS"]

    def test_providers_from_env_empty(self):
        from tempmail import EmailBox
        self.assertIsNone(EmailBox._providers_from_env())

    @unittest.skipIf(not __import__("importlib").util.find_spec("curl_cffi"), "requires curl_cffi (install in .venv)")
    def test_make_ncaori(self):
        from tempmail import EmailBox, NcaoriMail
        box = EmailBox(prefer=["ncaori"])
        impl = box._make("ncaori")
        self.assertIsInstance(impl, NcaoriMail)

    @unittest.skipIf(not __import__("importlib").util.find_spec("curl_cffi"), "requires curl_cffi (install in .venv)")
    def test_make_zoromail(self):
        from tempmail import EmailBox, Zoromail
        box = EmailBox(prefer=["zoromail"])
        impl = box._make("zoromail")
        self.assertIsInstance(impl, Zoromail)

    def test_make_unknown_raises(self):
        from tempmail import EmailBox
        box = EmailBox(prefer=[])
        with self.assertRaises(ValueError):
            box._make("bogus")

    def test_wait_code_without_create_raises(self):
        from tempmail import EmailBox
        box = EmailBox(prefer=["ncaori"])
        with self.assertRaises(RuntimeError):
            box.wait_code(timeout=1)

    def test_create_account_all_fail(self):
        from tempmail import EmailBox
        box = EmailBox(prefer=["ncaori", "zoromail"])
        # Both will fail on network — no monkeypatch needed for coverage.
        with self.assertRaises(RuntimeError):
            box.create_account()


if __name__ == "__main__":
    unittest.main()
