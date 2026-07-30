import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from signup import (
    extract_otp,
    extract_otp_from_message,
    _strip_html,
    _decode_subject,
    _message_for,
    is_bare_gmail,
)


class TestOTPExtraction(unittest.TestCase):
    def test_labeled_6digit_code(self):
        self.assertEqual(extract_otp("Your verification code: 482916"), "482916")

    def test_confirmation_code(self):
        self.assertEqual(extract_otp("Confirmation code: 735182"), "735182")

    def test_otp_labeled(self):
        self.assertEqual(extract_otp("Your OTP: 284619"), "284619")

    def test_one_time_password(self):
        self.assertEqual(extract_otp("One-time password: 918273"), "918273")

    def test_noise_rejected(self):
        self.assertIsNone(extract_otp("Code: 123456"))
        self.assertIsNone(extract_otp("Code: 000000"))

    def test_bare_6digit_with_aws_context(self):
        self.assertEqual(extract_otp("AWS signin: code 374829"), "374829")

    def test_bare_6digit_no_context(self):
        self.assertIsNone(extract_otp("Your number is 482916"))

    def test_subject_extraction(self):
        subj = _decode_subject("=?UTF-8?B?VmVyaWZ5IHlvdXIgQVdTIEJ1aWxkZXIgSUQgZW1haWwgYWRkcmVzcw==?=")
        self.assertIn("AWS", subj)

    def test_strip_html(self):
        html_str = "<html><body><p>Your code: <b>482916</b></p></body></html>"
        self.assertIn("482916", _strip_html(html_str))

    def test_extract_from_message_html(self):
        raw = (
            b"From: sender@signin.aws\r\n"
            b"Subject: Verify your AWS Builder ID email address\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n\r\n"
            b"<html><body><p>Your verification code: 482916</p></body></html>"
        )
        self.assertEqual(extract_otp_from_message(raw), "482916")

    def test_extract_from_message_plain(self):
        raw = (
            b"From: sender@signin.aws\r\n"
            b"Subject: Verify your AWS Builder ID email address\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Your verification code: 482916"
        )
        self.assertEqual(extract_otp_from_message(raw), "482916")

    def test_extract_from_message_subject_only(self):
        """OTP code in subject line should be found."""
        raw = (
            b"From: sender@signin.aws\r\n"
            b"Subject: [code: 738291] Verify your AWS Builder ID email address\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Click the link to verify your email."
        )
        self.assertEqual(extract_otp_from_message(raw), "738291")


class TestRecipientCheck(unittest.TestCase):
    """_message_for guards plus-alias inboxes against cross-alias OTP reuse."""

    def _raw(self, to: bytes) -> bytes:
        return (
            b"From: sender@signin.aws\r\n"
            b"To: " + to + b"\r\n"
            b"Subject: Verify your AWS Builder ID email address\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Your verification code: 482916"
        )

    def test_exact_match(self):
        self.assertTrue(
            _message_for(self._raw(b"base+abc@gmail.com"), "base+abc@gmail.com")
        )

    def test_case_insensitive(self):
        self.assertTrue(
            _message_for(self._raw(b"Base+ABC@Gmail.com"), "base+abc@gmail.com")
        )

    def test_wrong_recipient_rejected(self):
        self.assertFalse(
            _message_for(self._raw(b"other+xyz@gmail.com"), "base+abc@gmail.com")
        )

    def test_substring_prefix_not_matched(self):
        # "xbase+abc@gmail.com" contains "base+abc@gmail.com" as a substring —
        # only exact address match may pass (guards against containment bugs).
        self.assertFalse(
            _message_for(self._raw(b"xbase+abc@gmail.com"), "base+abc@gmail.com")
        )

    def test_display_name_form(self):
        self.assertTrue(
            _message_for(
                self._raw(b"Base Account <base+abc@gmail.com>"),
                "base+abc@gmail.com",
            )
        )

    def test_cc_counts(self):
        raw = (
            b"From: sender@signin.aws\r\n"
            b"To: someone@example.com\r\n"
            b"Cc: base+abc@gmail.com\r\n"
            b"Subject: x\r\n\r\n"
            b"Your verification code: 482916"
        )
        self.assertTrue(_message_for(raw, "base+abc@gmail.com"))

    def test_garbage_bytes_rejected(self):
        self.assertFalse(_message_for(b"\x00\x01not-a-message", "base+abc@gmail.com"))


class TestBareGmailGuard(unittest.TestCase):
    """is_bare_gmail must mirror KiroProvider.detectMethod (index.js)."""

    def test_bare_gmail_rejected(self):
        self.assertTrue(is_bare_gmail("user@gmail.com"))
        self.assertTrue(is_bare_gmail("USER@GMAIL.COM"))

    def test_plus_alias_allowed(self):
        self.assertFalse(is_bare_gmail("user+tag123@gmail.com"))
        self.assertFalse(is_bare_gmail("USER+TAG@GMAIL.COM"))

    def test_empty_plus_tag_rejected(self):
        # "user+@gmail.com" — Gmail normalizes the empty tag to bare gmail.
        self.assertTrue(is_bare_gmail("user+@gmail.com"))
        self.assertTrue(is_bare_gmail("USER+@GMAIL.COM"))

    def test_whitespace_padded_bare_gmail_rejected(self):
        # run() strips KIRO_EMAIL; the guard must agree with the trimmed value.
        self.assertTrue(is_bare_gmail("user@gmail.com "))
        self.assertTrue(is_bare_gmail("  user@gmail.com"))

    def test_whitespace_padded_plus_alias_allowed(self):
        self.assertFalse(is_bare_gmail(" user+tag@gmail.com "))

    def test_non_gmail_allowed(self):
        self.assertFalse(is_bare_gmail("user@outlook.com"))
        self.assertFalse(is_bare_gmail("user+tag@minom.my.id"))

    def test_empty_and_none_allowed(self):
        self.assertFalse(is_bare_gmail(""))
        self.assertFalse(is_bare_gmail(None))


if __name__ == "__main__":
    unittest.main()
