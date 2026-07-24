import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from signup import extract_otp, extract_otp_from_message, _strip_html, _decode_subject


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


if __name__ == "__main__":
    unittest.main()
