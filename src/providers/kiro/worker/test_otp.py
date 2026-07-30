import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
import signup
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


# ---- consumed-OTP regression (stale signup code re-served at login OTP) ----
#
# AWS Builder ID signup has two OTP moments in one worker process: the signup
# OTP and the minted login workflow's get-email-otp-login-credential step.
# Gmail EXPUNGE is label-scoped — expunging from INBOX leaves the message
# searchable in All Mail (whose localized name varies per account locale), so
# deletion cannot guarantee the stale mail is unreachable. Without consumed
# tracking the second read_otp re-serves the signup code and AWS rejects it
# with EMAIL_OTP_AUTHENTICATION_FAILED (the live PLUS_B failure, run
# mo88wgk9). tempmail's Ncaori.wait_code has the equivalent guard (_seen_ids).


def _otp_mail(to: str, code: str, mid: str) -> bytes:
    """Minimal RFC822 OTP mail. mid makes the bytes unique per message."""
    return (
        f"From: no-reply@signin.aws\r\n"
        f"To: {to}\r\n"
        f"Subject: Verify your AWS Builder ID email address\r\n"
        f"Message-ID: {mid}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"\r\n"
        f"Your verification code: {code}"
    ).encode()


class FakeIMAP:
    """Minimal imaplib.IMAP4_SSL stand-in for read_otp.

    Implements exactly the surface read_otp touches: login/select/search/
    fetch/store/expunge/logout plus the .state attribute _select_mailbox
    checks. SEARCH matches the TO+FROM query against each message's To:
    header (the FROM-only fallback never fires here — every fake mail has
    both headers). Messages flagged \\Deleted are invisible to SEARCH and
    removed by expunge(), mirroring real IMAP visibility.
    """

    def __init__(self, messages):
        # messages: list of [raw_bytes, deleted_flag]
        self._msgs = messages
        self.state = "AUTH"

    def login(self, user, pw):
        return ("OK", [b"logged in"])

    def select(self, mailbox):
        self.state = "SELECTED"
        return ("OK", [str(len(self._msgs)).encode()])

    def search(self, charset, criteria):
        # criteria like: (TO "base+tag@gmail.com" FROM "signin.aws")
        toks = criteria.replace("(", " ").replace(")", " ").split()
        want_to = None
        for idx, tok in enumerate(toks):
            if tok == "TO" and idx + 1 < len(toks):
                want_to = toks[idx + 1].strip('"').lower()
        ids = []
        for num, (raw, deleted) in enumerate(self._msgs, start=1):
            if deleted:
                continue
            if want_to is not None and want_to not in raw.decode().lower():
                continue
            ids.append(str(num).encode())
        return ("OK", [b" ".join(ids)])

    def fetch(self, num, spec):
        raw = self._msgs[int(num) - 1][0]
        return ("OK", [(b"1 (RFC822)", raw)])

    def store(self, num, op, flags):
        if "\\Deleted" in flags:
            self._msgs[int(num) - 1][1] = True
        return ("OK", [b""])

    def expunge(self):
        self._msgs[:] = [m for m in self._msgs if not m[1]]
        return ("OK", [b""])

    def logout(self):
        self.state = "LOGOUT"
        return ("BYE", [b""])


_FAKE_CFG = {
    "host": "imap.test",  # not gmail.com → read_otp sweeps INBOX only
    "port": "993",
    "user": "u",
    "password": "p",
    "tls": "true",
}


class TestConsumedOtpTracking(unittest.TestCase):
    """read_otp must never re-serve a code it already returned (#130)."""

    def setUp(self):
        signup._CONSUMED_OTP_KEYS.clear()

    tearDown = setUp

    def _read(self, snapshots, **kw):
        """read_otp against a queue of FakeIMAP snapshots (one per poll).

        Each snapshot is the mailbox state at that poll: a list of
        [raw_bytes, deleted_flag] pairs. read_otp opens a fresh connection
        per attempt, so attempt N sees snapshots[N]. The queue is padded by
        repeating the final state so no attempt dies on an exhausted
        side_effect (which would surface as a noisy empty imap-error).
        """
        cfg = dict(_FAKE_CFG, **kw)
        retries = 3
        padded = snapshots + [snapshots[-1]] * max(0, retries - len(snapshots))
        with mock.patch.object(signup, "time") as fake_time, mock.patch.object(
            signup.imaplib,
            "IMAP4_SSL",
            side_effect=[FakeIMAP(s) for s in padded],
        ):
            fake_time.time.side_effect = lambda: 0.0
            return signup.read_otp("base+tag@gmail.com", cfg, retries=retries, delay=0)

    def test_second_read_skips_stale_and_returns_new_code(self):
        """The PLUS_B shape: stale signup mail still visible at login OTP.

        Read 1 (signup OTP): only the signup mail exists → returned.
        Read 2 (login OTP): the stale mail is STILL searchable (Gmail
        EXPUNGE is label-scoped — All Mail re-surfaces it) and the new
        login mail has NOT arrived at the first poll. Unfixed code
        returns the stale code on that poll (AWS rejects it with
        EMAIL_OTP_AUTHENTICATION_FAILED); the fix must skip the consumed
        mail, keep polling, and return the new code once it lands.
        (Newest-first iteration alone would mask the bug if stale+fresh
        shared one poll — the race is stale-visible-before-fresh-arrives.)
        """
        stale = _otp_mail("base+tag@gmail.com", "482916", "<stale@test>")
        fresh = _otp_mail("base+tag@gmail.com", "735182", "<fresh@test>")
        self.assertEqual(self._read([[[stale, False]]]), "482916")
        self.assertEqual(
            self._read([[[stale, False]], [[stale, False], [fresh, False]]]),
            "735182",
        )

    def test_consumed_mail_never_reserved_even_alone(self):
        """A consumed mail with no replacement must yield None, not a re-serve."""
        stale = _otp_mail("base+tag@gmail.com", "482916", "<stale@test>")
        self.assertEqual(self._read([[[stale, False]]]), "482916")
        self.assertIsNone(self._read([[[stale, False]]]))

    def test_consumed_key_scoped_per_target_email(self):
        """Distinct plus-aliases sharing one inbox must not mask each other."""
        mail_a = _otp_mail("base+tagA@gmail.com", "284619", "<a@test>")
        mail_b = _otp_mail("base+tagB@gmail.com", "918273", "<b@test>")
        cfg = dict(_FAKE_CFG)
        with mock.patch.object(signup, "time") as fake_time, mock.patch.object(
            signup.imaplib,
            "IMAP4_SSL",
            side_effect=[
                FakeIMAP([[mail_a, False]]),
                FakeIMAP([[mail_b, False]]),
            ],
        ):
            fake_time.time.side_effect = lambda: 0.0
            self.assertEqual(signup.read_otp("base+tagA@gmail.com", cfg, retries=2, delay=0), "284619")
            self.assertEqual(signup.read_otp("base+tagB@gmail.com", cfg, retries=2, delay=0), "918273")

    def test_gate_rejected_mail_not_marked_consumed(self):
        """A FROM-only-fallback hit for another alias stays re-checkable —
        marking it consumed would deadlock the retry loop to None."""
        other = _otp_mail("other+tag@gmail.com", "374829", "<other@test>")
        mine = _otp_mail("base+tag@gmail.com", "738291", "<mine@test>")
        # Attempt 1: only the foreign mail → gate rejects → no code.
        self.assertIsNone(self._read([[[other, False]]]))
        # Attempt 2: foreign mail still there + mine arrived → must return
        # mine (proves the foreign mail was NOT marked consumed).
        self.assertEqual(self._read([[[other, False], [mine, False]]]), "738291")

    def test_delete_after_read_still_deletes_returned_mail(self):
        """delete_after_read must flag the returned mail \\Deleted (and the
        consumed-mark must not depend on deletion happening)."""
        stale = _otp_mail("base+tag@gmail.com", "482916", "<stale@test>")
        msgs = [[stale, False]]
        self.assertEqual(self._read([msgs], delete_after_read="true"), "482916")
        self.assertEqual(msgs, [], "returned mail must be expunged")


if __name__ == "__main__":
    unittest.main()
