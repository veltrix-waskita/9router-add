"""Hermetic mocked register round for the qoder worker (Task 3 Step 3).

Patches signup._session + tempmail.EmailBox so run() executes without
network, then prints the emitted JSONL to stdout. Verifies the full
register->otp->step2->pat->me happy path end to end.
"""
import io
import json
import os
import sys
import unittest.mock as mock
from contextlib import redirect_stdout

WORKER_DIR = "/home/elzanom/WORKER/9router-add/src/providers/qoder/worker"
sys.path.insert(0, WORKER_DIR)

import signup  # noqa: E402


class FakeResp:
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


def main():
    box = mock.Mock()
    box.address = "mocked@ncaori.my.id"
    box.create_account.return_value = box.address
    box.wait_code.return_value = "482913"

    s = mock.Mock()
    s.get.side_effect = [
        FakeResp(200, text="<signup>"),               # signup_page
        FakeResp(200, json_data={"id": "u1"}),        # login_me
    ]
    s.post.side_effect = [
        FakeResp(400, text='{"errorMessage":"Code required"}'),   # step1
        FakeResp(200, text=""),                                    # step2
        FakeResp(201, json_data={"token": "pt-mock-token-01"}),    # PAT
    ]

    env = {
        "QODER_EMAIL": "",
        "QODER_PASSWORD": "MockPass123!",
        "QODER_NAME": "Nexus",
        "QODER_EMAIL_SOURCE": "tempmail",
        "QODER_PROXY": "",
    }
    buf = io.StringIO()
    with mock.patch.dict(os.environ, env, clear=False):
        with mock.patch("signup._session", return_value=s):
            with mock.patch("tempmail.EmailBox", return_value=box):
                with redirect_stdout(buf):
                    rc = signup.run()
    for line in buf.getvalue().splitlines():
        if line.strip():
            print(line)
    print(f"PROBE_EXIT={rc}")


if __name__ == "__main__":
    main()