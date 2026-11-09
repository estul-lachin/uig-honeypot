"""Tests for vps/sentinel.py. Run: python3 -m unittest discover -s tests

No network: a fake opener stands in for Entra ID and the ingestion endpoint.
IPs are from the RFC 5737 documentation ranges.
"""

import datetime
import gzip
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "vps"))
import sentinel  # noqa: E402

NOW = datetime.datetime(2026, 11, 9, 12, tzinfo=datetime.timezone.utc)
ENV = {"HP_AZ_TENANT": "t", "HP_AZ_CLIENT_ID": "c", "HP_AZ_CLIENT_SECRET": "s",
       "HP_AZ_DCE": "https://dce.example", "HP_AZ_DCR": "dcr-1"}


def ev(i, day="2026-11-09", **kw):
    return json.dumps({"eventid": "cowrie.command.input", "timestamp": f"{day}T10:00:{i:02d}.000000Z",
                       "src_ip": "198.51.100.7", "src_port": "40000", "dst_ip": "10.0.0.2",
                       "session": "s1", "input": f"cmd {i}", **kw})


class FakeResponse(io.BytesIO):
    status = 204

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeAzure:
    def __init__(self, fail=None):
        self.posts, self.tokens, self.fail = [], 0, list(fail or [])

    def __call__(self, req, timeout=None):
        if "login.microsoftonline.com" in req.full_url:
            self.tokens += 1
            return FakeResponse(json.dumps({"access_token": "tok", "expires_in": 3600}).encode())
        if self.fail:
            code = self.fail.pop(0)
            raise urllib.error.HTTPError(req.full_url, code, "err", {"Retry-After": "0"}, io.BytesIO(b"x"))
        assert req.headers["Authorization"] == "Bearer tok"
        self.posts.append(json.loads(gzip.decompress(req.data)))
        return FakeResponse(b"")


class SentinelTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.logs = os.path.join(self.tmp.name, "logs")
        self.state = os.path.join(self.tmp.name, "state", "sentinel.json")
        os.makedirs(self.logs)
        os.makedirs(os.path.dirname(self.state))
        patcher = mock.patch.object(sentinel.time, "sleep", lambda s: None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def path(self, name):
        return os.path.join(self.logs, name)

    def write(self, name, lines, mode="w"):
        with open(self.path(name), mode) as fh:
            fh.write("".join(line + "\n" for line in lines))

    def run_once(self, fake):
        return sentinel.run(self.logs, self.state, sentinel.Client(ENV, opener=fake), NOW)

    def sent_inputs(self, fake):
        return [r["input"] for batch in fake.posts for r in batch]

    def test_shapes_rows_for_the_table(self):
        self.write("cowrie.json", [ev(1)])
        fake = FakeAzure()
        self.run_once(fake)
        row = fake.posts[0][0]
        self.assertEqual(row["src_port"], 40000)          # coerced to int
        self.assertNotIn("dst_ip", row)                   # not a column
        self.assertEqual(row["timestamp"], "2026-11-09T10:00:01.000000Z")

    def test_only_new_complete_lines(self):
        self.write("cowrie.json", [ev(1), ev(2)])
        with open(self.path("cowrie.json"), "a") as fh:
            fh.write(ev(3)[:20])                          # half-written line
        fake = FakeAzure()
        self.assertEqual(self.run_once(fake), 2)
        with open(self.path("cowrie.json"), "a") as fh:
            fh.write(ev(3)[20:] + "\n")
        self.assertEqual(self.run_once(fake), 1)
        self.assertEqual(self.run_once(fake), 0)
        self.assertEqual(self.sent_inputs(fake), ["cmd 1", "cmd 2", "cmd 3"])

    def test_follows_rotation(self):
        self.write("cowrie.json", [ev(1)])
        fake = FakeAzure()
        self.run_once(fake)
        self.write("cowrie.json", [ev(2)], mode="a")      # written before rotation, not sent yet
        os.rename(self.path("cowrie.json"), self.path("cowrie.json.2026-11-09"))
        self.write("cowrie.json", [ev(3, day="2026-11-10")])
        self.run_once(fake)
        self.assertEqual(self.sent_inputs(fake), ["cmd 1", "cmd 2", "cmd 3"])

    def test_first_run_backfills_recent_rotated_logs_only(self):
        self.write("cowrie.json.2026-11-01", [ev(1, day="2026-11-01")])
        self.write("cowrie.json.2026-11-08", [ev(2, day="2026-11-08")])
        self.write("cowrie.json", [ev(3)])
        fake = FakeAzure()
        self.run_once(fake)
        self.assertEqual(self.sent_inputs(fake), ["cmd 2", "cmd 3"])

    def test_batches_stay_under_the_limit(self):
        big = "x" * 5000
        self.write("cowrie.json", [ev(i % 60, input=f"{big}{i}") for i in range(400)])
        fake = FakeAzure()
        self.assertEqual(self.run_once(fake), 400)
        self.assertGreater(len(fake.posts), 1)
        for batch in fake.posts:
            self.assertLess(len(json.dumps(batch)), 1_000_000)

    def test_retries_throttling_then_succeeds(self):
        self.write("cowrie.json", [ev(1)])
        fake = FakeAzure(fail=[429, 503])
        self.assertEqual(self.run_once(fake), 1)

    def test_auth_failure_keeps_offset(self):
        self.write("cowrie.json", [ev(1)])
        with self.assertRaises(sentinel.Fatal):
            self.run_once(FakeAzure(fail=[403]))
        fake = FakeAzure()
        self.run_once(fake)
        self.assertEqual(self.sent_inputs(fake), ["cmd 1"])   # nothing was skipped

    def test_no_settings_does_nothing(self):
        for k in ENV:
            os.environ.pop(k, None)
        self.assertEqual(sentinel.main(["--logs", self.logs, "--state", self.state + ".x"]), 0)
        self.assertFalse(os.path.exists(self.state + ".x"))


if __name__ == "__main__":
    unittest.main()
