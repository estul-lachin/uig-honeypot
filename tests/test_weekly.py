"""Tests for vps/weekly.py. Run: python3 -m unittest discover -s tests

All IPs below are from documentation ranges (RFC 5737), never real hosts.
2026-11-02 is a Monday: week 2026-W45 is 11-02..11-08, W46 is 11-09..11-15.
"""

import argparse
import datetime
import json
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "vps"))
import aggregate  # noqa: E402
import weekly  # noqa: E402

UTC = datetime.timezone.utc
HONEYPOT_IP = "203.0.113.10"


def ev(eventid, ts, **kw):
    return json.dumps({"eventid": eventid, "timestamp": ts, **kw})


def session(day, ip, sid, password, cmd=None, hour="10"):
    ts = f"{day}T{hour}:00:0"
    out = [ev("cowrie.session.connect", ts + "0.000Z", src_ip=ip, session=sid, protocol="ssh"),
           ev("cowrie.login.success", ts + "1.000Z", src_ip=ip, session=sid, username="root", password=password)]
    if cmd:
        out.append(ev("cowrie.command.input", ts + "2.000Z", src_ip=ip, session=sid, input=cmd))
    return out


class WeeklyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.logs, self.state, self.reports = (os.path.join(d, x) for x in ("logs", "state", "reports"))
        os.makedirs(self.logs)
        # W45: the honeypot starts on Thursday 11-05
        self.write("cowrie.json.2026-11-05", session("2026-11-05", "198.51.100.7", "a1", "admin", "uname -a"))
        self.write("cowrie.json.2026-11-08", session("2026-11-08", "198.51.100.8", "a2", "admin", "uname -a"))
        # W46
        self.write("cowrie.json.2026-11-10",
                   session("2026-11-10", "198.51.100.7", "b1", "admin", "uname -a", hour="03")
                   + session("2026-11-10", "198.51.100.9", "b2", "S3cret!", "cat /etc/shadow", hour="03")
                   + [ev("cowrie.session.file_download", "2026-11-10T03:00:05.000Z", src_ip="198.51.100.9",
                         session="b2", url=f"http://192.0.2.55/bins.sh?h={HONEYPOT_IP}", shasum="cd" * 32)])
        # live file: W47, not finished
        self.write("cowrie.json", session("2026-11-16", "198.51.100.7", "c1", "admin"))

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, lines):
        with open(os.path.join(self.logs, name), "w") as fh:
            fh.write("\n".join(lines) + "\n")

    def run_at(self, now):
        a = argparse.Namespace(logs=self.logs, state=self.state, out=os.path.join(self.tmp.name, "stats.json"),
                               recent_out=None, reports=self.reports, redact=[HONEYPOT_IP], exclude_ip=[])
        aggregate.run(a, aggregate.NO_GEO, now)
        with open(os.path.join(self.reports, "index.json")) as fh:
            return json.load(fh)["weeks"]

    def report(self, week):
        with open(os.path.join(self.reports, week + ".json")) as fh:
            raw = fh.read()
        return raw, json.loads(raw)

    def test_only_finished_weeks(self):
        # Monday 11-16 01:00 UTC: W46 ended an hour ago, still inside the grace period
        self.assertEqual(self.run_at(datetime.datetime(2026, 11, 16, 1, tzinfo=UTC)), ["2026-W45"])
        self.assertEqual(self.run_at(datetime.datetime(2026, 11, 16, 3, tzinfo=UTC)), ["2026-W46", "2026-W45"])

    def test_week_contents(self):
        self.run_at(datetime.datetime(2026, 11, 16, 3, tzinfo=UTC))
        _, w45 = self.report("2026-W45")
        self.assertTrue(w45["partial"])
        self.assertIsNone(w45["previous"])
        _, w = self.report("2026-W46")
        self.assertFalse(w["partial"])
        self.assertEqual((w["from"], w["to"]), ("2026-11-09", "2026-11-15"))
        self.assertEqual(w["totals"]["sessions"], 2)
        self.assertEqual(w["previous"]["sessions"], 2)
        self.assertEqual(w["new"]["passwords"], [{"value": "S3cret!", "count": 1}])   # "admin" was seen in W45
        self.assertEqual([c["value"] for c in w["new"]["commands"]], ["cat /etc/shadow"])
        self.assertTrue(w["downloads"][0]["new"])
        self.assertEqual(next(h for h in w["hours_utc"] if h["hour"] == "03")["sessions"], 2)
        ttps = {t["id"]: t["sessions"] for t in w["ttps"]}
        self.assertEqual(ttps["T1078"], 2)
        self.assertEqual(ttps["T1003.008"], 1)
        self.assertEqual(ttps["T1105"], 1)

    def test_nothing_private_is_published(self):
        self.run_at(datetime.datetime(2026, 11, 16, 3, tzinfo=UTC))
        raw, _ = self.report("2026-W46")
        self.assertIsNone(re.search(r"\d+\.\d+\.\d+\.\d+", raw))
        self.assertNotIn("http://", raw)
        self.assertNotIn("src_ip", raw)
        self.assertIn("[honeypot-ip]", raw)

    def test_finished_reports_are_never_rewritten(self):
        self.run_at(datetime.datetime(2026, 11, 16, 3, tzinfo=UTC))
        raw, _ = self.report("2026-W46")
        os.remove(os.path.join(self.logs, "cowrie.json.2026-11-10"))   # raw log pruned
        self.run_at(datetime.datetime(2026, 11, 30, 3, tzinfo=UTC))
        self.assertEqual(self.report("2026-W46")[0], raw)

    def test_empty(self):
        for f in os.listdir(self.logs):
            os.remove(os.path.join(self.logs, f))
        self.assertEqual(self.run_at(datetime.datetime(2026, 11, 16, 3, tzinfo=UTC)), [])


if __name__ == "__main__":
    unittest.main()
