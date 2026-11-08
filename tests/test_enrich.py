"""Tests for vps/enrich.py and the reputation summary. Run: python3 -m unittest discover -s tests

No network: a fake fetcher stands in for AbuseIPDB. enrich.py skips non-global
addresses (RFC 1918, and the RFC 5737 documentation ranges the other tests use),
so the "attackers" here are well-known public DNS resolvers. They are only ever
passed to the fake fetcher, never looked up for real.
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
import enrich  # noqa: E402

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 11, 20, 12, tzinfo=UTC)
A, B, C = "8.8.4.4", "9.9.9.9", "1.0.0.1"     # stand-ins, only seen by the fake fetcher
HONEYPOT = "8.8.8.8"


def connect(ts, ip):
    return json.dumps({"eventid": "cowrie.session.connect", "timestamp": ts, "src_ip": ip, "session": ts})


class FakeAbuseIPDB:
    def __init__(self, fail_after=None):
        self.calls, self.fail_after = [], fail_after

    def __call__(self, ip, key):
        assert key == "test-key"
        if self.fail_after is not None and len(self.calls) >= self.fail_after:
            raise enrich.RateLimited()
        self.calls.append(ip)
        return {"ipAddress": ip, "abuseConfidenceScore": {A: 100, B: 0}.get(ip, 30),
                "totalReports": {A: 812, B: 0}.get(ip, 4), "isp": "Example <Hosting>\x1b",
                "usageType": "Data Center/Web Hosting/Transit", "countryCode": "NL", "isTor": False}


class EnrichTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.logs = os.path.join(self.tmp.name, "logs")
        self.cache = os.path.join(self.tmp.name, "enrich", "abuseipdb.json")
        os.makedirs(self.logs)
        os.makedirs(os.path.dirname(self.cache))
        self.write("cowrie.json.2026-11-19", [connect("2026-11-19T10:00:00.000000Z", A),
                                              connect("2026-11-19T11:00:00.000000Z", "10.0.0.5")])
        self.write("cowrie.json.2026-11-01", [connect("2026-11-01T10:00:00.000000Z", C)])  # too old to scan
        self.write("cowrie.json", [connect("2026-11-20T11:00:00.000000Z", B),
                                   connect("2026-11-20T11:30:00.000000Z", HONEYPOT)])

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, lines):
        with open(os.path.join(self.logs, name), "w") as fh:
            fh.write("\n".join(lines) + "\n")

    def run_at(self, now, fake):
        enrich.run(self.logs, self.cache, "test-key", now, [HONEYPOT], fake)
        with open(self.cache) as fh:
            return json.load(fh)

    def test_checks_recent_public_sources_once(self):
        fake = FakeAbuseIPDB()
        c = self.run_at(NOW, fake)
        self.assertEqual(fake.calls, [B, A])                  # newest first; no private, old or own IP
        self.assertEqual(c["ips"][A]["abuseConfidenceScore"], 100)
        self.assertEqual(c["budget"], {"2026-11-20": 2})
        fake2 = FakeAbuseIPDB()
        self.run_at(NOW, fake2)
        self.assertEqual(fake2.calls, [])                     # cached

    def test_recheck_only_when_stale_and_seen_again(self):
        self.run_at(NOW, FakeAbuseIPDB())
        later = NOW + datetime.timedelta(days=8)
        self.write("cowrie.json", [connect("2026-11-28T09:00:00.000000Z", B)])
        fake = FakeAbuseIPDB()
        self.run_at(later, fake)
        self.assertEqual(fake.calls, [B])                     # A is stale but not seen again

    def test_rate_limit_keeps_what_was_done(self):
        c = self.run_at(NOW, FakeAbuseIPDB(fail_after=1))
        self.assertEqual(list(c["ips"]), [B])

    def test_daily_budget(self):
        os.makedirs(os.path.dirname(self.cache), exist_ok=True)
        with open(self.cache, "w") as fh:
            json.dump({"ips": {}, "budget": {"2026-11-20": enrich.DAILY_BUDGET}}, fh)
        fake = FakeAbuseIPDB()
        self.run_at(NOW, fake)
        self.assertEqual(fake.calls, [])

    def test_no_key_does_nothing(self):
        os.environ.pop("HP_ABUSEIPDB_KEY", None)
        self.assertEqual(enrich.main(["--logs", self.logs, "--cache", self.cache + ".x"]), 0)
        self.assertFalse(os.path.exists(self.cache + ".x"))

    def test_summary_has_no_ips(self):
        self.run_at(NOW, FakeAbuseIPDB())
        rep = aggregate.load_reputation(self.cache)
        out = aggregate.reputation({A, B, "203.0.113.9"}, rep)
        raw = json.dumps(out)
        self.assertIsNone(re.search(r"\d+\.\d+\.\d+\.\d+", raw))
        self.assertEqual((out["sources"], out["checked"], out["never_reported"]), (3, 2, 1))
        self.assertEqual({b["range"]: b["sources"] for b in out["scores"]},
                         {"0": 1, "1-24": 0, "25-74": 0, "75-100": 1})
        self.assertEqual(out["isps"][0], {"value": "Example <Hosting>", "count": 2})  # control char stripped

    def test_stats_json_includes_reputation(self):
        self.run_at(NOW, FakeAbuseIPDB())
        out = os.path.join(self.tmp.name, "stats.json")
        a = argparse.Namespace(logs=self.logs, state=os.path.join(self.tmp.name, "state"), out=out,
                               recent_out=None, reports=None, reputation=self.cache,
                               redact=[HONEYPOT], exclude_ip=[HONEYPOT])
        aggregate.run(a, aggregate.NO_GEO, NOW)
        with open(out) as fh:
            raw = fh.read()
        s = json.loads(raw)
        self.assertEqual(s["reputation"]["checked"], 2)
        for ip in (A, B, C, HONEYPOT):
            self.assertNotIn(ip, raw)


if __name__ == "__main__":
    unittest.main()
