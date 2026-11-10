"""Tests for vps/network.py. Run: python3 -m unittest discover -s tests

IPs are from the RFC 5737 documentation ranges (sources) and RFC 1918 (the VPS itself).
"""

import datetime
import gzip
import json
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "vps"))
import network  # noqa: E402

NOW = datetime.datetime(2026, 11, 9, 12, tzinfo=datetime.timezone.utc)
HONEYPOT_IP = "192.0.2.50"
ETH0 = "172.16.0.10"
SSH_PORT = 48022


def alert(ts, src, dest_port=22, sid=2001219, sig="ET SCAN Potential SSH Scan", sev=2,
          cat="Attempted Information Leak", meta=None, dest=ETH0):
    return {"timestamp": ts, "event_type": "alert", "src_ip": src, "src_port": 40000, "dest_ip": dest,
            "dest_port": dest_port, "proto": "TCP",
            "alert": {"signature_id": sid, "rev": 1, "signature": sig, "category": cat, "severity": sev,
                      "metadata": meta or {}}}


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.sur = os.path.join(self.tmp.name, "suricata")
        self.cow = os.path.join(self.tmp.name, "cowrie")
        os.makedirs(self.sur)
        os.makedirs(self.cow)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, path, events, gz=False):
        with (gzip.open if gz else open)(path, "wt", encoding="utf-8") as fh:
            for ev in events:
                fh.write((ev if isinstance(ev, str) else json.dumps(ev)) + "\n")

    def run_it(self, **kw):
        kw.setdefault("redact", [HONEYPOT_IP])
        return network.run(self.sur, NOW, **kw)


class NetworkTest(Fixture):
    def test_inbound_counted_outbound_only_totalled(self):
        self.write(os.path.join(self.sur, "eve.json"), [
            alert("2026-11-09T10:00:00.000000+0000", "198.51.100.7"),
            alert("2026-11-09T10:01:00.000000+0000", "198.51.100.7", dest_port=3306, sid=2010937,
                  sig="ET SCAN Suspicious inbound to mySQL port 3306", cat="Potentially Bad Traffic"),
            alert("2026-11-09T10:02:00.000000+0000", "203.0.113.9"),
            # the VPS's own traffic (eth0 and the Cowrie bridge)
            alert("2026-11-09T10:03:00.000000+0000", ETH0, dest="198.51.100.200", dest_port=443),
            alert("2026-11-09T10:04:00.000000+0000", "172.18.0.2", dest="198.51.100.200", dest_port=23),
            {"timestamp": "2026-11-09T10:05:00.000000+0000", "event_type": "flow", "src_ip": "198.51.100.7"},
            "not json",
        ])
        d = self.run_it()
        self.assertEqual(d["totals"], {"alerts": 3, "outbound_alerts": 2, "sources": 2, "signatures": 2,
                                       "high": 0})
        self.assertEqual(d["daily"], [{"day": "2026-11-09", "alerts": 3, "high": 0, "sources": 2}])
        self.assertEqual(d["signatures"][0]["sid"], 2001219)
        self.assertEqual((d["signatures"][0]["count"], d["signatures"][0]["sources"]), (2, 2))
        self.assertEqual([(p["port"], p["sources"]) for p in d["ports"]], [(22, 2), (3306, 1)])
        self.assertNotIn(443, [p["port"] for p in d["ports"]])  # outbound only

    def test_no_ip_addresses_and_hidden_port(self):
        self.write(os.path.join(self.sur, "eve.json"), [
            alert("2026-11-09T10:00:00.000000+0000", "198.51.100.7", dest_port=SSH_PORT),
            alert("2026-11-09T10:00:01.000000+0000", "198.51.100.8", sid=9000001,
                  sig=f"ET TEST odd name with {HONEYPOT_IP} and 203.0.113.77 in it"),
        ])
        d = self.run_it(hide_ports=[SSH_PORT])
        s = json.dumps(d)
        self.assertNotIn(str(SSH_PORT), s)
        self.assertIn("[honeypot-ip]", s)
        self.assertEqual(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", s), [])
        self.assertEqual(d["totals"]["alerts"], 2)  # the alert still counts, only its port is hidden

    def test_window_and_rotations(self):
        self.write(os.path.join(self.sur, "eve.json.1.gz"), [
            alert("2026-10-01T10:00:00.000000+0000", "198.51.100.1"),  # older than 30 days
            alert("2026-11-08T23:59:00.000000+0000", "198.51.100.2", sev=1, sid=2066000,
                  sig="ET WEB_SERVER Example Auth Bypass (CVE-2026-0001)", cat="Attempted Administrator Privilege Gain",
                  meta={"cve": ["CVE_2026_0001"], "mitre_technique_id": ["T1190"]}),
        ], gz=True)
        self.write(os.path.join(self.sur, "eve.json"), [
            alert("2026-11-09T01:00:00.000000+0000", "198.51.100.3", sev=1, sid=2066000,
                  sig="ET WEB_SERVER Example Auth Bypass (CVE-2026-0001)", meta={"cve": ["CVE_2026_0001"]}),
        ])
        d = self.run_it()
        self.assertEqual(d["totals"]["alerts"], 2)
        self.assertEqual(d["totals"]["high"], 2)
        self.assertEqual([x["day"] for x in d["daily"]], ["2026-11-08", "2026-11-09"])
        self.assertEqual(d["cves"], [{"cve": "CVE-2026-0001", "count": 2, "sources": 2, "first_day": "2026-11-08",
                                      "last_day": "2026-11-09",
                                      "signature": "ET WEB_SERVER Example Auth Bypass (CVE-2026-0001)"}])
        self.assertEqual(d["ttps"], [{"id": "T1190", "sources": 1}])
        self.assertEqual(d["severity"], [{"severity": 1, "label": "high", "alerts": 2}])

    def test_cowrie_overlap_and_countries(self):
        self.write(os.path.join(self.sur, "eve.json"), [
            alert("2026-11-09T10:00:00.000000+0000", "198.51.100.7"),
            alert("2026-11-09T10:00:00.000000+0000", "203.0.113.9", dest_port=5432),
            alert("2026-11-09T10:00:00.000000+0000", HONEYPOT_IP),  # excluded
        ])
        self.write(os.path.join(self.cow, "cowrie.json"), [
            {"timestamp": "2026-11-09T10:00:05.000000Z", "eventid": "cowrie.session.connect",
             "src_ip": "198.51.100.7", "session": "a1"},
            {"timestamp": "2026-11-09T10:00:05.000000Z", "eventid": "cowrie.session.connect",
             "src_ip": "192.0.2.99", "session": "a2"},
        ])
        geo = lambda ip: {"cc": "NL"} if ip == "198.51.100.7" else {}
        d = self.run_it(cowrie_logs=self.cow, exclude=[HONEYPOT_IP], geo=geo)
        self.assertEqual(d["cowrie"], {"sources": 2, "also_cowrie": 1, "suricata_only": 1})
        self.assertEqual(d["countries"], {"NL": 1, "??": 1})
        self.assertIsNone(self.run_it()["cowrie"])

    def test_engine_from_last_stats_record(self):
        rec = lambda up, pk, dr: {"timestamp": "2026-11-09T11:59:00.000000+0000", "event_type": "stats",
                                  "stats": {"uptime": up, "capture": {"kernel_packets": pk, "kernel_drops": dr},
                                            "detect": {"engines": [{"rules_loaded": 53000}]}}}
        self.write(os.path.join(self.sur, "stats.json"), [rec(60, 10, 5), rec(300, 2000, 1), '{"partial'])
        self.assertEqual(self.run_it()["engine"], {"at": "2026-11-09T11:59:00.000000Z", "uptime_s": 300,
                                                   "packets": 2000, "drops": 1, "drop_pct": 0.05,
                                                   "rules_loaded": 53000})

    def test_empty(self):
        d = self.run_it()
        self.assertEqual(d["totals"]["alerts"], 0)
        self.assertEqual((d["first_day"], d["daily"], d["engine"]), (None, [], None))

    def test_main_hide_port_empty_value(self):
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000+0000")
        self.write(os.path.join(self.sur, "eve.json"), [alert(now, "198.51.100.7")])
        out = os.path.join(self.tmp.name, "network.json")
        self.assertEqual(network.main(["--suricata-logs", self.sur, "--out", out, "--hide-port=",
                                       "--hide-port", "23"]), 0)
        with open(out, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["totals"]["alerts"], 1)


if __name__ == "__main__":
    unittest.main()
