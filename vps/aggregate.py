#!/usr/bin/env python3
"""Turn Cowrie JSON logs into one public, privacy-safe stats.json.

Raw logs stay on the VPS. The output never contains attacker IPs, the
honeypot's own IP (values given with --redact), or live URLs: IPv4
addresses and URLs inside strings are defanged.

Rotated logs (cowrie.json.YYYY-MM-DD) are complete, so each one is parsed
once into a small partial file under --state. The live cowrie.json is
parsed on every run and never cached. Partials outlive the raw logs, so
history survives log cleanup. Each counter in a partial keeps only its
top KEEP entries, so long-tail counts are approximate.
"""

import argparse
import collections
import datetime
import glob
import json
import os
import re
import sys

KEEP = 500          # entries kept per counter in a partial
TOP = 20            # entries published per top list
MAX_LEN = 120       # longest string published
COUNTERS = ("usernames", "passwords", "pairs", "commands", "clients", "downloads")

IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
URL_SCHEME = re.compile(r"\b(https?|ftp|tftp)://", re.IGNORECASE)
DEFANG = {"http": "hxxp", "https": "hxxps"}
CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def clean(value, redact):
    """Make an attacker-supplied string safe to publish."""
    s = CONTROL.sub(" ", str(value))
    for r in redact:
        s = s.replace(r, "[honeypot-ip]")
    s = URL_SCHEME.sub(lambda m: DEFANG.get(m.group(1).lower(), m.group(1)) + "[:]//", s)
    s = IPV4.sub(r"\1[.]\2[.]\3[.]\4", s)
    s = " ".join(s.split())
    return s if len(s) <= MAX_LEN else s[: MAX_LEN - 1] + "…"


def new_day():
    return {"sessions": 0, "logins": 0, "logins_ok": 0, "commands_run": 0,
            "ssh": 0, "telnet": 0, "ips": set(),
            **{c: collections.Counter() for c in COUNTERS}}


def parse(path, redact, exclude):
    """Return {day: bucket} for one log file. Bad lines are skipped."""
    days = collections.defaultdict(new_day)
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                ev = json.loads(line)
                day = ev["timestamp"][:10]
                eid = ev["eventid"]
            except (ValueError, KeyError, TypeError):
                continue
            if ev.get("src_ip") in exclude:
                continue
            b = days[day]
            if eid == "cowrie.session.connect":
                b["sessions"] += 1
                b["ips"].add(ev.get("src_ip", ""))
                proto = ev.get("protocol", "ssh")
                if proto in ("ssh", "telnet"):
                    b[proto] += 1
            elif eid in ("cowrie.login.failed", "cowrie.login.success"):
                b["logins"] += 1
                if eid == "cowrie.login.success":
                    b["logins_ok"] += 1
                user = clean(ev.get("username", ""), redact)
                pw = clean(ev.get("password", ""), redact)
                b["usernames"][user] += 1
                b["passwords"][pw] += 1
                b["pairs"][f"{user} / {pw}"] += 1
            elif eid == "cowrie.command.input":
                b["commands_run"] += 1
                b["commands"][clean(ev.get("input", ""), redact)] += 1
            elif eid == "cowrie.client.version":
                b["clients"][clean(ev.get("version", ""), redact)] += 1
            elif eid == "cowrie.session.file_download" and ev.get("shasum"):
                url = clean(ev.get("url", ""), redact)
                b["downloads"][f"{ev['shasum']} {url}".strip()] += 1
    return days


def to_json(days):
    out = {}
    for day, b in days.items():
        d = dict(b)
        d["ips"] = sorted(b["ips"])
        for c in COUNTERS:
            d[c] = dict(b[c].most_common(KEEP))
        out[day] = d
    return out


def from_json(data):
    days = {}
    for day, d in data.items():
        b = new_day()
        for k in ("sessions", "logins", "logins_ok", "commands_run", "ssh", "telnet"):
            b[k] = d.get(k, 0)
        b["ips"] = set(d.get("ips", []))
        for c in COUNTERS:
            b[c] = collections.Counter(d.get(c, {}))
        days[day] = b
    return days


def merge(into, days):
    for day, b in days.items():
        t = into[day]
        for k in ("sessions", "logins", "logins_ok", "commands_run", "ssh", "telnet"):
            t[k] += b[k]
        t["ips"] |= b["ips"]
        for c in COUNTERS:
            t[c].update(b[c])


def atomic_write(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, separators=(",", ":"))
        fh.write("\n")
    os.replace(tmp, path)


def top(counter):
    return [{"value": k, "count": v} for k, v in counter.most_common(TOP)]


def build(all_days, now):
    ips, total = set(), new_day()
    for b in all_days.values():
        ips |= b["ips"]
    for b in all_days.values():
        for k in ("sessions", "logins", "logins_ok", "commands_run", "ssh", "telnet"):
            total[k] += b[k]
        for c in COUNTERS:
            total[c].update(b[c])
    downloads = []
    for k, v in total["downloads"].most_common(TOP):
        sha, _, url = k.partition(" ")
        downloads.append({"sha256": sha, "url": url, "count": v})
    days = sorted(all_days)
    return {
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "first_day": days[0] if days else None,
        "last_day": days[-1] if days else None,
        "totals": {
            "sessions": total["sessions"],
            "unique_sources": len(ips),
            "login_attempts": total["logins"],
            "logins_accepted": total["logins_ok"],
            "commands_run": total["commands_run"],
            "ssh_sessions": total["ssh"],
            "telnet_sessions": total["telnet"],
        },
        "daily": [{"day": d,
                   "sessions": all_days[d]["sessions"],
                   "login_attempts": all_days[d]["logins"],
                   "unique_sources": len(all_days[d]["ips"])} for d in days],
        "top": {
            "usernames": top(total["usernames"]),
            "passwords": top(total["passwords"]),
            "pairs": top(total["pairs"]),
            "commands": top(total["commands"]),
            "clients": top(total["clients"]),
        },
        "downloads": downloads,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--logs", required=True, help="Cowrie log directory")
    ap.add_argument("--state", required=True, help="directory for cached partials")
    ap.add_argument("--out", required=True, help="stats.json to write")
    ap.add_argument("--redact", action="append", default=[],
                    help="string to replace with [honeypot-ip] (repeatable)")
    ap.add_argument("--exclude-ip", action="append", default=[],
                    help="source IP whose events are ignored (repeatable)")
    a = ap.parse_args(argv)
    redact = [r for r in a.redact if r]
    exclude = set(a.exclude_ip)
    os.makedirs(a.state, exist_ok=True)

    all_days = collections.defaultdict(new_day)
    for path in sorted(glob.glob(os.path.join(a.logs, "cowrie.json.*"))):
        if path.endswith(".tmp"):
            continue
        part = os.path.join(a.state, os.path.basename(path) + ".partial.json")
        if not os.path.exists(part):
            atomic_write(part, to_json(parse(path, redact, exclude)))
    for part in sorted(glob.glob(os.path.join(a.state, "*.partial.json"))):
        with open(part, encoding="utf-8") as fh:
            merge(all_days, from_json(json.load(fh)))
    live = os.path.join(a.logs, "cowrie.json")
    if os.path.exists(live):
        merge(all_days, parse(live, redact, exclude))

    now = datetime.datetime.now(datetime.timezone.utc)
    atomic_write(a.out, build(all_days, now))
    return 0


if __name__ == "__main__":
    sys.exit(main())
