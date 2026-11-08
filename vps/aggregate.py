#!/usr/bin/env python3
"""Turn Cowrie JSON logs into public, privacy-safe stats.json and recent.json.

Raw logs stay on the VPS. The output never contains attacker IPs, the
honeypot's own IP (values given with --redact), or live URLs: IPv4
addresses and URLs inside strings are defanged. With --geoip, sources are
reduced to country, city and coordinates rounded to GEO_DIGITS decimals.

recent.json holds the last RECENT_WINDOW seconds of events, for the
replayed attack map.

Rotated logs (cowrie.json.YYYY-MM-DD) are complete, so each one is parsed
once into a small partial file under --state. The live cowrie.json is
parsed on every run and never cached. Partials outlive the raw logs, so
history survives log cleanup. Each counter in a partial keeps only its
top KEEP entries, so long-tail counts are approximate.

Sessions are also tagged with MITRE ATT&CK techniques from ttp_rules.json
(next to this script); each technique counts once per session.
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
COUNTERS = ("usernames", "passwords", "pairs", "commands", "clients", "downloads", "countries",
            "ttps", "hours")
# Bump when the partial format changes: old partials are then ignored and
# rebuilt from the raw logs that are still on disk.
PARTIAL_SUFFIX = ".v2.partial.json"
RULES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ttp_rules.json")
RECENT_WINDOW = 3600  # seconds of events in recent.json
RECENT_MAX = 2000     # cap on events in recent.json (newest kept)
GEO_DIGITS = 1        # coordinate rounding: 0.1 degree is about 11 km

IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
URL_SCHEME = re.compile(r"\b(https?|ftp|tftp)://", re.IGNORECASE)
DEFANG = {"http": "hxxp", "https": "hxxps"}
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# Cowrie writes some raw bytes as literal text, e.g. "enable\\x00".
ESCAPED_CONTROL = re.compile(r"\\x(?:[01][0-9a-fA-F]|7[fF])")


def clean(value, redact):
    """Make an attacker-supplied string safe to publish."""
    s = CONTROL.sub(" ", ESCAPED_CONTROL.sub(" ", str(value)))
    for r in redact:
        s = s.replace(r, "[honeypot-ip]")
    s = URL_SCHEME.sub(lambda m: DEFANG.get(m.group(1).lower(), m.group(1)) + "[:]//", s)
    s = IPV4.sub(r"\1[.]\2[.]\3[.]\4", s)
    s = " ".join(s.split())
    return s if len(s) <= MAX_LEN else s[: MAX_LEN - 1] + "…"


def load_rules(path=RULES_FILE):
    """Return (event rules {eventid: [id]}, [(compiled pattern, id)], {id: meta})."""
    with open(path, encoding="utf-8") as fh:
        rules = json.load(fh)["rules"]
    by_event, patterns, meta = collections.defaultdict(list), [], {}
    for r in rules:
        meta.setdefault(r["id"], {"id": r["id"], "name": r["name"], "tactic": r["tactic"]})
        if "event" in r:
            by_event[r["event"]].append(r["id"])
        else:
            patterns.append((re.compile(r["pattern"]), r["id"]))
    return dict(by_event), patterns, meta


RULES = load_rules()


def tag(eid, text=None, rules=RULES):
    """ATT&CK technique IDs for one event (a set, possibly empty)."""
    by_event, patterns, _ = rules
    ids = set(by_event.get(eid, ()))
    if text:
        ids.update(tid for rx, tid in patterns if rx.search(text))
    return ids


def new_day():
    return {"sessions": 0, "logins": 0, "logins_ok": 0, "commands_run": 0,
            "ssh": 0, "telnet": 0, "ips": set(),
            **{c: collections.Counter() for c in COUNTERS}}


class Geo:
    """IP -> {"cc", "city", "lat", "lon"} from a DB-IP/MaxMind-format .mmdb.

    Without a database (or the maxminddb module) every lookup returns {}.
    """

    def __init__(self, path=None, reader=None):
        self.reader, self.cache = reader, {}
        if reader is None and path and os.path.exists(path):
            try:
                import maxminddb
                self.reader = maxminddb.open_database(path)
            except ImportError:
                print("warning: python3-maxminddb missing, no geo data", file=sys.stderr)

    def __call__(self, ip):
        if not self.reader or not ip:
            return {}
        if ip not in self.cache:
            try:
                rec = self.reader.get(ip) or {}
            except ValueError:
                rec = {}
            loc = rec.get("location") or {}
            out = {}
            cc = (rec.get("country") or {}).get("iso_code")
            if cc:
                out["cc"] = cc
            city = ((rec.get("city") or {}).get("names") or {}).get("en")
            if city:
                out["city"] = clean(city, [])
            if loc.get("latitude") is not None and loc.get("longitude") is not None:
                out["lat"] = round(loc["latitude"], GEO_DIGITS)
                out["lon"] = round(loc["longitude"], GEO_DIGITS)
            self.cache[ip] = out
        return self.cache[ip]


NO_GEO = Geo()


def epoch(ts):
    return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


def parse(path, redact, exclude, geo=NO_GEO, since=None, recent=None):
    """Return {day: bucket} for one log file. Bad lines are skipped.

    With `recent` (a list) and `since` (epoch seconds), events at or after
    `since` are also appended to `recent` in their public form.
    """
    days = collections.defaultdict(new_day)
    tagged = set()  # (day, session, technique): count each once per session
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                ev = json.loads(line)
                day = ev["timestamp"][:10]
                eid = ev["eventid"]
            except (ValueError, KeyError, TypeError, AttributeError):
                continue
            if ev.get("src_ip") in exclude:
                continue
            b = days[day]
            item = None
            text = ev.get("input") if eid == "cowrie.command.input" else None
            for tid in tag(eid, str(text) if text is not None else None):
                key = (day, ev.get("session"), tid)
                if key not in tagged:
                    tagged.add(key)
                    b["ttps"][tid] += 1
            if eid == "cowrie.session.connect":
                b["sessions"] += 1
                b["ips"].add(ev.get("src_ip", ""))
                proto = ev.get("protocol", "ssh")
                if proto in ("ssh", "telnet"):
                    b[proto] += 1
                b["hours"][ev["timestamp"][11:13]] += 1
                cc = geo(ev.get("src_ip")).get("cc")
                b["countries"][cc or "??"] += 1
                item = {"kind": "connect", "proto": proto if proto in ("ssh", "telnet") else "ssh"}
            elif eid in ("cowrie.login.failed", "cowrie.login.success"):
                b["logins"] += 1
                ok = eid == "cowrie.login.success"
                if ok:
                    b["logins_ok"] += 1
                user = clean(ev.get("username", ""), redact)
                pw = clean(ev.get("password", ""), redact)
                b["usernames"][user] += 1
                b["passwords"][pw] += 1
                b["pairs"][f"{user} / {pw}"] += 1
                item = {"kind": "login", "ok": ok, "text": f"{user} / {pw}"}
            elif eid == "cowrie.command.input":
                b["commands_run"] += 1
                cmd = clean(ev.get("input", ""), redact)
                b["commands"][cmd] += 1
                item = {"kind": "command", "text": cmd}
            elif eid == "cowrie.client.version":
                b["clients"][clean(ev.get("version", ""), redact)] += 1
            elif eid == "cowrie.session.file_download" and ev.get("shasum"):
                url = clean(ev.get("url", ""), redact)
                b["downloads"][f"{ev['shasum']} {url}".strip()] += 1
                item = {"kind": "download", "text": url}
            if item is not None and recent is not None:
                try:
                    t = epoch(ev["timestamp"])
                except ValueError:
                    continue
                if t >= since:
                    recent.append({"t": round(t, 1), **item, **geo(ev.get("src_ip"))})
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
        # every country seen ("??" = no geo data), for the map's shading
        "countries": dict(total["countries"].most_common()),
        "ttps": ttp_list(total["ttps"]),
    }


def ttp_list(counter):
    """Every technique seen, most sessions first, with its name and tactic."""
    meta = RULES[2]
    return [{**meta.get(k, {"id": k, "name": k, "tactic": ""}), "sessions": v}
            for k, v in counter.most_common()]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--logs", required=True, help="Cowrie log directory")
    ap.add_argument("--state", required=True, help="directory for cached partials")
    ap.add_argument("--out", required=True, help="stats.json to write")
    ap.add_argument("--redact", action="append", default=[],
                    help="string to replace with [honeypot-ip] (repeatable)")
    ap.add_argument("--exclude-ip", action="append", default=[],
                    help="source IP whose events are ignored (repeatable)")
    ap.add_argument("--geoip", help="DB-IP Lite City .mmdb (optional)")
    ap.add_argument("--recent-out", help="recent.json to write (optional)")
    ap.add_argument("--reports", help="directory for weekly reports (optional, see weekly.py)")
    a = ap.parse_args(argv)
    return run(a, Geo(a.geoip), datetime.datetime.now(datetime.timezone.utc))


def run(a, geo, now):
    redact = [r for r in a.redact if r]
    exclude = set(a.exclude_ip)
    os.makedirs(a.state, exist_ok=True)
    since = now.timestamp() - RECENT_WINDOW
    recent = [] if a.recent_out else None

    all_days = collections.defaultdict(new_day)
    rotated = [p for p in sorted(glob.glob(os.path.join(a.logs, "cowrie.json.*")))
               if not p.endswith(".tmp")]
    for path in rotated:
        part = os.path.join(a.state, os.path.basename(path) + PARTIAL_SUFFIX)
        if not os.path.exists(part):
            atomic_write(part, to_json(parse(path, redact, exclude, geo)))
    for part in sorted(glob.glob(os.path.join(a.state, "*" + PARTIAL_SUFFIX))):
        with open(part, encoding="utf-8") as fh:
            merge(all_days, from_json(json.load(fh)))
    # Just after midnight the last hour is split across the newest rotated
    # file and the live one; rescan the rotated one for events only.
    if recent is not None and rotated and os.path.getmtime(rotated[-1]) >= since:
        parse(rotated[-1], redact, exclude, geo, since, recent)
    live = os.path.join(a.logs, "cowrie.json")
    if os.path.exists(live):
        merge(all_days, parse(live, redact, exclude, geo, since, recent))

    atomic_write(a.out, build(all_days, now))
    if getattr(a, "reports", None):
        import weekly  # imports this module, so not at the top
        weekly.write_reports(all_days, a.reports, now)
    if recent is not None:
        recent.sort(key=lambda e: e["t"])
        atomic_write(a.recent_out, {
            "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "from": round(since), "to": round(now.timestamp()),
            "events": recent[-RECENT_MAX:],
        })
    return 0


if __name__ == "__main__":
    sys.exit(main())
