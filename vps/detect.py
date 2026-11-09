#!/usr/bin/env python3
"""Run the uig-detections Sigma rules on the raw Cowrie logs and write detections.json.

The rules come from https://detections.uig.me/rules.json, the Sigma logic as plain data, built
by uig-detections. The last good copy is cached, so a failed download only means older rules.
sigma_eval.py next to this script is a verbatim copy of uig-detections' tools/sigma_eval.py,
the evaluator its CI tests run on, so a rule counts here exactly as it does in its tests.

The output never contains IP addresses: per rule, the sessions and alerts in the last --days
days, the first and last day it fired, and the most common matching command, cleaned with
aggregate.clean() (URLs and IPv4 addresses defanged, the honeypot's own IP redacted).
detections.uig.me reads it back when it builds.
"""

import argparse
import collections
import datetime
import glob
import json
import os
import sys
import urllib.request

import aggregate
import sigma_eval

RULES_URL = "https://detections.uig.me/rules.json"
DAYS = 30


def check_rules(data):
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("rules"), list):
        raise ValueError("unexpected rules.json format")
    return data


def fetch_rules(url, cache, opener=urllib.request.urlopen):
    """rules.json from url (cached on success), else the cached copy, else None."""
    try:
        with opener(url, timeout=30) as r:
            data = check_rules(json.load(r))
        aggregate.atomic_write(cache, data)
        return data
    except (OSError, ValueError) as e:
        print(f"warning: {url}: {e}; using the cached rules", file=sys.stderr)
    try:
        with open(cache, encoding="utf-8") as fh:
            return check_rules(json.load(fh))
    except (OSError, ValueError):
        return None


def compile_rules(data):
    """[(rule, kind, matcher)]: kind "event" with match(ev), or "correlation" with {base: match}."""
    out = []
    for r in data["rules"]:
        try:
            if "correlation" in r:
                base = {n: sigma_eval.compile_rule(r["base"][n]) for n in r["correlation"]["rules"]}
                out.append((r, "correlation", base))
            else:
                out.append((r, "event", sigma_eval.compile_rule(r["detection"])))
        except (sigma_eval.Unsupported, KeyError, TypeError, ValueError) as e:
            print(f"warning: skipping rule {r.get('name')}: {e}", file=sys.stderr)
    return out


def events(logs, since, exclude):
    """Events at or after `since` (epoch seconds), oldest file first. Bad lines are skipped."""
    for path in sorted(glob.glob(os.path.join(logs, "cowrie.json*"))):
        if path.endswith(".tmp"):
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    ev = json.loads(line)
                    t = aggregate.epoch(ev["timestamp"])
                except (ValueError, KeyError, TypeError, AttributeError):
                    continue
                if t >= since and ev.get("src_ip") not in exclude:
                    yield ev


def readable(cmd):
    """False if cleaning would blank over half of it, e.g. a hex chunk of \\x00 bytes."""
    kept = aggregate.CONTROL.sub("", aggregate.ESCAPED_CONTROL.sub("", cmd))
    return len("".join(kept.split())) >= 0.5 * len("".join(cmd.split()))


class Hits:
    def __init__(self):
        self.sessions, self.days, self.alerts, self.examples = set(), set(), 0, collections.Counter()

    def add(self, ev):
        self.sessions.add(str(ev.get("session")))
        self.days.add(str(ev["timestamp"])[:10])
        if ev.get("eventid") == "cowrie.command.input" and ev.get("input"):
            # counted raw: cleaning first would merge hex chunks into one meaningless line
            self.examples[str(ev["input"])] += 1

    def to_json(self, rule, redact):
        days = sorted(self.days)
        ranked = [x for x, _ in self.examples.most_common()]
        example = next((x for x in ranked if readable(x)), ranked[0] if ranked else None)
        return {"id": rule.get("id"), "sessions": len(self.sessions), "alerts": self.alerts,
                "first_seen": days[0] if days else None, "last_seen": days[-1] if days else None,
                "example": aggregate.clean(example, redact) if example is not None else None}


def run(logs, rules, now, days=DAYS, redact=(), exclude=()):
    redact = [r for r in redact if r]
    exclude = {x for x in exclude if x}
    since = now.timestamp() - days * 86400
    compiled = compile_rules(rules)
    hits = {r["name"]: Hits() for r, _, _ in compiled}
    # Correlations need their events in order; keep only the ones a base rule matches.
    pending = {r["name"]: [] for r, kind, _ in compiled if kind == "correlation"}
    # Some unsupported constructs only fail when an event reaches them: drop that rule, keep the rest.
    broken = set()

    def drop(r, e):
        print(f"warning: dropping rule {r.get('name')}: {e}", file=sys.stderr)
        broken.add(r["name"])

    for ev in events(logs, since, exclude):
        for r, kind, m in compiled:
            if r["name"] in broken:
                continue
            try:
                if kind == "event":
                    if m(ev):
                        hits[r["name"]].alerts += 1
                        hits[r["name"]].add(ev)
                elif any(b(ev) for b in m.values()):
                    pending[r["name"]].append(ev)
            except (sigma_eval.Unsupported, KeyError, TypeError, ValueError) as e:
                drop(r, e)
    for r, kind, m in compiled:
        if kind != "correlation" or r["name"] in broken:
            continue
        evs = sorted(pending[r["name"]], key=lambda ev: aggregate.epoch(ev["timestamp"]))
        involved = []
        try:
            hits[r["name"]].alerts = len(sigma_eval.correlate(r["correlation"], m, evs, involved))
        except (sigma_eval.Unsupported, KeyError, TypeError, ValueError) as e:
            drop(r, e)
            continue
        for ev in involved:
            hits[r["name"]].add(ev)
    return {
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "days": days,
        "from": datetime.datetime.fromtimestamp(since, datetime.timezone.utc).strftime("%Y-%m-%d"),
        "to": now.strftime("%Y-%m-%d"),
        "rules": {r["name"]: hits[r["name"]].to_json(r, redact) for r, _, _ in compiled
                  if r["name"] not in broken},
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--logs", required=True, help="Cowrie log directory")
    ap.add_argument("--out", required=True, help="detections.json to write")
    ap.add_argument("--rules-url", default=RULES_URL)
    ap.add_argument("--rules-cache", required=True, help="last good rules.json")
    ap.add_argument("--days", type=int, default=DAYS)
    ap.add_argument("--redact", action="append", default=[],
                    help="string to replace with [honeypot-ip] (repeatable)")
    ap.add_argument("--exclude-ip", action="append", default=[],
                    help="source IP whose events are ignored (repeatable)")
    a = ap.parse_args(argv)
    rules = fetch_rules(a.rules_url, a.rules_cache)
    if rules is None:
        print("no rules (download failed and no cache); detections.json not written", file=sys.stderr)
        return 1
    now = datetime.datetime.now(datetime.timezone.utc)
    aggregate.atomic_write(a.out, run(a.logs, rules, now, a.days, a.redact, a.exclude_ip))
    return 0


if __name__ == "__main__":
    sys.exit(main())
