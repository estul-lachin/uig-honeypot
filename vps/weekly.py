#!/usr/bin/env python3
"""Weekly reports: one public JSON file per finished ISO week (UTC).

Called by aggregate.py (--reports DIR) with the per-day buckets it already
built, so reports use the same sanitized values as stats.json and keep
working after the raw logs are pruned. A week is written once, when it has
been over for GRACE seconds, and never rewritten. index.json lists them.

"New this week" means not seen on any earlier day. Partials keep only the
top KEEP entries per counter, so a rare value can be reported as new again.
"""

import datetime
import os

import aggregate

GRACE = 2 * 3600  # wait for the last day's log to rotate and be parsed
NEW_TOP = 15


def iso_week(day):
    y, w, _ = datetime.date.fromisoformat(day).isocalendar()
    return f"{y}-W{w:02d}"


def week_bounds(week):
    """(monday, next monday) as dates."""
    y, w = week.split("-W")
    monday = datetime.date.fromisocalendar(int(y), int(w), 1)
    return monday, monday + datetime.timedelta(days=7)


def total(days):
    t = aggregate.new_day()
    for b in days:
        for k in ("sessions", "logins", "logins_ok", "commands_run", "ssh", "telnet"):
            t[k] += b[k]
        t["ips"] |= b["ips"]
        for c in aggregate.COUNTERS:
            t[c].update(b[c])
    return t


def totals(t):
    return {
        "sessions": t["sessions"],
        "unique_sources": len(t["ips"]),
        "login_attempts": t["logins"],
        "logins_accepted": t["logins_ok"],
        "commands_run": t["commands_run"],
        "ssh_sessions": t["ssh"],
        "telnet_sessions": t["telnet"],
    }


def new_values(this, before):
    return [{"value": k, "count": v} for k, v in this.most_common() if k not in before][:NEW_TOP]


def build_week(all_days, week):
    monday, end = week_bounds(week)
    in_week = sorted(d for d in all_days if monday.isoformat() <= d < end.isoformat())
    earlier = [all_days[d] for d in all_days if d < monday.isoformat()]
    prev_start = (monday - datetime.timedelta(days=7)).isoformat()
    prev = [all_days[d] for d in all_days if prev_start <= d < monday.isoformat()]
    t, seen = total(all_days[d] for d in in_week), total(earlier)

    downloads = []
    for k, v in t["downloads"].most_common(aggregate.TOP):
        sha, _, url = k.partition(" ")
        downloads.append({"sha256": sha, "url": url, "count": v,
                          "new": not any(s.startswith(sha) for s in seen["downloads"])})
    hours = [{"hour": f"{h:02d}", "sessions": t["hours"].get(f"{h:02d}", 0)} for h in range(24)]
    return {
        "week": week,
        "from": monday.isoformat(),
        "to": (end - datetime.timedelta(days=1)).isoformat(),
        # the honeypot (or its data) started after this Monday
        "partial": not earlier and in_week[0] > monday.isoformat(),
        "totals": totals(t),
        "previous": totals(total(prev)) if prev else None,
        "daily": [{"day": d, "sessions": all_days[d]["sessions"],
                   "login_attempts": all_days[d]["logins"],
                   "unique_sources": len(all_days[d]["ips"])} for d in in_week],
        "hours_utc": hours,
        "top": {c: aggregate.top(t[c]) for c in ("usernames", "passwords", "pairs", "commands", "clients")},
        "new": {
            "passwords": new_values(t["passwords"], seen["passwords"]),
            "commands": new_values(t["commands"], seen["commands"]),
        },
        "downloads": downloads,
        "ttps": aggregate.ttp_list(t["ttps"]),
        "countries": [{"cc": k, "sessions": v} for k, v in t["countries"].most_common(aggregate.TOP)],
    }


def write_reports(all_days, out_dir, now):
    """Write every finished week that has data and no file yet; refresh index.json."""
    os.makedirs(out_dir, exist_ok=True)
    weeks = sorted({iso_week(d) for d in all_days if all_days[d]["sessions"]})
    for week in weeks:
        path = os.path.join(out_dir, week + ".json")
        _, end = week_bounds(week)
        over = datetime.datetime.combine(end, datetime.time(), datetime.timezone.utc).timestamp() + GRACE
        if now.timestamp() >= over and not os.path.exists(path):
            rep = build_week(all_days, week)
            rep["generated_at"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            aggregate.atomic_write(path, rep)
    done = sorted((f[:-5] for f in os.listdir(out_dir)
                   if f.endswith(".json") and f != "index.json" and not f.endswith(".tmp")), reverse=True)
    aggregate.atomic_write(os.path.join(out_dir, "index.json"),
                           {"generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "weeks": done})
