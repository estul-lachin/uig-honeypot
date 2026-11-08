#!/usr/bin/env python3
"""Look up the honeypot's source IPs in AbuseIPDB (check only, never report).

Reads the Cowrie logs, finds source IPs that have no cached result or whose
result is older than MAX_AGE_DAYS and that were seen again since, and calls
the AbuseIPDB v2 /check endpoint for each. Results are cached in --cache
(private: it holds IPs). aggregate.py turns the cache into IP-free summaries;
./hp pull copies it to the Mac for the Splunk lookup.

The API key comes from the HP_ABUSEIPDB_KEY environment variable, never from
the command line. Without it, the script does nothing and exits 0. The daily
call budget stays under the free plan's 1000 checks per day.
"""

import argparse
import datetime
import glob
import ipaddress
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.abuseipdb.com/api/v2/check"
DAILY_BUDGET = 900      # free plan: 1000 checks per UTC day
MAX_AGE_DAYS = 7        # re-check an IP seen again after this long
LOOKBACK_DAYS = 3       # rotated logs scanned for new IPs (plus the live one)
FIELDS = ("abuseConfidenceScore", "totalReports", "numDistinctUsers", "lastReportedAt",
          "countryCode", "usageType", "isp", "domain", "isTor")


class RateLimited(Exception):
    pass


def fetch(ip, key, timeout=20):
    """AbuseIPDB /check for one IP: the 'data' object."""
    url = API + "?" + urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    req = urllib.request.Request(url, headers={"Key": key, "Accept": "application/json",
                                               "User-Agent": "uig-honeypot-enrich"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)["data"]
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise RateLimited() from e
        raise


def public_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global


def sources(logs, now, exclude):
    """{ip: last seen (epoch)} from the live log and the last LOOKBACK_DAYS rotated ones."""
    since = (now - datetime.timedelta(days=LOOKBACK_DAYS)).strftime("%Y-%m-%d")
    paths = [p for p in glob.glob(os.path.join(logs, "cowrie.json.*"))
             if not p.endswith(".tmp") and p.rsplit(".", 1)[-1] >= since]
    live = os.path.join(logs, "cowrie.json")
    if os.path.exists(live):
        paths.append(live)
    seen = {}
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if '"cowrie.session.connect"' not in line:
                    continue
                try:
                    ev = json.loads(line)
                    ip, ts = ev["src_ip"], ev["timestamp"]
                    t = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
                except (ValueError, KeyError, TypeError):
                    continue
                if ip in exclude or not public_ip(ip):
                    continue
                seen[ip] = max(seen.get(ip, 0), t)
    return seen


def load(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {"ips": {}, "budget": {}}


def save(path, cache):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cache, fh, separators=(",", ":"), sort_keys=True)
    os.replace(tmp, path)


def due(ips, seen, now):
    """IPs to check, most recently seen first."""
    max_age = MAX_AGE_DAYS * 86400
    out = []
    for ip, last in seen.items():
        rec = ips.get(ip)
        if rec is None or (now.timestamp() - rec["checked"] > max_age and last > rec["checked"]):
            out.append((last, ip))
    return [ip for _, ip in sorted(out, reverse=True)]


def run(logs, cache_path, key, now, exclude=(), fetcher=fetch):
    cache = load(cache_path)
    today = now.strftime("%Y-%m-%d")
    used = cache.get("budget", {}).get(today, 0)
    todo = due(cache["ips"], sources(logs, now, set(exclude)), now)
    checked = 0
    try:
        for ip in todo:
            if used >= DAILY_BUDGET:
                break
            data = fetcher(ip, key)
            used += 1
            checked += 1
            cache["ips"][ip] = {"checked": round(now.timestamp()),
                                **{k: data.get(k) for k in FIELDS}}
    except RateLimited:
        print("AbuseIPDB rate limit reached; continuing next run", file=sys.stderr)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError) as e:
        print(f"AbuseIPDB lookup failed: {e}; continuing next run", file=sys.stderr)
    cache["budget"] = {today: used}  # only today's count matters
    save(cache_path, cache)
    print(f"checked {checked} IP(s), {len(todo) - checked} still due, {used}/{DAILY_BUDGET} used today")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--logs", required=True, help="Cowrie log directory")
    ap.add_argument("--cache", required=True, help="JSON cache of AbuseIPDB results (private)")
    ap.add_argument("--exclude-ip", action="append", default=[], help="never look up this IP")
    a = ap.parse_args(argv)
    key = os.environ.get("HP_ABUSEIPDB_KEY", "").strip()
    if not key:
        print("HP_ABUSEIPDB_KEY not set; skipping enrichment")
        return 0
    os.makedirs(os.path.dirname(os.path.abspath(a.cache)), mode=0o700, exist_ok=True)
    return run(a.logs, a.cache, key, datetime.datetime.now(datetime.timezone.utc),
               [x for x in a.exclude_ip if x])


if __name__ == "__main__":
    sys.exit(main())
