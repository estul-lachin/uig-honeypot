#!/usr/bin/env python3
"""Summarize Suricata's alerts into a public, privacy-safe network.json.

Reads eve.json and its rotations (alerts only, flattened by sentinel.shape_suricata() exactly as
they go to Sentinel) for the last --days days, and the latest engine counters from stats.json.

The output never contains IP addresses. Sources are only counted, and reduced to a country with
--geoip; signatures and categories are ET rule names, cleaned with aggregate.clean() anyway. An
alert is inbound when its source is not a local address (RFC 1918, loopback, link-local: eth0
and the Cowrie network); outbound alerts are the VPS's own traffic and are only counted.

With --cowrie-logs, each inbound source is also looked up in Cowrie's logs for the same days, to
show how much of what Suricata sees never reached the SSH/Telnet honeypot at all. Ports given with
--hide-port (the real sshd's) are left out of the port list, so it never reveals them.
"""

import argparse
import collections
import datetime
import glob
import ipaddress
import json
import os
import sys

import aggregate
import detect
import sentinel

DAYS = 30
TOP = 20
LOCAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fe80::/10", "fc00::/7")]
STATS_TAIL = 1 << 20  # bytes read from the end of stats.json for the last record
SEVERITY = {1: "high", 2: "medium", 3: "low"}


def local(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in LOCAL)


def alerts(suricata_logs, since, exclude=()):
    return detect._read(sorted(glob.glob(os.path.join(suricata_logs, "eve.json*"))), since, set(exclude),
                        sentinel.shape_suricata)


def cowrie_sources(logs, since, exclude=()):
    out = set()
    for ev in detect._read(sorted(glob.glob(os.path.join(logs, "cowrie.json*"))), since, set(exclude)):
        if ev.get("eventid") == "cowrie.session.connect" and ev.get("src_ip"):
            out.add(ev["src_ip"])
    return out


def engine(stats_path):
    """Counters from the newest stats.json record, or None."""
    try:
        with open(stats_path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            fh.seek(max(0, fh.tell() - STATS_TAIL))
            lines = fh.read().splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        try:
            ev = json.loads(line)
            s = ev["stats"]
        except (ValueError, KeyError, TypeError):
            continue
        cap = s.get("capture") or {}
        eng = ((s.get("detect") or {}).get("engines") or [{}])[0]
        packets, drops = cap.get("kernel_packets"), cap.get("kernel_drops")
        return {
            "at": sentinel.utc(ev["timestamp"]) if ev.get("timestamp") else None,
            "uptime_s": s.get("uptime"),
            "packets": packets,
            "drops": drops,
            "drop_pct": round(100 * drops / packets, 3) if packets and drops is not None else None,
            "rules_loaded": eng.get("rules_loaded"),
        }
    return None


def split(value):
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def build(events, now, days=DAYS, redact=(), geo=aggregate.NO_GEO, cowrie=None, eng=None, hide_ports=()):
    redact = [r for r in redact if r]
    hide_ports = set(hide_ports)
    total = outbound = 0
    daily = collections.defaultdict(lambda: {"alerts": 0, "high": 0, "sources": set()})
    sources, by_sev, cats = set(), collections.Counter(), collections.Counter()
    sigs = {}   # sid -> {"value", "category", "severity", "count", "sources"}
    ports = {}  # (port, proto) -> {"count", "sources"}
    cves = {}   # cve -> {"count", "sources", "first_day", "last_day", "signature"}
    ttps = collections.defaultdict(set)  # technique -> sources
    for ev in events:
        total += 1
        src = ev.get("src_ip")
        if not src or local(src):
            outbound += 1
            continue
        day = ev["timestamp"][:10]
        sev = ev.get("severity")
        d = daily[day]
        d["alerts"] += 1
        d["high"] += sev == 1
        d["sources"].add(src)
        sources.add(src)
        by_sev[sev] += 1
        cat = aggregate.clean(ev.get("category") or "Uncategorized", redact)
        cats[cat] += 1
        sid = ev.get("signature_id")
        s = sigs.setdefault(sid, {"sid": sid, "value": aggregate.clean(ev.get("signature") or "?", redact),
                                  "category": cat, "severity": sev, "count": 0, "sources": set()})
        s["count"] += 1
        s["sources"].add(src)
        if ev.get("dest_port") is not None and ev["dest_port"] not in hide_ports:
            p = ports.setdefault((ev["dest_port"], aggregate.clean(ev.get("proto") or "?", redact)),
                                 {"count": 0, "sources": set()})
            p["count"] += 1
            p["sources"].add(src)
        for cve in split(ev.get("cve")):
            # ET writes CVE_2026_24061 in its metadata
            c = cves.setdefault(aggregate.clean(cve.upper().replace("_", "-"), redact), {
                "count": 0, "sources": set(), "first_day": day, "last_day": day,
                "signature": s["value"]})
            c["count"] += 1
            c["sources"].add(src)
            c["first_day"], c["last_day"] = min(c["first_day"], day), max(c["last_day"], day)
        for t in split(ev.get("mitre_technique")):
            ttps[aggregate.clean(t, redact)].add(src)

    countries = collections.Counter(geo(ip).get("cc") or "??" for ip in sources)
    first = (now - datetime.timedelta(days=days - 1)).strftime("%Y-%m-%d")
    order = lambda d: sorted(d.values(), key=lambda x: (-x["count"], str(x.get("sid", ""))))
    out = {
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "days": days,
        "first_day": min(daily) if daily else None,
        "last_day": max(daily) if daily else None,
        "totals": {
            "alerts": total - outbound,
            "outbound_alerts": outbound,
            "sources": len(sources),
            "signatures": len(sigs),
            "high": by_sev[1],
        },
        "daily": [{"day": d, "alerts": daily[d]["alerts"], "high": daily[d]["high"],
                   "sources": len(daily[d]["sources"])} for d in sorted(daily) if d >= first],
        "severity": [{"severity": k, "label": SEVERITY.get(k, "other"), "alerts": by_sev[k]}
                     for k in sorted(by_sev, key=lambda k: (k is None, k))],
        "categories": [{"value": k, "count": v} for k, v in cats.most_common(12)],
        "signatures": [{**s, "sources": len(s["sources"])} for s in order(sigs)[:TOP]],
        "ports": [{"port": port, "proto": proto, "count": p["count"], "sources": len(p["sources"])}
                  for (port, proto), p in sorted(ports.items(), key=lambda kv: (-len(kv[1]["sources"]),
                                                                                -kv[1]["count"], kv[0][0]))[:15]],
        "countries": dict(countries.most_common()),
        "cves": [{"cve": k, **v, "sources": len(v["sources"])}
                 for k, v in sorted(cves.items(), key=lambda kv: (-len(kv[1]["sources"]), kv[0]))],
        "ttps": [{"id": k, "sources": len(v)} for k, v in sorted(ttps.items(), key=lambda kv: (-len(kv[1]), kv[0]))],
        "cowrie": None,
        "engine": eng,
    }
    if cowrie is not None:
        both = len(sources & cowrie)
        out["cowrie"] = {"sources": len(sources), "also_cowrie": both, "suricata_only": len(sources) - both}
    return out


def run(suricata_logs, now, days=DAYS, redact=(), exclude=(), geo=aggregate.NO_GEO, cowrie_logs=None,
        hide_ports=()):
    since = now.timestamp() - days * 86400
    exclude = [e for e in exclude if e]
    cowrie = cowrie_sources(cowrie_logs, since, exclude) if cowrie_logs else None
    eng = engine(os.path.join(suricata_logs, "stats.json"))
    return build(alerts(suricata_logs, since, exclude), now, days, redact, geo, cowrie, eng, hide_ports)


def port(v):
    return int(v) if v.strip() else None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--suricata-logs", required=True, help="Suricata log directory (eve.json, stats.json)")
    ap.add_argument("--out", required=True, help="network.json to write")
    ap.add_argument("--cowrie-logs", help="Cowrie log directory, for the overlap count (optional)")
    ap.add_argument("--geoip", help="DB-IP Lite City .mmdb (optional)")
    ap.add_argument("--days", type=int, default=DAYS)
    ap.add_argument("--redact", action="append", default=[],
                    help="string to replace with [honeypot-ip] (repeatable)")
    ap.add_argument("--exclude-ip", action="append", default=[],
                    help="source IP whose alerts are ignored (repeatable)")
    ap.add_argument("--hide-port", action="append", default=[], type=port,
                    help="destination port left out of the port list (repeatable; empty is ignored)")
    a = ap.parse_args(argv)
    now = datetime.datetime.now(datetime.timezone.utc)
    data = run(a.suricata_logs, now, a.days, a.redact, a.exclude_ip, aggregate.Geo(a.geoip), a.cowrie_logs,
               [x for x in a.hide_port if x is not None])
    aggregate.atomic_write(a.out, data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
