#!/usr/bin/env python3
"""Summarize Suricata on the VPS for ./hp nsm: resource use, packet drops, alert volume, top signatures.

Prints counts and signature names only, never addresses, so the output can be shared.

  report.py [HOURS]        alerts from the last HOURS hours (default 24)
"""

import datetime
import gzip
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

LOG = Path("/var/log/suricata")


def lines(name):
    """The log and its rotations, oldest first."""
    files = sorted(LOG.glob(name + ".*"), key=lambda p: p.stat().st_mtime) + [LOG / name]
    for p in files:
        if not p.exists():
            continue
        opener = gzip.open if p.suffix == ".gz" else open
        with opener(p, "rt", encoding="utf-8", errors="replace") as f:
            yield from f


def unit(prop):
    out = subprocess.run(["systemctl", "show", "suricata", "-p", prop, "--value"], capture_output=True, text=True)
    return out.stdout.strip()


def mb(v):
    return f"{int(v) / 2**20:.0f} MB" if v.isdigit() else "n/a"


def main(hours=24):
    now = datetime.datetime.now(datetime.timezone.utc)
    since = now - datetime.timedelta(hours=hours)
    print(f"suricata: {unit('ActiveState')} since {unit('ActiveEnterTimestamp')}, "
          f"{unit('NRestarts')} restarts")
    print(f"memory: {mb(unit('MemoryCurrent'))} now, peak {mb(unit('MemoryPeak'))}, cap {mb(unit('MemoryMax'))}")
    swap = subprocess.run(["free", "-m"], capture_output=True, text=True).stdout.splitlines()
    print("host:", " | ".join(" ".join(l.split()[:4]) for l in swap[1:3]))

    last = None
    for line in lines("stats.json"):
        last = line
    if last:
        s = json.loads(last).get("stats", {})
        cap = s.get("capture", {})
        pk, dr = cap.get("kernel_packets", 0), cap.get("kernel_drops", 0)
        print(f"packets: {pk:,} seen, {dr:,} dropped ({100 * dr / pk:.2f}%)" if pk else "packets: none yet")
        print(f"rules: {s.get('detect', {}).get('engines', [{}])[0].get('rules_loaded', 'n/a')} loaded, "
              f"{s.get('detect', {}).get('engines', [{}])[0].get('rules_failed', 'n/a')} failed")

    sigs, cats, sev, n = Counter(), Counter(), Counter(), 0
    for line in lines("eve.json"):
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("event_type") != "alert":
            continue
        ts = datetime.datetime.fromisoformat(ev["timestamp"].replace("+0000", "+00:00"))
        if ts < since:
            continue
        a = ev["alert"]
        n += 1
        sigs[(a.get("signature_id"), a.get("signature", "?"))] += 1
        cats[a.get("category") or "?"] += 1
        sev[a.get("severity")] += 1
    size = sum(p.stat().st_size for p in LOG.glob("eve.json*"))
    print(f"\nalerts, last {hours} h: {n:,} ({n * 24 / hours:,.0f} a day); eve.json and rotations {size / 2**20:.1f} MB")
    print("by severity (1 high, 3 low):", dict(sorted(sev.items(), key=lambda x: (x[0] is None, x[0]))))
    print("\ntop categories:")
    for c, k in cats.most_common(8):
        print(f"  {k:7,}  {c}")
    print("\ntop signatures:")
    for (sid, name), k in sigs.most_common(20):
        print(f"  {k:7,}  {sid}  {name}")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 24)
