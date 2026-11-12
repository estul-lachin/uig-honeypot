#!/usr/bin/env python3
"""Make the pseudonymized demo copy of the honeypot logs, for recordings and guide.uig.me.

Reads what ./hp pull copied into logs/ (cowrie.json*, suricata-alerts.json) and writes one file per UTC
day into logs-demo/:

  cowrie-YYYY-MM-DD.json     the columns of Cowrie_CL      (vps/sentinel.py shape)
  suricata-YYYY-MM-DD.json   the columns of Suricata_CL    (vps/sentinel.py shape_suricata)

so Splunk (index honeypot_demo) and Wazuh see exactly the rows that Sentinel has, under the same rule
that the workspace functions HP_Cowrie / HP_Suricata apply (azure/demo-functions.sh):

  - src_ip / dest_ip: a public IPv4 becomes "src-" + first 8 hex of sha256(HP_PSEUDO_SALT + ip);
    private ones (10/8, 172.16/12, 192.168/16) stay
  - any other string field: every \\d{1,3}(\\.\\d{1,3}){3} becomes "[ip]"
  - Suricata alerts to or from the real sshd port (HP_SSH_PORT) are dropped

The salt never leaves the Mac and the workspace; without it nobody can map a pseudonym back.
A day's file is rewritten only when its content changes, and always the same way for the same input,
so Splunk sees an append (same first bytes) rather than a new file.

  HP_PSEUDO_SALT=... HP_SSH_PORT=... python3 siem/pseudo.py [--logs logs] [--out logs-demo]
"""

import argparse
import glob
import hashlib
import ipaddress
import json
import os
import re
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "vps"))
from sentinel import shape, shape_suricata  # noqa: E402

IPV4 = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
ADDR_FIELDS = ("src_ip", "dest_ip")


def pseudonym(ip, salt):
    try:
        a = ipaddress.IPv4Address(ip)
    except ValueError:
        return ip
    if any(a in n for n in PRIVATE):
        return ip
    return "src-" + hashlib.sha256((salt + ip).encode()).hexdigest()[:8]


def scrub(row, salt):
    out = {}
    for k, v in row.items():
        if k in ADDR_FIELDS and isinstance(v, str):
            out[k] = pseudonym(v, salt)
        elif isinstance(v, str):
            out[k] = IPV4.sub("[ip]", v)
        else:
            out[k] = v
    return out


def read_lines(path):
    with open(path, "rb") as fh:
        for line in fh:
            try:
                yield json.loads(line)
            except ValueError:
                continue


def collect(logs, salt, ssh_port):
    days = {"cowrie": defaultdict(list), "suricata": defaultdict(list)}
    # No de-duplication: Sentinel keeps every row the shipper sent, so the copy does too.
    for f in sorted(glob.glob(os.path.join(logs, "cowrie.json*"))):
        for ev in read_lines(f):
            row = shape(ev)
            if row:
                days["cowrie"][row["timestamp"][:10]].append(scrub(row, salt))
    f = os.path.join(logs, "suricata-alerts.json")
    if os.path.isfile(f):
        for ev in read_lines(f):
            row = shape_suricata(ev)
            if not row or (ssh_port and ssh_port in (row.get("src_port"), row.get("dest_port"))):
                continue
            days["suricata"][row["timestamp"][:10]].append(scrub(row, salt))
    return days


def write_days(days, out):
    os.makedirs(out, exist_ok=True)
    os.chmod(out, 0o700)
    changed = 0
    for source, by_day in days.items():
        for day, rows in sorted(by_day.items()):
            rows.sort(key=lambda r: r["timestamp"])
            text = "".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n" for r in rows)
            path = os.path.join(out, f"{source}-{day}.json")
            if os.path.isfile(path):
                with open(path, encoding="utf-8") as fh:
                    if fh.read() == text:
                        continue
            with open(path + ".tmp", "w", encoding="utf-8") as fh:
                fh.write(text)
            os.replace(path + ".tmp", path)
            changed += 1
    return changed


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--logs", default=os.path.join(HERE, "..", "logs"))
    ap.add_argument("--out", default=os.path.join(HERE, "..", "logs-demo"))
    a = ap.parse_args(argv)
    salt = os.environ.get("HP_PSEUDO_SALT", "")
    if len(salt) < 16:
        print("set HP_PSEUDO_SALT in .env.local (16+ random characters, e.g. openssl rand -hex 16)", file=sys.stderr)
        return 2
    port = os.environ.get("HP_SSH_PORT")
    days = collect(a.logs, salt, int(port) if port and port.isdigit() else None)
    n = write_days(days, a.out)
    total = {s: sum(map(len, d.values())) for s, d in days.items()}
    print(f"logs-demo/: {total['cowrie']:,} Cowrie and {total['suricata']:,} Suricata rows, "
          f"{n} day file(s) updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
