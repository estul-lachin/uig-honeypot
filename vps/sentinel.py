#!/usr/bin/env python3
"""Ship new Cowrie events or Suricata alerts to Microsoft Sentinel (Azure Monitor Logs Ingestion API).

Runs every 10 minutes (uig-sentinel.timer, uig-sentinel-suricata.timer). Reads
only what was appended to the log since the last run, follows rotation, and
posts the events in gzip batches to the data collection rule, which writes
them to Cowrie_CL or Suricata_CL (its transform turns `timestamp` into
TimeGenerated). The offset is saved after every accepted batch, so a failure
resends at most one batch and never skips events.

Rotation: Cowrie renames cowrie.json to cowrie.json.YYYY-MM-DD (a new inode),
which is followed by inode. logrotate copies eve.json to eve.json.1.gz and
truncates it in place (same inode). The state keeps a hash of the file's first
bytes; if they changed, or the file is now shorter than the offset, it was
truncated: finish the newest rotated copy, then start the live file at 0.

Suricata: only `alert` events are sent (eve.json may also hold flow or stats
lines), with the alert's fields flattened and the timestamp in UTC.

Credentials come from the environment (HP_AZ_TENANT, HP_AZ_CLIENT_ID,
HP_AZ_CLIENT_SECRET, HP_AZ_DCE, HP_AZ_DCR). Without them it does nothing.
The service principal can only write to that one DCR.
"""

import argparse
import datetime
import glob
import gzip
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

FIELDS = {"timestamp": str, "eventid": str, "src_ip": str, "src_port": int, "dst_port": int, "session": str,
          "protocol": str, "username": str, "password": str, "input": str, "url": str, "shasum": str,
          "outfile": str, "version": str, "hassh": str, "arch": str, "duration_ms": int, "message": str,
          "sensor": str}
SURICATA_FIELDS = {"timestamp": str, "flow_id": int, "src_ip": str, "src_port": int, "dest_ip": str,
                   "dest_port": int, "proto": str, "app_proto": str, "signature_id": int, "rev": int,
                   "signature": str, "category": str, "severity": int, "signature_severity": str,
                   "cve": str, "mitre_tactic": str, "mitre_technique": str}
BATCH_BYTES = 800_000          # API limit is 1 MB per call
MAX_BYTES_PER_RUN = 50_000_000  # runaway guard; the workspace also has a daily cap
FIRST_RUN_DAYS = 1             # on first run, also send date-named rotated logs this recent
DATED = re.compile(r"\d{4}-\d{2}-\d{2}")


class Fatal(Exception):
    pass


def typed(ev, fields):
    out = {}
    for k, typ in fields.items():
        v = ev.get(k)
        if v is None:
            continue
        try:
            out[k] = typ(v)
        except (TypeError, ValueError):
            continue
    return out


def shape(ev):
    """Keep only the table's columns, with the column types. None if unusable."""
    if not isinstance(ev, dict) or "timestamp" not in ev or "eventid" not in ev:
        return None
    return typed(ev, FIELDS)


def utc(ts):
    """Suricata's "2026-11-10T14:53:09.123456+0800" as "2026-11-10T06:53:09.123456Z"."""
    t = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z").astimezone(datetime.timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def shape_suricata(ev):
    """An alert flattened to Suricata_CL's columns; None for anything that is not an alert."""
    if not isinstance(ev, dict) or ev.get("event_type") != "alert" or not isinstance(ev.get("alert"), dict):
        return None
    a = ev["alert"]
    meta = a.get("metadata") if isinstance(a.get("metadata"), dict) else {}
    try:
        flat = {**ev, **a, "timestamp": utc(ev["timestamp"])}
    except (KeyError, TypeError, ValueError):
        return None
    # ET metadata values are lists; join them ("T1110,T1078").
    for col, key in (("signature_severity", "signature_severity"), ("cve", "cve"),
                     ("mitre_tactic", "mitre_tactic_id"), ("mitre_technique", "mitre_technique_id")):
        vals = meta.get(key)
        flat[col] = ",".join(map(str, vals)) if isinstance(vals, list) else None
    return typed(flat, SURICATA_FIELDS)


SOURCES = {
    "cowrie": {"base": "cowrie.json", "stream": "Custom-CowrieRaw", "shape": shape},
    "suricata": {"base": "eve.json", "stream": "Custom-SuricataRaw", "shape": shape_suricata},
}


def read_from(path, offset, shaper=shape):
    """(events, new offset) for complete lines after offset (a .gz file is read uncompressed)."""
    with (gzip.open if path.endswith(".gz") else open)(path, "rb") as fh:
        fh.seek(offset)
        data = fh.read()
    end = data.rfind(b"\n") + 1
    events, pos = [], offset
    for line in data[:end].splitlines(keepends=True):
        pos += len(line)
        try:
            ev = shaper(json.loads(line))
        except ValueError:
            ev = None
        if ev:
            events.append((ev, pos))
    return events, offset + end


class Client:
    def __init__(self, env, opener=urllib.request.urlopen, stream="Custom-CowrieRaw"):
        self.env, self.open, self.token, self.expires = env, opener, None, 0
        self.stream = stream

    def _token(self):
        if self.token and time.time() < self.expires - 300:
            return self.token
        body = urllib.parse.urlencode({
            "grant_type": "client_credentials", "client_id": self.env["HP_AZ_CLIENT_ID"],
            "client_secret": self.env["HP_AZ_CLIENT_SECRET"], "scope": "https://monitor.azure.com//.default",
        }).encode()
        url = f"https://login.microsoftonline.com/{self.env['HP_AZ_TENANT']}/oauth2/v2.0/token"
        with self.open(urllib.request.Request(url, data=body), timeout=30) as r:
            tok = json.load(r)
        self.token, self.expires = tok["access_token"], time.time() + int(tok.get("expires_in", 3600))
        return self.token

    def post(self, rows):
        url = (f"{self.env['HP_AZ_DCE'].rstrip('/')}/dataCollectionRules/{self.env['HP_AZ_DCR']}"
               f"/streams/{self.stream}?api-version=2023-01-01")
        body = gzip.compress(json.dumps(rows, separators=(",", ":")).encode())
        for attempt in range(4):
            req = urllib.request.Request(url, data=body, method="POST", headers={
                "Authorization": f"Bearer {self._token()}", "Content-Type": "application/json",
                "Content-Encoding": "gzip"})
            try:
                with self.open(req, timeout=60) as r:
                    if r.status in (200, 204):
                        return
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    raise Fatal(f"ingestion refused ({e.code}): check the secret and the DCR role") from e
                if e.code not in (429, 500, 502, 503, 504):
                    raise Fatal(f"ingestion failed ({e.code}): {e.read()[:300]!r}") from e
                wait = int(e.headers.get("Retry-After", 0) or 0) or 5 * 2 ** attempt
            except (urllib.error.URLError, TimeoutError, OSError):
                wait = 5 * 2 ** attempt
            time.sleep(min(wait, 60))
        raise Fatal("ingestion failed after retries")


def batches(events):
    batch, size = [], 2
    for ev, pos in events:
        n = len(json.dumps(ev, separators=(",", ":"))) + 1
        if batch and size + n > BATCH_BYTES:
            yield batch
            batch, size = [], 2
        batch.append((ev, pos))
        size += n
    if batch:
        yield batch


def load_state(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None


def save_state(path, state):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    os.replace(tmp, path)


def head(path, offset):
    """Hash of the first bytes before offset (they never change unless the file is truncated)."""
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read(min(offset, 256))).hexdigest()


def truncated(path, state):
    off = state.get("offset", 0)
    if os.path.getsize(path) < off:
        return True
    return bool(off and state.get("head") and head(path, off) != state["head"])


def plan(logs, state, now, base="cowrie.json"):
    """[(path, start offset, inode)] to send, oldest first, and the new live inode."""
    live = os.path.join(logs, base)
    rotated = sorted(p for p in glob.glob(os.path.join(logs, base + ".*")) if not p.endswith(".tmp"))
    live_ino = os.stat(live).st_ino if os.path.exists(live) else None
    work = []
    if state is None:  # first run: recent date-named rotated logs and the live file, from the start
        since = (now - datetime.timedelta(days=FIRST_RUN_DAYS)).strftime("%Y-%m-%d")
        work += [(p, 0, os.stat(p).st_ino) for p in rotated
                 if DATED.fullmatch(p[len(live) + 1:]) and p[len(live) + 1:] >= since]
    elif state.get("inode") == live_ino and truncated(live, state):
        # copied and truncated in place: the rest of what we were reading is in the newest copy
        if rotated:
            newest = max(rotated, key=os.path.getmtime)
            work.append((newest, state["offset"], None))
        state = None if live_ino is None else {"inode": live_ino, "offset": 0}
    elif state.get("inode") != live_ino:
        # the file we were following was rotated: finish it wherever it went
        for p in rotated:
            if os.stat(p).st_ino == state.get("inode"):
                work.append((p, state.get("offset", 0), state["inode"]))
                break
    if live_ino is not None:
        start = state["offset"] if state and state.get("inode") == live_ino else 0
        work.append((live, start, live_ino))
    return work, live_ino


def run(logs, state_path, client, now, source="cowrie"):
    src = SOURCES[source]
    state = load_state(state_path)
    work, live_ino = plan(logs, state, now, src["base"])
    sent = sent_bytes = 0
    for path, start, ino in work:
        events, end = read_from(path, start, src["shape"])
        is_live = ino == live_ino
        for batch in batches(events):
            client.post([ev for ev, _ in batch])
            sent += len(batch)
            sent_bytes += sum(len(json.dumps(ev)) for ev, _ in batch)
            if is_live:
                off = batch[-1][1]
                save_state(state_path, {"inode": ino, "offset": off, "head": head(path, off)})
            if sent_bytes > MAX_BYTES_PER_RUN:
                print(f"stopping at {sent} events: per-run limit reached", file=sys.stderr)
                return sent
        if is_live:
            save_state(state_path, {"inode": ino, "offset": end, "head": head(path, end)})
    if live_ino is None:
        save_state(state_path, {"inode": None, "offset": 0})
    return sent


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--source", choices=sorted(SOURCES), default="cowrie")
    ap.add_argument("--logs", required=True, help="log directory (Cowrie's, or /var/log/suricata)")
    ap.add_argument("--state", required=True, help="state file (offset in the live log)")
    a = ap.parse_args(argv)
    env = {k: os.environ.get(k, "").strip() for k in
           ("HP_AZ_TENANT", "HP_AZ_CLIENT_ID", "HP_AZ_CLIENT_SECRET", "HP_AZ_DCE", "HP_AZ_DCR")}
    if not all(env.values()):
        print("Sentinel settings not set; skipping")
        return 0
    os.makedirs(os.path.dirname(os.path.abspath(a.state)), mode=0o700, exist_ok=True)
    try:
        n = run(a.logs, a.state, Client(env, stream=SOURCES[a.source]["stream"]),
                datetime.datetime.now(datetime.timezone.utc), a.source)
    except Fatal as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"sent {n} {a.source} event(s) to Sentinel")
    return 0


if __name__ == "__main__":
    sys.exit(main())
