#!/usr/bin/env python3
"""Build Cowrie's fake filesystem (fs.pickle) for the db-backup persona.

Cowrie ships a generic filesystem with well-known tells: /.dockerenv, a user
"phil", /etc/hostname "svr04" and /etc/hosts "nas3" (while the prompt says
HP_FAKE_HOSTNAME), an empty os-release and fstab, and empty /opt and /srv.
Scanners check for some of these and leave. This script starts from the
bundled pickle and turns it into one consistent machine: a small company's
PostgreSQL backup server with a cron job, a backup script, a week of dumps
and their log.

Runs inside the Cowrie image at deploy time (see harden.sh), so the pickle
format always matches the Cowrie version:

  python3 build_fs.py --hostname db-backup-01 --out /out/fs.pickle

Everything here is fiction: no real hosts, addresses or people.
"""

import argparse
import datetime
import os
import pickle
import stat
import sys

try:  # node layout; the fallback values match Cowrie 3.1.3, for tests without Cowrie
    from cowrie.shell.fs import (A_CONTENTS, A_CTIME, A_GID, A_MODE, A_NAME, A_REALFILE, A_SIZE,
                                 A_TARGET, A_TYPE, A_UID, T_DIR, T_FILE)
except ImportError:
    A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(10)
    T_DIR, T_FILE = 1, 2

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = os.path.join(HERE, "files")
BUNDLED = "/cowrie/cowrie-git/src/cowrie/data/fs.pickle"

OPS_UID = 1000
PG_UID, PG_GID = 105, 111
DAY = 86400
# relative path under files/ -> (uid, gid, mode); everything else is root:root 0644
OWNERS = {
    "opt/pgbackup/pg-backup.sh": (0, 0, 0o755),
    "root/.bash_history": (0, 0, 0o600),
    "home/ops/.bash_history": (OPS_UID, OPS_UID, 0o600),
}
DUMPS = 7  # nightly dumps kept on display
# Cowrie's `free` reads the host's real /proc/meminfo, so the fake one (and df's tmpfs sizes) match the
# VPS: 1682 MiB. Change it with the VPS size, or `free` and `cat /proc/meminfo` disagree.
MEM_KB = 1_722_368
UNSCALED = ("Hugepagesize", "Hugetlb", "VmallocTotal")


def node(name, typ, uid=0, gid=0, size=0, mode=0o644, ctime=0, contents=None):
    n = [None] * 10
    n[A_NAME], n[A_TYPE], n[A_UID], n[A_GID], n[A_SIZE] = name, typ, uid, gid, size
    n[A_MODE] = (stat.S_IFDIR if typ == T_DIR else stat.S_IFREG) | mode
    n[A_CTIME], n[A_CONTENTS], n[A_TARGET], n[A_REALFILE] = ctime, contents, None, None
    if typ == T_DIR and contents is None:
        n[A_CONTENTS] = []
    return n


def parts(path):
    return [p for p in path.split("/") if p]


def get(root, path):
    n = root
    for p in parts(path):
        if n[A_TYPE] != T_DIR:
            return None
        n = next((k for k in n[A_CONTENTS] if k[A_NAME] == p), None)
        if n is None:
            return None
    return n


def mkdirs(root, path, uid=0, gid=0, mode=0o755, ctime=0):
    n = root
    for p in parts(path):
        k = next((k for k in n[A_CONTENTS] if k[A_NAME] == p), None)
        if k is None:
            k = node(p, T_DIR, uid, gid, 4096, mode, ctime)
            n[A_CONTENTS].append(k)
        n = k
    return n


def put(root, path, data=None, size=None, uid=0, gid=0, mode=0o644, ctime=0):
    """Create or replace a file. data=None gives a file with only a size (contents never shown)."""
    d, name = os.path.split(path)
    parent = mkdirs(root, d, ctime=ctime)
    parent[A_CONTENTS][:] = [k for k in parent[A_CONTENTS] if k[A_NAME] != name]
    if size is None:
        size = len(data or b"")
    parent[A_CONTENTS].append(node(name, T_FILE, uid, gid, size, mode, ctime, data))


def remove(root, path):
    d, name = os.path.split(path)
    parent = get(root, d)
    if parent is not None:
        parent[A_CONTENTS][:] = [k for k in parent[A_CONTENTS] if k[A_NAME] != name]


def edit(root, path, fn):
    """Rewrite a text file's lines with fn(list of lines) -> list of lines."""
    n = get(root, path)
    if n is None or not isinstance(n[A_CONTENTS], bytes):
        return
    lines = fn(n[A_CONTENTS].decode().splitlines())
    n[A_CONTENTS] = ("\n".join(lines) + "\n").encode()
    n[A_SIZE] = len(n[A_CONTENTS])


def without_user(lines, *users):
    return [line for line in lines if line.split(":")[0] not in users]


def group_lines(lines):
    """Drop phil from every group; add ops and postgres groups."""
    out = []
    for line in without_user(lines, "phil", "ops", "postgres"):
        f = line.split(":")
        if len(f) == 4:
            members = [m for m in f[3].split(",") if m and m not in ("phil", "ops")]
            f[3] = ",".join(members + ["ops"] if f[0] == "sudo" else members)
            line = ":".join(f)
        out.append(line)
    return out + [f"ops:x:{OPS_UID}:", f"postgres:x:{PG_GID}:"]


def scale_meminfo(lines, total_kb=MEM_KB):
    """Scale every kB value so MemTotal becomes total_kb (sizes of fixed things stay)."""
    old = next((int(line.split()[1]) for line in lines if line.startswith("MemTotal:")), 0)
    if not old:
        return lines
    out = []
    for line in lines:
        f = line.split()
        if len(f) == 3 and f[2] == "kB" and f[1].isdigit() and not f[0].rstrip(":").startswith(UNSCALED):
            key, new = f[0], str(round(int(f[1]) * total_kb / old))
            line = key + new.rjust(len(line) - len(key) - 3) + " kB"
        out.append(line)
    return out


def dump_size(day):
    """A plausible dump size for one day, about 1.2-1.4 GB (deterministic; df shows 9.1G used)."""
    return 1_180_000_000 + day.toordinal() * 7919 % 97 * 2_350_000


def apply(root, hostname, today, files=FILES):
    t0 = int(datetime.datetime(today.year, today.month, today.day, tzinfo=datetime.timezone.utc).timestamp())
    installed = t0 - 400 * DAY  # when the "server" was set up

    # tells
    remove(root, "/.dockerenv")
    remove(root, "/home/phil")
    edit(root, "/etc/passwd", lambda ls: without_user(ls, "phil", "ops", "postgres") + [
        f"postgres:x:{PG_UID}:{PG_GID}:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash",
        f"ops:x:{OPS_UID}:{OPS_UID}:Operations,,,:/home/ops:/bin/bash"])
    edit(root, "/etc/shadow", lambda ls: without_user(ls, "phil", "ops", "postgres") + [
        "postgres:*:19800:0:99999:7:::", "ops:!:19800:0:99999:7:::"])
    edit(root, "/etc/group", group_lines)
    edit(root, "/proc/meminfo", scale_meminfo)
    meminfo = get(root, "/proc/meminfo")
    if meminfo is not None:
        meminfo[A_SIZE] = 0  # like every /proc file

    # one hostname everywhere
    put(root, "/etc/hostname", f"{hostname}\n".encode(), ctime=installed)
    put(root, "/etc/hosts", (f"127.0.0.1\tlocalhost\n127.0.1.1\t{hostname}\n10.20.0.11\tdb-primary.internal\n\n"
                             "# The following lines are desirable for IPv6 capable hosts\n"
                             "::1     localhost ip6-localhost ip6-loopback\n"
                             "ff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n").encode(), ctime=installed)

    # the persona's files (files/ mirrors the fake root)
    for d, _, names in os.walk(files):
        for name in sorted(names):
            src = os.path.join(d, name)
            rel = os.path.relpath(src, files).replace(os.sep, "/")
            uid, gid, mode = OWNERS.get(rel, (0, 0, 0o644))
            with open(src, "rb") as fh:
                put(root, "/" + rel, fh.read(), uid=uid, gid=gid, mode=mode, ctime=t0 - 30 * DAY)
    home = mkdirs(root, "/home/ops")
    home[A_UID] = home[A_GID] = OPS_UID
    home[A_MODE] = stat.S_IFDIR | 0o750
    mkdirs(root, "/var/lib/postgresql", PG_UID, PG_GID, 0o755, installed)

    # a week of nightly dumps and their log, ending last night
    mkdirs(root, "/srv/backup", 0, 0, 0o755, installed)
    mkdirs(root, "/srv/backup/postgres", PG_UID, PG_GID, 0o750, installed)
    log = []
    for i in range(DUMPS, 0, -1):
        day = today - datetime.timedelta(days=i)
        name = f"appdb_{day.isoformat()}.sql.gz"
        done = t0 - i * DAY + 2 * 3600 + 30 * 60 + 400 + i * 37  # 02:30 plus the dump's run time
        put(root, f"/srv/backup/postgres/{name}", size=dump_size(day), uid=PG_UID, gid=PG_GID, mode=0o640,
            ctime=done)
        stamp = datetime.datetime.fromtimestamp(done, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        log.append(f"{stamp} ok {name} {dump_size(day)}")
    put(root, "/var/log/pg-backup.log", ("\n".join(log) + "\n").encode(), uid=PG_UID, gid=PG_GID, mode=0o640,
        ctime=t0 - DAY + 2 * 3600 + 30 * 60 + 437)
    return root


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--hostname", required=True)
    ap.add_argument("--src", default=BUNDLED, help="Cowrie's bundled fs.pickle")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    with open(a.src, "rb") as fh:
        root = pickle.load(fh)  # Cowrie's own file from the image, not untrusted input
    apply(root, a.hostname, datetime.datetime.now(datetime.timezone.utc).date())
    tmp = a.out + ".tmp"
    with open(tmp, "wb") as fh:
        pickle.dump(root, fh)
    os.replace(tmp, a.out)
    print(f"wrote {a.out} for {a.hostname}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
