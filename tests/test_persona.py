"""Tests for vps/persona/build_fs.py. Run: python3 -m unittest discover -s tests

Uses a small hand-made tree in Cowrie's node layout, so Cowrie need not be
installed. The real pickle is checked at deploy time and by hand (README).
"""

import datetime
import os
import stat
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "vps", "persona"))
import build_fs as b  # noqa: E402

TODAY = datetime.date(2026, 11, 13)
MEMINFO = ("MemTotal:        4054744 kB\nMemFree:          997740 kB\n"
           "Hugepagesize:       2048 kB\nHugePages_Total:       0\n")


def tree():
    root = b.node("", b.T_DIR, mode=0o755)
    b.put(root, "/.dockerenv", b"")
    b.put(root, "/etc/passwd", b"root:x:0:0:root:/root:/bin/bash\nphil:x:1000:1000:Phil California,,,:/home/phil:/bin/bash\n")
    b.put(root, "/etc/shadow", b"root:*:15800:0:99999:7:::\nphil:$6$x:15800:0:99999:7:::\n")
    b.put(root, "/etc/group", b"root:x:0:\ncdrom:x:24:phil\nsudo:x:27:\nphil:x:1000:\n")
    b.put(root, "/etc/hostname", b"svr04\n")
    b.put(root, "/proc/meminfo", MEMINFO.encode())
    b.mkdirs(root, "/home/phil")
    return root


def text(root, path):
    return b.get(root, path)[b.A_CONTENTS].decode()


class PersonaTest(unittest.TestCase):
    def setUp(self):
        self.root = b.apply(tree(), "db-backup-01", TODAY)

    def test_tells_removed(self):
        self.assertIsNone(b.get(self.root, "/.dockerenv"))
        self.assertIsNone(b.get(self.root, "/home/phil"))
        for f in ("/etc/passwd", "/etc/shadow", "/etc/group"):
            self.assertNotIn("phil", text(self.root, f), f)

    def test_users_and_groups(self):
        self.assertIn("ops:x:1000:1000:", text(self.root, "/etc/passwd"))
        self.assertIn("postgres:x:105:111:", text(self.root, "/etc/passwd"))
        group = text(self.root, "/etc/group")
        self.assertIn("cdrom:x:24:\n", group)
        self.assertIn("sudo:x:27:ops\n", group)
        home = b.get(self.root, "/home/ops")
        self.assertEqual((home[b.A_UID], home[b.A_MODE]), (1000, stat.S_IFDIR | 0o750))

    def test_one_hostname(self):
        self.assertEqual(text(self.root, "/etc/hostname"), "db-backup-01\n")
        self.assertIn("127.0.1.1\tdb-backup-01\n", text(self.root, "/etc/hosts"))

    def test_persona_files(self):
        self.assertIn("ID=debian", text(self.root, "/usr/lib/os-release"))
        self.assertIn("/opt/pgbackup/pg-backup.sh", text(self.root, "/etc/cron.d/pg-backup"))
        script = b.get(self.root, "/opt/pgbackup/pg-backup.sh")
        self.assertEqual(script[b.A_MODE], stat.S_IFREG | 0o755)
        self.assertEqual(script[b.A_SIZE], len(script[b.A_CONTENTS]))
        self.assertEqual(b.get(self.root, "/root/.bash_history")[b.A_MODE] & 0o777, 0o600)

    def test_week_of_dumps_ending_last_night(self):
        dumps = b.get(self.root, "/srv/backup/postgres")[b.A_CONTENTS]
        names = sorted(n[b.A_NAME] for n in dumps)
        self.assertEqual(len(names), 7)
        self.assertEqual(names[0], "appdb_2026-11-06.sql.gz")
        self.assertEqual(names[-1], "appdb_2026-11-12.sql.gz")
        for n in dumps:
            self.assertIsNone(n[b.A_CONTENTS])       # size only: never readable
            self.assertGreater(n[b.A_SIZE], 1_000_000_000)
            self.assertEqual(n[b.A_UID], 105)
        # df shows 9.1G used on /srv/backup
        self.assertAlmostEqual(sum(n[b.A_SIZE] for n in dumps) / 2**30, 8.5, delta=0.8)
        log = text(self.root, "/var/log/pg-backup.log").splitlines()
        self.assertEqual(len(log), 7)
        self.assertTrue(log[-1].startswith("2026-11-12T02:"))
        self.assertEqual(b.get(self.root, "/srv/backup")[b.A_UID], 0)

    def test_meminfo_matches_the_vps(self):
        lines = text(self.root, "/proc/meminfo").splitlines()
        self.assertEqual(lines[0].split()[1], str(b.MEM_KB))
        self.assertEqual(lines[1].split()[1], str(round(997740 * b.MEM_KB / 4054744)))
        self.assertEqual(lines[2].split()[1], "2048")    # page size is not memory size
        self.assertEqual(lines[3], "HugePages_Total:       0")
        self.assertEqual(len(lines[0]), len("MemTotal:        4054744 kB"))  # columns stay aligned
        self.assertEqual(b.get(self.root, "/proc/meminfo")[b.A_SIZE], 0)

    def test_idempotent(self):
        again = b.apply(self.root, "db-backup-01", TODAY)
        for f in ("/etc/passwd", "/etc/shadow", "/etc/group"):
            users = [line.split(":")[0] for line in text(again, f).splitlines()]
            self.assertEqual((users.count("ops"), users.count("postgres")), (1, 1), f)
        self.assertIn("sudo:x:27:ops\n", text(again, "/etc/group"))


if __name__ == "__main__":
    unittest.main()
