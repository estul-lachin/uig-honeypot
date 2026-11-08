# Detections

Six scheduled searches in the local Splunk (`siem/app/honeypot/default/savedsearches.conf`), run on the
honeypot's raw Cowrie logs. Everything on a honeypot is malicious by definition, so these don't separate
good from bad. They pick out the sessions worth an analyst's time from thousands of identical scans.

Shared design choices:

- **Hourly, over the last 7 days of event time.** `./hp pull` delivers logs in batches, so a search over
  the last hour would miss events that arrive late. The wide window catches them, and **throttling**
  (`alert.suppress.fields`) makes each finding alert only once (per session, URL, wordlist or IP).
- **ATT&CK tagging comes from one source.** The `cowrie_ttp` macro is generated from `vps/ttp_rules.json`,
  the same rules that tag the public weekly reports, so Splunk and the website never disagree.
- Sample output below is from real traffic, with the IPs replaced by `203.0.113.x` and URLs defanged.

## HP-01 Login followed by tool download

**ATT&CK:** T1078 Valid Accounts → T1105 Ingress Tool Transfer. **Throttle:** session.

A session logs in and tries to fetch or write a tool within 5 minutes. This is the dropper chain of
Mirai-style botnets: guess a password, then pull a binary with `wget`/`curl`/`tftp`, or, when no
downloader exists, write it byte by byte with `echo -ne "\x7f\x45..." >> .d`.

```spl
index=honeypot sourcetype=cowrie:json eventid IN ("cowrie.login.success", "cowrie.command.input",
    "cowrie.session.file_download", "cowrie.session.file_download.failed")
| `cowrie_ttp`
| eval login_t=if(eventid=="cowrie.login.success", _time, null()),
       dl_t=if(isnotnull(mvfind(ttp, "^T1105$")), _time, null())
| stats min(login_t) AS login_t min(dl_t) AS dl_t values(username) AS username ... by session src_ip
| where isnotnull(login_t) AND isnotnull(dl_t) AND dl_t>=login_t AND dl_t-login_t<=300
```

```
    login_time        session    username seconds_to_download download_commands download_command
2026-11-08 18:15:46 8bc71e892e59 root                    14.5                 7 /bin/busybox echo -ne "\x23\x21\x2F\x62\x69\x6E..." > .k
2026-11-08 18:02:40 9c5ffe8fbb3c root                     4.6               412 /bin/busybox echo -ne "\x00\x00\x00\x00\x00\x00..." >> .d
```

The second session wrote a binary in 412 `echo` chunks 4.6 seconds after logging in: fully automated.
The first decodes to a shell script (`#!/bin/sh`, `for proc_dir in /proc/*`) that kills processes whose
binary was deleted, which clears out competing malware before the bot moves in.

**False positives:** none on a honeypot. On a real server, admins who `curl` installers right after
logging in would match; there you'd restrict it to `/tmp`, `/dev/shm` or hex `echo` writes.

## HP-02 New download URL

**ATT&CK:** T1105. **Throttle:** URL. **State:** the `honeypot_seen_urls` lookup.

A download URL never seen before, taken from commands (`rex` on `wget`/`curl`/`tftp`/`ftpget` URLs) and from
Cowrie's download events. The search merges this run's URLs with the stored list (`inputlookup`), writes
the result back (`outputlookup`) and returns only the ones that weren't stored. This is the first-seen
pattern from threat hunting: new infrastructure is more interesting than the 500th hit on a known one.

```
    first_seen                  dl_url             sources count
2026-11-08 18:02:46 hxxp[:]//203.0.113.x/wget.sh          1     2
2026-11-08 18:02:46 hxxp[:]//203.0.113.x/curl.sh          1     2
2026-11-08 18:03:11 hxxp[:]//203.0.113.x:69/tftp.sh       1     1
2026-11-08 18:03:41 hxxp[:]//203.0.113.x/ftpget.sh         1     1
```

One host, one script per download tool: the bot tries `wget`, then `curl`, `tftp` and `ftpget`, whichever
the device has. A second run returns nothing, since all four are now in the lookup.

**Tuning:** the lookup grows forever. Prune rows with an old `last_seen` if it gets large.

## HP-03 Shared wordlist across sources

**ATT&CK:** T1110 Brute Force. **Throttle:** wordlist hash.

Three or more source IPs try exactly the same set of passwords (3 or more) in the same hour. Each source
alone stays under any per-IP brute-force threshold; together they are one campaign run from many hosts.
The password set is sorted and hashed (`md5(mvjoin(mvsort(passwords)))`) to give the campaign an ID.

Tested with synthetic events (three documentation-range IPs, the same three passwords):

```
      hour                   wordlist             n sources    src_ips    passwords
2026-11-07 05:00 597a95f697db92172a565eed3838f3e1 3       3 198.51.100.11 dragon
                                                            198.51.100.12 letmein
                                                            198.51.100.13 sunshine
```

**Blind spot:** bots that try a random slice of a large list never share an exact set. A looser
version would compare overlap (e.g. Jaccard similarity) instead of equality.

## HP-04 Persistence attempt

**ATT&CK:** T1098.004 SSH Authorized Keys, T1053.003 Cron, T1098 Account Manipulation. **Throttle:** session.

The attacker plans to come back: adds an SSH key, a cron job or changes a password. On a real server this is
the highest-priority finding, because the attacker no longer needs the weak password that let them in.

## HP-05 Crypto miner

**ATT&CK:** T1496 Resource Hijacking. **Throttle:** session.

Miner names (`xmrig`, `minerd`), pool protocols (`stratum+tcp://`) or coin names in commands. The pool
address is extracted, since it is the most useful indicator to block on a real network.

## HP-06 Returning source

**Throttle:** source IP. Runs daily over 30 days.

A source IP that connects again after more than 7 days of silence. Most scanners hit once; one that
returns probably keeps a target list (it remembers the honeypot accepted a login), and is worth a
reputation lookup.

```spl
index=honeypot sourcetype=cowrie:json eventid="cowrie.session.connect"
| bin _time span=1d | stats count AS sessions by src_ip _time
| sort 0 src_ip _time
| streamstats current=f window=1 last(_time) AS previous by src_ip
| where _time-previous > 7*86400
```

HP-03 to HP-06 were checked against synthetic events in a separate test index, because the honeypot hadn't
produced matching traffic yet. Each returned the expected row.

## What the tagging found first

On the first day, most sessions were Mirai-style telnet bots: `enable`, `system`, `shell`, `sh` to escape
a router CLI (T1059.008, 23 of 26 sessions with a login), then `/bin/busybox` probes, writable-directory tests
(`echo > /dev/shm/.b && sh /dev/shm/.b`) and a binary written by `echo`. The rules started out written for
SSH-style Linux attacks and missed all of this. Seeing it in Splunk led to three new rules (T1059.008, T1027,
hex-`echo` T1105). That loop of hunting, finding a gap and fixing the rule is the main reason to have a SIEM
on this data.
