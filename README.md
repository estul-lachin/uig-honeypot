# uig-honeypot

A [Cowrie](https://github.com/cowrie/cowrie) SSH/Telnet honeypot on a small VPS, with a public page at
**https://honeypot.uig.me** that replays the last hour of attacks on a world map, plus
[weekly reports](https://honeypot.uig.me/reports.html) mapped to MITRE ATT&CK. The raw logs stay private
(on the VPS, and in a local Splunk for detection work). Only aggregated stats with no IPs and no live
links get published.

```
VPS (Debian 13)
├─ real sshd on a high port, key-only
├─ Docker: Cowrie on 22/23, read-only, no capabilities, no outbound connections
├─ every 10 minutes: sentinel.py → new events to Microsoft Sentinel (Logs Ingestion API, write-only identity)
└─ hourly systemd timer
     enrich.py    → AbuseIPDB lookups of new source IPs (check only, never reports; cache stays private)
     aggregate.py → stats.json + recent.json (GeoIP: country/city/coords, never IPs)
                    ATT&CK tags from ttp_rules.json; weekly.py → reports/YYYY-Www.json per finished week
     detect.py    → detections.json: where the detections.uig.me Sigma rules fired in the last 30 days
                    (rules from detections.uig.me/rules.json, run by a copy of its evaluator, sigma_eval.py)
     publish.sh   → force-push one commit to the uig-honeypot-data repo (deploy key, that repo only)
GitHub
├─ uig-honeypot-data: the JSON files, replaced hourly
└─ uig-honeypot Pages: site/ (static; reads the JSON from the data repo; notes/ holds weekly notes)
Mac
├─ ./hp: setup, deploy, status, fetch (local preview), pull (raw logs → logs/, private)
└─ siem/: local Splunk with the honeypot app: ATT&CK macro, IP reputation lookup, 7 detections, dashboard
```

## Setup

1. `cp .env.example .env.local` and fill it in. Your SSH key must already be in
   `/root/.ssh/authorized_keys` on the VPS (`ssh-copy-id root@<host>`).
2. `./hp prepare` installs Docker and switches sshd to key-only. sshd then listens on **both** 22 and
   `HP_SSH_PORT`, so you can't get locked out.
3. Open `HP_SSH_PORT`, 22 and 23 (TCP) in the provider's security group.
4. `./hp finalize` connects on the new port, which proves that port works, and then drops 22 from sshd.
5. `./hp build-image` is only needed if the VPS can't pull from Docker Hub (common on mainland-China
   VPSes, where uploads from abroad can also crawl at a few KB/s). It builds `uig/cowrie:<version>` on
   the VPS from the pinned, hash-checked Cowrie source, using only in-country Debian and PyPI mirrors.
   Then set `COWRIE_IMAGE=uig/cowrie:3.1.3` in `.env.local`.
6. `./hp deploy`, then `./hp status` after an hour.
7. Publishing: create the public data repo, set `HP_DATA_REPO=owner/name` in `.env.local`, run
   `./hp publish-setup` (adds the VPS's deploy key with write access to that repo only), then
   `./hp deploy` again.

## The page

`site/` is plain HTML, CSS and JS (D3 from jsDelivr, the Natural Earth 1:50m map vendored). It
shades countries by total sessions and replays `recent.json`. Each new session is drawn as a line
from its source to the honeypot. Quiet stretches longer than 3 s are skipped, and with
`prefers-reduced-motion` nothing animates. Preview locally:

```
./hp fetch && python3 -m http.server -d site 8000   # open http://127.0.0.1:8000/?data=data/
```

Attacker-supplied strings are only ever inserted with `textContent`, never as HTML.

## Weekly reports and ATT&CK mapping

`vps/ttp_rules.json` maps Cowrie events and command text to MITRE ATT&CK techniques (regexes that
Python and Splunk both understand). `aggregate.py` counts each technique once per session, and
`weekly.py` writes one report per finished ISO week (UTC) two hours after it ends: totals with the change
from the previous week, values never seen before, TTPs, the hours of day, and the top lists. Reports are written once
and outlive the 30-day raw-log retention. Notes for a week go in `site/notes/YYYY-Www.md`
(see `site/notes/README.md`).

## IP reputation (AbuseIPDB)

`vps/enrich.py` runs before each hourly aggregation and looks up source IPs from the last three days in
[AbuseIPDB](https://www.abuseipdb.com/) (`/check` only: this honeypot never reports IPs). Each IP is looked
up once and again only if it returns after 7 days; at most 900 lookups a day, inside the free plan's 1000.
Results are cached in `data/enrich/abuseipdb.json` on the VPS (private). The public pages get only a
summary with no IPs: score ranges, how many sources had never been reported, network types and ISPs.
`./hp pull` copies the cache to the Mac as the Splunk lookup `ip_reputation`, which adds `abuse_score`,
`abuse_reports`, `abuse_isp` and more to every event automatically.

Setup: create a free AbuseIPDB account and API key, put `HP_ABUSEIPDB_KEY=...` in `.env.local`, then
`./hp deploy`. The key is written to `/opt/uig-honeypot/.env` (mode 600) and read from the environment,
never from the command line. Without a key the step is skipped.

## Microsoft Sentinel

The raw events also go to a Log Analytics workspace with Microsoft Sentinel (Canada Central).
`vps/sentinel.py` runs every 10 minutes, reads only what was appended to `cowrie.json` since the last
run (it follows the daily rotation by inode), and posts gzip batches to the Azure Monitor Logs Ingestion
API. A data collection rule turns Cowrie's `timestamp` into `TimeGenerated` and writes the `Cowrie_CL`
table. The VPS's service principal has only *Monitoring Metrics Publisher* on that one rule: it can add
rows and nothing else. Its settings (`HP_AZ_*`) go from `.env.local` to `/opt/uig-honeypot/.env` (mode 600).

The analytics rules come from [uig-detections](https://github.com/estul-lachin/uig-detections): the same
Sigma rules as detections.uig.me, converted to KQL, checked in Sentinel against test events and deployed
as scheduled rules that raise incidents grouped by source IP. The workspace has a 0.1 GB daily cap and the
subscription a CAD 5 monthly budget alert; the honeypot sends a few MB a day.

## Local SIEM (Splunk)

```
./hp pull          # raw cowrie.json* → logs/ (git-ignored; contains attacker IPs)
./hp siem up       # http://127.0.0.1:8010, admin / HP_SPLUNK_PASSWORD from .env.local
./hp siem reload   # after editing ttp_rules.json or the app
./hp siem down     # stop; ./hp siem reset also deletes the index
```

`siem/app/honeypot` defines the `honeypot` index, the `cowrie:json` sourcetype, the `cowrie_ttp`
macro and `ttp_rules` lookup (both generated from `vps/ttp_rules.json` by `siem/gen_splunk.py`),
seven scheduled detections and the *Honeypot overview* dashboard. The detections are described, with SPL
and false positives, in [docs/detections.md](docs/detections.md). Splunk runs as a 60-day Enterprise
trial; after that the Free license still searches but doesn't run scheduled alerts.

## Link preview

`site/og-image.png` (1200x630, shown by LinkedIn and others) is rendered from `assets/og-image.html` with the same
headless-Chrome command as in [uig-home](https://github.com/estul-lachin/uig-home#readme).

## Safety

- **No outbound connections from the honeypot.** `uig-egress.sh` drops every NEW connection that
  starts on the Cowrie bridge, to the internet and to the host itself. The fake `wget`/`curl` fail,
  but their URLs are still logged. SSH forwarding is disabled in Cowrie.
- **The container is locked down.** It runs as uid 999 with a read-only root filesystem, `cap_drop: ALL`,
  `no-new-privileges`, and memory and PID limits.
- **Published data is sanitized.** stats.json has no source IPs, only unique counts. The VPS's own IP
  is replaced with `[honeypot-ip]`. IPs and URLs are defanged (`hxxp[:]//192[.]0[.]2[.]1`),
  control characters are stripped, and strings are capped at 120 characters. Malware is listed by
  SHA-256 only and is never published as a file. See `tests/test_aggregate.py`. detections.json
  holds only counts, days and one example command per rule, cleaned the same way (`tests/test_detect.py`).
- **The VPS can't touch this repo.** Its deploy key writes only to the data repo, so a compromised
  VPS could at worst publish bad numbers, not change the page's code.
- **Never log in to port 22 with a real password.** Cowrie accepts it, and the password would
  appear in the public top-password list.

## Tests

```
python3 -m unittest discover -s tests
python3 siem/gen_splunk.py --check   # Splunk macro and lookup match ttp_rules.json
shellcheck hp vps/*.sh
```
