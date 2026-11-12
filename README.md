# uig-honeypot

A [Cowrie](https://github.com/cowrie/cowrie) SSH/Telnet honeypot on a small VPS, with a public page at
**https://honeypot.uig.me** that replays the last hour of attacks on a world map, plus
[weekly reports](https://honeypot.uig.me/reports.html) mapped to MITRE ATT&CK and a
[network view](https://honeypot.uig.me/network.html) of the Suricata IDS alerts. The raw logs stay private
(on the VPS, and in a local Splunk for detection work). Only aggregated stats with no IPs and no live
links get published.

```
VPS (Debian 13)
├─ real sshd on a high port, key-only
├─ Docker: Cowrie on 22/23, read-only, no capabilities, no outbound connections
├─ Suricata on eth0: passive IDS, alerts only (vps/suricata/)
├─ every 10 minutes: sentinel.py → new Cowrie events and Suricata alerts to Microsoft Sentinel
│                    (Logs Ingestion API, write-only identity)
└─ hourly systemd timer
     enrich.py    → AbuseIPDB lookups of new source IPs (check only, never reports; cache stays private)
     aggregate.py → stats.json + recent.json (GeoIP: country/city/coords, never IPs)
                    ATT&CK tags from ttp_rules.json; weekly.py → reports/YYYY-Www.json per finished week
     detect.py    → detections.json: where the detections.uig.me Sigma rules fired in the last 30 days,
                    on Cowrie's logs and Suricata's alerts (rules from detections.uig.me/rules.json, run
                    by a copy of its evaluator, sigma_eval.py)
     network.py   → network.json: Suricata alerts of the last 30 days (ports, signatures, CVEs,
                    countries, overlap with Cowrie), counts only
     publish.sh   → force-push one commit to the uig-honeypot-data repo (deploy key, that repo only)
GitHub
├─ uig-honeypot-data: the JSON files, replaced hourly
└─ uig-honeypot Pages: site/ (static; reads the JSON from the data repo; notes/ holds weekly notes)
Mac
├─ ./hp: setup, deploy, status, fetch (local preview), pull (raw logs → logs/, private), demo
├─ siem/: local Splunk with the honeypot app: ATT&CK macro, IP reputation lookup, 7 detections, dashboard
└─ siem-wazuh/: local Wazuh on the pseudonymized copy (logs-demo/), for guide.uig.me
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
rows and nothing else.

Suricata alerts use the same rule and identity: `azure/suricata.sh` (run on the Mac with the Azure CLI,
idempotent) creates the `Suricata_CL` table and adds a second stream to the rule, so no new role is
needed. `uig-sentinel-suricata.timer` runs `sentinel.py --source suricata` every 10 minutes. It sends
`alert` events only (never flows or protocol logs), flattened to one row each: addresses and ports,
signature, category, severity, ET's signature severity, CVE and the rule's ATT&CK IDs, with the timestamp in UTC. logrotate copies
and truncates `eve.json` in place, so the shipper keeps a hash of the file's first bytes and finishes
the rotated copy (`eve.json.1.gz`) when they change. Its settings (`HP_AZ_*`) go from `.env.local` to `/opt/uig-honeypot/.env` (mode 600).

The analytics rules come from [uig-detections](https://github.com/estul-lachin/uig-detections): the same
Sigma rules as detections.uig.me, converted to KQL, checked in Sentinel against test events and deployed
as scheduled rules whose alerts become one incident per source IP. The workspace has a 0.1 GB daily cap and the
subscription a CAD 5 monthly budget alert; the honeypot sends a few MB a day. SOAR playbooks in
uig-detections (`soar/`) enrich, triage and escalate the incidents.

## Network monitoring (Suricata)

Cowrie only sees what reaches its SSH and Telnet ports. Suricata watches everything on `eth0` as a
passive IDS: it never blocks, it only alerts. `./hp nsm-setup` (idempotent) does it in `vps/suricata/`:

- adds a 1 GB swapfile (the VPS had none) and installs Debian's Suricata 7 and `suricata-update`;
- writes `/etc/suricata/uig-suricata.yaml` from the package's config with `make-config.py`, which
  replaces only what matters here: `HOME_NET` (this VPS and the Cowrie network), alerts-only `eve.json`
  plus 5-minute engine counters in `stats.json`, the "low" detection profile and small memcaps;
- runs the package's unit with that config, capped at 700 MB of memory and restarted on failure, so a
  spike restarts Suricata instead of the OOM killer picking Cowrie;
- updates the ET Open rules daily (`uig-suricata-update.timer`), minus the few in `disable.conf`.

Tuning (`vps/suricata/disable.conf`) only turns off rules that fire on the VPS's own traffic: its TLS
to Aliyun, its own `apt-get`, and Cowrie's fake BusyBox banner going back out. Everything an outside
host sends stays on, however noisy, because that is what a honeypot is for. The first 24 hours: 692
alerts, 0 packets dropped, 530 MB peak memory; the tuning removes 158 of those alerts, all outbound.

Captures happen before Docker's NAT, so alerts carry the real source address; like the Cowrie logs, they
stay on the VPS. `./hp nsm [HOURS]` prints memory, packet drops, alert volume and the top signatures,
with no addresses.

The public [network view](https://honeypot.uig.me/network.html) reads `network.json`, written hourly by
`vps/network.py`: alerts on incoming traffic over the last 30 days by day, port, category, signature, CVE
and source country, plus how many of the flagged sources ever opened a Cowrie session (most never do: they
scan database, RDP and web ports). Sources are counted, never listed. An alert is inbound when its source is
not a local address; outbound alerts are only counted. The real sshd's port (`HP_SSH_PORT`, passed as
`--hide-port`) is left out of the port list. To turn it off: `systemctl disable --now suricata uig-suricata-update.timer`.

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

## Pseudonymized copy: Splunk, Sentinel and Wazuh on the same rows

[guide.uig.me](https://guide.uig.me) shows the same investigations in three SIEMs, and recordings of
them, without a single real address. `./hp pull` also fetches the Suricata alerts and then runs
`./hp demo`, which writes `logs-demo/` (git-ignored) with `siem/pseudo.py`:

- rows shaped exactly like `Cowrie_CL` and `Suricata_CL` (the shaping code of `vps/sentinel.py`)
- a public `src_ip`/`dest_ip` becomes `src-` + 8 hex of sha256(`HP_PSEUDO_SALT` + ip); any other IPv4 in
  a string becomes `[ip]`; Suricata alerts on the real sshd port are dropped

The workspace functions `HP_Cowrie` and `HP_Suricata` (`azure/demo-functions.sh`) apply the same rule in
KQL; checked row for row against the copy. Splunk indexes the copy as `index=honeypot_demo`.

```
./hp wazuh up      # https://127.0.0.1:8444, admin / Lab-Wazuh-2026 (localhost only, pseudonymized data)
./hp wazuh load    # replay logs-demo/ into the manager (deletes the previous alerts first)
./hp wazuh down    # stop; ./hp wazuh reset also deletes the alerts
```

`load` sends each line into the manager's analysis queue (`siem-wazuh/inject.py`), so the alert count
equals the row count. `siem-wazuh/config/local_rules.xml` (100100-100202) turns every event into an
alert, with ATT&CK IDs on logins, downloads and persistence. `siem-wazuh/pipeline.sh` makes an alert keep
its event time (Wazuh would stamp the replay time), cut to milliseconds, Wazuh's own precision.

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
  network.json holds only counts, ports, ET rule names and countries; it never lists the real sshd's
  port (`tests/test_network.py`).
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
