# uig-honeypot

A [Cowrie](https://github.com/cowrie/cowrie) SSH/Telnet honeypot on a small VPS, with a public page at
**https://honeypot.uig.me** that replays the last hour of attacks on a world map. The raw logs stay on
the VPS. Only aggregated stats with no IPs and no live links get published.

```
VPS (Debian 13)
├─ real sshd on a high port, key-only
├─ Docker: Cowrie on 22/23, read-only, no capabilities, no outbound connections
└─ hourly systemd timer
     aggregate.py → stats.json + recent.json (GeoIP: country/city/coords, never IPs)
     publish.sh   → force-push one commit to the uig-honeypot-data repo (deploy key, that repo only)
GitHub
├─ uig-honeypot-data: the two JSON files, replaced hourly
└─ uig-honeypot Pages: site/ (static; reads the JSON from the data repo)
Mac
└─ ./hp: setup, deploy, status, fetch (local preview)
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

## Safety

- **No outbound connections from the honeypot.** `uig-egress.sh` drops every NEW connection that
  starts on the Cowrie bridge, to the internet and to the host itself. The fake `wget`/`curl` fail,
  but their URLs are still logged. SSH forwarding is disabled in Cowrie.
- **The container is locked down.** It runs as uid 999 with a read-only root filesystem, `cap_drop: ALL`,
  `no-new-privileges`, and memory and PID limits.
- **Published data is sanitized.** stats.json has no source IPs, only unique counts. The VPS's own IP
  is replaced with `[honeypot-ip]`. IPs and URLs are defanged (`hxxp[:]//192[.]0[.]2[.]1`),
  control characters are stripped, and strings are capped at 120 characters. Malware is listed by
  SHA-256 only and is never published as a file. See `tests/test_aggregate.py`.
- **The VPS can't touch this repo.** Its deploy key writes only to the data repo, so a compromised
  VPS could at worst publish bad numbers, not change the page's code.
- **Never log in to port 22 with a real password.** Cowrie accepts it, and the password would
  appear in the public top-password list.

## Tests

```
python3 -m unittest discover -s tests
shellcheck hp vps/*.sh
```
