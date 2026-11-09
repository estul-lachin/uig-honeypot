#!/usr/bin/env bash
# Install and start Suricata as a passive IDS next to Cowrie (run by ./hp nsm-setup, as root, on the VPS).
# Idempotent: run it again after changing anything in vps/suricata/.
#
# Suricata only watches (af-packet on eth0) and never blocks. It writes alerts to
# /var/log/suricata/eve.json and engine counters to stats.json; both stay on the VPS (they hold IPs).
# Undo: systemctl disable --now suricata uig-suricata-update.timer
set -euo pipefail
umask 022
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
say() { echo "==> $*"; }

# 1. Swap. The VPS has no swap, so a memory spike would go straight to the OOM killer.
if ! swapon --show=NAME --noheadings | grep -qx /swapfile; then
    say "Adding a 1 GB swapfile"
    [ -f /swapfile ] || { fallocate -l 1G /swapfile; chmod 600 /swapfile; mkswap /swapfile >/dev/null; }
    swapon /swapfile
    grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >>/etc/fstab
fi
echo 'vm.swappiness=10' >/etc/sysctl.d/99-uig-swap.conf
sysctl -q -p /etc/sysctl.d/99-uig-swap.conf

# 2. Packages (Debian's Suricata 7 and suricata-update, from the configured mirror).
if ! command -v suricata >/dev/null || ! command -v suricata-update >/dev/null || ! python3 -c 'import yaml' 2>/dev/null; then
    say "Installing suricata, suricata-update and python3-yaml"
    apt-get update -q
    DEBIAN_FRONTEND=noninteractive apt-get install -yq --no-install-recommends suricata suricata-update python3-yaml
fi
# The package starts Suricata with its stock config; stop it until ours is in place.
systemctl stop suricata 2>/dev/null || true

# 3. Config. HOME_NET is eth0's own address (Aliyun maps the public IP to it) and the Cowrie network.
eth0=$(ip -4 -o addr show eth0 | awk '{split($4, a, "/"); print a[1]; exit}')
net=$(docker network ls -q -f name=cowrie | head -1)
cowrie=$( [ -z "$net" ] || docker network inspect "$net" --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}')
[ -n "$eth0" ] || { echo "error: no IPv4 address on eth0" >&2; exit 1; }
home="[$eth0/32${cowrie:+,$cowrie}]"
say "HOME_NET has $(echo "$home" | tr -cd ',' | wc -c | awk '{print $1 + 1}') entries"
python3 "$HERE/make-config.py" /etc/suricata/suricata.yaml /etc/suricata/uig-suricata.yaml "$home"

# 4. Rules: ET Open through suricata-update (about 6 MB; slow from here, a few minutes).
if [ ! -s /var/lib/suricata/rules/suricata.rules ]; then
    say "Downloading ET Open rules (takes a few minutes)"
    suricata-update --suricata-conf /etc/suricata/uig-suricata.yaml --no-test --no-reload -q
fi
say "Testing the config and rules"
# (no -q here: for suricata, -q means "NFQUEUE", not "quiet")
suricata -T -c /etc/suricata/uig-suricata.yaml >/dev/null

# 5. systemd: the package's unit with our config, a memory cap, and restarts.
mkdir -p /etc/systemd/system/suricata.service.d
cat >/etc/systemd/system/suricata.service.d/uig.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/suricata -D --af-packet -c /etc/suricata/uig-suricata.yaml --pidfile /run/suricata.pid
MemoryMax=700M
Restart=on-failure
RestartSec=30
Nice=5
EOF
install -m 644 "$HERE/uig-suricata-update.service" "$HERE/uig-suricata-update.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now suricata
systemctl enable --now uig-suricata-update.timer

say "Started. Give it a minute, then: ./hp nsm"
