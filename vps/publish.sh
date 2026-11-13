#!/usr/bin/env bash
# Push stats.json, recent.json, detections.json and network.json to the public data repo (HP_DATA_REPO) as a
# single orphan commit, force-pushed, so the repo never grows. The deploy key
# on this VPS can write only to that data repo, never to the code repo.
# Run after every aggregation by uig-aggregate.service (hourly) and by
# uig-live.service (every minute, with --quiet). A lock keeps the two apart.
set -euo pipefail
umask 022
APP=/opt/uig-honeypot
KEY=$APP/data/deploy_key
WORK=$APP/data/publish
QUIET=0
[ "${1:-}" = --quiet ] && QUIET=1

if [ -z "${HP_DATA_REPO:-}" ]; then
    echo "HP_DATA_REPO not set; not publishing"
    exit 0
fi
[ -f "$KEY" ] || { echo "error: $KEY missing; run ./hp publish-setup" >&2; exit 1; }

exec 9>"$APP/data/publish.lock"
if ! flock -w 120 9; then
    echo "another publish is still running; skipped" >&2
    exit 1
fi

# GitHub's published ed25519 host key, pinned instead of trusted on first use.
KNOWN=$APP/data/github_known_hosts
echo "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl" >"$KNOWN"
export GIT_SSH_COMMAND="ssh -i $KEY -o IdentitiesOnly=yes -o UserKnownHostsFile=$KNOWN -o StrictHostKeyChecking=yes -o ConnectTimeout=30"

rm -rf "$WORK"
mkdir -p "$WORK"
cd "$WORK"
git init -q -b main
cp "$APP/data/stats.json" "$APP/data/recent.json" .
# Rule hits for detections.uig.me (see detect.py); skipped if that run failed.
[ ! -f "$APP/data/detections.json" ] || cp "$APP/data/detections.json" .
# Suricata alert summary (see network.py); skipped if that run failed.
[ ! -f "$APP/data/network.json" ] || cp "$APP/data/network.json" .
# Weekly reports (see weekly.py): small, written once per finished week.
if [ -d "$APP/data/reports" ]; then
    mkdir reports
    cp "$APP"/data/reports/*.json reports/
fi
cat >README.md <<'EOF'
# uig-honeypot-data

Aggregated, privacy-safe output of the honeypot described in
https://github.com/estul-lachin/uig-honeypot, read by https://honeypot.uig.me.
Replaced every minute by a single force-pushed commit. No IP addresses.
recent.json (the last hour of events) is rebuilt every minute; the other files every hour.
reports/ holds one file per finished ISO week (UTC) and an index.json.
detections.json counts where the https://detections.uig.me rules fired in the last 30 days.
network.json summarizes the Suricata IDS alerts of the last 30 days (counts only).
IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0.
EOF
git add -A
git -c user.name="uig-honeypot" -c user.email="uig-honeypot@users.noreply.github.com" \
    commit -q -m "Data as of $(date -u +%Y-%m-%dT%H:%M:%SZ)"
git push -q --force "$HP_DATA_REPO" main
[ "$QUIET" = 1 ] || echo "published to $HP_DATA_REPO"
