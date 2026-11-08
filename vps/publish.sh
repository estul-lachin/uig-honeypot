#!/usr/bin/env bash
# Push stats.json and recent.json to the public data repo (HP_DATA_REPO) as a
# single orphan commit, force-pushed, so the repo never grows. The deploy key
# on this VPS can write only to that data repo, never to the code repo.
# Run after every aggregation by uig-aggregate.service.
set -euo pipefail
umask 022
APP=/opt/uig-honeypot
KEY=$APP/data/deploy_key
WORK=$APP/data/publish

if [ -z "${HP_DATA_REPO:-}" ]; then
    echo "HP_DATA_REPO not set; not publishing"
    exit 0
fi
[ -f "$KEY" ] || { echo "error: $KEY missing; run ./hp publish-setup" >&2; exit 1; }

# GitHub's published ed25519 host key, pinned instead of trusted on first use.
KNOWN=$APP/data/github_known_hosts
echo "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl" >"$KNOWN"
export GIT_SSH_COMMAND="ssh -i $KEY -o IdentitiesOnly=yes -o UserKnownHostsFile=$KNOWN -o StrictHostKeyChecking=yes -o ConnectTimeout=30"

rm -rf "$WORK"
mkdir -p "$WORK"
cd "$WORK"
git init -q -b main
cp "$APP/data/stats.json" "$APP/data/recent.json" .
# Weekly reports (see weekly.py): small, written once per finished week.
if [ -d "$APP/data/reports" ]; then
    mkdir reports
    cp "$APP"/data/reports/*.json reports/
fi
cat >README.md <<'EOF'
# uig-honeypot-data

Aggregated, privacy-safe output of the honeypot described in
https://github.com/estul-lachin/uig-honeypot, read by https://honeypot.uig.me.
Replaced every hour by a single force-pushed commit. No IP addresses.
reports/ holds one file per finished ISO week (UTC) and an index.json.
IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0.
EOF
git add -A
git -c user.name="uig-honeypot" -c user.email="uig-honeypot@users.noreply.github.com" \
    commit -q -m "Data as of $(date -u +%Y-%m-%dT%H:%M:%SZ)"
git push -q --force "$HP_DATA_REPO" main
echo "published to $HP_DATA_REPO"
