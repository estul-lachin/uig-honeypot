#!/usr/bin/env bash
# Fetch the free DB-IP Lite City database (CC BY 4.0, https://db-ip.com; the
# public page credits it). DB-IP publishes one file per month; fall back to
# last month's early in a month. Atomic: a failed download keeps the old file.
set -euo pipefail
umask 022
DEST=/opt/uig-honeypot/data/geoip/dbip-city-lite.mmdb
mkdir -p "$(dirname "$DEST")"
tmp=$(mktemp "$DEST.XXXXXX")
trap 'rm -f "$tmp" "$tmp.gz"' EXIT

for month in "$(date -u +%Y-%m)" "$(date -u -d "$(date -u +%Y-%m-01) -1 day" +%Y-%m)"; do
    url="https://download.db-ip.com/free/dbip-city-lite-$month.mmdb.gz"
    if curl -fsSL --retry 3 --max-time 900 -o "$tmp.gz" "$url"; then
        gunzip -c "$tmp.gz" >"$tmp"
        python3 -c 'import maxminddb, sys; maxminddb.open_database(sys.argv[1]).get("1.1.1.1")' "$tmp"
        chmod 644 "$tmp"
        mv "$tmp" "$DEST"
        echo "installed DB-IP Lite City $month"
        exit 0
    fi
done
echo "error: could not download DB-IP Lite City" >&2
exit 1
