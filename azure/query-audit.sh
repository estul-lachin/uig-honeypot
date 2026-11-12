#!/usr/bin/env bash
# Turn on query auditing for the honeypot workspace: every query lands in LAQueryLogs (who, from which
# client, how long), in the same workspace. uig-guide's tools/activity.py counts the portal ones per day
# for the "hands-on activity" calendar on guide.uig.me (counts only, never query text or names).
# Run on the Mac with the Azure CLI logged in; idempotent. Volume: one small row per query, far below the
# workspace's 0.1 GB daily cap.
#   Undo: az monitor diagnostic-settings delete --name uig-query-audit --resource <workspace id>
set -euo pipefail
umask 022
RG=${RG:-rg-uig-sentinel}
WS=${WS:-law-uig-honeypot}
id=$(az monitor log-analytics workspace show -g "$RG" -n "$WS" --query id -o tsv)
az monitor diagnostic-settings create --name uig-query-audit --resource "$id" --workspace "$id" \
    --logs '[{"category": "Audit", "enabled": true}]' -o none
echo "==> Query audit on: LAQueryLogs fills within about 15 minutes of the next query"
