#!/usr/bin/env bash
# Create the Suricata_CL table and add a Suricata stream to the honeypot's data collection rule.
# Run on the Mac with the Azure CLI logged in; idempotent (run it again after changing a column).
#
# The stream goes into the existing rule (dcr-uig-cowrie) on purpose: the VPS's service principal
# already has Monitoring Metrics Publisher on that one rule, so no new role assignment is needed and
# the identity still cannot write anywhere else. The Cowrie stream and flow are left as they are.
#
# Only alerts are sent (sentinel.py --source suricata), never flows or protocol logs: a few hundred
# rows a day, far below the workspace's 0.1 GB daily cap.
#   Undo: remove the Suricata stream and flow from the rule, then
#         az monitor log-analytics workspace table delete -g rg-uig-sentinel --workspace-name law-uig-honeypot -n Suricata_CL
set -euo pipefail
umask 022
RG=${RG:-rg-uig-sentinel}
WS=${WS:-law-uig-honeypot}
DCR=${DCR:-dcr-uig-cowrie}
API=2023-03-11

# Columns sent by vps/sentinel.py (SURICATA_FIELDS); the rule turns `timestamp` into TimeGenerated.
cols="timestamp:string flow_id:long src_ip:string src_port:int dest_ip:string dest_port:int proto:string
app_proto:string signature_id:int rev:int signature:string category:string severity:int
signature_severity:string cve:string mitre_tactic:string mitre_technique:string"

table_cols=(TimeGenerated=datetime)
for c in $cols; do [ "${c%%:*}" = timestamp ] || table_cols+=("${c%%:*}=${c#*:}"); done

echo "==> Table Suricata_CL"
if az monitor log-analytics workspace table show -g "$RG" --workspace-name "$WS" -n Suricata_CL -o none 2>/dev/null; then
    az monitor log-analytics workspace table update -g "$RG" --workspace-name "$WS" -n Suricata_CL \
        --columns "${table_cols[@]}" -o none
else
    az monitor log-analytics workspace table create -g "$RG" --workspace-name "$WS" -n Suricata_CL \
        --plan Analytics --columns "${table_cols[@]}" -o none
fi

echo "==> Stream Custom-SuricataRaw on $DCR"
sub=$(az account show --query id -o tsv)
url="https://management.azure.com/subscriptions/$sub/resourceGroups/$RG/providers/Microsoft.Insights/dataCollectionRules/$DCR?api-version=$API"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
az rest --method get --url "$url" -o json >"$tmp/current.json"
COLS="$cols" python3 - "$tmp/current.json" "$tmp/new.json" <<'EOF'
import json, os, sys
cur = json.load(open(sys.argv[1]))
p = cur["properties"]
cols = [{"name": c.split(":")[0], "type": c.split(":")[1]} for c in os.environ["COLS"].split()]
p["streamDeclarations"]["Custom-SuricataRaw"] = {"columns": cols}
law = p["destinations"]["logAnalytics"][0]["name"]
flow = {"streams": ["Custom-SuricataRaw"], "destinations": [law], "outputStream": "Custom-Suricata_CL",
        "transformKql": "source | extend TimeGenerated = todatetime(timestamp) | project-away timestamp"}
p["dataFlows"] = [f for f in p["dataFlows"] if f["streams"] != ["Custom-SuricataRaw"]] + [flow]
keep = ("dataCollectionEndpointId", "streamDeclarations", "dataFlows", "destinations", "description")
body = {"location": cur["location"], "tags": cur.get("tags") or {},
        "properties": {k: p[k] for k in keep if k in p}}
json.dump(body, open(sys.argv[2], "w"))
print("    streams:", ", ".join(body["properties"]["streamDeclarations"]))
EOF
az rest --method put --url "$url" --body @"$tmp/new.json" -o none
echo "Done. Rows arrive in Suricata_CL a few minutes after the VPS's first run."
