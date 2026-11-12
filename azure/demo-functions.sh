#!/usr/bin/env bash
# Create the workspace functions HP_Cowrie and HP_Suricata: Cowrie_CL and Suricata_CL with the same
# pseudonyms as siem/pseudo.py (the demo copy that Splunk and Wazuh read), for recordings, case reports
# and guide.uig.me. Run on the Mac with the Azure CLI logged in; idempotent.
#
#   set -a; . ./.env.local; set +a; ./azure/demo-functions.sh
#
# Needs HP_PSEUDO_SALT and HP_SSH_PORT. Both end up in the function bodies, which only readers of this
# workspace can see; never paste a function body anywhere public. Query time costs nothing extra:
# a function is a saved query, not a table.
#   Undo: az monitor log-analytics workspace saved-search delete -g rg-uig-sentinel --workspace-name law-uig-honeypot -n HP_Cowrie --yes
set -euo pipefail
umask 022
RG=${RG:-rg-uig-sentinel}
WS=${WS:-law-uig-honeypot}
: "${HP_PSEUDO_SALT:?set HP_PSEUDO_SALT in .env.local (the same value siem/pseudo.py uses)}"
: "${HP_SSH_PORT:?set HP_SSH_PORT in .env.local}"
case $HP_PSEUDO_SALT in *[!A-Za-z0-9_-]*) echo "HP_PSEUDO_SALT: use letters, digits, - and _ only" >&2; exit 2 ;; esac
case $HP_SSH_PORT in *[!0-9]*) echo "HP_SSH_PORT must be a number" >&2; exit 2 ;; esac

# Same rule as siem/pseudo.py: public src/dest IPv4 -> src-<8 hex of sha256(salt+ip)>, every other
# string column: any \d{1,3}(\.\d{1,3}){3} -> [ip].
ip_col() { echo "$1 = iff(isempty($1) or ipv4_is_private($1), $1, strcat('src-', substring(hash_sha256(strcat('$HP_PSEUDO_SALT', $1)), 0, 8)))"; }
scrub() {
    local out=() c
    for c in "$@"; do out+=("$c = replace_regex($c, @'\\d{1,3}(\\.\\d{1,3}){3}', '[ip]')"); done
    local IFS=,; echo "${out[*]}"
}

cowrie="Cowrie_CL
| extend $(ip_col src_ip)
| extend $(scrub eventid session protocol username password input url shasum outfile version hassh arch message sensor)"

suricata="Suricata_CL
| where coalesce(src_port, 0) != $HP_SSH_PORT and coalesce(dest_port, 0) != $HP_SSH_PORT
| extend $(ip_col src_ip), $(ip_col dest_ip)
| extend $(scrub proto app_proto signature category signature_severity cve mitre_tactic mitre_technique)"

save() {
    local name=$1 body=$2 verb=create
    az monitor log-analytics workspace saved-search show -g "$RG" --workspace-name "$WS" -n "$name" -o none 2>/dev/null \
        && verb=update
    az monitor log-analytics workspace saved-search "$verb" -g "$RG" --workspace-name "$WS" -n "$name" \
        --category "uig demo (pseudonymized)" --display-name "$name" --func-alias "$name" \
        --saved-query "$body" -o none
    echo "==> $name ($verb)"
}
save HP_Cowrie "$cowrie"
save HP_Suricata "$suricata"
echo "Try in Logs: HP_Cowrie | take 5   (functions can take a few minutes to appear)"
