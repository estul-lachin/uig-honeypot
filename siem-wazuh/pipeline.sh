#!/usr/bin/env bash
# Make replayed honeypot events keep their own time. Wazuh stamps an alert with the time the manager saw
# it, and the alerts pipeline turns that into @timestamp and the daily index. For a replay that would put
# every event on the replay day, so this inserts one processor (tag hp-event-time) right after the JSON
# step: for alerts from location honeypot-*, `timestamp` becomes the event's own time (data.timestamp)
# (cut to milliseconds, Wazuh's own format: date_index_name refuses microseconds) and the replay time
# is kept in data.replayed_at. Idempotent; run by ./hp wazuh load.
set -euo pipefail
cd "$(dirname "$0")"
idx() { docker compose exec -T wazuh.indexer curl -sk -u admin:Lab-Wazuh-2026 "$@"; }
P=filebeat-7.10.2-wazuh-alerts-pipeline
idx "https://localhost:9200/_ingest/pipeline/$P" | python3 -c '
import json, sys
p = json.load(sys.stdin)["'"$P"'"]
procs = [x for x in p["processors"] if (list(x.values())[0] or {}).get("tag") != "hp-event-time"]
script = ("if (ctx.location != null && ctx.location.startsWith(\"honeypot-\") && ctx.data != null "
          "&& ctx.data.timestamp != null) { "
          "String t = ctx.data.timestamp; if (t.length() >= 24 && t.endsWith(\"Z\")) { "
          "ctx.data.replayed_at = ctx.timestamp; ctx.timestamp = t.substring(0, 23) + \"+0000\"; } }")
procs.insert(1, {"script": {"tag": "hp-event-time", "lang": "painless", "source": script}})
p["processors"] = procs
json.dump(p, sys.stdout)
' | idx -X PUT "https://localhost:9200/_ingest/pipeline/$P" -H 'Content-Type: application/json' --data-binary @- -o /dev/null -w '%{http_code}' \
  | grep -q 200 || { echo "error: could not update the ingest pipeline" >&2; exit 1; }
echo "==> Ingest pipeline: honeypot alerts keep their event time"
