#!/bin/sh
# Nightly logical backup of the application database (run by /etc/cron.d/pg-backup).
set -eu
DB=appdb
HOST=db-primary.internal
DEST=/srv/backup/postgres
STAMP=$(date +%F)
OUT="$DEST/${DB}_$STAMP.sql.gz"

pg_dump -h "$HOST" -U backup "$DB" | gzip -6 > "$OUT.part"
mv "$OUT.part" "$OUT"
echo "$(date -Is) ok $(basename "$OUT") $(stat -c %s "$OUT")"
