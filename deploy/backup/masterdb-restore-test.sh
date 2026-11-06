#!/usr/bin/env bash
# Proves that the newest MasterDB backup can actually be restored.
#
# Installed on the VPS as /usr/local/sbin/masterdb-restore-test and run weekly
# by masterdb-restore-test.timer (Sunday ~04:00). Run it by hand with:
#     masterdb-restore-test
#
# It never touches the live database except for one read-only count query.
#   1. Takes the newest /var/backups/masterdb/masterdb-*.dump (fails if it is
#      older than MAX_AGE_HOURS: a restore test of a stale backup proves little).
#   2. Starts a throwaway postgres:16-alpine container: random name, random
#      password that only exists inside this script, no network, no ports, --rm.
#   3. pg_restore's the dump into it (single transaction, stops on first error).
#   4. Checks flyway_schema_history exists and has as many rows as the live DB.
#   5. Always removes the container (trap), then prints PASS or FAIL and
#      records the result in status.json via masterdb-backup-status.

set -euo pipefail
umask 077

BACKUP_DIR=/var/backups/masterdb
LIVE_CONTAINER=masterdb-postgres
LIVE_DB=masterdb
LIVE_USER=masterdb
IMAGE=postgres:16-alpine
MAX_AGE_HOURS=48
SCRATCH_DB=restoretest
STATUS_HELPER=/usr/local/sbin/masterdb-backup-status

name="masterdb-restoretest-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
started=no
reason="unexpected error (see the messages above)"
t0="$(date +%s)"
at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

log() { echo "masterdb-restore-test: $*"; }
fail() { reason="$*"; exit 1; }

finish() {
  rc=$?
  if [ "$started" = yes ]; then
    docker rm -f "$name" >/dev/null 2>&1 || true
    log "throwaway container $name removed"
  fi
  if [ "$rc" -eq 0 ]; then
    ok=true
    detail="PASS: $(basename "${dump:-?}") restored, flyway_schema_history rows ${restored_rows:-?} = live ${live_rows:-?}, ${restored_tables:-?} tables, $(( $(date +%s) - t0 ))s"
  else
    ok=false
    detail="FAIL: $reason"
  fi
  echo "$detail"
  if [ "$(id -u)" -eq 0 ]; then
    "$STATUS_HELPER" restore-test "$at" "$ok" "$detail" \
      || echo "masterdb-restore-test: WARNING: could not update $BACKUP_DIR/status.json" >&2
  fi
  exit "$rc"
}
trap finish EXIT
trap 'reason="interrupted"; exit 130' INT
trap 'reason="terminated"; exit 143' TERM

[ "$(id -u)" -eq 0 ] || fail "run as root"

dump="$(find "$BACKUP_DIR" -maxdepth 1 -name 'masterdb-*.dump' 2>/dev/null | sort | tail -n 1 || true)"
[ -n "$dump" ] || fail "no dump found in $BACKUP_DIR"
age_h=$(( ( $(date +%s) - $(stat -c %Y "$dump") ) / 3600 ))
log "newest dump: $(basename "$dump"), $(du -h "$dump" | cut -f1), ${age_h}h old"
[ "$age_h" -le "$MAX_AGE_HOURS" ] || fail "newest dump is ${age_h}h old (limit ${MAX_AGE_HOURS}h): nightly backups have stopped"

# The password is generated here, handed to docker through the environment
# (not the command line, so `ps` never shows it) and never printed. Nothing can
# reach the container anyway: --network none, no published ports.
POSTGRES_PASSWORD="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
export POSTGRES_PASSWORD

log "starting throwaway container $name"
started=yes
docker run -d --rm --name "$name" \
  --network none \
  --memory 1g --cpu-shares 256 \
  -e POSTGRES_PASSWORD -e POSTGRES_DB="$SCRATCH_DB" \
  "$IMAGE" >/dev/null
unset POSTGRES_PASSWORD

# Wait for the real server. The image first runs a temporary init server on the
# Unix socket only, so ask on TCP 127.0.0.1 (inside the container's own
# loopback), which only answers once the final server is up.
ready=no
for _ in $(seq 1 60); do
  if docker exec "$name" pg_isready -q -h 127.0.0.1 -U postgres -d "$SCRATCH_DB" 2>/dev/null; then
    ready=yes; break
  fi
  sleep 1
done
[ "$ready" = yes ] || fail "throwaway Postgres did not start within 60s"

log "restoring into the throwaway container"
# --no-owner/--no-privileges: the masterdb role does not exist in the scratch
# server. --single-transaction + --exit-on-error: any error fails the test.
docker exec -i "$name" pg_restore -h 127.0.0.1 -U postgres -d "$SCRATCH_DB" \
    --no-owner --no-privileges --single-transaction --exit-on-error < "$dump" \
  || fail "pg_restore reported errors"

q() { docker exec "$name" psql -h 127.0.0.1 -U postgres -d "$SCRATCH_DB" -XAtqc "$1"; }

[ "$(q "select to_regclass('public.flyway_schema_history') is not null")" = t ] \
  || fail "flyway_schema_history is missing from the restored database"
restored_rows="$(q 'select count(*) from public.flyway_schema_history')"
restored_tables="$(q "select count(*) from information_schema.tables where table_schema = 'public'")"

# Read-only query against the live database.
live_rows="$(docker exec -e PGOPTIONS='-c default_transaction_read_only=on' "$LIVE_CONTAINER" \
  psql -U "$LIVE_USER" -d "$LIVE_DB" -XAtqc 'select count(*) from public.flyway_schema_history')" \
  || fail "could not read the row count from the live database"

[ "$restored_rows" = "$live_rows" ] \
  || fail "flyway_schema_history has $restored_rows rows in the backup but $live_rows live (a migration deployed after the dump would explain it; run masterdb-backup and retest)"
