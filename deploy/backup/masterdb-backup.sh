#!/usr/bin/env bash
# Nightly backup of the MasterDB Postgres database.
#
# Installed on the VPS as /usr/local/sbin/masterdb-backup and run by
# masterdb-backup.timer (daily ~03:15). Run it by hand with:
#     systemctl start masterdb-backup && journalctl -u masterdb-backup -n 20 --no-pager
#
# What it does:
#   1. pg_dump inside the running masterdb-postgres container (custom format,
#      compressed) into a temporary file in /var/backups/masterdb.
#   2. Checks pg_dump's exit status and that the file is readable by pg_restore.
#   3. Only then renames it to masterdb-YYYYmmdd-HHMMSS.dump.
#   4. Only then deletes dumps beyond the newest $KEEP. A failing night never
#      deletes anything, so the good dumps survive a broken backup.
# Any failure exits non-zero, which systemd shows as "failed".
# After every run (ok or not) it updates status.json via masterdb-backup-status.

set -euo pipefail
umask 077   # dumps are 600, the directory 700: root only.

BACKUP_DIR=/var/backups/masterdb
CONTAINER=masterdb-postgres
DB_NAME=masterdb
DB_USER=masterdb
KEEP=14
LOCK=/run/lock/masterdb-backup.lock
STATUS_HELPER=/usr/local/sbin/masterdb-backup-status

log() { echo "masterdb-backup: $*"; }
die() { error="$*"; echo "masterdb-backup: ERROR: $*" >&2; exit 1; }
utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }

record=no; error=""; tmp=""; final=""
finish() {
  rc=$?
  [ -n "$tmp" ] && rm -f "$tmp"
  if [ "$record" = yes ]; then
    ok=false; file=""; size=""
    if [ "$rc" -eq 0 ]; then
      ok=true; file="$(basename "$final")"; size="$(stat -c %s "$final")"
    else
      [ -n "$error" ] || error="unexpected error (exit $rc), see journalctl -u masterdb-backup"
    fi
    "$STATUS_HELPER" backup "$started_at" "$(utc)" "$ok" "$file" "$size" \
        "$(( $(date +%s%3N) - start_ms ))" "$error" "$KEEP" \
      || echo "masterdb-backup: WARNING: could not update $BACKUP_DIR/status.json" >&2
  fi
  exit "$rc"
}
trap finish EXIT

[ "$(id -u)" -eq 0 ] || die "run as root"

# One run at a time (a manual run while the timer fires, for example).
# A run that finds another one busy leaves status.json to that one.
exec 9>"$LOCK"
flock -n 9 || die "another backup is still running"
record=yes
started_at="$(utc)"
start_ms="$(date +%s%3N)"

docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -qx true \
  || die "container $CONTAINER is not running"

install -d -m 700 -o root -g root "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# Leftovers of a run that was killed hard (power loss, kill -9).
find "$BACKUP_DIR" -maxdepth 1 -name '.masterdb-*.partial' -mmin +60 -delete

# Disk guard: the dumps share the disk with the database itself. If a dump
# filled the disk, Postgres would stop. Ask for twice the last dump + 1 GB.
last="$(find "$BACKUP_DIR" -maxdepth 1 -name 'masterdb-*.dump' | sort | tail -n 1)"
last_bytes=0
[ -n "$last" ] && last_bytes="$(stat -c %s "$last")"
need_kb=$(( last_bytes * 2 / 1024 + 1024 * 1024 ))
free_kb="$(df -Pk "$BACKUP_DIR" | awk 'NR==2 {print $4}')"
[ "$free_kb" -gt "$need_kb" ] \
  || die "not enough free disk: $((free_kb / 1024)) MB free, want $((need_kb / 1024)) MB"

stamp="$(date +%Y%m%d-%H%M%S)"
final="$BACKUP_DIR/masterdb-$stamp.dump"
tmp="$BACKUP_DIR/.masterdb-$stamp.dump.partial"

log "dumping $DB_NAME from $CONTAINER to $final"

# No pipe: the output goes straight to the file, so the exit status we test is
# pg_dump's own (docker exec passes it through). nice runs inside the
# container, where pg_dump does the compressing; the unit's Nice=/IOScheduling
# apply to the docker client, which writes the file on the host.
if ! docker exec "$CONTAINER" nice -n 10 pg_dump -U "$DB_USER" -d "$DB_NAME" -Fc > "$tmp"; then
  die "pg_dump failed; previous dumps left untouched"
fi
[ -s "$tmp" ] || die "pg_dump wrote an empty file; previous dumps left untouched"

# Prove the file is a complete, readable archive before keeping it.
if ! entries="$(docker exec -i "$CONTAINER" pg_restore --list < "$tmp" | grep -vc '^;')"; then
  die "pg_restore --list could not read the dump; previous dumps left untouched"
fi

chmod 600 "$tmp"
mv "$tmp" "$final"
tmp=""
sync -f "$final" 2>/dev/null || sync

duration=$(( ($(date +%s%3N) - start_ms) / 1000 ))
size="$(du -h "$final" | cut -f1)"
log "OK: $(basename "$final"), $size, $entries archive entries, ${duration}s"

# Retention: only reached when today's dump is safely on disk.
mapfile -t dumps < <(find "$BACKUP_DIR" -maxdepth 1 -name 'masterdb-*.dump' | sort -r)
if [ "${#dumps[@]}" -gt "$KEEP" ]; then
  for old in "${dumps[@]:$KEEP}"; do
    rm -f -- "$old"
    log "deleted old dump $(basename "$old")"
  done
fi
kept="$(find "$BACKUP_DIR" -maxdepth 1 -name 'masterdb-*.dump' | wc -l)"
log "kept $kept dump(s) (limit $KEEP), $(du -sh "$BACKUP_DIR" | cut -f1) in $BACKUP_DIR"
