#!/usr/bin/env python3
"""Writes /var/backups/masterdb/status.json, the summary the MasterDB app will read.

Installed as /usr/local/sbin/masterdb-backup-status. Called by masterdb-backup and
masterdb-restore-test after every run; each call updates its own part and keeps the
other part from the previous file. Never contains secrets.

    masterdb-backup-status backup STARTED_AT FINISHED_AT OK FILE SIZE_BYTES DURATION_MS ERROR KEEP
    masterdb-backup-status restore-test AT OK DETAIL
    masterdb-backup-status refresh        # only re-reads the dump list and the schedule

Times are ISO-8601 UTC ("2026-11-06T17:32:45Z"); OK is "true" or "false"; empty
FILE / SIZE_BYTES / ERROR become null. The file is written atomically (temp file
in the same folder, then rename), mode 644.
"""
import fcntl
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

BACKUP_DIR = "/var/backups/masterdb"
STATUS = os.path.join(BACKUP_DIR, "status.json")
LOCK = "/run/lock/masterdb-backup-status.lock"
TIMERS = {"backup": "masterdb-backup.timer", "restoreTest": "masterdb-restore-test.timer"}
DEFAULT_KEEP = 14


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def on_calendar(timer):
    """Effective OnCalendar values, drop-ins included (an empty OnCalendar= resets)."""
    try:
        out = subprocess.run(["systemctl", "cat", timer], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return []
    values = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("OnCalendar="):
            value = line.split("=", 1)[1].strip()
            values = values + [value] if value else []
    return values


def dumps():
    items = []
    for name in os.listdir(BACKUP_DIR):
        if name.startswith("masterdb-") and name.endswith(".dump"):
            st = os.stat(os.path.join(BACKUP_DIR, name))
            items.append({"file": name, "sizeBytes": st.st_size, "createdAt": iso(st.st_mtime)})
    return sorted(items, key=lambda d: d["file"], reverse=True)


def opt(value, cast=str):
    return cast(value) if value != "" else None


def main(argv):
    if not argv or argv[0] not in ("backup", "restore-test", "refresh"):
        sys.exit(__doc__)
    os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
    with open(LOCK, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            with open(STATUS) as f:
                status = json.load(f)
        except (OSError, ValueError):
            status = {}

        kind = argv[0]
        if kind == "backup":
            started, finished, ok, file, size, duration, error, keep = argv[1:9]
            status["lastBackup"] = {
                "startedAt": started, "finishedAt": finished, "ok": ok == "true",
                "file": opt(file), "sizeBytes": opt(size, int), "durationMs": int(duration),
                "error": opt(error),
            }
            status["retentionDays"] = int(keep)
        elif kind == "restore-test":
            at, ok, detail = argv[1:4]
            status["lastRestoreTest"] = {"at": at, "ok": ok == "true", "detail": detail}

        status.setdefault("lastBackup", None)
        status.setdefault("lastRestoreTest", None)
        status.setdefault("retentionDays", DEFAULT_KEEP)
        status["schedule"] = {key: on_calendar(timer) for key, timer in TIMERS.items()}
        status["backups"] = dumps()
        status["updatedAt"] = iso(datetime.now(timezone.utc).timestamp())

        fd, tmp = tempfile.mkstemp(prefix=".status-", suffix=".tmp", dir=BACKUP_DIR)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(status, f, indent=2)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o644)
            os.replace(tmp, STATUS)
        except BaseException:
            os.unlink(tmp)
            raise


if __name__ == "__main__":
    main(sys.argv[1:])
