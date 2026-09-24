#!/usr/bin/env bash
# Install OR repatch data retention (logrotate) for /var/log/modsec_audit.log
# on THIS box. Separate from install-alerting.sh on purpose: retention can be
# rolled out / tuned without touching the alerting pipeline. Same rules as
# that script: self-contained, run on the box as root, `cat >` full overwrite
# so re-running is a safe repatch.
#
# Usage (on the box, as root):
#   ./install-audit-retention.sh [retention_days] [max_size] [--now]
#     retention_days  rotated files kept (1 per day), default 14
#     max_size        also rotate early once the live file passes this at the
#                     daily logrotate run, default 1G (logrotate size syntax)
#     --now           rotate immediately after install (use on boxes where the
#                     audit log is already multi-GB)
#
# Why copytruncate, NOT rename + create + nginx reload:
#   - libmodsecurity v3 NEVER reopens the audit log on nginx reload. Its
#     SharedFiles keeps open FILE* handles keyed by file NAME and reuses them
#     when the reloaded config names the same path; the fclose in its close
#     path is commented out (src/utils/shared_files.cc, 3.0.12). Verified on
#     3.0.16: after a rename, neither `nginx -s reload` (HUP) nor
#     `nginx -s reopen` (USR1) moves writes to the new file -- only a full
#     restart does. The previous rename+reload version of this script left
#     the live file at 0 bytes after the first rotation (OneBox-Proxy01-UAT,
#     2026-09-24 00:00) while ModSecurity kept writing the rotated file, so
#     every Discord alert showed "(unknown)" details.
#   - copytruncate keeps the same inode. ModSecurity opens the file with
#     fopen("a") (O_APPEND), so after the truncate its next write lands at
#     the new end of file: no restart, no NUL-filled sparse gap (verified).
#   - fail2ban's modsec-detect-alert jail (logpath ... tail) keeps following
#     the file across a copytruncate -- verified with backend polling and
#     auto/pyinotify: a DETECT hit after rotation still fires.
#   - Cost: the whole live file is copied once per rotation (needs that much
#     free disk for a moment), and lines ModSecurity writes between the copy
#     and the truncate are lost -- a window of the copy duration, once a day.
#     A smaller max_size keeps both small.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root (sudo ./install-audit-retention.sh [days] [max_size] [--now])" >&2
  exit 1
fi

ROTATE_NOW=0
ARGS=()
for a in "$@"; do
  if [ "$a" = "--now" ]; then ROTATE_NOW=1; else ARGS+=("$a"); fi
done
DAYS="${ARGS[0]:-14}"
MAXSIZE="${ARGS[1]:-1G}"
[[ "$DAYS" =~ ^[0-9]+$ ]] && [ "$DAYS" -ge 1 ] || { echo "retention_days must be a positive integer, got '$DAYS'" >&2; exit 1; }
[[ "$MAXSIZE" =~ ^[0-9]+[kMG]?$ ]] || { echo "max_size must look like 500M / 1G, got '$MAXSIZE'" >&2; exit 1; }

AUDIT_LOG="/var/log/modsec_audit.log"
CONF="/etc/logrotate.d/modsec-audit"

command -v logrotate >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y logrotate; }

if [ ! -f "$AUDIT_LOG" ]; then
  echo "WARN: $AUDIT_LOG does not exist yet -- config installed anyway (missingok)." >&2
fi

# SecAuditLogType Concurrent writes one file per transaction under
# SecAuditLogStorageDir, which this config does not cover.
if grep -rqsE '^\s*SecAuditLogType\s+Concurrent' /etc/nginx /etc/modsecurity 2>/dev/null; then
  echo "WARN: SecAuditLogType Concurrent found -- per-transaction files in SecAuditLogStorageDir are NOT rotated by this script." >&2
fi

# Two logrotate stanzas for the same path make logrotate error out on EVERY
# run (all logs, not just this one), so refuse rather than install a duplicate.
DUP=$(grep -lsF "$AUDIT_LOG" /etc/logrotate.conf /etc/logrotate.d/* 2>/dev/null | grep -vxF "$CONF" || true)
if [ -n "$DUP" ]; then
  echo "ERROR: $AUDIT_LOG is already covered by: $DUP -- remove that stanza first." >&2
  exit 1
fi

# A box rotated by the old rename+reload version still has ModSecurity
# writing a renamed file (live path empty). copytruncate can't fix that --
# only moving the file ModSecurity writes back onto the live path, or a
# restart, can. Detect it and say so instead of rotating an empty file.
WRITTEN=""
if [ -d /proc ]; then
  for p in $(pgrep -f 'nginx: (master|worker)' 2>/dev/null); do
    for fd in /proc/"$p"/fd/*; do
      t=$(readlink "$fd" 2>/dev/null) || continue
      case "$t" in "$AUDIT_LOG"*) WRITTEN+="$t"$'\n' ;; esac
    done
  done
fi
WRITTEN=$(printf '%s' "$WRITTEN" | sort -u | sed '/^$/d')
if [ -n "$WRITTEN" ] && ! printf '%s\n' "$WRITTEN" | grep -qxF "$AUDIT_LOG"; then
  echo "WARN: nginx/ModSecurity is NOT writing $AUDIT_LOG, it is writing:" >&2
  printf '  %s\n' $WRITTEN >&2
  echo "  (left over from the old rename+reload rotation). Fix, no restart needed:" >&2
  echo "    mv -f '$(printf '%s' "$WRITTEN" | head -1 | sed 's/ (deleted)$//')' $AUDIT_LOG" >&2
  echo "  then re-run this script. (If it says '(deleted)': systemctl restart nginx.)" >&2
fi

cat > "$CONF" <<EOF_R
# Managed by install-audit-retention.sh -- edit that script and re-run it.
# Keeps ${DAYS} rotated days; also rotates early past ${MAXSIZE} (checked at
# the daily logrotate run). copytruncate: libmodsecurity never reopens the
# audit log on nginx reload -- see the script header before changing this.
${AUDIT_LOG} {
    daily
    maxsize ${MAXSIZE}
    rotate ${DAYS}
    maxage ${DAYS}
    missingok
    notifempty
    compress
    delaycompress
    dateext
    dateformat -%Y%m%d-%s
    copytruncate
    su root root
}
EOF_R
chmod 644 "$CONF"

echo "--- logrotate dry run ---"
logrotate -d "$CONF" 2>&1 | tail -20

if [ "$ROTATE_NOW" -eq 1 ]; then
  echo "--- rotating now ---"
  logrotate -f -v "$CONF"
  sleep 2
  ls -lh "${AUDIT_LOG}"* 2>/dev/null
  echo "Check the live file keeps growing (send any request that ModSecurity logs):"
  echo "  ls -l $AUDIT_LOG ; sleep 30 ; ls -l $AUDIT_LOG"
fi

echo "installed: $CONF (keep ${DAYS} days, early rotate > ${MAXSIZE}, copytruncate)"
echo "RETENTION_OK $(hostname)"
