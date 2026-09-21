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
# Why rename + create + nginx reload, NOT copytruncate:
#   - copytruncate copies the whole file every rotation (multi-GB here) and
#     drops any lines written between the copy and the truncate.
#   - libmodsecurity keeps the audit log fd open. A plain rename without a
#     reopen means ModSecurity keeps writing into the rotated file and the live
#     path goes silent -- the "audit log stale" failure the Discord alert
#     already detects (pueantaecloud/box-dedicate). nginx reload (HUP) rebuilds
#     the ModSecurity rule set, which reopens SecAuditLog at the new file.
#   - fail2ban's modsec-detect-alert jail follows the path and picks up the new
#     file after rotation on its own.
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

# Recreate the new file with the same owner/mode the current one has, since
# that's whatever this box's nginx/ModSecurity is known to write successfully.
if [ -f "$AUDIT_LOG" ]; then
  read -r MODE OWNER GROUP < <(stat -c '%a %U %G' "$AUDIT_LOG")
else
  MODE=640; OWNER=root; GROUP=adm
fi

cat > "$CONF" <<EOF_R
# Managed by install-audit-retention.sh -- edit that script and re-run it.
# Keeps ${DAYS} rotated days; also rotates early past ${MAXSIZE} (checked at
# the daily logrotate run).
${AUDIT_LOG} {
    daily
    maxsize ${MAXSIZE}
    rotate ${DAYS}
    maxage ${DAYS}
    missingok
    notifempty
    compress
    # Rotated file stays plain for one cycle: any line ModSecurity writes
    # between the rename and the reload lands there, not in a gzip.
    delaycompress
    dateext
    dateformat -%Y%m%d-%s
    create ${MODE} ${OWNER} ${GROUP}
    su root root
    sharedscripts
    postrotate
        # Reload so ModSecurity reopens SecAuditLog. If the nginx config is
        # currently broken, reload would be refused anyway -- log it loudly
        # instead; the Discord alert will then show "AUDIT LOG STALE".
        if nginx -t -q >/dev/null 2>&1; then
            systemctl reload nginx >/dev/null 2>&1 || { [ -s /run/nginx.pid ] && kill -HUP "\$(cat /run/nginx.pid)"; } || true
        else
            logger -t modsec-audit-retention "nginx -t failed: nginx NOT reloaded after rotating ${AUDIT_LOG}; ModSecurity still writing to rotated file"
        fi
    endscript
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
  echo "Check the live file is growing again (send any request that ModSecurity logs):"
  echo "  ls -l $AUDIT_LOG ; sleep 30 ; ls -l $AUDIT_LOG"
fi

echo "installed: $CONF (keep ${DAYS} days, early rotate > ${MAXSIZE}, create ${MODE} ${OWNER} ${GROUP})"
echo "RETENTION_OK $(hostname)"
