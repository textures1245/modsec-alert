#!/usr/bin/env bash
# Install OR repatch the fail2ban -> Discord ModSec alerting on THIS box.
# Self-contained: no SSH, no remote execution. Copy this one file to the
# target host (scp/rsync/paste) and run it there directly as root.
#
# This is the ONLY script -- there is no separate modsec-discord-alert.sh to
# keep in sync. It's written inline below (search EOF_E) and every artifact
# this script writes uses `cat > path` (full overwrite, not append), so
# re-running this exact same command on an already-installed box is a safe
# repatch: it pushes whatever version of this file you're holding, then
# restarts fail2ban to pick it up. No separate "patch" script, no manual
# heredoc-syncing between two files -- edit this file, re-run it, done.
#
# Usage (on the box, as root -- same command for first install and repatch):
#   ./install-alerting.sh '<discord_webhook_url>' '<public_ip>'
#
# Prereqs before running this against a real box:
#   1. Discord webhook created in the dedicated #modsec-alerts channel (t_1785815110)
#   2. Public IP for this box (from the fleet inventory sheet) -- these VMs are
#      NAT'd, `hostname -I` only ever returns the internal IP, so this can't
#      be auto-detected on-box and must be supplied.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root (sudo ./install-alerting.sh '<webhook_url>' '<public_ip>')" >&2
  exit 1
fi

WEBHOOK="${1:?usage: ./install-alerting.sh <discord_webhook_url> <public_ip>}"
PUBLIC_IP="${2:?usage: ./install-alerting.sh <discord_webhook_url> <public_ip>}"

echo "$PUBLIC_IP" > /etc/modsec-alert-public-ip
chmod 644 /etc/modsec-alert-public-ip

command -v fail2ban-client >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y fail2ban; }

cat > /etc/fail2ban/filter.d/modsec-block.conf <<'EOF_A'
# Matches confirmed real sample (t_1783925596, ssddedicated incident):
# ...[error] 3934726#3934726: *22968489 [client 172.16.1.254] ModSecurity: Access denied with code 403 (phase 2). Matched ...
[Definition]
failregex = \[client <HOST>\] ModSecurity: Access denied with code 403 \(phase \d+\)\.
ignoreregex =
EOF_A

cat > /etc/fail2ban/filter.d/modsec-detect.conf <<'EOF_B'
# Detects the CRS "Inbound Anomaly Score Exceeded" summary rule (id 949110)
# logged as Warning -- this is the DetectionOnly-mode equivalent of the
# block line in modsec-block.conf: a single per-request summary line, not
# one of the many individual contributing-rule warnings, so it stays as
# low-volume as the block alert instead of repeating the noise that got the
# old modsec-warning-spike jail (rate-counted over EVERY Warning line)
# removed. In blocking mode this same rule instead produces "Access denied"
# (matched by modsec-block.conf), never "Warning", so this filter does not
# double-fire alongside the block jail.
#
# UNVERIFIED against a live DetectionOnly box -- no confirmed real sample
# yet (unlike modsec-block.conf's t_1783925596 sample). Validate the exact
# line shape with `fail2ban-regex` against a real error.log entry before
# relying on this in production; CRS's msg text can drift across versions,
# hence anchoring on the rule id token rather than message wording.
[Definition]
failregex = \[client <HOST>\] ModSecurity: Warning\. .*\[id "949110"\]
ignoreregex =
EOF_B

# Repatch cleanup: the modsec-warning-spike jail/filter (rate counter on
# ModSecurity Warning-level lines) was removed -- too noisy, no per-request
# detail, mostly just echoed the same filename-FP noise the block alerts
# already cover. Delete any leftover filter file from a prior install.
rm -f /etc/fail2ban/filter.d/modsec-warning-spike.conf

cat > /etc/fail2ban/action.d/discord-alert.conf <<'EOF_C'
# Deliberately does NOT interpolate <matches> (raw, attacker-influenced log
# text) into the shell command -- only fail2ban-validated/local fields (<ip> is
# regex-constrained to IP-address characters by fail2ban itself, jail name and
# hostname are local config, not request-derived). Avoids shell-injection via
# crafted ModSecurity payloads ending up in the audit log.
[Definition]
actionstart =
actionstop =
actioncheck =
actionban  = /usr/local/bin/modsec-discord-alert.sh '%(discord_webhook)s' '<level>' '<ip>' '%(name)s'
actionunban =

[Init]
level = BLOCK
discord_webhook = REPLACE_ME_AT_INSTALL_TIME
EOF_C

cat > /usr/local/bin/modsec-discord-alert.sh <<'EOF_E'
#!/usr/bin/env bash
# Called by fail2ban's action.d/discord-alert.conf with 4 fail2ban-controlled
# args: webhook url, level literal, <HOST>-matched ip, jail name. Never raw
# log content from fail2ban itself.
#
# For BLOCK alerts, this script does its OWN safe lookup into modsec_audit.log
# by unique_id (validated numeric.numeric before reuse, extracted via -oP, not
# via fail2ban <matches> substitution -- the real "Access denied" line already
# contains literal backticks/single-quotes as part of ModSecurity's own fixed
# message format, which would break naive shell interpolation regardless of
# attacker input). Every value pulled from the log -- including genuinely
# attacker-controlled "Matched Data" snippets -- only ever flows into
# `python3 json.dumps`, never back into a shell command.
#
# Every invocation logs its outcome (Discord's HTTP status + response) to
# LOGFILE -- check this first when "no alert showed up".
set -uo pipefail
WEBHOOK="$1"; LEVEL="$2"; SRC_IP="$3"; JAIL="$4"
HOST="$(hostname)"
LOGFILE="/var/log/modsec-discord-alert.log"
AUDIT_LOG="/var/log/modsec_audit.log"
PUBLIC_IP_FILE="/etc/modsec-alert-public-ip"
# If the audit-log entry we found is older than this, the file has likely
# stopped being appended to (rotation without reopen, wrong SecAuditLog path,
# etc) -- confirmed failure mode on pueantaecloud/box-dedicate before. Flag it
# instead of silently reposting stale detail as if it were the current ban.
STALE_THRESHOLD_SECS=300
PUBLIC_IP="unknown"
[ -r "$PUBLIC_IP_FILE" ] && PUBLIC_IP="$(cat "$PUBLIC_IP_FILE")"

# Discord renders ANSI SGR codes inside ```ansi fenced code blocks.
RED=$'\e[1;31m'; GRN=$'\e[1;32m'; YEL=$'\e[1;33m'; CYN=$'\e[1;36m'; GRY=$'\e[2;37m'; RST=$'\e[0m'

# DETECT (SecRuleEngine DetectionOnly, filter.d/modsec-detect.conf) gets its
# own color/icon/title so it reads as distinct from a real BLOCK in Discord
# -- this would have been denied, but wasn't.
if [ "$LEVEL" = "DETECT" ]; then
  ALERT_COLOR="$YEL"; ALERT_ICON="🔍"; ALERT_TITLE="ModSec DETECT-ONLY Alert (would have blocked)"
else
  ALERT_COLOR="$RED"; ALERT_ICON="🛡️"; ALERT_TITLE="ModSec BLOCK Alert"
fi

# Full-file grep/awk against this audit log (unrotated, multi-GB and growing)
# was taking 40-60s+ under load and getting killed by fail2ban's action
# timeout before ever reaching the curl call below -- confirmed 2026-08-17 on
# a 4GB file, a single `grep -c` alone took ~3.75s. The transaction we care
# about is always the one just appended, so slice a generous recent window
# once and search that instead of scanning the full file on every lookup.
TAIL_LOG="$(mktemp)"
trap 'rm -f "$TAIL_LOG"' EXIT
tail -c 20000000 "$AUDIT_LOG" > "$TAIL_LOG" 2>/dev/null

# BLOCK looks for the actual "Access denied" line; DETECT (SecRuleEngine
# DetectionOnly) never produces that line -- the same 949110 anomaly-score
# rule instead logs as a Warning (see filter.d/modsec-detect.conf). Keeping
# these as two distinct greps (rather than one pattern covering both) means
# a BLOCK invocation can never accidentally pick up a DETECT-only line or
# vice versa.
if [ "$LEVEL" = "DETECT" ]; then
  LAST_EVENT=$(grep "ModSecurity: Warning" "$TAIL_LOG" 2>/dev/null | grep -F '[id "949110"]' | tail -1)
else
  LAST_EVENT=$(grep "ModSecurity: Access denied with code 403" "$TAIL_LOG" 2>/dev/null | tail -1)
fi
  UID_RAW=$(printf '%s' "$LAST_EVENT" | grep -oP '(?<=\[unique_id ")[^"]+' | head -1)
  UID_SAFE=""
  if [[ "$UID_RAW" =~ ^[0-9]+\.[0-9]+$ ]]; then
    UID_SAFE="$UID_RAW"
  fi

  SCORE=$(printf '%s' "$LAST_EVENT" | grep -oP "(?<=Value: \`)[0-9]+" | head -1)
  [ -z "$SCORE" ] && SCORE="?"
  API_URI=$(printf '%s' "$LAST_EVENT" | grep -oP '(?<=\[uri ")[^"]+' | head -1)
  [ -z "$API_URI" ] && API_URI="(unknown)"

  TS="(unknown)"
  RULES_TEXT=""
  REQ_LINE=""
  BODY_RAW=""
  if [ -n "$UID_SAFE" ]; then
    # -B1 grabs the "---TAG---A--" marker line together with the Section A
    # content line in one pass, so TAG is available for free alongside TS.
    AB_PAIR=$(grep -B1 -F -- " ${UID_SAFE} " "$TAIL_LOG" 2>/dev/null | tail -2)
    TAG=$(printf '%s\n' "$AB_PAIR" | head -1 | grep -oP '(?<=^---)[A-Za-z0-9]+(?=---A--$)')
    SECTION_A=$(printf '%s\n' "$AB_PAIR" | tail -1)
    TS_EXTRACT=$(printf '%s' "$SECTION_A" | grep -oP '(?<=^\[)[^\]]+')
    [ -n "$TS_EXTRACT" ] && TS="$TS_EXTRACT"

    STALE=0
    AGE=""
    if [ -n "$TS_EXTRACT" ]; then
      BLOCK_EPOCH=$(python3 -c "
import datetime, sys
try:
    print(int(datetime.datetime.strptime(sys.argv[1], '%d/%b/%Y:%H:%M:%S %z').timestamp()))
except Exception:
    pass
" "$TS_EXTRACT" 2>/dev/null)
      if [ -n "$BLOCK_EPOCH" ]; then
        AGE=$(( $(date +%s) - BLOCK_EPOCH ))
        [ "$AGE" -gt "$STALE_THRESHOLD_SECS" ] && STALE=1
      fi
    fi

    if [ -n "$TAG" ]; then
      # Single pass pulls both Section B (full request line incl. query
      # string) and Section I (compact request body, when SecAuditLogParts
      # includes I -- confirmed present in this fleet's modsecurity.conf).
      AWK_OUT=$(awk -v tag="$TAG" '
        $0 == "---" tag "---B--" { sec="B"; next }
        $0 == "---" tag "---I--" { sec="I"; next }
        /^---/ { sec=""; next }
        sec=="B" && !gotreq && NF { print "REQ:" $0; gotreq=1; next }
        sec=="I" { print "BODY:" $0 }
      ' "$TAIL_LOG" 2>/dev/null)
      REQ_LINE=$(printf '%s\n' "$AWK_OUT" | grep '^REQ:' | sed 's/^REQ://' | head -c 300)
      BODY_RAW=$(printf '%s\n' "$AWK_OUT" | grep '^BODY:' | sed 's/^BODY://' | tr '\n' ' ' | head -c 200)
    fi

    DIV="────────────────────────────────────"
    RULE_NUM=0
    # Excludes id 949110 itself: in DETECT mode that's the summary line
    # LAST_EVENT already came from (would otherwise show up twice -- once as
    # the alert header, once again as "rule 1" in this per-rule breakdown).
    # In BLOCK mode this exclusion is a no-op: 949110 there logs as "Access
    # denied", never "Warning", so it was never in this grep's output anyway.
    WARNINGS=$(grep -F -- "unique_id \"${UID_SAFE}\"" "$TAIL_LOG" 2>/dev/null | grep "ModSecurity: Warning" | grep -v -F '[id "949110"]')
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      RID=$(printf '%s' "$line" | grep -oP '(?<=\[id ")[0-9]+' | head -1)
      RMSG=$(printf '%s' "$line" | grep -oP '(?<=\[msg ")[^"]+' | head -1)
      # Prefer "found within FIELD: VALUE" (the actual payload+field, most
      # useful for triage) over the short pre-match fragment; fall back to
      # the short fragment for rules whose [data] doesn't use that phrasing.
      RDATA=$(printf '%s' "$line" | grep -oP '(?<=found within ).*?(?="\])' | head -1)
      if [ -z "$RDATA" ]; then
        RDATA=$(printf '%s' "$line" | grep -oP '(?<=Matched Data: ).*?(?="\])' | head -1)
      fi
      RDATA="${RDATA:0:150}"
      [ -z "$RID" ] && continue
      [ -z "$RMSG" ] && RMSG="(no msg)"
      RULE_NUM=$((RULE_NUM + 1))
      [ "$RULE_NUM" -gt 1 ] && RULES_TEXT+="${GRY}${DIV}${RST}"$'\n'
      RULES_TEXT+=$(printf '%d) [%s%s%s] %s' "$RULE_NUM" "$YEL" "$RID" "$RST" "$RMSG")
      RULES_TEXT+=$'\n'
      if [ -n "$RDATA" ]; then
        RULES_TEXT+=$(printf '   \xe2\x94\x94\xe2\x94\x80 %s%s%s' "$RED" "$RDATA" "$RST")
        RULES_TEXT+=$'\n'
      fi
    done <<< "$WARNINGS"
  fi
[ -z "$RULES_TEXT" ] && RULES_TEXT="(no rule detail found -- check unique_id lookup)"
  DIV_EQ="════════════════════════════════════"
  DIV_DA="────────────────────────────────────"
  INTERNAL_IP=$(printf '%s' "$LAST_EVENT" | grep -oP '(?<=\[hostname ")[^"]+' | head -1)

  # Full request line (method+path+query) when found; fall back to the
  # path-only [uri] field from the block line if Section B lookup failed.
  REQ_DISPLAY="${REQ_LINE:-$API_URI}"
  BODY_LINE=""
  # $(...) strips trailing newlines, so append \n outside the substitution.
  [ -n "$BODY_RAW" ] && BODY_LINE="$(printf '📦 %sRequest Body%s : %s%s%s' "$CYN" "$RST" "$YEL" "$BODY_RAW" "$RST")"$'\n'

  STALE_BANNER=""
  if [ "${STALE:-0}" -eq 1 ]; then
    STALE_BANNER="$(printf '%s⚠️  AUDIT LOG STALE (entry is %ss old)%s' "$RED" "$AGE" "$RST")"$'\n'
    STALE_BANNER+="$(printf '%sThis alert on src=%s is real (matched live nginx error.log) -- but the detail below is the LAST entry modsec_audit.log ever wrote, not this event. modsec_audit.log has likely stopped appending. Check SecAuditEngine/SecAuditLog path + logrotate reopen signal.%s' "$YEL" "$SRC_IP" "$RST")"$'\n'
    STALE_BANNER+="${GRY}${DIV_DA}${RST}"$'\n'
  fi

  MSG=$(cat <<MSGEOF
${ALERT_COLOR}${ALERT_ICON} ${ALERT_TITLE}${RST}
${GRY}${DIV_EQ}${RST}
${STALE_BANNER}
📅 ${CYN}วันที่/เวลา${RST}  : ${TS}
🖥️  ${CYN}โฮสต์ (VM)${RST}   : ${HOST}
🌐 ${CYN}Public IP${RST}    : ${GRN}${PUBLIC_IP}${RST}
🔒 ${CYN}Internal IP${RST}  : ${GRN}${INTERNAL_IP}${RST}
😈 ${CYN}IP ผู้โจมตี${RST}   : ${RED}${SRC_IP}${RST}
${GRY}${DIV_DA}${RST}
🔗 ${CYN}Request${RST}      : ${YEL}${REQ_DISPLAY}${RST}
${BODY_LINE}⚠️  ${CYN}Score${RST}        : ${RED}${SCORE}${RST} (threshold: 7)
🆔 ${CYN}Unique ID${RST}    : ${UID_SAFE:-unknown}
${GRY}${DIV_EQ}${RST}
📋 กฎที่ตรวจพบ (Rules Matched)
${GRY}${DIV_EQ}${RST}
${RULES_TEXT}${GRY}${DIV_EQ}${RST}
MSGEOF
)

PAYLOAD=$(printf '```ansi\n%s\n```' "$MSG" | python3 -c 'import json,sys; print(json.dumps({"content": sys.stdin.read()}))')

RESP_FILE="$(mktemp)"
HTTP_CODE=$(curl -sS -o "$RESP_FILE" -w '%{http_code}' -m 5 -X POST -H "Content-Type: application/json" -d "$PAYLOAD" "$WEBHOOK" 2>>"$LOGFILE")
CURL_EXIT=$?
RESP_BODY=$(head -c 300 "$RESP_FILE" 2>/dev/null)
rm -f "$RESP_FILE"

printf '%s level=%s jail=%s src=%s stale=%s age=%s curl_exit=%s http=%s resp=%s\n' \
  "$(date -Is)" "$LEVEL" "$JAIL" "$SRC_IP" "${STALE:-0}" "${AGE:-NA}" "$CURL_EXIT" "${HTTP_CODE:-none}" "${RESP_BODY:-}" >> "$LOGFILE"

if [ "$CURL_EXIT" -ne 0 ] || [ "$HTTP_CODE" != "204" ]; then
  exit 1
fi

EOF_E
chmod 700 /usr/local/bin/modsec-discord-alert.sh
touch /var/log/modsec-discord-alert.log && chmod 640 /var/log/modsec-discord-alert.log

sed "s#REPLACE_ME_AT_INSTALL_TIME#${WEBHOOK}#" > /etc/fail2ban/jail.d/modsec-alert.local <<'EOF_D'
[DEFAULT]
discord_webhook = REPLACE_ME_AT_INSTALL_TIME

[modsec-block-alert]
enabled  = true
filter   = modsec-block
# main error_log AND every per-vhost override (confirmed on box-dedicate.one.th:
# vhost has its own error_log, main /var/log/nginx/error.log never saw the block)
logpath  = /var/log/nginx/error.log
           /var/log/nginx/*error*.log
backend  = auto
maxretry = 1
findtime = 60
# bantime=1 (near-zero) hit a fail2ban internal debounce quirk: confirmed live
# on box-dedicate.one.th, "Ignore <ip>, expired bantime" fired even 5s after
# the prior unban -- not simple 1s-window suppression, an edge case bantime
# this low isn't built for. 30s is a real dedup window: repeat alerts from the
# same source within it collapse into one, which is correct alerting practice
# anyway (a scanner hammering one endpoint shouldn't page 10x), and it's long
# enough to sit outside fail2ban's internal tick/debounce edge case.
bantime  = 30
action   = discord-alert[level="BLOCK", discord_webhook="%(discord_webhook)s"]

[modsec-detect-alert]
# Covers boxes/vhosts running SecRuleEngine DetectionOnly, where ModSecurity
# never emits the "Access denied" line the modsec-block-alert jail above
# watches for -- it logs the same anomaly-score-exceeded event as a Warning
# instead (see filter.d/modsec-detect.conf). Same logpath/dedup rationale as
# modsec-block-alert; kept as a separate jail (not folded into the block
# filter) so the action can pass a distinct level and the alert script can
# tell a real block apart from a would-have-blocked detection.
enabled  = true
filter   = modsec-detect
logpath  = /var/log/nginx/error.log
           /var/log/nginx/*error*.log
backend  = auto
maxretry = 1
findtime = 60
bantime  = 30
action   = discord-alert[level="DETECT", discord_webhook="%(discord_webhook)s"]
EOF_D
chmod 640 /etc/fail2ban/jail.d/modsec-alert.local

# Project-wide rule: this box's fail2ban is alerting-only, never banning.
# Our modsec jails above already override `action` themselves (unaffected
# either way); this additionally strips any OTHER jail's default ban action
# (e.g. a stock sshd jail from jail.d/defaults-debian.conf) so nothing on
# this box performs a real ban as a side effect of this install.
# NOTE: does not retroactively unban IPs already banned before this ran --
# check `iptables -L -n | grep f2b` / `fail2ban-client unban --all` if needed.
cat > /etc/fail2ban/jail.d/00-disable-default-ban.local <<'EOF_F'
[DEFAULT]
action =
banaction =
EOF_F

systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban
sleep 1
fail2ban-client status
echo "--- jail: modsec-block-alert ---"
fail2ban-client status modsec-block-alert
echo "--- jail: modsec-detect-alert ---"
fail2ban-client status modsec-detect-alert
echo "public IP baked in: $(cat /etc/modsec-alert-public-ip)"
echo "INSTALL_OK $(hostname)"
echo "Next: trigger a real block on this host and confirm the Discord message lands."
echo "Next (if this box runs SecRuleEngine DetectionOnly): trigger a would-block request and confirm modsec-detect-alert fires -- the 949110 regex in filter.d/modsec-detect.conf is unverified against a real DetectionOnly log line, validate with fail2ban-regex first."
