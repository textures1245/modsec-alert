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
# Detects CRS rule 949110 ("Inbound Anomaly Score Exceeded") logged as
# Warning, i.e. a would-have-blocked request on a SecRuleEngine DetectionOnly
# box. In blocking mode the same rule logs "Access denied" instead (caught by
# modsec-block.conf), so the two jails never double-fire.
#
# Reads modsec_audit.log, NOT nginx error_log: confirmed live on
# OneBox-Proxy01-UAT (2026-09-21, t_1789988729) that the nginx connector only
# writes disruptive actions to error_log -- Warning lines never appear there
# at error/notice/info level, only in the audit log's Section H.
#
# Audit entries are multi-line: client IP is on the Section A line, the
# 949110 Warning is several lines later in Section H. The skip group refuses
# to cross another "---TAG---A--" marker, so a Warning is never attributed to
# the previous transaction's IP. The date prefix is optional in the regex
# because fail2ban may cut the matched timestamp out of the line.
# Alert-only (this fleet never bans); a crafted request body could still
# spoof lines here, which at worst mislabels the source IP in Discord.
[Init]
maxlines = 100

[Definition]
failregex = ^---[A-Za-z0-9]+---A--\n(?:\[[^\]]+\])?\s*\S+ <HOST> \d+ \S+ \d+\s*\n(?:(?!---[A-Za-z0-9]+---A--)[^\n]*\n)*?ModSecurity: Warning\. .*\[id "949110"\]
datepattern = ^\[%%d/%%b/%%Y:%%H:%%M:%%S %%z\]
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

# Repeat-alert suppression (BLOCK and DETECT alike). The same incident -- same
# level + attacker IP + method/path (query string dropped) + matched rule ids
# -- is sent at most DEDUP_MAX times; the last one carries a "muted" banner,
# then that incident stays silent for DEDUP_MUTE_SECS. After the mute expires
# the counter resets and the next hit alerts again. Unique ID and timestamp
# are deliberately NOT part of the key (they differ on every request).
# Suppressed hits are still logged to LOGFILE with suppressed=1.
# Reset one/all mutes by hand: rm /var/lib/modsec-discord-alert/<key|*>
DEDUP_MAX=3
DEDUP_MUTE_SECS=14400
DEDUP_DIR="/var/lib/modsec-discord-alert"
mkdir -p "$DEDUP_DIR" && chmod 700 "$DEDUP_DIR"
REQ_SIG=$(printf '%s' "${REQ_LINE:-$API_URI}" | awk '{ if (NF >= 2) print $1 " " $2; else print $0 }')
REQ_SIG="${REQ_SIG%%\?*}"
RULE_SIG=$(printf '%s' "$RULE_IDS" | tr ',' '\n' | grep -v '^$' | sort -u | paste -sd, -)
DEDUP_KEY=$(printf '%s|%s|%s|%s' "$LEVEL" "$SRC_IP" "$REQ_SIG" "$RULE_SIG" | sha256sum | cut -c1-32)
STATE_FILE="$DEDUP_DIR/$DEDUP_KEY"
# Serialize read-modify-write across concurrent fail2ban action runs; lock is
# held until this script exits (fd 9 closes).
exec 9>"$DEDUP_DIR/.lock"
flock -w 10 9 || true
find "$DEDUP_DIR" -type f ! -name .lock -mmin +600 -delete 2>/dev/null
NOW=$(date +%s)
D_COUNT=0; D_FIRST=0; D_MUTE_UNTIL=0
[ -r "$STATE_FILE" ] && read -r D_COUNT D_FIRST D_MUTE_UNTIL < "$STATE_FILE"
[[ "$D_COUNT" =~ ^[0-9]+$ ]] || D_COUNT=0
[[ "$D_FIRST" =~ ^[0-9]+$ ]] || D_FIRST=0
[[ "$D_MUTE_UNTIL" =~ ^[0-9]+$ ]] || D_MUTE_UNTIL=0

if [ "$D_MUTE_UNTIL" -gt "$NOW" ]; then
  printf '%s level=%s jail=%s src=%s suppressed=1 key=%s req=%s rules=%s muted_until=%s\n' \
    "$(date -Is)" "$LEVEL" "$JAIL" "$SRC_IP" "$DEDUP_KEY" "$REQ_SIG" "$RULE_SIG" "$(date -d "@$D_MUTE_UNTIL" -Is)" >> "$LOGFILE"
  exit 0
fi
# Mute expired, or first hit is outside the counting window -> start fresh.
if [ "$D_MUTE_UNTIL" -gt 0 ] || [ $(( NOW - D_FIRST )) -ge "$DEDUP_MUTE_SECS" ]; then
  D_COUNT=0; D_FIRST="$NOW"; D_MUTE_UNTIL=0
fi
D_COUNT=$(( D_COUNT + 1 ))
MUTE_BANNER=""
if [ "$D_COUNT" -ge "$DEDUP_MAX" ]; then
  D_MUTE_UNTIL=$(( NOW + DEDUP_MUTE_SECS ))
  MUTE_BANNER="$(printf '%s🔕 แจ้งเตือนซ้ำครั้งที่ %s/%s -- เหตุการณ์นี้ (IP + Request + Rules เดิม) จะถูกปิดเสียงถึง %s%s' "$GRY" "$D_COUNT" "$DEDUP_MAX" "$(date -d "@$D_MUTE_UNTIL" '+%d/%b/%Y %H:%M:%S %z')" "$RST")"$'\n'
elif [ "$D_COUNT" -gt 1 ]; then
  MUTE_BANNER="$(printf '%s🔁 แจ้งเตือนซ้ำครั้งที่ %s/%s%s' "$GRY" "$D_COUNT" "$DEDUP_MAX" "$RST")"$'\n'
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
# Covers boxes running SecRuleEngine DetectionOnly. Watches modsec_audit.log,
# not error_log: the nginx connector never writes Warning-level rule matches
# to error_log (confirmed 2026-09-21, see filter.d/modsec-detect.conf).
# "tail" starts at end of file so a restart doesn't rescan a multi-GB log.
# Test from a non-local IP: fail2ban ignores 127.0.0.1 (ignoreself), so a
# `curl https://localhost/...` test will never alert.
enabled  = true
filter   = modsec-detect
logpath  = /var/log/modsec_audit.log tail
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
echo "Next (if this box runs SecRuleEngine DetectionOnly): validate first with: tail -c 2000000 /var/log/modsec_audit.log > /tmp/audit-sample.log && fail2ban-regex /tmp/audit-sample.log /etc/fail2ban/filter.d/modsec-detect.conf -- then send a would-block request from a NON-local IP (127.0.0.1 is ignored) and confirm modsec-detect-alert fires."
