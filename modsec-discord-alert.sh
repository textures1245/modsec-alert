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

if [ "$LEVEL" = "BLOCK" ]; then
  LAST_BLOCK=$(grep "ModSecurity: Access denied with code 403" "$AUDIT_LOG" 2>/dev/null | tail -1)
  UID_RAW=$(printf '%s' "$LAST_BLOCK" | grep -oP '(?<=\[unique_id ")[^"]+' | head -1)
  UID_SAFE=""
  if [[ "$UID_RAW" =~ ^[0-9]+\.[0-9]+$ ]]; then
    UID_SAFE="$UID_RAW"
  fi

  SCORE=$(printf '%s' "$LAST_BLOCK" | grep -oP "(?<=Value: \`)[0-9]+" | head -1)
  [ -z "$SCORE" ] && SCORE="?"
  API_URI=$(printf '%s' "$LAST_BLOCK" | grep -oP '(?<=\[uri ")[^"]+' | head -1)
  [ -z "$API_URI" ] && API_URI="(unknown)"

  TS="(unknown)"
  RULES_TEXT=""
  REQ_LINE=""
  BODY_RAW=""
  if [ -n "$UID_SAFE" ]; then
    # -B1 grabs the "---TAG---A--" marker line together with the Section A
    # content line in one pass, so TAG is available for free alongside TS.
    AB_PAIR=$(grep -B1 -F -- " ${UID_SAFE} " "$AUDIT_LOG" 2>/dev/null | tail -2)
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
      ' "$AUDIT_LOG" 2>/dev/null)
      REQ_LINE=$(printf '%s\n' "$AWK_OUT" | grep '^REQ:' | sed 's/^REQ://' | head -c 300)
      BODY_RAW=$(printf '%s\n' "$AWK_OUT" | grep '^BODY:' | sed 's/^BODY://' | tr '\n' ' ' | head -c 200)
    fi

    DIV="────────────────────────────────────"
    RULE_NUM=0
    WARNINGS=$(grep -F -- "unique_id \"${UID_SAFE}\"" "$AUDIT_LOG" 2>/dev/null | grep "ModSecurity: Warning")
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
  INTERNAL_IP=$(printf '%s' "$LAST_BLOCK" | grep -oP '(?<=\[hostname ")[^"]+' | head -1)

  # Full request line (method+path+query) when found; fall back to the
  # path-only [uri] field from the block line if Section B lookup failed.
  REQ_DISPLAY="${REQ_LINE:-$API_URI}"
  BODY_LINE=""
  # $(...) strips trailing newlines, so append \n outside the substitution.
  [ -n "$BODY_RAW" ] && BODY_LINE="$(printf '📦 %sRequest Body%s : %s%s%s' "$CYN" "$RST" "$YEL" "$BODY_RAW" "$RST")"$'\n'

  STALE_BANNER=""
  if [ "${STALE:-0}" -eq 1 ]; then
    STALE_BANNER="$(printf '%s⚠️  AUDIT LOG STALE (entry is %ss old)%s' "$RED" "$AGE" "$RST")"$'\n'
    STALE_BANNER+="$(printf '%sBan on src=%s is real (matched live nginx error.log) -- but the detail below is the LAST entry modsec_audit.log ever wrote, not this ban. modsec_audit.log has likely stopped appending. Check SecAuditEngine/SecAuditLog path + logrotate reopen signal.%s' "$YEL" "$SRC_IP" "$RST")"$'\n'
    STALE_BANNER+="${GRY}${DIV_DA}${RST}"$'\n'
  fi

  MSG=$(cat <<MSGEOF
${RED}🛡️ ModSec BLOCK Alert${RST}
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
else
  # WARNING-SPIKE: no single transaction to reference, this is a rate alert.
  DIV_EQ="════════════════════════════════════"
  MSG=$(cat <<MSGEOF
${YEL}⚠️ ModSec WARNING-SPIKE Alert${RST}
${GRY}${DIV_EQ}${RST}
🖥️  ${CYN}โฮสต์ (VM)${RST}  : ${HOST}
🔒 ${CYN}Internal IP${RST} : ${YEL}${SRC_IP}${RST}
📂 ${CYN}Jail${RST}        : ${JAIL}
${GRY}${DIV_EQ}${RST}
อัตราการยิง Warning เกิน threshold ในช่วงเวลาที่กำหนด
ดูรายละเอียดเต็มได้ที่ modsec_audit.log บนโฮสต์นี้
MSGEOF
)
fi

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
