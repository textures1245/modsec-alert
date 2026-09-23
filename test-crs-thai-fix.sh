#!/usr/bin/env bash
# Test the Thai UTF-8 false-positive fix (install-crs-thai-fix.sh) against a
# live box. Replays the Thai requests that were actually blocked, plus attack
# controls that must stay blocked. Read-only for the box: it only sends HTTP.
#
#   THAI cases   -> must NOT be 403 (any other code = passed the WAF)
#   ATTACK cases -> MUST be 403
#
# Run it BEFORE the fix too: THAI rows failing there proves the test really
# reproduces the problem. After the fix every row must PASS.
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
#   CRS itself does. The backend just answers 404.
# MODE=real: the real endpoints. Exclusions DO apply (can hide a failure), and
#   the requests reach the backend -- register_business_v2 may really create
#   a business on UAT. Use only to confirm the real flow after MODE=dummy passes.
#
# RESOLVE_IP: send to this IP but keep the hostname (TLS SNI + Host header),
#   e.g. 127.0.0.1 when running on the proxy itself. fail2ban ignores
#   127.0.0.1, so the ATTACK rows then post no Discord alerts. From anywhere
#   else, expect one BLOCK alert per 30s for the attack rows (the jail only
#   alerts, it does not ban).
#
# INSECURE=1: curl -k (self-signed / IP certs).
#
# Every request carries "X-WAF-Test: <run>-<case>"; on a FAIL, find the rule
# ids that fired with the grep printed at the end.
set -uo pipefail

BASE="${1:-}"
[ -n "$BASE" ] || { echo "usage: $0 https://host [see header for MODE/RESOLVE_IP/INSECURE]" >&2; exit 2; }
BASE="${BASE%/}"
MODE="${MODE:-dummy}"
RUN="t$(date +%H%M%S)"

CURL=(curl -s -o /dev/null -w '%{http_code}' --max-time 15)
[ "${INSECURE:-0}" = 1 ] && CURL+=(-k)
if [ -n "${RESOLVE_IP:-}" ]; then
  hostport="${BASE#*://}"; host="${hostport%%/*}"; host="${host%%:*}"
  port="${hostport#*:}"; [ "$port" = "$hostport" ] && { [[ "$BASE" == https* ]] && port=443 || port=80; }
  CURL+=(--resolve "$host:$port:$RESOLVE_IP")
fi

p() {  # path per MODE
  if [ "$MODE" = real ]; then echo "$1"; else echo "/__waf_test$1"; fi
}

PASS=0; FAIL=0; FAILED_IDS=()
row() {  # id expect code desc
  local id="$1" expect="$2" code="$3" desc="$4" ok
  if [ "$code" = 000 ]; then ok=ERROR
  elif [ "$expect" = BLOCK ] && [ "$code" = 403 ]; then ok=PASS
  elif [ "$expect" = ALLOW ] && [ "$code" != 403 ]; then ok=PASS
  else ok=FAIL; fi
  if [ "$ok" = PASS ]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); FAILED_IDS+=("$RUN-$id"); fi
  printf '%-4s %-6s %-5s %-5s %s\n' "$id" "$expect" "$code" "$ok" "$desc"
}

json() {  # id expect path body desc
  row "$1" "$2" "$("${CURL[@]}" -X POST "$BASE$(p "$3")" -H "X-WAF-Test: $RUN-$1" \
    -H 'Content-Type: application/json' --data-binary "$4")" "$5"
}
get() {   # id expect path+query desc
  row "$1" "$2" "$("${CURL[@]}" "$BASE$(p "$3")" -H "X-WAF-Test: $RUN-$1")" "$4"
}
form() {  # id expect path desc -- name=value ...  (application/x-www-form-urlencoded)
  local id="$1" expect="$2" path="$3" desc="$4"; shift 5
  local args=(); for kv in "$@"; do args+=(--data-urlencode "$kv"); done
  row "$id" "$expect" "$("${CURL[@]}" -X POST "$BASE$(p "$path")" -H "X-WAF-Test: $RUN-$id" "${args[@]}")" "$desc"
}
multipart() {  # id expect path desc -- name=value ...
  local id="$1" expect="$2" path="$3" desc="$4"; shift 5
  local args=(); for kv in "$@"; do args+=(--form-string "$kv"); done
  row "$id" "$expect" "$("${CURL[@]}" -X POST "$BASE$(p "$path")" -H "X-WAF-Test: $RUN-$id" "${args[@]}")" "$desc"
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
printf '%-4s %-6s %-5s %-5s %s\n' ID EXPECT CODE RESULT CASE
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

echo "---- ATTACK: must stay blocked (must be 403) ----"
json A1 BLOCK "$INBOX" '{"header_info":{"CustomerName":"1'"'"' UNION SELECT username,password FROM users--"}}' "SQLi UNION"
json A2 BLOCK "$INBOX" '{"header_info":{"CustomerName":"<script>alert(1)</script>"}}' "XSS script tag"
json A3 BLOCK "$INBOX" '{"header_info":{"Doc_remark1":"../../../../etc/passwd"}}' "LFI path traversal"
get  A4 BLOCK "/search?q=1%u0027%20UNION%20SELECT%20password%20FROM%20users--" "SQLi %u-encoded quote"
get  A5 BLOCK "/search?q=%u003Cscript%u003Ealert(1)%u003C/script%u003E" "XSS %u-encoded"
json A6 BLOCK "$INBOX" '{"header_info":{"CustomerName":"1＇ OR 1=1--"}}' "SQLi full-width quote (rule 1000200)"
json A7 BLOCK "$INBOX" '{"header_info":{"CustomerName":"＜script＞alert(1)＜/script＞"}}' "XSS full-width brackets (rule 1000201)"
json A8 BLOCK "$INBOX" '{"header_info":{"CustomerName":"นายคอมสามสอง'"'"' UNION SELECT username,password FROM users--"}}' "SQLi hidden after Thai text"
multipart A9 BLOCK "$REG" "SQLi inside register_business_v2 form" -- \
  "business_name_th=แอสราส เมดิคอล" "SoiName=นวมินทร์ 163' UNION SELECT username,password FROM users--"

echo "----"
echo "PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -gt 0 ]; then
  # awk prints the whole audit-log transaction (Native format, ---xxx---A-- to
  # the next one) that carries the test header, so the H section with the rule
  # ids is included however long the logged body is.
  echo "rule ids that fired, per failed case (run on the proxy box):"
  for id in "${FAILED_IDS[@]}"; do
    echo "  tail -c 500M /var/log/modsec_audit.log | awk -v id='X-WAF-Test: $id' '/^---[A-Za-z0-9]+---A--/{if(hit)print buf; buf=\"\"; hit=0} {buf=buf\"\\n\"\$0} index(\$0,id){hit=1} END{if(hit)print buf}' | grep -oP '\\[id \"\\K[0-9]+' | sort -u | tr '\\n' ' '; echo"
  done
  echo "THAI FAIL (403): fix not applied / CRS re-cloned -> run install-crs-thai-fix.sh"
  echo "ATTACK FAIL (not 403): client IP whitelisted (whitelist-ip.txt), MODE=real path excluded, or rule engine DetectionOnly"
  exit 1
fi
