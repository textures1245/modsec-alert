#!/usr/bin/env bash
# Install OR re-apply the Thai UTF-8 false-positive fix for OWASP CRS on THIS
# box. Separate from the other install-*.sh scripts. Run on the box as root.
#
# Problem: CRS runs t:utf8toUnicode,t:urlDecodeUni on ~30 SQLi/XSS/LFI/PHP
# rules (942100, 941xxx, 930xxx, 933200...). utf8toUnicode turns Thai
# U+0E00-U+0E7F into %u0Exx and urlDecodeUni keeps only the LOW byte, so
# normal Thai letters become SQL/path chars before libinjection sees them:
#   ว U+0E27 -> '    อ U+0E2D -> -  (ออ = "--")   ร U+0E23 -> #
#   ล U+0E25 -> %    ฮ U+0E2E -> .    ฯ U+0E2F -> /    ศ/ษ -> ( )
# Every Thai address / name field can trip 942100 (score 5 per field).
#
# Fix (verified A/B against owasp/modsecurity-crs:nginx, CRS 4.25.1,
# libmodsecurity 3.0.16, inbound threshold 7):
#   1. strip "t:utf8toUnicode," from the CRS rule files in place (same ids,
#      same order, same skipAfter/paranoia markers -- exclusions keep working)
#   2. add a compensating rule set (/etc/modsecurity/crs-thai-fullwidth.conf):
#      only values that contain full-width ASCII (U+FF01-U+FF5E, the evasion
#      utf8toUnicode existed for, e.g. 1＇ OR 1=1--) get the old decode +
#      libinjection SQLi/XSS, and are denied outright. Plain Thai never does.
#
# Why not SecRuleUpdateActionById 942100 "t:none,...": in libmodsecurity v3
# updated transformations are APPENDED after the rule's own chain
# (rule_with_actions.cc executeTransformations), t:none there does not reset
# it -- utf8toUnicode still runs. nginx -t passes, the 403 stays.
#
# The CRS dir is a git clone: `git pull`, or re-running nginx-modsecutiry.sh
# (rm -rf + re-clone), silently reverts step 1. Re-run this script after ANY
# CRS update. To update CRS: `git -C <crs> checkout -- rules && git -C <crs>
# pull`, then re-run this script.
#
# Usage:
#   ./install-crs-thai-fix.sh
#   MODSEC_MAIN_CONF=/etc/nginx/modsec/main.conf CRS_RULES_DIR=/etc/nginx/modsec/coreruleset/rules \
#     ./install-crs-thai-fix.sh        (override auto-detection)
#
# If `nginx -t` fails, every file is rolled back and nginx is not reloaded.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root (sudo ./install-crs-thai-fix.sh)" >&2
  exit 1
fi

COMP_CONF="/etc/modsecurity/crs-thai-fullwidth.conf"
STAMP="$(date +%Y%m%d-%H%M%S)"
# Backups live OUTSIDE the rules dir: CRS is loaded with rules/*.conf, a
# *.conf backup next to the originals would be loaded too (duplicate ids).
BAK_DIR="/var/backups/crs-thai-fix-$STAMP"

# ---- find the ModSecurity main config --------------------------------------
MAIN_CONF="${MODSEC_MAIN_CONF:-}"
if [ -z "$MAIN_CONF" ]; then
  mapfile -t CANDIDATES < <(grep -rhoP '^\s*modsecurity_rules_file\s+\K[^;]+' /etc/nginx 2>/dev/null | sort -u)
  if [ "${#CANDIDATES[@]}" -ne 1 ]; then
    echo "ERROR: expected exactly one modsecurity_rules_file in /etc/nginx, found ${#CANDIDATES[@]}: ${CANDIDATES[*]:-none}" >&2
    echo "Re-run with MODSEC_MAIN_CONF=/path/to/main.conf" >&2
    exit 1
  fi
  MAIN_CONF="${CANDIDATES[0]}"
fi
[ -f "$MAIN_CONF" ] || { echo "ERROR: $MAIN_CONF not found" >&2; exit 1; }

# ---- find the CRS rules dir (Include .../rules/*.conf in main.conf) --------
RULES_DIR="${CRS_RULES_DIR:-}"
if [ -z "$RULES_DIR" ]; then
  mapfile -t RDIRS < <(grep -oP '^\s*Include\s+\K\S+(?=/\*\.conf\s*$)' "$MAIN_CONF" \
    | while read -r d; do ls "$d"/REQUEST-942-*.conf >/dev/null 2>&1 && echo "$d"; done | sort -u)
  if [ "${#RDIRS[@]}" -ne 1 ]; then
    echo "ERROR: expected one CRS rules dir (Include <dir>/*.conf with REQUEST-942-*.conf) in $MAIN_CONF, found ${#RDIRS[@]}: ${RDIRS[*]:-none}" >&2
    echo "Re-run with CRS_RULES_DIR=/path/to/coreruleset/rules" >&2
    exit 1
  fi
  RULES_DIR="${RDIRS[0]}"
fi
ls "$RULES_DIR"/REQUEST-942-*.conf >/dev/null 2>&1 || { echo "ERROR: $RULES_DIR has no REQUEST-942-*.conf" >&2; exit 1; }

# awk, not grep|wc: grep exits 1 on zero matches, which pipefail + set -e
# turns into a silent abort right after a successful strip.
count_u8() { awk '{ n += gsub(/t:utf8toUnicode/, "") } END { print n + 0 }' "$RULES_DIR"/*.conf; }

# ---- backups ----------------------------------------------------------------
mkdir -p "$BAK_DIR/rules"
cp -p "$MAIN_CONF" "$BAK_DIR/main.conf"
[ -f "$COMP_CONF" ] && cp -p "$COMP_CONF" "$BAK_DIR/crs-thai-fullwidth.conf"

rollback() {
  echo "nginx -t FAILED -- rolling back, nginx NOT reloaded. Backups: $BAK_DIR" >&2
  if compgen -G "$BAK_DIR/rules/*.conf" >/dev/null; then cp -p "$BAK_DIR"/rules/*.conf "$RULES_DIR"/; fi
  cp -p "$BAK_DIR/main.conf" "$MAIN_CONF"
  if [ -f "$BAK_DIR/crs-thai-fullwidth.conf" ]; then cp -p "$BAK_DIR/crs-thai-fullwidth.conf" "$COMP_CONF"; else rm -f "$COMP_CONF"; fi
  exit 1
}

# ---- step 1: strip t:utf8toUnicode from CRS --------------------------------
BEFORE="$(count_u8)"
if [ "$BEFORE" -gt 0 ]; then
  mapfile -t FILES < <(grep -l 't:utf8toUnicode' "$RULES_DIR"/*.conf)
  cp -p "${FILES[@]}" "$BAK_DIR/rules/"
  # "t:utf8toUnicode," mid-chain, then ",t:utf8toUnicode" if it ever ends a chain.
  sed -i -e 's/t:utf8toUnicode,//g' -e 's/,t:utf8toUnicode//g' "${FILES[@]}"
  AFTER="$(count_u8)"
  if [ "$AFTER" -ne 0 ]; then
    echo "ERROR: $AFTER t:utf8toUnicode left after sed (unexpected rule layout) -- restoring." >&2
    cp -p "$BAK_DIR"/rules/*.conf "$RULES_DIR"/
    exit 1
  fi
  echo "stripped t:utf8toUnicode: $BEFORE occurrence(s) in ${#FILES[@]} file(s) under $RULES_DIR"
else
  echo "CRS already patched (0 t:utf8toUnicode in $RULES_DIR)"
fi

# ---- step 2: compensating full-width evasion rules -------------------------
mkdir -p "$(dirname "$COMP_CONF")"
cat > "$COMP_CONF" <<'EOF_COMP'
# GENERATED by install-crs-thai-fix.sh -- do NOT edit, re-run the script.
# t:utf8toUnicode was stripped from CRS (Thai low-byte false positives).
# It existed to catch full-width ASCII evasion (U+FF01-U+FF5E, UTF-8
# EF BC 81..EF BD 9E, e.g. 1＇ OR 1=1--). Only values containing such
# characters get the old lossy decode + libinjection, and are denied
# outright (not scored: one hit is 5 < inbound threshold). Plain Thai never
# reaches the lossy decode.
SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer|XML:/* \
    "@rx (?:\xef\xbc[\x81-\xbf]|\xef\xbd[\x80-\x9e])" \
    "id:1000200,phase:2,deny,status:403,log,capture,t:none,\
    msg:'Full-width ASCII evasion: SQLi via libinjection',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
    tag:'attack-sqli',tag:'local/thai-utf8-fix',severity:'CRITICAL',chain"
    SecRule MATCHED_VARS "@detectSQLi" \
        "t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls"

SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer|XML:/* \
    "@rx (?:\xef\xbc[\x81-\xbf]|\xef\xbd[\x80-\x9e])" \
    "id:1000201,phase:2,deny,status:403,log,capture,t:none,\
    msg:'Full-width ASCII evasion: XSS via libinjection',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
    tag:'attack-xss',tag:'local/thai-utf8-fix',severity:'CRITICAL',chain"
    SecRule MATCHED_VARS "@detectXSS" \
        "t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls"
EOF_COMP
chmod 644 "$COMP_CONF"

# Hook it in right BEFORE the CRS rules Include (phase 2, runs before 949110).
INCLUDE_LINE="Include $COMP_CONF"
if ! grep -qxF "$INCLUDE_LINE" "$MAIN_CONF"; then
  RULES_LINE=$(grep -nE "^\s*Include\s+${RULES_DIR//./\\.}/\*\.conf\s*$" "$MAIN_CONF" | head -1 | cut -d: -f1 || true)
  if [ -z "$RULES_LINE" ]; then
    echo "ERROR: no 'Include $RULES_DIR/*.conf' line in $MAIN_CONF -- add this line yourself right BEFORE the CRS rules include, then re-run:" >&2
    echo "  $INCLUDE_LINE" >&2
    rollback
  fi
  sed -i "${RULES_LINE}i # Thai UTF-8 fix, managed by install-crs-thai-fix.sh -- must stay before CRS rules\n${INCLUDE_LINE}" "$MAIN_CONF"
  echo "hooked $COMP_CONF into $MAIN_CONF (before line $RULES_LINE)"
fi

# ---- test, reload ------------------------------------------------------------
nginx -t || rollback
systemctl reload nginx 2>/dev/null || nginx -s reload
sleep 2

echo "backups: $BAK_DIR"
echo "verify (Thai must NOT be 403, attacks MUST be 403):"
echo "  curl -sk -o /dev/null -w '%{http_code}\\n' -X POST https://<host>/<path> -H 'Content-Type: application/json' \\"
echo "    --data-binary '{\"a\":\"แขวงคลองเตย เขตคลองเตย กรุงเทพมหานคร\",\"b\":\"นายคอมสามสอง โกสามสองยี่สิบเก้า\"}'"
echo "  ... --data-binary '{\"q\":\"1＇ OR 1=1--\"}'                                   # 403 (rule 1000200)"
echo "  ... --data-binary '{\"q\":\"1'\"'\"' UNION SELECT username,password FROM users--\"}'   # 403"
echo "CRS_THAI_FIX_OK $(hostname)"
