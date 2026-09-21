#!/usr/bin/env bash
# Install OR re-apply the ModSecurity IP whitelist on THIS box. Separate from
# install-alerting.sh / install-audit-retention.sh. Run on the box as root.
#
# You edit two plain-text data files, then re-run this script. The script
# never overwrites them (it only creates them with examples if missing):
#
#   /etc/modsecurity/whitelist-ip.txt        -- IP fully bypasses ModSecurity
#     <ip_or_cidr>[,<ip_or_cidr>...]
#       10.0.0.5
#       192.168.70.0/24
#
#   /etc/modsecurity/whitelist-ip-path.txt   -- IP bypass only on one path
#     <ip_or_cidr>[,...]  <path>  [all | <rule_id>[,<rule_id>|<from>-<to>...]]
#       203.154.27.43  /admin/api/send_email_by_template_with_cc
#       203.154.27.43  /admin/api/*   942100,941100-941999
#     path: exact match, or prefix match when it ends in "*"
#     3rd column: "all" (default) turns ModSecurity off for that request;
#                 rule ids only remove those rules, everything else still runs
#
# Lines are validated strictly (IP/CIDR chars, safe path chars, numeric rule
# ids) because they are written into ModSecurity config; one bad line aborts
# the whole run and nothing is changed.
#
# From these the script generates /etc/modsecurity/whitelist.conf, hooks it
# into the ModSecurity main config (the file nginx's modsecurity_rules_file
# points at) right BEFORE the first CRS Include -- it must load before CRS so
# the bypass beats CRS's own phase-1 rules -- then `nginx -t` and reload. If
# `nginx -t` fails, every file is rolled back and nginx is not reloaded.
#
# Whitelisted requests are "nolog": no audit log entry, so no Discord alert.
#
# Usage:
#   ./install-modsec-whitelist.sh
#   MODSEC_MAIN_CONF=/etc/nginx/modsec/main.conf ./install-modsec-whitelist.sh
#     (override auto-detection of the main config)
#
# Behind a load balancer: ModSecurity matches REMOTE_ADDR, i.e. the TCP peer.
# Without nginx realip (set_real_ip_from + real_ip_header) that is the LB's IP
# for every request, and whitelisting it whitelists everyone. The script warns
# if it can't find real_ip_header in /etc/nginx. Never match X-Forwarded-For
# directly -- the client controls that header.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root (sudo ./install-modsec-whitelist.sh)" >&2
  exit 1
fi

DATA_DIR="/etc/modsecurity"
IP_FILE="$DATA_DIR/whitelist-ip.txt"
PATH_FILE="$DATA_DIR/whitelist-ip-path.txt"
OUT_CONF="$DATA_DIR/whitelist.conf"
# Rule id ranges reserved for generated rules (outside CRS 9xxxxx ranges).
ID_IP_BASE=1000000
ID_PATH_BASE=1000100

mkdir -p "$DATA_DIR"

if [ ! -f "$IP_FILE" ]; then
  cat > "$IP_FILE" <<'EOF_IP'
# Full ModSecurity bypass. One IP or CIDR per line (comma-separated also OK).
# Edit, then re-run install-modsec-whitelist.sh. Lines starting with # ignored.
# 10.0.0.5
# 192.168.70.0/24
EOF_IP
  echo "created $IP_FILE (examples only, all commented out)"
fi

if [ ! -f "$PATH_FILE" ]; then
  cat > "$PATH_FILE" <<'EOF_PATH'
# IP + path bypass. Columns (whitespace-separated):
#   <ip_or_cidr>[,...]  <path>  [all | <rule_id>[,<rule_id>|<from>-<to>...]]
# path ending in * = prefix match, otherwise exact match (query string ignored).
# 3rd column: all (default) = ModSecurity off for that request,
#             rule ids = only those rules removed, the rest still inspect.
# Edit, then re-run install-modsec-whitelist.sh. Lines starting with # ignored.
# 203.154.27.43  /admin/api/send_email_by_template_with_cc
# 203.154.27.43  /admin/api/*   942100,941100-941999
EOF_PATH
  echo "created $PATH_FILE (examples only, all commented out)"
fi

IP_RE='^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$'
PATH_RE='^/[A-Za-z0-9._~%:@+=!$&,;/-]*\*?$'
RULES_RE='^(all|[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*)$'

ERRORS=0
err() { echo "ERROR: $1" >&2; ERRORS=$((ERRORS + 1)); }

# Validates a comma-separated IP list, echoes it back normalized.
check_ips() {
  local src="$1" list="$2" ip
  IFS=',' read -ra _ips <<< "$list"
  [ "${#_ips[@]}" -gt 0 ] || { err "$src: empty IP list"; return; }
  for ip in "${_ips[@]}"; do
    [[ "$ip" =~ $IP_RE ]] || err "$src: invalid IP/CIDR '$ip'"
  done
}

strip() { sed -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$1"; }

# ---- full-bypass IPs -------------------------------------------------------
BYPASS_IPS=""
n=0
while IFS= read -r line; do
  n=$((n + 1))
  [ -z "$line" ] && continue
  line="${line//[[:space:]]/}"
  check_ips "$IP_FILE line $n" "$line"
  BYPASS_IPS+="${BYPASS_IPS:+,}$line"
done < <(strip "$IP_FILE")

# ---- IP + path -------------------------------------------------------------
PATH_RULES=""
id="$ID_PATH_BASE"
n=0
while IFS= read -r line; do
  n=$((n + 1))
  [ -z "$line" ] && continue
  read -r f_ip f_path f_rules f_extra <<< "$line"
  src="$PATH_FILE line $n"
  f_rules="${f_rules:-all}"
  [ -n "${f_extra:-}" ] && { err "$src: too many columns"; continue; }
  [ -n "${f_path:-}" ] || { err "$src: missing path"; continue; }
  check_ips "$src" "$f_ip"
  [[ "$f_path" =~ $PATH_RE ]] || { err "$src: invalid path '$f_path' (must start with /, no quotes/spaces/backslashes, * only at end)"; continue; }
  [[ "$f_rules" =~ $RULES_RE ]] || { err "$src: invalid rule list '$f_rules' (all, or ids like 942100,941100-941999)"; continue; }

  if [[ "$f_path" == *\* ]]; then
    OP="@beginsWith ${f_path%\*}"
  else
    OP="@streq ${f_path}"
  fi
  if [ "$f_rules" = "all" ]; then
    CTL="ctl:ruleEngine=Off"
  else
    CTL=""
    IFS=',' read -ra _rids <<< "$f_rules"
    for r in "${_rids[@]}"; do CTL+="${CTL:+,}ctl:ruleRemoveById=$r"; done
  fi

  # IP is checked first (cheap); the path compare runs on the decoded,
  # normalized path so "/admin/api/x/../../other" or %2e%2e tricks can't
  # reach a different path while riding a prefix whitelist.
  PATH_RULES+="# $PATH_FILE line $n: $f_ip $f_path $f_rules"$'\n'
  PATH_RULES+="SecRule REMOTE_ADDR \"@ipMatch ${f_ip}\" \"id:${id},phase:1,pass,nolog,chain\""$'\n'
  PATH_RULES+="    SecRule REQUEST_FILENAME \"${OP}\" \"t:none,t:urlDecodeUni,t:normalizePath,${CTL}\""$'\n'
  id=$((id + 1))
done < <(strip "$PATH_FILE")

if [ "$ERRORS" -gt 0 ]; then
  echo "$ERRORS error(s) -- nothing changed." >&2
  exit 1
fi

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

INCLUDE_LINE="Include $OUT_CONF"
STAMP="$(date +%Y%m%d-%H%M%S)"
MAIN_BAK=""
if ! grep -qxF "$INCLUDE_LINE" "$MAIN_CONF"; then
  CRS_LINE=$(grep -niE '^\s*Include\s+\S*(crs|owasp|coreruleset)' "$MAIN_CONF" | head -1 | cut -d: -f1 || true)
  if [ -z "$CRS_LINE" ]; then
    echo "ERROR: no CRS Include line found in $MAIN_CONF -- add this line yourself right BEFORE the CRS includes, then re-run:" >&2
    echo "  $INCLUDE_LINE" >&2
    exit 1
  fi
  MAIN_BAK="$MAIN_CONF.bak-whitelist-$STAMP"
  cp -p "$MAIN_CONF" "$MAIN_BAK"
  sed -i "${CRS_LINE}i # IP whitelist, managed by install-modsec-whitelist.sh -- must stay before CRS\n${INCLUDE_LINE}" "$MAIN_CONF"
  echo "hooked $OUT_CONF into $MAIN_CONF (before line $CRS_LINE), backup: $MAIN_BAK"
fi

# ---- write generated rules, test, reload (rollback on failure) -------------
OUT_BAK=""
if [ -f "$OUT_CONF" ]; then
  OUT_BAK="$OUT_CONF.prev"
  cp -p "$OUT_CONF" "$OUT_BAK"
fi

{
  echo "# GENERATED by install-modsec-whitelist.sh at $STAMP -- do NOT edit."
  echo "# Edit $IP_FILE / $PATH_FILE and re-run the script instead."
  echo
  if [ -n "$BYPASS_IPS" ]; then
    echo "# Full bypass ($IP_FILE)"
    echo "SecRule REMOTE_ADDR \"@ipMatch ${BYPASS_IPS}\" \"id:${ID_IP_BASE},phase:1,pass,nolog,ctl:ruleEngine=Off\""
    echo
  fi
  printf '%s' "$PATH_RULES"
} > "$OUT_CONF"
chmod 644 "$OUT_CONF"

rollback() {
  echo "nginx -t FAILED -- rolling back, nginx NOT reloaded." >&2
  if [ -n "$OUT_BAK" ]; then mv -f "$OUT_BAK" "$OUT_CONF"; else rm -f "$OUT_CONF"; fi
  [ -n "$MAIN_BAK" ] && cp -p "$MAIN_BAK" "$MAIN_CONF"
  exit 1
}

nginx -t || rollback
systemctl reload nginx 2>/dev/null || nginx -s reload
# Reload is async: old workers keep serving (old rules) until new ones start.
sleep 2
rm -f "$OUT_BAK"

if ! grep -rqsE '^\s*real_ip_header\s' /etc/nginx; then
  echo "WARN: no real_ip_header in /etc/nginx. If this box sits behind a load balancer/proxy," >&2
  echo "      REMOTE_ADDR is the proxy's IP and the whitelist will not match real clients." >&2
fi

echo "--- active whitelist ($OUT_CONF) ---"
grep -v '^#' "$OUT_CONF" | sed '/^$/d' || true
echo "WHITELIST_OK $(hostname)"
