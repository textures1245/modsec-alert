#!/usr/bin/env bash
# Versioned, fleet-identical ModSecurity false-positive patch for Onebox
# Dedicated. Every box that runs the same version of this script ends up with
# byte-identical managed config -- `--status` proves it with a hash.
#
# Source of truth: Obsidian "Onebox Dedicated ModSec Patching Tracker"
# (canonical config + root-cause reference) and the task Document
# "Modsecurity Patch Detail" (tabs: รายการกฎที่ยกเว้น, Patch Version).
#
# What it owns (and nothing else):
#   $MANAGED_DIR/before-crs.conf  BASELINE engine settings + CRS tx vars (id 1009900),
#                                 URI-scoped ctl: rules (ids 1009001+), all generated
#   $MANAGED_DIR/after-crs.conf   GLOBAL_REMOVE + SecRuleUpdateTargetById for every
#                                 RULES x FIELDS pair -- never hand-edit, never paste
#   $MANAGED_DIR/VERSION          installed PATCH_VERSION + content hash
#   two Include lines in the ModSecurity main config, around the CRS rules Include
#   statements in the LEGACY_FILES next to the main config that this patch
#   covers or replaces: install comments them out ("#[onebox-patch retired] "),
#   --uninstall brings them back. Statements it does not cover stay active and
#   are printed ("kept active"). Missing legacy files are fine.
# Replaces legacy-patch-modsec-after-install-modec.sh + its rules/ copy-over:
# do not run that script on a patched box -- it overwrites main.conf (drops
# the Include lines) and re-adds the bypasses fixed in PV-2026-10-16.
# Other hand-maintained exclusions (RESPONSE-999-*.conf, whitelist script
# output) are left alone; duplicates are harmless (target updates accumulate,
# verified libmodsecurity 3.0.17). --audit lists them so they can be retired.
#
# Needs python3 for install (legacy retire) and --audit.
#
# The managed files live OUTSIDE the CRS rules dir: re-cloning CRS does not wipe
# them. install-crs-thai-fix.sh is still separate (it edits CRS in place) and
# must be re-run after any CRS update; --status reports whether it is applied.
#
# To change the patch: edit RULES / FIELDS / ENDPOINTS below, bump
# PATCH_VERSION, add a CHANGELOG line, commit, re-run on every box.
# ENDPOINTS ids come from list position: append new entries, never reorder.
#
# Usage (as root, on the box):
#   ./install-modsec-patch.sh             install / re-sync to this version
#   ./install-modsec-patch.sh --status    one line per box: version, drift, CRS, thai-fix
#   ./install-modsec-patch.sh --audit     read-only: is THIS script's patch in effect? (below)
#   ./install-modsec-patch.sh --audit --json   same, one JSON object (fleet collection)
#   ./install-modsec-patch.sh --check-body read-only: locations that take >=100 MB bodies with ModSecurity on and no guard
#   ./install-modsec-patch.sh --print     print the generated config, change nothing
#   ./install-modsec-patch.sh --uninstall remove the managed files + Include lines
#   MODSEC_MAIN_CONF=... CRS_RULES_DIR=... ./install-modsec-patch.sh   (override detection)
#
# Big-upload guard (PV-2026-10-29): with `modsecurity on` the connector spools
# the whole body and libmodsecurity then reads it into RAM (~2x its size), so a
# multi-GB PUT OOM-kills nginx. Install therefore (1) writes BYPASS_MAP_FILE
# (the $bypass_waf map: Content-Length >= 9 digits, or chunked) and (2) adds the
# guard to every BYPASS_LOCATIONS location it finds in the nginx config: an
# `error_page 418` + `if ($bypass_waf)` at the top of the location and a named
# location `@<name>_nowaf` right after it (copy of the block, with
# `modsecurity_rules 'SecRequestBodyAccess Off'`). Edited files are backed up,
# the added lines carry "# onebox-patch: guard begin/end" markers, --uninstall
# removes them. A location it cannot copy safely (proxy_pass with a URI,
# limit_except, modsecurity off) is left alone and reported. --check-body lists
# every location that takes >= 100 MB through ModSecurity with no guard.
#
# If `nginx -t` fails, every touched file is restored and nginx is not reloaded.
# Install prints what changed vs the previously installed version, then runs
# --audit. Install exit: 0 installed + covered, 1 installed with gaps (or
# refused before changing anything -- the message says "Nothing changed"),
# 2 installed but the audit could not run, 3 nginx -t failed and rolled back.
#
# --audit (needs python3) follows the Include chain from the ModSecurity main
# config -- only files nginx actually loads count -- and checks every patch
# exclusion (RULES x FIELDS pair, ENDPOINTS action) against everything loaded,
# managed or hand-written. Per exclusion: FULL / N/A pass; PARTIAL (only
# narrower-scoped legacy lines), UNKNOWN (regex/chain/IP scope, inline nginx
# rules, unresolved Include), INEFFECTIVE (ctl: rule in the same or a later
# phase than its target, loaded after it), MISSING fail. Also lists every
# legacy exclusion with a risk tag (red: engine off / whole rule removed
# globally, yellow: whole rule removed for an endpoint, green: one field) and
# orphan files (exclusions on disk that nothing Includes). See CONTEXT.md.
# Exit: 0 covered, 1 gaps, 2 audit could not run.
set -euo pipefail

PATCH_VERSION="PV-2026-10-30"

CHANGELOG=(
  "PV-2026-10-13  First script-managed version. Global field list = tracker canonical (2026-08-17) + 932125/932380/932370/942140. /business-drive/: 911100+920340 whole-rule (tracker id 1000010, minus 920640: not canonical per Document) + 932125/932380 off REQUEST_FILENAME. check_duplicate_inbox 942100 fields (POST-method chain dropped)."
  "PV-2026-10-15  FIELDS += json.data.array_0..9.file_path_real (POST /onebox-centrifugo/api/publish, 932370 on Thai cost-estimate path, unique_id 179207345281.765841, EXTEEM-106)."
  "PV-2026-10-16  Takes over the legacy files (sec_actions / sec_rule_removal / sec_base_modsecurity_disable): BASELINE + GLOBAL_REMOVE + their endpoint rules, legacy statements retired. Security fixes (bypasses confirmed live, libmodsecurity 3.0.17 / CRS 4.29): /onlyofficeds/ 949110 removal no longer matchable from the query string of any URL (REQUEST_URI @rx -> REQUEST_FILENAME prefix, normalized); valid JSON padded past the 128K no-files limit skipped inspection -- closed by restoring 200002 (denies over-limit bodies under ProcessPartial), NoFilesLimit 128K -> 1M; ProcessPartial kept so >13 MB raw PUTs still pass (multipart >13 MB now 400); 200002-200005 restored (body parse / multipart / engine-error checks). All URI-scoped exclusions in the managed config are path-normalized; legacy statements the patch does not cover stay as they were (install prints them)."
  "PV-2026-10-28  Big-upload guard: manages the nginx http-level \$bypass_waf map (conf.d/onebox-waf-bypass.conf); --check-body and an install-time warning list locations with modsecurity on, client_max_body_size >= 100 MB and no body guard (EXTEEM-106 nginx OOM, 4 GB rclone PUT, task t_1793008028). No change to exclusions or baseline."
  "PV-2026-10-29  Install also applies the guard to BYPASS_LOCATIONS (/business-drive/): error_page 418 + if (\$bypass_waf) in the location and a generated @<name>_nowaf named location (SecRequestBodyAccess Off), marker-delimited, backed up, removed by --uninstall. Locations it cannot copy safely are reported, not edited. No change to exclusions or baseline."
  "PV-2026-10-30  /business-drive/: 934190 (SSRF, scheme-less localhost) excluded on ARGS:json.icons.array_0..9.src only -- a PUT of a web-app manifest.json whose icon URL is http://localhost/... scored 15 and was blocked (ONEBOX-TRONEX-01, unique_id 179316468594.863633). 934190 stays active everywhere else and on every other field."
)

# Engine settings enforced on every box, emitted into before-crs.conf so they
# override modsecurity.conf and the legacy files (last directive loaded wins).
# Values = what the legacy sec_base_modsecurity_disable.conf ran with, except
# the two marked FIX.
BASELINE=(
  "SecRequestBodyAccess On"
  "SecRequestBodyLimit 13107200"
  "SecRequestBodyNoFilesLimit 1048576"        # FIX: was 131072 -- legit JSON up to 1 MiB
  # ProcessPartial is safe ONLY with 200002 active (RESTORE): libmodsecurity v3
  # flags an over-limit body as REQBODY_ERROR and 200002 denies it (400), so a
  # payload padded past the limit is blocked. Raw PUTs (octet-stream, no body
  # processor) over 13 MB still pass, as before. Reject would also deny those
  # -- verified: 20 MB rclone/WebDAV PUT 403 under Reject, 200 here.
  "SecRequestBodyLimitAction ProcessPartial"
  "SecRequestBodyJsonDepthLimit 10000"
  "SecArgumentsLimit 100000"
  "SecPcreMatchLimit 1000000"
  "SecPcreMatchLimitRecursion 1000000"
  "SecResponseBodyAccess On"
  "SecResponseBodyLimit 524288"
  "SecResponseBodyLimitAction ProcessPartial"
  "SecResponseBodyMimeType text/plain text/html text/xml application/json application/xml application/javascript text/javascript"
  "SecAuditEngine RelevantOnly"
  "SecAuditLogParts ABFHZ"
  "SecAuditLogType Serial"
  "SecAuditLog /var/log/modsec_audit.log"
)
# CRS variables (phase-1 SecAction, before CRS so 901 keeps them). Threshold 7
# kept from legacy (CRS default 5) -- lowering it is a separate change.
BASELINE_TX="tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE MOVE MKCOL PROPFIND PROPPATCH COPY LOCK UNLOCK|tx.inbound_anomaly_score_threshold=7|tx.outbound_anomaly_score_threshold=7"

# Rules switched off for every request. "id|reason" -- kept exactly as the
# legacy sec_rule_removal.conf / sec_base_modsecurity_disable.conf ran them
# (FP fixes, hit counts from the legacy file). Narrowing each to the endpoint
# that needed it is follow-up work; --audit lists them.
GLOBAL_REMOVE=(
  "200007|too many arguments (>=1000); SecArgumentsLimit raised instead"
  "200008|not defined in current modsecurity.conf; kept for older boxes"
  "920100|invalid HTTP request line (1156 hits)"
  "920340|Content-Length > 0 without Content-Type"
  "920350|numeric Host header"
  "920420|content-type enforcement, rclone octet-stream (43 hits)"
  "920440|URL file extension restricted (23 hits)"
  "920450|Expect header"
  "920470|illegal Content-Type header (22 hits)"
  "930100|path traversal, needed for file paths (170 hits)"
  "930130|restricted file, rclone/.DS_Store (110 hits)"
  "932130|RCE unix shell expression (60 hits)"
  "932180|restricted file upload (4 hits)"
  "932260|RCE unix shell code (23 hits)"
  "933135|PHP injection (2 hits)"
  "933210|PHP injection (24 hits)"
  "934100|RFI (6 hits)"
  "934110|SSRF, OnlyOffice iframe (2 hits)"
  "934130|RFI common parameter (4 hits)"
  "934170|generic RFI (20 hits)"
  "941170|XSS libinjection (20 hits)"
  "942101|SQLi libinjection (paranoia 2 sibling)"
  "942360|SQL meta-character anomaly (54 hits)"
  "942540|SQL comment (6 hits)"
  "942550|magic quotes bypass (2 hits)"
  "950100|data leakage in downloaded files"
  "950110|data leakage in downloaded files"
  "950120|data leakage in downloaded files"
  "950130|data leakage in downloaded files"
  "950140|data leakage in downloaded files"
  "950150|data leakage in downloaded files"
  "950160|data leakage in downloaded files"
  "950170|data leakage in downloaded files"
  "950180|data leakage in downloaded files"
  "950190|data leakage in downloaded files"
  "951190|Ingres SQL information leakage"
  "953100|session fixation / PHP leakage (98 hits)"
  "953110|session fixation / PHP leakage (36 hits)"
  "956100|Ruby errors/stack traces in downloaded files"
  "956110|Ruby errors/stack traces in downloaded files"
  "956120|Ruby errors/stack traces in downloaded files"
  "956130|Ruby errors/stack traces in downloaded files"
)

# Rules that must stay active: removing any of them switches off a whole class
# of protection. Install retires legacy removals of them; --audit fails if
# anything loaded still removes them (globally).
RESTORE=(200002 200003 200004 200005)

# Legacy statements (by rule id) this patch replaces outright -- retired even
# though their old scope differs (that difference is the fix).
#   900110 thresholds, 900200 allowed methods -> BASELINE_TX
#   900210 onlyofficeds (spoofable @rx)       -> ENDPOINTS /onlyofficeds/
#   900211 business-drive octet-stream        -> ENDPOINTS /business-drive/
#   900213 only_office ARGS_NAMES             -> ENDPOINTS /document_editor/...
#   90215  localsync json.filename 942100     -> covered by RULES x FIELDS
#   900230 data leakage @rx                   -> ENDPOINTS 5 prefixes
SUPERSEDED_IDS=(900110 900200 900210 900211 900213 90215 900230)

# Legacy files (next to the ModSecurity main config) whose covered statements
# install retires. Missing files are fine (fresh nginx-mod installs).
LEGACY_FILES=(sec_actions.conf sec_rule_removal.conf sec_base_modsecurity_disable.conf)
RETIRE_MARK="#[onebox-patch retired] "
NOTE_MARK="#[onebox-patch note] "

# Rules excluded from every FIELDS entry (after CRS). Unknown ids on an older
# CRS are accepted silently by nginx -t (verified, CRS 4.29 / libmodsecurity 3).
RULES=(
  200002
  920230 920240 920270 920271 920272 920273
  932120 932125 932230 932250 932330 932340 932370 932380
  933100 933110 933120 933130 933140 933151 933160 933180
  941100 941101 941120
  942100 942101 942140 942151 942190 942290
)

# File/path/message JSON fields the Onebox app sends. Exact names only:
# libmodsecurity v3 rejects regex targets.
FIELDS=(
  json.filename json.file_name json.folderPath json.folder_path json.path
  json.data.data json.file_path_real json.file_path_temp json.path_file
  json.file_info.full_path json.file_info.display_full_path
  json.file_info.filename json.file_info.origin_filename
  json.destination_path json.err_message
  # centrifugo publish: libmodsecurity names JSON array items by position, so
  # every index must be listed. Extend if a payload ever carries >10 files.
  json.data.array_0.file_path_real json.data.array_1.file_path_real
  json.data.array_2.file_path_real json.data.array_3.file_path_real
  json.data.array_4.file_path_real json.data.array_5.file_path_real
  json.data.array_6.file_path_real json.data.array_7.file_path_real
  json.data.array_8.file_path_real json.data.array_9.file_path_real
)

# URI-prefix-scoped ctl: actions (before CRS). "prefix|action action ...".
# Never move REQUEST_FILENAME exclusions to the global list: they must stay
# URI-scoped.
# Response-side data-leakage rules off for file download paths (legacy 900230).
DATALEAK_OFF=""
for _r in 951100 951110 951120 951130 951140 951150 951160 951170 951180 951190 951200 951210 951220 \
          951230 951240 951250 951260 952100 952110 953100 953110 953120 956100 956110 956120 956130 \
          950100 950110 950120 950130 950140 950150 950160 950170 950180 950190; do
  DATALEAK_OFF+="${DATALEAK_OFF:+ }ruleRemoveById=$_r"
done
# 934190 on icon URLs inside an uploaded manifest.json (PV-2026-10-30).
MANIFEST_ICON_OFF=""
for _i in 0 1 2 3 4 5 6 7 8 9; do
  MANIFEST_ICON_OFF+="${MANIFEST_ICON_OFF:+ }ruleRemoveTargetById=934190;ARGS:json.icons.array_${_i}.src"
done
ENDPOINTS=(
  "/business-drive/|ruleRemoveById=911100 ruleRemoveById=920340 ruleRemoveTargetById=932125;REQUEST_FILENAME ruleRemoveTargetById=932380;REQUEST_FILENAME ruleRemoveById=920420 ruleRemoveById=930130 $MANIFEST_ICON_OFF"
  "/onebox_uploads/api/check_duplicate_inbox|ruleRemoveTargetById=942100;ARGS:json.header_info.Doc_remark1 ruleRemoveTargetById=942100;ARGS:json.header_info.BuyerLineTwo"
  # legacy 900210, scope FIXED (was REQUEST_URI @rx, matchable from any query
  # string). 949110 = blocking off for OnlyOffice itself -- FP follow-up open.
  "/onlyofficeds/|ruleRemoveById=934110 ruleRemoveById=949110"
  "/document_editor/api/v1/get/only_office|ruleRemoveTargetById=930120;ARGS_NAMES"
  # legacy 900230 ^/(business-drive|downloads|extension_pdfjs|build|onlyofficeds), same prefixes
  "/business-drive|$DATALEAK_OFF"
  "/downloads|$DATALEAK_OFF"
  "/extension_pdfjs|$DATALEAK_OFF"
  "/build|$DATALEAK_OFF"
  "/onlyofficeds|$DATALEAK_OFF"
)

ID_BASE=1009000
ID_MAX=1009999
MANAGED_DIR="/etc/modsecurity/onebox-patch"
MARK_BEFORE="# onebox-patch: before CRS -- managed by install-modsec-patch.sh"
MARK_AFTER="# onebox-patch: after CRS -- managed by install-modsec-patch.sh"

# ---- generation --------------------------------------------------------------
BASELINE_ID=$((ID_BASE + 900))

gen_after() {
  local targets="" f r e
  for f in "${FIELDS[@]}"; do targets+="${targets:+,}!ARGS:$f"; done
  echo "# GENERATED by install-modsec-patch.sh $PATCH_VERSION -- do NOT edit, re-run the script."
  local ids=""
  for e in "${GLOBAL_REMOVE[@]}"; do
    printf '# %s  %s\n' "${e%%|*}" "${e#*|}"
    ids+="${ids:+ }${e%%|*}"
  done
  [ -n "$ids" ] && printf 'SecRuleRemoveById %s\n' "$ids"
  for r in "${RULES[@]}"; do
    printf 'SecRuleUpdateTargetById %s "%s"\n' "$r" "$targets"
  done
}

gen_before() {
  local i=0 e prefix actions a ctl id setvars="" kv
  echo "# GENERATED by install-modsec-patch.sh $PATCH_VERSION -- do NOT edit, re-run the script."
  for e in "${BASELINE[@]}"; do echo "$e"; done
  IFS='|' read -ra _tx <<< "$BASELINE_TX"
  for kv in "${_tx[@]}"; do setvars+=",setvar:'$kv'"; done
  printf 'SecAction "id:%s,phase:1,pass,nolog,t:none%s"\n' "$BASELINE_ID" "$setvars"
  for e in "${ENDPOINTS[@]}"; do
    i=$((i + 1)); id=$((ID_BASE + i))
    prefix="${e%%|*}"; actions="${e#*|}"; ctl=""
    for a in $actions; do ctl+=",ctl:$a"; done
    printf 'SecRule REQUEST_FILENAME "@beginsWith %s" "id:%s,phase:1,pass,nolog,t:none,t:urlDecodeUni,t:normalizePath%s"\n' \
      "$prefix" "$id" "$ctl"
  done
}

# ---- big-upload guard (nginx http level) -------------------------------------
# Bodies with a Content-Length of BYPASS_MIN_DIGITS+ digits (9 = 100 MB) or
# chunked (no length) set $bypass_waf=1. A location routes those to a named
# location that runs `modsecurity_rules 'SecRequestBodyAccess Off'`. Not part
# of content_hash: it is an nginx file, not ModSecurity config.
BYPASS_MAP_FILE="/etc/nginx/conf.d/onebox-waf-bypass.conf"
BYPASS_MIN_DIGITS=9
BYPASS_MIN_BYTES=100000000
# Locations (exact prefix as written in `location`) that get the guard on install.
BYPASS_LOCATIONS=("/business-drive/")
BYPASS_MARK="# onebox-patch: nginx http-level map -- managed by install-modsec-patch.sh"

gen_bypass_map() {
  echo "$BYPASS_MARK"
  echo "# GENERATED by install-modsec-patch.sh $PATCH_VERSION -- do NOT edit, re-run the script."
  cat <<MAPEOF
map "\$http_content_length:\$http_transfer_encoding" \$bypass_waf {
    default                          0;
    "~^\d{$BYPASS_MIN_DIGITS,}:"      1;   # Content-Length >= 100 MB
    "~:chunked\$"                    1;   # no Content-Length
}
MAPEOF
}

content_hash() { { gen_before; gen_after; } | sha256sum | cut -c1-12; }
installed_hash() { cat "$MANAGED_DIR/before-crs.conf" "$MANAGED_DIR/after-crs.conf" 2>/dev/null | sha256sum | cut -c1-12; }

# One line per patch item of a managed dir: "rule N", "field F",
# "endpoint PREFIX ctl:...". Endpoint ids are positional, so they are left out
# -- a diff then shows content changes, not renumbering.
manifest() {
  local dir="$1" line prefix
  [ -f "$dir/after-crs.conf" ] && {
    awk '/^SecRuleRemoveById/ {for (i = 2; i <= NF; i++) print "global-remove " $i}' "$dir/after-crs.conf"
    awk '/^SecRuleUpdateTargetById/ {print "rule " $2}' "$dir/after-crs.conf"
    awk '/^SecRuleUpdateTargetById/ {print $3; exit}' "$dir/after-crs.conf" \
      | tr -d '"' | tr ',' '\n' | sed -n 's/^!ARGS:/field /p'
  }
  [ -f "$dir/before-crs.conf" ] && {
    grep -E '^Sec' "$dir/before-crs.conf" | grep -vE '^Sec(Rule|Action) ' | sed 's/^/setting /'
    grep -E '^SecAction ' "$dir/before-crs.conf" | grep -oE "setvar:'[^']+'" | sed "s/^setvar:'\(.*\)'$/setting \1/"
  }
  [ -f "$dir/before-crs.conf" ] && grep '^SecRule ' "$dir/before-crs.conf" | while IFS= read -r line; do
    prefix="$(grep -oP '@beginsWith \K[^"]+' <<<"$line")"
    grep -oE 'ctl:[^,"]+' <<<"$line" | sed "s|^|endpoint $prefix |"
  done
  return 0
}

# Print what changed between two managed dirs (old may not exist).
print_changes() {
  local old="$1" new="$2" prev="$3" a b
  if [ ! -f "$old/after-crs.conf" ]; then
    echo "changes: first install -- $(manifest "$new" | grep -c '^rule') rules, $(manifest "$new" | grep -c '^field') fields, $(manifest "$new" | grep -c '^endpoint') endpoint actions, $(manifest "$new" | grep -c '^global-remove') global removals, $(manifest "$new" | grep -c '^setting') baseline settings"
    return 0
  fi
  a="$(manifest "$old" | sort -u)"; b="$(manifest "$new" | sort -u)"
  if [ "$a" = "$b" ]; then
    echo "changes vs $prev: none (same exclusions)"
    return 0
  fi
  echo "changes vs $prev:"
  comm -13 <(echo "$a") <(echo "$b") | sed 's/^/  + /'
  comm -23 <(echo "$a") <(echo "$b") | sed 's/^/  - /'
}

# Read-only coverage audit. Args: "json" or "". Needs MAIN_CONF, RULES_DIR and
# the compute_status vars. Exit 0 covered, 1 gaps, 2 audit could not run.
run_audit() {
  command -v python3 >/dev/null 2>&1 || { echo "AUDIT ERROR: python3 not found -- --audit needs it" >&2; return 2; }
  # nginx -T = exactly the nginx files nginx loads (stale *.bak / sites-available
  # must not count). Empty dump -> python falls back to walking AUDIT_NGINX_DIR.
  local dump rc=0
  dump="$(mktemp)"
  nginx -T >"$dump" 2>/dev/null || : >"$dump"
  AUD_NGINX_DUMP="$dump" \
  AUD_JSON="${1:-}" AUD_MAIN_CONF="$MAIN_CONF" AUD_RULES_DIR="$RULES_DIR" AUD_MANAGED_DIR="$MANAGED_DIR" \
  AUD_PATCH_VERSION="$PATCH_VERSION" AUD_PATCH_HASH="$(content_hash)" \
  AUD_INSTALLED="$inst_pv" AUD_STATE="$state" AUD_CRS="${crs:-unknown}" AUD_THAI="$thai" \
  AUD_RULES="${RULES[*]}" AUD_FIELDS="${FIELDS[*]}" AUD_ENDPOINTS="$(printf '%s\n' "${ENDPOINTS[@]}")" \
  AUD_BASELINE="$(printf '%s\n' "${BASELINE[@]}")" AUD_BASELINE_TX="$BASELINE_TX" \
  AUD_GLOBAL_REMOVE="$(printf '%s\n' "${GLOBAL_REMOVE[@]}")" AUD_RESTORE="${RESTORE[*]}" \
  AUD_SUPERSEDED="${SUPERSEDED_IDS[*]}" AUD_LEGACY_FILES="${LEGACY_FILES[*]}" \
  AUD_RETIRE_MARK="$RETIRE_MARK" AUD_NOTE_MARK="$NOTE_MARK" AUD_MODE="${AUDIT_MODE:-audit}" \
  AUD_NGINX_DIR="${AUDIT_NGINX_DIR:-/etc/nginx}" \
  AUD_SWEEP_DIRS="${AUDIT_SWEEP_DIRS:-/etc/nginx /etc/modsecurity /etc/modsecurity.d}" \
  python3 - <<'PY_AUDIT' || rc=$?
import glob, json, os, re, socket, sys, time, traceback

# Any crash is "audit could not run" (exit 2), never a coverage verdict.
def _crash(*exc):
    traceback.print_exception(*exc)
    print("AUDIT ERROR: audit crashed -- result unknown", file=sys.stderr)
    sys.stdout.flush()
    os._exit(2)
sys.excepthook = _crash
try:
    sys.stdout.reconfigure(encoding="utf-8")
except AttributeError:
    pass

E = os.environ
MAIN, RULES_DIR, MANAGED = E["AUD_MAIN_CONF"], E["AUD_RULES_DIR"], E["AUD_MANAGED_DIR"]
real = os.path.realpath
RULES_REAL, MANAGED_REAL = real(RULES_DIR), real(MANAGED)

# ---------------------------------------------------------------- parsing
def logical_lines(path):
    """(first_line, last_line, statement): \\-continuations joined, # comments dropped."""
    out, buf, start, n = [], "", 0, 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.rstrip("\r\n")
            if not buf:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                start = n
            if line.rstrip().endswith("\\"):
                buf += line.rstrip()[:-1] + " "
                continue
            out.append((start, n, (buf + line).strip()))
            buf = ""
    if buf.strip():
        out.append((start, n, buf.strip()))
    return out

def tokens(s):
    """Whitespace split, double quotes group, \\x inside quotes -> x."""
    out, cur, inq, has, i = [], "", False, False, 0
    while i < len(s):
        c = s[i]
        if inq and c == "\\" and i + 1 < len(s):
            cur += s[i + 1]; i += 2; continue
        if c == '"':
            inq, has = not inq, True
        elif c.isspace() and not inq:
            if cur or has:
                out.append(cur)
            cur, has = "", False
        else:
            cur += c
        i += 1
    if cur or has:
        out.append(cur)
    return out

def split_actions(s):
    """Comma split that respects 'single-quoted' values (msg:'a, b')."""
    out, cur, inq = [], "", False
    for c in s:
        if c == "'":
            inq = not inq
        if c == "," and not inq:
            out.append(cur.strip()); cur = ""
        else:
            cur += c
    if cur.strip():
        out.append(cur.strip())
    return out

def id_ranges(text):
    """'932370', '932100-932200', '1 2 3' -> [(lo, hi), ...]"""
    out = []
    for p in re.split(r"[\s,]+", text.strip()):
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", p)
        if m:
            out.append((int(m.group(1)), int(m.group(2) or m.group(1))))
    return out

def in_ranges(rid, ranges):
    return ranges is None or any(lo <= rid <= hi for lo, hi in ranges)

PHASES = {"request": 2, "response": 4, "logging": 5}
def phase_of(actions):
    for a in actions:
        if a.lower().startswith("phase:"):
            v = a.split(":", 1)[1].strip().strip("'").lower()
            return int(v) if v.isdigit() else PHASES.get(v, 2)
    return 2

def is_crs_rule_file(path):
    r = real(path)
    b = os.path.basename(r)
    return r.startswith(RULES_REAL + os.sep) and re.match(r"(REQUEST|RESPONSE)-9\d\d-", b) and "EXCLUSION-RULES" not in b

# ---------------------------------------------------------------- load chain
gaps, loaded, stmts, seen = [], [], [], set()

def walk(path, depth=0):
    rp = real(path)
    if rp in seen or depth > 20:
        return
    seen.add(rp)
    try:
        lines = logical_lines(path)
    except OSError as e:
        gaps.append({"kind": "UNKNOWN", "what": "cannot read loaded file %s: %s" % (path, e.strerror)})
        return
    loaded.append(path)
    for n, n_end, text in lines:
        toks = tokens(text)
        if not toks:
            continue
        if toks[0].lower() == "include" and len(toks) > 1:
            pat = toks[1]
            if not os.path.isabs(pat):
                pat = os.path.join(os.path.dirname(path), pat)
            hits = sorted(glob.glob(pat))
            if not hits:
                gaps.append({"kind": "UNKNOWN", "what": "Include %s (%s:%d) resolves to no file" % (toks[1], path, n)})
            for h in hits:
                walk(h, depth + 1)
            continue
        stmts.append({"file": path, "line": n, "end": n_end, "toks": toks, "order": len(stmts)})

if not os.path.isfile(MAIN):
    print("AUDIT ERROR: main config %s not found" % MAIN, file=sys.stderr); sys.exit(2)
walk(MAIN)

# ---------------------------------------------------------------- rule defs + exclusions
defs = {}      # rule id -> (order, phase)
excl = []      # one per exclusion action
engine = "On"
chain_open = None

def add(st, src, kind, scope, ranges, target, risk, desc, phase=None, ctl=False, extra=""):
    excl.append({"file": st["file"], "line": st["line"], "end": st.get("end", st["line"]), "order": st["order"], "source": src,
                 "kind": kind, "scope": scope, "ranges": ranges, "target": target, "risk": risk,
                 "desc": desc, "phase": phase, "ctl": ctl})

def scope_of(toks, chained):
    if chained:
        return ("unknown", "chained rule: " + " ".join(toks[1:3]))
    if len(toks) < 3:
        return ("unknown", " ".join(toks[1:]))
    var, op = toks[1], toks[2]
    m = re.fullmatch(r"@(beginsWith|streq)\s+(\S+)", op.strip())
    if var.upper() in ("REQUEST_URI", "REQUEST_FILENAME", "REQUEST_URI_RAW") and m:
        return ("prefix" if m.group(1) == "beginsWith" else "exact", m.group(2))
    return ("unknown", "%s %s" % (var, op))

# Rules whose removal switches off a whole class of protection, not one check.
CRITICAL = {
    949110: "inbound blocking off -- nothing is denied",
    949111: "inbound blocking off -- nothing is denied",
    959100: "outbound blocking off",
    200002: "body parse errors pass -- send invalid JSON/XML and no body rule sees ARGS",
    200003: "multipart strict errors pass -- multipart evasion",
    200004: "multipart unmatched boundary passes -- multipart evasion",
    200005: "engine errors (PCRE limit hit) pass -- oversized input skips regex rules",
}

def scope_warn(toks, actions, chained):
    """Why a URI-scoped exclusion can be triggered on the wrong request."""
    if chained or len(toks) < 3 or toks[0].lower() != "secrule":
        return ""
    var, op = toks[1].upper(), toks[2].strip()
    ts = " ".join(a.lower() for a in actions)
    if var in ("REQUEST_URI", "REQUEST_URI_RAW", "REQUEST_LINE", "QUERY_STRING", "ARGS") or var.startswith("ARGS:"):
        if not (op.startswith("@beginsWith") or op.startswith("@streq") or re.match(r"@rx\s+\^", op)):
            return "SPOOFABLE: matches anywhere incl. query string (?x=...)"
    if var in ("REQUEST_URI", "REQUEST_FILENAME", "REQUEST_URI_RAW") and "normalizepath" not in ts and "normalisepath" not in ts:
        return "not path-normalized: /prefix/../other reaches other endpoints"
    return ""

for st in stmts:
    t = st["toks"]; d = t[0]; dl = d.lower()
    src = "managed" if real(st["file"]).startswith(MANAGED_REAL + os.sep) else "legacy"
    crs_def = is_crs_rule_file(st["file"])
    if dl == "secruleengine" and len(t) > 1:
        engine = t[1]
        if t[1].lower() == "off" and not crs_def:
            add(st, src, "engine", ("global", ""), None, None, "red", "SecRuleEngine Off")
        continue
    if dl in ("secrule", "secaction"):
        actions = split_actions(t[-1]) if len(t) >= (2 if dl == "secaction" else 4) else []
        chained_link = chain_open is not None
        head = chain_open or st
        if not chained_link:
            head["_phase"] = phase_of(actions)
            head["_ctls"] = []
            head["_toks"] = t
            head["_actions"] = actions
            for a in actions:
                if a.lower().startswith("id:"):
                    try:
                        defs[int(a[3:].strip().strip("'"))] = (st["order"], head["_phase"])
                    except ValueError:
                        pass
        head["_ctls"] += [a[4:] for a in actions if a.lower().startswith("ctl:")]
        has_chain = any(a.lower() == "chain" for a in actions)
        if has_chain:
            if chain_open is None:
                chain_open = st
                head["_chained"] = True
            continue
        chain_open = None
        if crs_def or not head["_ctls"]:
            continue
        if head["_toks"][0].lower() == "secaction":
            scope = ("global", "")
        else:
            scope = scope_of(head["_toks"], head.get("_chained", False))
        sdesc = {"global": "global", "prefix": "@beginsWith %s", "exact": "@streq %s"}.get(scope[0], "%s")
        sdesc = sdesc % scope[1] if "%s" in sdesc else sdesc
        if head["_toks"][0].lower() == "secrule" and scope[0] != "unknown":
            sdesc = "%s %s" % (head["_toks"][1], sdesc)
        n_before = len(excl)
        for c in head["_ctls"]:
            k, _, v = c.partition("=")
            kl = k.lower()
            if kl == "ruleengine":
                if v.lower() != "on":
                    add(head, src, "engine", scope, None, None, "red", "%s  ctl:ruleEngine=%s" % (sdesc, v), head["_phase"], True)
            elif kl == "ruleremovebyid":
                add(head, src, "rule", scope, id_ranges(v), None, "red" if scope[0] == "global" else "yellow",
                    "%s  ctl:ruleRemoveById=%s" % (sdesc, v), head["_phase"], True)
            elif kl == "ruleremovetargetbyid":
                rid, _, tgt = v.partition(";")
                add(head, src, "target", scope, id_ranges(rid), tgt, "green",
                    "%s  ctl:ruleRemoveTargetById=%s" % (sdesc, v), head["_phase"], True)
            elif kl in ("ruleremovebytag", "ruleremovebymsg", "ruleremovetargetbytag", "ruleremovetargetbymsg"):
                add(head, src, "bytag", scope, [], None, "yellow" if "target" not in kl else "green",
                    "%s  ctl:%s (not evaluated for coverage)" % (sdesc, c), head["_phase"], True)
        w = scope_warn(head["_toks"], head.get("_actions", []), head.get("_chained", False))
        for x in excl[n_before:]:
            x["warn"] = w
        continue
    if crs_def:
        continue
    if dl == "secruleremovebyid":
        add(st, src, "rule", ("global", ""), id_ranges(" ".join(t[1:])), None, "red", "global  " + " ".join(t))
    elif dl == "secruleupdatetargetbyid" and len(t) >= 3:
        for tgt in re.split(r"[,|]", t[2]):
            tgt = tgt.strip()
            if tgt.startswith("!"):
                add(st, src, "target", ("global", ""), id_ranges(t[1]), tgt[1:], "green",
                    "global  %s !%s" % (t[1], tgt[1:]))
    elif dl in ("secruleremovebytag", "secruleremovebymsg", "secruleupdatetargetbytag", "secruleupdatetargetbymsg"):
        add(st, src, "bytag", ("global", ""), [], None, "red" if "remove" in dl else "green",
            " ".join(t) + " (not evaluated for coverage)")

# No CRS rules found on the chain would make every patch rule N/A -> a false
# COVERED. That is a broken audit, not a verdict.
crs_loaded = [p for p in loaded if is_crs_rule_file(p)]
if not crs_loaded or not any(r in defs for r in map(int, E["AUD_RULES"].split())):
    print("AUDIT ERROR: no CRS rule definitions found on the Include chain from %s (rules dir %s) -- refusing to report coverage"
          % (MAIN, RULES_DIR), file=sys.stderr)
    sys.exit(2)

# Whole-rule removals that touch a CRITICAL rule are red wherever they are scoped.
for x in excl:
    x.setdefault("warn", "")
    x["critical"] = ""
    if x["kind"] == "rule":
        hit = [CRITICAL[r] for r in sorted(CRITICAL) if in_ranges(r, x["ranges"])]
        if hit:
            x["risk"], x["critical"] = "red", "; ".join(sorted(set(hit)))

# ---------------------------------------------------------------- engine settings
# Last occurrence in load order wins (CRS rule files excluded: their tx defaults
# only apply when nothing set them earlier).
SETTING_DIRECTIVES = ["SecRuleEngine", "SecRequestBodyAccess", "SecRequestBodyLimit", "SecRequestBodyNoFilesLimit",
                      "SecRequestBodyLimitAction", "SecRequestBodyJsonDepthLimit", "SecArgumentsLimit",
                      "SecPcreMatchLimit", "SecPcreMatchLimitRecursion", "SecResponseBodyAccess", "SecAuditLogParts"]
TX_SETTINGS = ["inbound_anomaly_score_threshold", "outbound_anomaly_score_threshold", "blocking_paranoia_level",
               "detection_paranoia_level", "paranoia_level"]
NOT_SETTINGS = ("secrule", "secaction", "secmarker", "secruleremovebyid", "secruleremovebytag", "secruleremovebymsg",
                "secruleupdatetargetbyid", "secruleupdatetargetbytag", "secruleupdatetargetbymsg",
                "secruleupdateactionbyid", "secdefaultaction")
P_BASELINE = [l.split(None, 1) for l in E.get("AUD_BASELINE", "").splitlines() if l.strip()]
P_BASELINE_TX = [kv.split("=", 1) for kv in E.get("AUD_BASELINE_TX", "").split("|") if "=" in kv]
CANON = {d.lower(): d for d in SETTING_DIRECTIVES + [b[0] for b in P_BASELINE]}
settings = {}
for st in stmts:
    if is_crs_rule_file(st["file"]):
        continue
    t = st["toks"]
    if t[0].lower().startswith("sec") and t[0].lower() not in NOT_SETTINGS and len(t) > 1:
        settings[CANON.get(t[0].lower(), t[0])] = (" ".join(t[1:]), "%s:%d" % (st["file"], st["line"]))
    if t[0].lower() in ("secaction", "secrule"):
        for m in re.finditer(r"setvar:'?tx\.(%s)=(\d+)" % "|".join(TX_SETTINGS), t[-1], re.I):
            settings["tx." + m.group(1).lower()] = (m.group(2), "%s:%d" % (st["file"], st["line"]))

def body_guard_active():
    """200002 loaded and not removed: over-limit bodies are denied even under ProcessPartial."""
    return 200002 in defs and not any(x["kind"] == "rule" and in_ranges(200002, x["ranges"]) for x in excl)

def setting_warn(k, v):
    try:
        n = int(v.split()[0])
    except (ValueError, IndexError):
        n = None
    if k == "SecRequestBodyLimitAction" and v.lower().startswith("processpartial") and not body_guard_active():
        return "body past the limit is NOT inspected and 200002 is off -- pad the body, put the payload after it"
    if k == "SecRuleEngine" and v.lower() != "on":
        return "not blocking"
    if k == "SecRequestBodyAccess" and v.lower() != "on":
        return "request bodies not inspected at all"
    if k in ("tx.inbound_anomaly_score_threshold",) and n and n > 5:
        return "above CRS default 5 -- one critical hit alone does not block"
    if k in ("tx.blocking_paranoia_level", "tx.paranoia_level") and n is not None and n < 1:
        return "paranoia below 1"
    return ""

# ---------------------------------------------------------------- coverage
def target_match(have, want):
    if want is None:
        return have is None
    if have is None:
        return True
    hc, _, hk = have.partition(":"); wc, _, wk = want.partition(":")
    if hc.upper() != wc.upper():
        return False
    if not hk:
        return True
    if len(hk) > 1 and hk.startswith("/") and hk.endswith("/"):
        try:
            return re.search(hk[1:-1], wk) is not None
        except re.error:
            return False
    return hk == wk

def effective(x, rid):
    if not x["ctl"]:
        return True                       # config-time directives: order-free (verified 3.0.17)
    o, ph = defs[rid]
    return x["phase"] < ph or (x["phase"] == ph and x["order"] < o)

RANK = ["FULL", "UNKNOWN", "PARTIAL", "INEFFECTIVE", "MISSING"]

def status(scope, rid, target, only=None):
    """scope: None = global, else prefix string. -> (state, [sources])"""
    if rid not in defs:
        return "N/A", []
    best, srcs = "MISSING", []
    for x in excl:
        if only and x["source"] != only:
            continue
        if x["kind"] not in ("engine", "rule", "target"):
            continue
        if x["kind"] != "engine" and not in_ranges(rid, x["ranges"]):
            continue
        # A scoped engine-off (endpoint bypass, IP whitelist) is not coverage
        # of the patch's exclusions -- it would turn every pair PARTIAL and bury
        # the real gaps. Only a global engine-off counts; all are listed red.
        if x["kind"] == "engine" and x["scope"][0] != "global":
            continue
        if x["kind"] == "target" and not target_match(x["target"], target):
            continue
        sk, sv = x["scope"]
        if sk == "global":
            st = "FULL"
        elif sk == "unknown":
            st = "UNKNOWN"
        elif scope is None:
            st = "PARTIAL"
        elif sk == "prefix" and scope.startswith(sv):
            st = "FULL"
        elif sv.startswith(scope):
            st = "PARTIAL"
        else:
            continue
        if not effective(x, rid):
            st = "INEFFECTIVE"
        if RANK.index(st) < RANK.index(best):
            best, srcs = st, []
        if st == best:
            srcs.append("%s:%d" % (x["file"], x["line"]))
    return best, srcs

P_RULES = [int(r) for r in E["AUD_RULES"].split()]
P_FIELDS = E["AUD_FIELDS"].split()
glob_items = []
for r in P_RULES:
    for f in P_FIELDS:
        s, srcs = status(None, r, "ARGS:" + f)
        glob_items.append({"rule": r, "field": f, "state": s, "sources": srcs})

ep_items = []
for e in filter(None, E["AUD_ENDPOINTS"].splitlines()):
    prefix, _, acts = e.partition("|")
    for a in acts.split():
        k, _, v = a.partition("=")
        if k == "ruleRemoveById":
            for lo, hi in id_ranges(v):
                for rid in range(lo, hi + 1):
                    s, srcs = status(prefix, rid, None)
                    ep_items.append({"prefix": prefix, "action": "ruleRemoveById=%d" % rid, "state": s, "sources": srcs})
        elif k == "ruleRemoveTargetById":
            rid, _, tgt = v.partition(";")
            s, srcs = status(prefix, int(rid), tgt)
            ep_items.append({"prefix": prefix, "action": a, "state": s, "sources": srcs})

P_GLOBAL_REMOVE = [int(l.split("|", 1)[0]) for l in E.get("AUD_GLOBAL_REMOVE", "").splitlines() if l.strip()]
P_RESTORE = [int(r) for r in E.get("AUD_RESTORE", "").split()]
gr_items = []
for rid in P_GLOBAL_REMOVE:
    s, srcs = status(None, rid, None)
    gr_items.append({"rule": rid, "state": s, "sources": srcs})

# Restored rules must not be removed by anything loaded (any scope).
restore_items = []
for rid in P_RESTORE:
    if rid not in defs:
        restore_items.append({"rule": rid, "state": "NOT-LOADED", "by": []}); continue
    by = ["%s:%d" % (x["file"], x["line"]) for x in excl
          if x["kind"] == "rule" and in_ranges(rid, x["ranges"]) and (not x["ctl"] or effective(x, rid))]
    restore_items.append({"rule": rid, "state": "REMOVED" if by else "ACTIVE", "by": by})

# Baseline settings must be the effective (last loaded) value.
def norm(v):
    return " ".join(v.split()).lower()
baseline_items = []
for b in P_BASELINE:
    name, want = CANON.get(b[0].lower(), b[0]), b[1] if len(b) > 1 else ""
    have, where = settings.get(name, ("(unset)", ""))
    baseline_items.append({"setting": name, "want": want, "have": have, "at": where, "ok": norm(have) == norm(want)})
for k, want in P_BASELINE_TX:
    key = k.lower()
    if key[3:] not in TX_SETTINGS:
        continue                          # tx.allowed_methods: string, not tracked
    have, where = settings.get(key, ("(unset)", ""))
    baseline_items.append({"setting": key, "want": want, "have": have, "at": where, "ok": norm(have) == norm(want)})

# ---------------------------------------------------------------- inline nginx rules, orphans
def nginx_files():
    """(path, [lines]) of the nginx config. Prefer the `nginx -T` dump (only
    files nginx loads); fall back to walking the nginx dir."""
    files, cur = [], None
    try:
        with open(E.get("AUD_NGINX_DUMP", ""), encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = re.match(r"# configuration file (.+):$", line.rstrip("\n"))
                if m:
                    cur = (m.group(1), []); files.append(cur)
                elif cur:
                    cur[1].append(line)
    except OSError:
        pass
    if files:
        return files, "nginx -T"
    for root, _, fns in os.walk(E["AUD_NGINX_DIR"], followlinks=True):
        for fn in fns:
            p = os.path.join(root, fn)
            try:
                with open(p, encoding="utf-8", errors="replace") as fh:
                    files.append((p, fh.readlines()))
            except OSError:
                pass
    return files, "walk of %s (nginx -T unavailable)" % E["AUD_NGINX_DIR"]

ngx_files, ngx_source = nginx_files()
for p, lines in ngx_files:
    for n, line in enumerate(lines, 1):
        s = line.strip()
        if s.startswith("#"):
            continue
        # The big-upload guard (only SecRequestBodyAccess Off, see --check-body)
        # carries no exclusion, so it is not an unknown.
        if re.match(r"modsecurity_rules\s+([\x27\x22])\s*SecRequestBodyAccess\s+Off\s*;?\s*\1\s*;", s):
            continue
        if re.match(r"modsecurity_rules(_remote)?\s", s):
            gaps.append({"kind": "UNKNOWN", "what": "inline/remote ModSecurity rules in %s:%d (not audited)" % (p, n)})
        m = re.match(r"modsecurity_rules_file\s+([^;\s]+)", s)
        if m and real(m.group(1)) != real(MAIN):
            gaps.append({"kind": "UNKNOWN", "what": "second rules file %s (%s:%d) not audited" % (m.group(1), p, n)})

EXCL_RE = re.compile(r"^(SecRuleRemoveBy|SecRuleUpdateTargetBy|SecRuleEngine\s+Off)|ctl:rule(Remove|Engine)", re.I)
loaded_real = {real(p) for p in loaded}
orphans, swept = [], set()
for d in E["AUD_SWEEP_DIRS"].split():
    for root, _, files in os.walk(d, followlinks=True):
        for fn in files:
            p = os.path.join(root, fn); rp = real(p)
            if ".conf" not in fn or rp in loaded_real or rp in swept or not os.path.isfile(rp) or os.path.getsize(rp) > 4 << 20:
                continue
            swept.add(rp)
            # A stock CRS rule file (backup copy etc.) carries its own ctl: --
            # not an exclusion anyone wrote. Custom files named like CRS lack the ver tag.
            if re.match(r"(REQUEST|RESPONSE)-9\d\d-", fn) and "EXCLUSION-RULES" not in fn:
                try:
                    with open(rp, encoding="utf-8", errors="replace") as fh:
                        if "ver:'OWASP_CRS/" in fh.read():
                            continue
                except OSError:
                    continue
            try:
                n = sum(1 for _, _, s in logical_lines(p) if EXCL_RE.search(s))
            except (OSError, UnicodeError):
                continue
            if n:
                orphans.append({"file": p, "exclusions": n})

# ---------------------------------------------------------------- verdict + output
def counts(items):
    c = {k: 0 for k in RANK + ["N/A"]}
    for i in items:
        c[i["state"]] += 1
    return c

gc, ec, grc = counts(glob_items), counts(ep_items), counts(gr_items)
for k in RANK[1:]:
    n = gc[k] + ec[k] + grc[k]
    if n:
        gaps.append({"kind": k, "what": "%d patch exclusion(s) %s" % (n, k)})
for i in restore_items:
    if i["state"] == "REMOVED":
        gaps.append({"kind": "REMOVED", "what": "rule %d must stay active but is removed by %s" % (i["rule"], ", ".join(i["by"]))})
for i in baseline_items:
    if not i["ok"]:
        gaps.append({"kind": "SETTING", "what": "%s is %s (want %s) at %s" % (i["setting"], i["have"], i["want"], i["at"] or "-")})
if E["AUD_STATE"].startswith("DRIFT"):
    gaps.append({"kind": "DRIFT", "what": "managed config hand-edited (%s)" % E["AUD_STATE"]})
covered = not gaps

def legacy_effective(x):
    """False when a ctl: exclusion can act on none of the loaded rules it names."""
    if not x["ctl"] or x["kind"] not in ("rule", "target"):
        return True
    named = [r for r in defs if in_ranges(r, x["ranges"])]
    return not named or any(effective(x, r) for r in named)

def retirable(x):
    """True when the managed config alone already gives this legacy exclusion
    the same or broader effect -- the line can be deleted from the box."""
    if x["kind"] not in ("rule", "target") or x["scope"][0] == "unknown" or not x["ranges"]:
        return False
    sk, sv = x["scope"]
    rids = [r for r in defs if in_ranges(r, x["ranges"])]
    return bool(rids) and all(status(None if sk == "global" else sv, r, x["target"], only="managed")[0] in ("FULL", "N/A") for r in rids)

legacy =[x for x in excl if x["source"] == "legacy"]
managed_n = sum(1 for x in excl if x["source"] == "managed")

# ---------------------------------------------------------------- retire mode (install)
# Comment out every statement in the legacy files that the (just written)
# managed config covers, restores, or replaces. Anything else stays active and
# is reported. Runs after the managed files are on the Include chain.
def stmt_id(t):
    m = re.search(r"(?:^|,)\s*id:'?(\d+)", t[-1]) if len(t) > 1 else None
    return int(m.group(1)) if m else None

if E.get("AUD_MODE") == "retire":
    LEG = set(E["AUD_LEGACY_FILES"].split())
    SUP = {int(i) for i in E["AUD_SUPERSEDED"].split()}
    RM, NM = E["AUD_RETIRE_MARK"], E["AUD_NOTE_MARK"]
    baseline_names = {b[0].lower() for b in P_BASELINE}
    by_stmt = {}
    for x in excl:
        by_stmt.setdefault((x["file"], x["line"]), []).append(x)
    plan, kept = {}, []
    for st in stmts:
        f, t = st["file"], st["toks"]
        if os.path.basename(f) not in LEG or real(f).startswith(MANAGED_REAL + os.sep) or is_crs_rule_file(f):
            continue
        dl, xs, why = t[0].lower(), by_stmt.get((f, st["line"]), []), None
        if dl in ("secrule", "secaction"):
            if st.get("_chained") or "_toks" not in st:
                pass                                   # chain links / chained rules: never touched
            elif stmt_id(t) in SUP:
                why = "replaced by the patch (id %d)" % stmt_id(t)
            elif xs and all(retirable(x) for x in xs):
                why = "covered by the patch"
        elif dl == "secruleremovebyid":
            rng = id_ranges(" ".join(t[1:]))
            if rng and all(hi - lo < 1000 for lo, hi in rng):
                rids = [r for lo, hi in rng for r in range(lo, hi + 1)]
                if all(r in P_RESTORE for r in rids):
                    why = "RESTORED -- rule must stay active"
                elif all(r in P_RESTORE or r in P_GLOBAL_REMOVE for r in rids):
                    why = "in GLOBAL_REMOVE"
        elif dl == "secruleupdatetargetbyid":
            if xs and all(retirable(x) for x in xs):
                why = "covered by the patch"
        elif dl in baseline_names:
            why = "baseline setting"
        if why:
            plan.setdefault(f, []).append((st["line"], st["end"], why, " ".join(t)[:110]))
        elif xs:
            kept.append((f, st["line"], " ".join(t)[:140]))
    shift = {}
    for f, items in sorted(plan.items()):
        with open(f, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        shift[f] = 0 if any(l.startswith(NM) for l in lines) else 2
        for s, e, _, _ in items:
            for i in range(s - 1, e):
                if not lines[i].startswith(RM):
                    lines[i] = RM + lines[i]
        if not any(l.startswith(NM) for l in lines):
            lines.insert(0, "%sStatements prefixed '%s' were moved into install-modsec-patch.sh (%s) and are no longer\n"
                            "%sloaded. Add new exclusions to that script, not here. --uninstall restores them.\n"
                            % (NM, RM.strip(), E["AUD_PATCH_VERSION"], NM))
        with open(f, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        print("retired %d statement(s) in %s" % (len(items), f))
        by_why = {}
        for s, _, why, txt in items:
            by_why.setdefault(why, []).append((s + shift[f], txt))
        for why, its in by_why.items():
            if len(its) <= 3:
                for s, txt in its:
                    print("    %-34s line %-4d %s" % (why, s, txt[:90]))
            else:
                print("    %-34s %d statements, lines %s" % (why, len(its), ",".join(str(s) for s, _ in its)))
    if not plan:
        print("retire: nothing to retire in legacy files (%s)" % " ".join(sorted(LEG)))
    if kept:
        print("kept active (NOT covered by the patch -- add to the script or leave):")
        for f, n, txt in kept:
            print("    %s:%d  %s" % (f, n + shift.get(f, 0), txt))
    sys.exit(0)

# One row per statement (file:line): a SecRuleUpdateTargetById with 15 fields or
# a SecRule with 36 ctl: actions is one decision, so one row.
RISKS = ["red", "yellow", "green"]
stmt_rows = {}
for x in legacy:
    stmt_rows.setdefault((x["file"], x["line"]), []).append(x)

def compact_ids(xs):
    ids = sorted({lo if lo == hi else (lo, hi) for x in xs for lo, hi in (x["ranges"] or [])},
                 key=lambda v: v if isinstance(v, int) else v[0])
    out = [str(v) if isinstance(v, int) else "%d-%d" % v for v in ids]
    return ",".join(out) if len(out) <= 6 else "%s ... %s (%d rules)" % (",".join(out[:4]), out[-1], len(out))

def row_of(xs):
    x0 = xs[0]
    risk = min((x["risk"] for x in xs), key=RISKS.index)
    kinds = {x["kind"] for x in xs}
    scope_txt = x0["desc"].split("  ")[0]
    if x0["kind"] == "engine":
        what = x0["desc"]
    elif kinds == {"target"}:
        tg = sorted({x["target"] for x in xs})
        tg_txt = ", ".join(tg) if len(tg) <= 3 else "%d targets" % len(tg)
        what = "%s  remove target %s  from %s" % (scope_txt, tg_txt, compact_ids(xs))
    elif kinds == {"rule"}:
        what = "%s  remove rule %s" % (scope_txt, compact_ids(xs))
    else:
        what = "%s  %d actions (%s)" % (scope_txt, len(xs), ", ".join(sorted(kinds)))
    n_ret = sum(1 for x in xs if retirable(x))
    eff = all(legacy_effective(x) for x in xs)
    crit = sorted({x["critical"] for x in xs if x["critical"]})
    warn = sorted({x["warn"] for x in xs if x["warn"]})
    return {"file": x0["file"], "line": x0["line"], "order": x0["order"], "risk": risk, "what": what,
            "exclusions": len(xs), "retirable": n_ret, "effective": eff, "critical": crit, "warn": warn}

rows = sorted((row_of(xs) for xs in stmt_rows.values()), key=lambda r: (RISKS.index(r["risk"]), r["order"]))
# The patch's own whole-rule removals are deliberate but still weaken the WAF:
# shown (red/yellow only -- the 800 field exclusions are not) so they stay visible.
m_rows_src = {}
for x in excl:
    if x["source"] == "managed" and x["kind"] in ("rule", "engine"):
        m_rows_src.setdefault((x["file"], x["line"]), []).append(x)
m_rows = sorted((dict(row_of(xs), retirable=0) for xs in m_rows_src.values()), key=lambda r: (RISKS.index(r["risk"]), r["order"]))
risks = []
for r in m_rows:
    for c in r["critical"]:
        risks.append("%s:%d  %s  (patch, by design)" % (r["file"], r["line"], c))
for r in rows:
    for c in r["critical"]:
        risks.append("%s:%d  %s" % (r["file"], r["line"], c))
    for w in r["warn"]:
        risks.append("%s:%d  %s" % (r["file"], r["line"], w))
for k, (v, where) in sorted(settings.items()):
    w = setting_warn(k, v)
    if w:
        risks.append("%s  %s %s -- %s" % (where, k, v, w))

report = {
    "host": socket.gethostname(), "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "latest_patch": E["AUD_PATCH_VERSION"], "latest_hash": E["AUD_PATCH_HASH"],
    "installed": E["AUD_INSTALLED"], "state": E["AUD_STATE"], "engine": engine,
    "crs": E["AUD_CRS"], "thai_fix": E["AUD_THAI"], "main_conf": MAIN, "loaded_files": loaded, "nginx_source": ngx_source,
    "global_removals": gr_items, "restored": restore_items, "baseline": baseline_items,
    "patch_rule_removals": [{k: r[k] for k in r if k != "order"} for r in m_rows],
    "coverage": {"global": gc, "endpoints": ec, "global_removals": grc,
                 "global_gaps": [i for i in glob_items if i["state"] not in ("FULL", "N/A")],
                 "endpoint_items": ep_items},
    "legacy": [{k: r[k] for k in r if k != "order"} for r in rows],
    "settings": {k: {"value": v, "at": w, "warn": setting_warn(k, v)} for k, (v, w) in settings.items()},
    "risks": risks,
    "managed_exclusions": managed_n, "orphans": orphans, "gaps": gaps,
    "result": "COVERED" if covered else "NOT COVERED",
}

if E["AUD_JSON"] == "json":
    print(json.dumps(report, ensure_ascii=False))
    sys.exit(0 if covered else 1)

ICON = {"red": "\U0001F534", "yellow": "\U0001F7E1", "green": "\U0001F7E2"}
def line_counts(c):
    return "  ".join("%s %d" % (k, c[k]) for k in ["FULL", "N/A"] + RANK[1:] if c[k] or k == "FULL")

print("ONEBOX MODSEC AUDIT  host=%s  %s" % (report["host"], report["time"]))
print("  latest patch   %s  hash %s (this script)" % (report["latest_patch"], report["latest_hash"]))
print("  installed      %s  state=%s" % (report["installed"], report["state"]))
print("  engine         SecRuleEngine %s   crs=%s  thai_fix=%s" % (engine, report["crs"], report["thai_fix"]))
print("  loaded config  %d files from %s  (nginx side: %s)" % (len(loaded), MAIN, ngx_source))
print()
print("COVERAGE of %s" % report["latest_patch"])
print("  global    %d pairs (%d rules x %d fields):  %s" % (len(glob_items), len(P_RULES), len(P_FIELDS), line_counts(gc)))
groups = {}
for i in report["coverage"]["global_gaps"]:
    groups.setdefault((i["state"], i["field"]), []).append(i["rule"])
byrules = {}
for (st, f), rules in groups.items():
    byrules.setdefault((st, tuple(rules)), []).append(f)
for (st, rules), fields in sorted(byrules.items(), key=lambda kv: RANK.index(kv[0][0])):
    rl = " ".join(map(str, rules)) if len(rules) <= 8 else "%d rules (%s ... %s)" % (len(rules), rules[0], rules[-1])
    fl = "all %d patch fields" % len(fields) if len(fields) == len(P_FIELDS) else ", ".join(fields)
    print("    %-11s %s  x  %s" % (st, rl, fl))
    if st in ("PARTIAL", "UNKNOWN", "INEFFECTIVE"):
        src = next(i["sources"] for i in report["coverage"]["global_gaps"] if i["state"] == st and i["rule"] == rules[0] and i["field"] == fields[0])
        print("                via %s" % ", ".join(src[:3]))
print("  endpoints %d actions:  %s" % (len(ep_items), line_counts(ec)))
ep_shown = {}
for i in ep_items:
    if i["state"] in ("FULL", "N/A"):
        ep_shown.setdefault((i["state"], i["prefix"]), []).append(i["action"])
    else:
        print("    %-11s %s  %s" % (i["state"], i["prefix"], i["action"]))
for (st, prefix), acts in ep_shown.items():
    print("    %-11s %s  %s" % (st, prefix, " ".join(acts) if len(acts) <= 3 else "%d actions" % len(acts)))
print("  global removals %d rules:  %s" % (len(gr_items), line_counts(grc)))
for i in gr_items:
    if i["state"] not in ("FULL", "N/A"):
        print("    %-11s %d" % (i["state"], i["rule"]))
print("  restored (must stay active): %s" % "  ".join("%d %s" % (i["rule"], i["state"]) for i in restore_items))
bad_base = [i for i in baseline_items if not i["ok"]]
print("  baseline settings %d:  %s" % (len(baseline_items), "all in effect" if not bad_base else "%d NOT in effect" % len(bad_base)))
for i in bad_base:
    print("    SETTING     %s = %s (want %s)  %s" % (i["setting"], i["have"], i["want"], i["at"]))
print()
print("ENGINE SETTINGS  (effective value, last one loaded wins)")
for k in SETTING_DIRECTIVES + ["tx." + s for s in TX_SETTINGS]:
    if k in settings:
        v, where = settings[k]
        w = setting_warn(k, v)
        print("  %s %-34s %-22s %s" % ("⚠️ " if w else "  ", k, v, where))
print()
print("PATCH WHOLE-RULE REMOVALS  %d statements (deliberate; listed so they stay visible)" % len(m_rows))
for r in m_rows:
    print("  %s %s:%d  %s%s" % (ICON[r["risk"]], r["file"], r["line"], r["what"], "  [see RISKS]" if r["critical"] else ""))
print()
print("LEGACY EXCLUSIONS  %d statements / %d exclusions (outside the managed config)" % (len(rows), len(legacy)))
for r in rows:
    flag = "" if r["effective"] else "  [INEFFECTIVE]"
    if r["retirable"] == r["exclusions"]:
        flag += "  [retire: covered by patch]"
    elif r["retirable"]:
        flag += "  [retire %d/%d: covered by patch]" % (r["retirable"], r["exclusions"])
    if r["critical"] or r["warn"]:
        flag += "  [see RISKS]"
    print("  %s %s:%d  %s%s" % (ICON[r["risk"]], r["file"], r["line"], r["what"], flag))
if risks:
    print()
    print("RISKS  (weaken the WAF for every request they match -- review each)")
    for k in risks:
        print("  ⚠️  %s" % k)
if orphans:
    print()
    print("ORPHAN FILES  exclusions on disk that nothing Includes -- no effect")
    for o in orphans:
        print("  %s  (%d exclusion statements)" % (o["file"], o["exclusions"]))
print()
if covered:
    print("RESULT: COVERED -- every %s exclusion is in effect" % report["latest_patch"])
else:
    print("RESULT: NOT COVERED")
    for g in gaps:
        print("  - [%s] %s" % (g["kind"], g["what"]))
sys.exit(0 if covered else 1)
PY_AUDIT
  rm -f "$dump"
  return "$rc"
}

if [ "${1:-}" = "--print" ]; then
  echo "### $MANAGED_DIR/before-crs.conf"; gen_before
  echo; echo "### $MANAGED_DIR/after-crs.conf"; gen_after
  echo; echo "### $PATCH_VERSION  hash $(content_hash)"
  exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root (sudo $0 ${1:-})" >&2
  exit 1
fi

# ---- locate config (same detection as install-crs-thai-fix.sh) ---------------
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
RULES_RE="^\s*Include\s+${RULES_DIR//./\\.}/\*\.conf\s*$"
INC_BEFORE="Include $MANAGED_DIR/before-crs.conf"
INC_AFTER="Include $MANAGED_DIR/after-crs.conf"

# ---- status / audit ----------------------------------------------------------------
# Sets inst_pv, state, crs, thai.
compute_status() {
  if [ -f "$MANAGED_DIR/VERSION" ]; then
    inst_pv="$(awk '{print $1}' "$MANAGED_DIR/VERSION")"
    if [ "$(installed_hash)" != "$(awk '{print $2}' "$MANAGED_DIR/VERSION")" ]; then
      state="DRIFT(hand-edited)"
    elif [ "$inst_pv" != "$PATCH_VERSION" ]; then
      state="VERSION-MISMATCH(script=$PATCH_VERSION)"
    elif [ "$(installed_hash)" != "$(content_hash)" ]; then
      state="CONTENT-MISMATCH(same version label, different lists -- bump PATCH_VERSION)"
    elif ! grep -qxF "$INC_BEFORE" "$MAIN_CONF" || ! grep -qxF "$INC_AFTER" "$MAIN_CONF"; then
      state="NOT-LOADED(include missing)"
    else
      state="OK"
    fi
  else
    inst_pv="none"; state="NOT-INSTALLED"
  fi
  crs="$(grep -ohE "ver:'OWASP_CRS/[^']+" "$RULES_DIR"/REQUEST-901-*.conf 2>/dev/null | head -1 | cut -d/ -f2 || true)"
  u8="$(awk '{ n += gsub(/t:utf8toUnicode/, "") } END { print n + 0 }' "$RULES_DIR"/*.conf)"
  [ "$u8" -eq 0 ] && thai="applied" || thai="NOT-applied($u8)"
}

# ---- big-upload guard: write the map, find unguarded locations ---------------
# Read-only. Walks `nginx -T` (brace-aware): a location is a GAP when it passes
# to a backend, ModSecurity is on for it (inherited or set), its
# client_max_body_size (own or inherited) is >= BYPASS_MIN_BYTES and nothing in
# it routes big bodies away from body inspection (a $bypass_waf test, or
# `SecRequestBodyAccess Off`). Returns 0 clean, 1 gaps, 2 could not run.
body_guard_check() {
  local dump gaps file loc bytes size
  command -v nginx >/dev/null 2>&1 || { echo "body-guard: SKIPPED -- nginx not found"; return 2; }
  dump="$(nginx -T 2>/dev/null || true)"
  [ -n "$dump" ] || { echo "body-guard: SKIPPED -- nginx -T printed nothing"; return 2; }
  gaps="$(awk -v min="$BYPASS_MIN_BYTES" '
    function bytes(v,   n, u) {
      if (v == "0") return 1e18
      n = v + 0; u = tolower(substr(v, length(v)))
      if (u == "k") n *= 1024; else if (u == "m") n *= 1048576; else if (u == "g") n *= 1073741824
      return n
    }
    function guard_all(   i) { for (i = 1; i <= d; i++) grd[i] = 1 }
    function stmt(t,   f) {
      split(t, f, /[ \t]+/)
      if (t ~ /bypass_waf/) guard_all()
      if (f[1] == "client_max_body_size") big[d] = bytes(f[2])
      else if (f[1] == "modsecurity") ms[d] = f[2]
      else if (f[1] == "modsecurity_rules" && t ~ /SecRequestBodyAccess[ \t]+Off/) grd[d] = 1
      else if (f[1] ~ /_pass$/) prx[d] = 1
    }
    /^# configuration file / { file = $4; sub(/:$/, "", file); next }
    {
      line = $0
      gsub(/"[^"]*[{}][^"]*"/, "Q", line)
      sub(/[ \t]*#.*/, "", line)
      gsub(/\{/, "\n{\n", line); gsub(/\}/, "\n}\n", line); gsub(/;/, ";\n", line)
      n = split(line, pc, "\n")
      for (i = 1; i <= n; i++) {
        t = pc[i]; gsub(/^[ \t]+|[ \t]+$/, "", t)
        if (t == "") continue
        if (t == "{") {
          d++; hdr[d] = pend; pend = ""
          ms[d] = ms[d-1]; big[d] = big[d-1]; grd[d] = 0; prx[d] = 0; src[d] = file
          if (hdr[d] ~ /bypass_waf/) guard_all()
        } else if (t == "}") {
          if (d > 0) {
            if (hdr[d] ~ /^location/ && prx[d] && ms[d] == "on" && !grd[d] && big[d] >= min)
              printf "%s|%s|%.0f\n", src[d], hdr[d], big[d]
            d--
          }
        } else if (t ~ /;$/) { sub(/;$/, "", t); stmt(t) }
        else pend = t
      }
    }' <<<"$dump" | sort -u)"
  if [ -z "$gaps" ]; then
    echo "body-guard: OK -- no location takes >= $((BYPASS_MIN_BYTES / 1000000)) MB bodies through ModSecurity unguarded"
    return 0
  fi
  while IFS='|' read -r file loc bytes; do
    if [ "$bytes" -ge 1000000000000000000 ]; then size="unlimited"; else size="$((bytes / 1000000)) MB"; fi
    echo "body-guard GAP: $loc  [$file]  client_max_body_size $size, modsecurity on, no guard"
  done <<<"$gaps"
  cat <<HINT
body-guard fix, per gap location (map \$bypass_waf comes from $BYPASS_MAP_FILE):
    error_page 418 = @<name>_nowaf;
    if (\$bypass_waf) { return 418; }
  plus a named location beside it, same proxy_pass / headers / client_max_body_size / timeouts:
    location @<name>_nowaf {
        modsecurity on;
        modsecurity_rules 'SecRequestBodyAccess Off';
        ...
    }
  (>= 100 MB bodies then skip body inspection; URI, headers and args are still checked.)
HINT
  return 1
}

# Add the guard to every BYPASS_LOCATIONS location found in the nginx config.
# Needs python3 and a loaded $bypass_waf map. Edited files are copied to
# $BAK_DIR/vhosts (MANIFEST "original|backup") for restore_backups. Prints one
# line per location: ADDED / already guarded / SKIPPED (reason). Non-zero = crash.
apply_bypass_locations() {
  local dump rc=0
  dump="$(mktemp)"
  nginx -T >"$dump" 2>/dev/null || : >"$dump"
  if ! grep -qE '^[[:space:]]*map[[:space:]].*\$bypass_waf' "$dump"; then
    echo "vhost guard: SKIPPED -- no \$bypass_waf map is loaded (see bypass map line above)"
    rm -f "$dump"; return 0
  fi
  BG_DUMP="$dump" BG_BAK="$BAK_DIR/vhosts" BG_LOCS="${BYPASS_LOCATIONS[*]}" BG_MANAGED="$BYPASS_MAP_FILE" \
  python3 - <<'PY_GUARD' || rc=$?
import os, re, shutil, sys

dump, bak, managed = os.environ["BG_DUMP"], os.environ["BG_BAK"], os.environ["BG_MANAGED"]
prefixes = os.environ["BG_LOCS"].split()
BEGIN = "# onebox-patch: guard begin (>= 100 MB bodies skip body inspection; install-modsec-patch.sh)"
END = "# onebox-patch: guard end"

text = open(dump, encoding="utf-8", errors="replace").read()
files = []
for m in re.finditer(r"^# configuration file (.+):$", text, re.M):
    if m.group(1) not in files and m.group(1) != managed:
        files.append(m.group(1))

def code(line):
    return re.sub(r"\s#.*$|^\s*#.*$", "", line)

def slug(prefix):
    return re.sub(r"[^A-Za-z0-9]+", "_", prefix).strip("_") + "_nowaf"

def backup(path):
    os.makedirs(bak, exist_ok=True)
    b = os.path.join(bak, path.replace("/", "%"))
    shutil.copy2(path, b)
    with open(os.path.join(bak, "MANIFEST"), "a") as fh:
        fh.write("%s|%s\n" % (path, b))

def process(path, prefix):
    try:
        src = open(path, encoding="utf-8").read()
    except OSError:
        return
    lines = src.split("\n")
    hdr = re.compile(r"^(\s*)location\s+(?:(?:=|\^~)\s+)?%s\s*\{\s*(?:#.*)?$" % re.escape(prefix))
    out, i, changed = [], 0, False
    name = "@" + slug(prefix)
    while i < len(lines):
        m = hdr.match(lines[i])
        if not m:
            out.append(lines[i]); i += 1; continue
        hind, depth, j = m.group(1), 0, i
        while j < len(lines):
            c = re.sub(r'"[^"]*"|\'[^\']*\'', "", code(lines[j]))
            depth += c.count("{") - c.count("}")
            if depth <= 0:
                break
            j += 1
        if j >= len(lines):
            print("vhost guard: SKIPPED %s in %s -- unbalanced braces" % (prefix, path))
            out.extend(lines[i:]); i = len(lines); break
        body = lines[i + 1:j]
        btxt = "\n".join(code(l) for l in body)
        why = None
        if "bypass_waf" in btxt:
            print("vhost guard: already guarded %s in %s" % (prefix, path)); why = "done"
        elif re.search(r"location\s+%s\b" % re.escape(name), text):
            why = "a location %s already exists" % name
        elif re.search(r"^\s*modsecurity\s+off\s*;", btxt, re.M):
            why = "modsecurity is off there"
        elif not re.search(r"^\s*proxy_pass\s", btxt, re.M):
            why = "no proxy_pass"
        elif re.search(r"^\s*limit_except\b", btxt, re.M):
            why = "limit_except cannot be copied into a named location -- add the guard by hand"
        else:
            pp = re.search(r"^\s*proxy_pass\s+(?:https?://)?[^/\s;]+(/[^\s;]*)?\s*;", btxt, re.M)
            if pp and pp.group(1):
                why = "proxy_pass has a URI part (named locations cannot) -- add the guard by hand"
        if why:
            if why != "done":
                print("vhost guard: SKIPPED %s in %s -- %s" % (prefix, path, why))
            out.extend(lines[i:j + 1]); i = j + 1; continue
        ind = re.match(r"\s*", body[0]).group(0) if body and body[0].strip() else hind + "    "
        out.append(lines[i])
        out += [ind + BEGIN, ind + "error_page 418 = %s;" % name,
                ind + "if ($bypass_waf) { return 418; }", ind + END]
        out.extend(body)
        out.append(lines[j])
        out += [hind + BEGIN, hind + "location %s {" % name,
                ind + "modsecurity on;", ind + "modsecurity_rules 'SecRequestBodyAccess Off';"]
        out.extend(l for l in body if not re.match(r"^\s*modsecurity\s+(on|off)\s*;", code(l)))
        out += [hind + "}", hind + END]
        print("vhost guard: ADDED %s in %s (named location %s)" % (prefix, path, name))
        changed = True
        i = j + 1
    if changed:
        backup(path)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(out))

for prefix in prefixes:
    found = False
    for path in files:
        try:
            if re.search(r"^\s*location\s+(?:(?:=|\^~)\s+)?%s\s*\{" % re.escape(prefix), open(path, encoding="utf-8").read(), re.M):
                found = True
                process(path, prefix)
        except OSError:
            pass
    if not found:
        print("vhost guard: %s not found in the nginx config -- nothing to guard" % prefix)
PY_GUARD
  rm -f "$dump"
  return "$rc"
}

# Install-time: write BYPASS_MAP_FILE unless nginx cannot load conf.d at http
# level or something else already defines $bypass_waf (a second map is a
# duplicate-variable error). Sets BYPASS_WRITTEN. Never fails the install: a bad
# result shows up in nginx -t and rolls back with everything else.
install_bypass_map() {
  local dump other
  dump="$(nginx -T 2>/dev/null || true)"
  if ! grep -qE "^[[:space:]]*include[[:space:]]+$(dirname "$BYPASS_MAP_FILE")/\*" <<<"$dump"; then
    echo "bypass map: SKIPPED -- nginx does not include $(dirname "$BYPASS_MAP_FILE")/*.conf at http level"
    return 0
  fi
  other="$(awk '/^# configuration file /{f=$4; sub(/:$/,"",f)} /^[[:space:]]*map[[:space:]].*\$bypass_waf/{print f; exit}' <<<"$dump")"
  if [ -n "$other" ] && [ "$other" != "$BYPASS_MAP_FILE" ]; then
    echo "bypass map: SKIPPED -- \$bypass_waf is already defined in $other (delete that map and re-run to let the script own it)"
    return 0
  fi
  gen_bypass_map > "$BYPASS_MAP_FILE"
  chmod 644 "$BYPASS_MAP_FILE"
  BYPASS_WRITTEN=1
}

if [ "${1:-}" = "--audit" ]; then
  case "${2:-}" in ""|--json) ;; *) echo "unknown option: $2 (--audit [--json])" >&2; exit 2 ;; esac
  compute_status
  rc=0; run_audit "${2:+json}" || rc=$?
  exit "$rc"
fi

if [ "${1:-}" = "--check-body" ]; then
  rc=0; body_guard_check || rc=$?
  exit "$rc"
fi

if [ "${1:-}" = "--status" ]; then
  compute_status
  # Exclusion lines outside the managed files and outside CRS's own rule files
  # (RESPONSE-999 / REQUEST-900 exclusion files are counted). -R: CRS dir is a
  # symlink on some installs.
  EXCL_RE='SecRuleUpdateTargetById|ctl:ruleRemove(Target)?ById'
  legacy="$(grep -RlE "$EXCL_RE" /etc/nginx /etc/modsecurity /etc/modsecurity.d "$RULES_DIR" 2>/dev/null | sort -u \
    | grep -v "^$MANAGED_DIR/" | grep -E '\.conf$' \
    | awk -F/ '$NF !~ /^(REQUEST|RESPONSE)-9[0-9][0-9]-/ || $NF ~ /EXCLUSION-RULES/' \
    | xargs -r cat 2>/dev/null | grep -vE '^[[:space:]]*#' | grep -cE "$EXCL_RE" || true)"
  echo "ONEBOX_PATCH host=$(hostname) installed=$inst_pv state=$state hash=$(installed_hash) crs=${crs:-unknown} thai_fix=$thai legacy_exclusion_lines=$legacy"
  exit 0
fi

# A config that already fails would make the rollback below blame this patch.
if ! nginx -t >/dev/null 2>&1; then
  echo "ERROR: nginx -t is ALREADY failing before this patch -- fix that first. Nothing changed." >&2
  nginx -t
  exit 1
fi

# ---- backups / rollback ------------------------------------------------------------
STAMP="$(date +%Y%m%d-%H%M%S)"
BAK_DIR="/var/backups/onebox-patch-$STAMP"
mkdir -p "$BAK_DIR"
cp -p "$MAIN_CONF" "$BAK_DIR/main.conf"
[ -d "$MANAGED_DIR" ] && cp -rp "$MANAGED_DIR" "$BAK_DIR/managed"
LEGACY_DIR="$(dirname "$MAIN_CONF")"
mkdir -p "$BAK_DIR/legacy"
BYPASS_WRITTEN=0
[ -f "$BYPASS_MAP_FILE" ] && cp -p "$BYPASS_MAP_FILE" "$BAK_DIR/bypass-map.conf"
for f in "${LEGACY_FILES[@]}"; do
  [ -f "$LEGACY_DIR/$f" ] && cp -p "$LEGACY_DIR/$f" "$BAK_DIR/legacy/$f"
done

restore_backups() {
  if [ -f "$BAK_DIR/vhosts/MANIFEST" ]; then
    while IFS='|' read -r orig bk; do cp -p "$bk" "$orig"; done < "$BAK_DIR/vhosts/MANIFEST"
  fi
  if [ -f "$BAK_DIR/bypass-map.conf" ]; then
    cp -p "$BAK_DIR/bypass-map.conf" "$BYPASS_MAP_FILE"
  elif [ "$BYPASS_WRITTEN" = 1 ]; then
    rm -f "$BYPASS_MAP_FILE"
  fi
  cp -p "$BAK_DIR/main.conf" "$MAIN_CONF"
  rm -rf "$MANAGED_DIR"
  [ -d "$BAK_DIR/managed" ] && cp -rp "$BAK_DIR/managed" "$MANAGED_DIR"
  for f in "${LEGACY_FILES[@]}"; do
    [ -f "$BAK_DIR/legacy/$f" ] && cp -p "$BAK_DIR/legacy/$f" "$LEGACY_DIR/$f"
  done
  return 0
}

rollback() {
  echo "nginx -t FAILED -- rolling back, nginx NOT reloaded. Backups: $BAK_DIR" >&2
  restore_backups
  exit 3
}

reload_nginx() {
  nginx -t || rollback
  systemctl reload nginx 2>/dev/null || nginx -s reload
  sleep 2
}

# ---- uninstall ---------------------------------------------------------------
if [ "${1:-}" = "--uninstall" ]; then
  sed -i -e "\\|^${MARK_BEFORE}\$|d" -e "\\|^${MARK_AFTER}\$|d" \
         -e "\\|^${INC_BEFORE}\$|d" -e "\\|^${INC_AFTER}\$|d" "$MAIN_CONF"
  rm -rf "$MANAGED_DIR"
  # Guard blocks this script added to vhosts (backed up, restorable).
  mkdir -p "$BAK_DIR/vhosts"
  for f in $(grep -rlF "# onebox-patch: guard begin" /etc/nginx 2>/dev/null || true); do
    b="$BAK_DIR/vhosts/$(echo "$f" | tr / %)"; cp -p "$f" "$b"; echo "$f|$b" >> "$BAK_DIR/vhosts/MANIFEST"
    sed -i '/# onebox-patch: guard begin/,/# onebox-patch: guard end/d' "$f"
  done
  # Only our own map; a location still using $bypass_waf makes nginx -t fail and rolls back.
  if [ -f "$BYPASS_MAP_FILE" ] && grep -qxF "$BYPASS_MARK" "$BYPASS_MAP_FILE"; then rm -f "$BYPASS_MAP_FILE"; fi
  # Bring retired legacy statements back: the box returns to its pre-patch behavior.
  for f in "${LEGACY_FILES[@]}"; do
    [ -f "$LEGACY_DIR/$f" ] || continue
    sed -i -e "/^#\\[onebox-patch note\\] /d" -e "s/^#\\[onebox-patch retired\\] //" "$LEGACY_DIR/$f"
  done
  reload_nginx
  echo "uninstalled. backups: $BAK_DIR"
  exit 0
fi

[ -n "${1:-}" ] && { echo "unknown option: $1 (see header)" >&2; exit 2; }

# Retiring legacy statements needs the audit parser.
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 not found -- install needs it (legacy retire + audit). Nothing changed." >&2; exit 1; }

# ---- preflight: managed id range must be free outside the managed files ------------
n_ep=${#ENDPOINTS[@]}
[ $((ID_BASE + n_ep)) -le "$ID_MAX" ] || { echo "ERROR: ENDPOINTS exceed id range $ID_BASE-$ID_MAX" >&2; exit 1; }
# `|| true`: zero matches is the normal case, and grep's exit 1 under pipefail
# + set -e would abort the script silently.
CLASH="$(grep -rhoE '"?id:[0-9]{7}' /etc/nginx /etc/modsecurity /etc/modsecurity.d 2>/dev/null \
  --exclude-dir="$(basename "$MANAGED_DIR")" | grep -oE '[0-9]{7}' \
  | awk -v lo="$ID_BASE" -v hi="$ID_MAX" '$1>=lo && $1<=hi' | sort -u | tr '\n' ' ' || true)"
if [ -n "$CLASH" ]; then
  echo "ERROR: ids reserved for this script already used elsewhere: $CLASH-- nothing changed." >&2
  exit 1
fi

if ! grep -qE "$RULES_RE" "$MAIN_CONF"; then
  echo "ERROR: no 'Include $RULES_DIR/*.conf' line in $MAIN_CONF -- cannot place the managed includes. Nothing changed." >&2
  exit 1
fi

# ---- write managed files -------------------------------------------------------------
PREV="$( [ -f "$MANAGED_DIR/VERSION" ] && cat "$MANAGED_DIR/VERSION" || echo none )"
mkdir -p "$MANAGED_DIR"
gen_before > "$MANAGED_DIR/before-crs.conf"
gen_after  > "$MANAGED_DIR/after-crs.conf"
echo "$PATCH_VERSION $(installed_hash)" > "$MANAGED_DIR/VERSION"
chmod 644 "$MANAGED_DIR"/*

# Include lines: before-crs right above the CRS rules Include, after-crs right below.
if ! grep -qxF "$INC_BEFORE" "$MAIN_CONF"; then
  sed -i -E "0,\\|${RULES_RE}|s||${MARK_BEFORE}\\n${INC_BEFORE}\\n&|" "$MAIN_CONF"
fi
if ! grep -qxF "$INC_AFTER" "$MAIN_CONF"; then
  sed -i -E "0,\\|${RULES_RE}|s||&\\n${MARK_AFTER}\\n${INC_AFTER}|" "$MAIN_CONF"
fi

# Comment out what the managed config now covers/replaces in the legacy files.
compute_status
rc=0; AUDIT_MODE=retire run_audit "" || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "ERROR: retiring legacy statements failed (exit $rc) -- restoring backups, nginx NOT reloaded. Backups: $BAK_DIR" >&2
  restore_backups
  exit 2
fi

install_bypass_map
apply_bypass_locations || { echo "ERROR: applying the vhost guard failed -- restoring backups, nginx NOT reloaded. Backups: $BAK_DIR" >&2; restore_backups; exit 2; }

reload_nginx

echo "installed $PATCH_VERSION (was: $PREV) -- ${#RULES[@]} rules x ${#FIELDS[@]} fields, $n_ep endpoint rules"
echo "backups: $BAK_DIR"
print_changes "$BAK_DIR/managed" "$MANAGED_DIR" "${PREV%% *}"
echo
# Installed and reloaded at this point; the audit only reports. Its exit code
# (0 covered / 1 gaps / 2 audit error) becomes the script's.
compute_status
rc=0; run_audit "" || rc=$?
echo
body_guard_check || true   # warning only; --check-body returns the status
exit "$rc"
