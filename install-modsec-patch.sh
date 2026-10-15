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
#   $MANAGED_DIR/after-crs.conf   SecRuleUpdateTargetById for every RULES x FIELDS
#                                 pair, generated -- never hand-edit, never paste
#   $MANAGED_DIR/before-crs.conf  URI-scoped ctl: rules, ids 1009000-1009999
#   $MANAGED_DIR/VERSION          installed PATCH_VERSION + content hash
#   two Include lines in the ModSecurity main config, around the CRS rules Include
# Hand-maintained exclusions (sec_actions.conf, RESPONSE-999-*.conf,
# sec_rule_removal.conf, install-modsec-whitelist.sh output) are left alone;
# duplicates of the same target removal are harmless (target updates
# accumulate, verified libmodsecurity 3.0.17). --status counts them and
# --audit lists them so they can be retired box by box.
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
#   ./install-modsec-patch.sh --print     print the generated config, change nothing
#   ./install-modsec-patch.sh --uninstall remove the managed files + Include lines
#   MODSEC_MAIN_CONF=... CRS_RULES_DIR=... ./install-modsec-patch.sh   (override detection)
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

PATCH_VERSION="PV-2026-10-15"

CHANGELOG=(
  "PV-2026-10-13  First script-managed version. Global field list = tracker canonical (2026-08-17) + 932125/932380/932370/942140. /business-drive/: 911100+920340 whole-rule (tracker id 1000010, minus 920640: not canonical per Document) + 932125/932380 off REQUEST_FILENAME. check_duplicate_inbox 942100 fields (POST-method chain dropped)."
  "PV-2026-10-15  FIELDS += json.data.array_0..9.file_path_real (POST /onebox-centrifugo/api/publish, 932370 on Thai cost-estimate path, unique_id 179207345281.765841, EXTEEM-106)."
)

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
ENDPOINTS=(
  "/business-drive/|ruleRemoveById=911100 ruleRemoveById=920340 ruleRemoveTargetById=932125;REQUEST_FILENAME ruleRemoveTargetById=932380;REQUEST_FILENAME"
  "/onebox_uploads/api/check_duplicate_inbox|ruleRemoveTargetById=942100;ARGS:json.header_info.Doc_remark1 ruleRemoveTargetById=942100;ARGS:json.header_info.BuyerLineTwo"
)

ID_BASE=1009000
ID_MAX=1009999
MANAGED_DIR="/etc/modsecurity/onebox-patch"
MARK_BEFORE="# onebox-patch: before CRS -- managed by install-modsec-patch.sh"
MARK_AFTER="# onebox-patch: after CRS -- managed by install-modsec-patch.sh"

# ---- generation --------------------------------------------------------------
gen_after() {
  local targets="" f r
  for f in "${FIELDS[@]}"; do targets+="${targets:+,}!ARGS:$f"; done
  echo "# GENERATED by install-modsec-patch.sh $PATCH_VERSION -- do NOT edit, re-run the script."
  for r in "${RULES[@]}"; do
    printf 'SecRuleUpdateTargetById %s "%s"\n' "$r" "$targets"
  done
}

gen_before() {
  local i=0 e prefix actions a ctl id
  echo "# GENERATED by install-modsec-patch.sh $PATCH_VERSION -- do NOT edit, re-run the script."
  for e in "${ENDPOINTS[@]}"; do
    i=$((i + 1)); id=$((ID_BASE + i))
    prefix="${e%%|*}"; actions="${e#*|}"; ctl=""
    for a in $actions; do ctl+=",ctl:$a"; done
    printf 'SecRule REQUEST_FILENAME "@beginsWith %s" "id:%s,phase:1,pass,nolog,t:none,t:urlDecodeUni,t:normalizePath%s"\n' \
      "$prefix" "$id" "$ctl"
  done
}

content_hash() { { gen_before; gen_after; } | sha256sum | cut -c1-12; }
installed_hash() { cat "$MANAGED_DIR/before-crs.conf" "$MANAGED_DIR/after-crs.conf" 2>/dev/null | sha256sum | cut -c1-12; }

# One line per patch item of a managed dir: "rule N", "field F",
# "endpoint PREFIX ctl:...". Endpoint ids are positional, so they are left out
# -- a diff then shows content changes, not renumbering.
manifest() {
  local dir="$1" line prefix
  [ -f "$dir/after-crs.conf" ] && {
    awk '/^SecRuleUpdateTargetById/ {print "rule " $2}' "$dir/after-crs.conf"
    awk '/^SecRuleUpdateTargetById/ {print $3; exit}' "$dir/after-crs.conf" \
      | tr -d '"' | tr ',' '\n' | sed -n 's/^!ARGS:/field /p'
  }
  [ -f "$dir/before-crs.conf" ] && grep '^SecRule' "$dir/before-crs.conf" | while IFS= read -r line; do
    prefix="$(grep -oP '@beginsWith \K[^"]+' <<<"$line")"
    grep -oE 'ctl:[^,"]+' <<<"$line" | sed "s|^|endpoint $prefix |"
  done
  return 0
}

# Print what changed between two managed dirs (old may not exist).
print_changes() {
  local old="$1" new="$2" prev="$3" a b
  if [ ! -f "$old/after-crs.conf" ]; then
    echo "changes: first install -- $(manifest "$new" | grep -c '^rule') rules, $(manifest "$new" | grep -c '^field') fields, $(manifest "$new" | grep -c '^endpoint') endpoint actions"
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
    """(lineno, statement) with \\-continuations joined and # comments dropped."""
    out, buf, start = [], "", 0
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
            out.append((start, (buf + line).strip()))
            buf = ""
    if buf.strip():
        out.append((start, buf.strip()))
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
    for n, text in lines:
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
        stmts.append({"file": path, "line": n, "toks": toks, "order": len(stmts)})

if not os.path.isfile(MAIN):
    print("AUDIT ERROR: main config %s not found" % MAIN, file=sys.stderr); sys.exit(2)
walk(MAIN)

# ---------------------------------------------------------------- rule defs + exclusions
defs = {}      # rule id -> (order, phase)
excl = []      # one per exclusion action
engine = "On"
chain_open = None

def add(st, src, kind, scope, ranges, target, risk, desc, phase=None, ctl=False, extra=""):
    excl.append({"file": st["file"], "line": st["line"], "order": st["order"], "source": src,
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
        continue
    if crs_def:
        continue
    if dl == "secruleremovebyid":
        add(st, src, "rule", ("global", ""), id_ranges(" ".join(t[1:])), None, "red", " ".join(t))
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
            try:
                n = sum(1 for _, s in logical_lines(p) if EXCL_RE.search(s))
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

gc, ec = counts(glob_items), counts(ep_items)
bad = lambda c: sum(v for k, v in c.items() if k not in ("FULL", "N/A"))
for k in RANK[1:]:
    n = gc[k] + ec[k]
    if n:
        gaps.append({"kind": k, "what": "%d patch exclusion(s) %s" % (n, k)})
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

report = {
    "host": socket.gethostname(), "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "latest_patch": E["AUD_PATCH_VERSION"], "latest_hash": E["AUD_PATCH_HASH"],
    "installed": E["AUD_INSTALLED"], "state": E["AUD_STATE"], "engine": engine,
    "crs": E["AUD_CRS"], "thai_fix": E["AUD_THAI"], "main_conf": MAIN, "loaded_files": loaded, "nginx_source": ngx_source,
    "coverage": {"global": gc, "endpoints": ec,
                 "global_gaps": [i for i in glob_items if i["state"] not in ("FULL", "N/A")],
                 "endpoint_items": ep_items},
    "legacy": [dict({k: x[k] for k in ("file", "line", "risk", "kind", "desc")}, effective=legacy_effective(x), retirable=retirable(x)) for x in legacy],
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
for i in ep_items:
    via = "" if i["state"] in ("MISSING", "N/A") else "  via " + ", ".join(i["sources"][:2])
    print("    %-11s %s  %s%s" % (i["state"], i["prefix"], i["action"], via))
print()
print("LEGACY EXCLUSIONS  %d (outside the managed config; %d managed exclusions not listed)" % (len(legacy), managed_n))
for x, j in sorted(zip(legacy, report["legacy"]), key=lambda p: (["red", "yellow", "green"].index(p[0]["risk"]), p[0]["order"])):
    flag = ("" if j["effective"] else "  [INEFFECTIVE]") + ("  [retire: covered by patch]" if j["retirable"] else "")
    print("  %s %s:%d  %s%s" % (ICON[x["risk"]], x["file"], x["line"], x["desc"], flag))
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

if [ "${1:-}" = "--audit" ]; then
  case "${2:-}" in ""|--json) ;; *) echo "unknown option: $2 (--audit [--json])" >&2; exit 2 ;; esac
  compute_status
  rc=0; run_audit "${2:+json}" || rc=$?
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

rollback() {
  echo "nginx -t FAILED -- rolling back, nginx NOT reloaded. Backups: $BAK_DIR" >&2
  cp -p "$BAK_DIR/main.conf" "$MAIN_CONF"
  rm -rf "$MANAGED_DIR"
  [ -d "$BAK_DIR/managed" ] && cp -rp "$BAK_DIR/managed" "$MANAGED_DIR"
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
  reload_nginx
  echo "uninstalled. backups: $BAK_DIR"
  exit 0
fi

[ -n "${1:-}" ] && { echo "unknown option: $1 (see header)" >&2; exit 2; }

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

reload_nginx

echo "installed $PATCH_VERSION (was: $PREV) -- ${#RULES[@]} rules x ${#FIELDS[@]} fields, $n_ep endpoint rules"
echo "backups: $BAK_DIR"
print_changes "$BAK_DIR/managed" "$MANAGED_DIR" "${PREV%% *}"
echo
# Installed and reloaded at this point; the audit only reports. Its exit code
# (0 covered / 1 gaps / 2 audit error) becomes the script's.
compute_status
rc=0; run_audit "" || rc=$?
exit "$rc"
