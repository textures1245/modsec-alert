#!/usr/bin/env bash
# Drive install-modsec-patch.sh the way an operator does -- on throwaway
# docker boxes laid out like the fleet -- and record which journeys passed
# for which version of the script.
#
#   verify.sh run               journeys whose inputs changed since their last PASS (default)
#   verify.sh run --all         every journey
#   verify.sh run <journey>...  just these (names: verify.sh status)
#   verify.sh status            last result per journey + whether it is stale now
#   verify.sh doctor            is this machine ready to verify? (read-only)
#   verify.sh cleanup           remove every box any verify run left behind
#   verify.sh image [--rebuild] build the cached box image (run does it when needed)
#
# Exit: 0 all selected journeys passed (or were skipped as unchanged), 1 a
# check failed, 2 verify itself could not run.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
PATCH="$REPO/install-modsec-patch.sh"
IMAGE="onebox-verify:latest"
LABEL="onebox.verify.run"
STATE="$HERE/state/results.json"
EVID_ROOT="$HERE/evidence"

JOURNEYS=(install-coverage bypasses legit-traffic lifecycle audit-edges)
# Which parts of install-modsec-patch.sh each journey proves. A journey is
# re-run by `run` only when one of its parts (or its own journey file, the
# fixtures, or this driver) changed since its last PASS.
#   data  = PATCH_VERSION .. generators (what gets excluded / enforced)
#   audit = the embedded python (audit + legacy retire)
#   flow  = everything else (detection, install, rollback, uninstall, status)
deps_of() {
  case "$1" in
    install-coverage) echo "data audit flow" ;;
    bypasses|legit-traffic) echo "data" ;;
    lifecycle) echo "flow audit" ;;
    audit-edges) echo "audit flow" ;;
  esac
}

# ---------------------------------------------------------------- fingerprints
sha() { shasum -a 256 | cut -c1-12; }
part() {
  case "$1" in
    data)  awk '/^PATCH_VERSION=/{f=1} /^content_hash\(\)/{f=0} f' "$PATCH" ;;
    audit) awk "/python3 - <<'PY_AUDIT'/{f=1} f; /^PY_AUDIT\$/{f=0}" "$PATCH" ;;
    flow)  awk "/^PATCH_VERSION=/{d=1} /^content_hash\\(\\)/{d=0} /python3 - <<'PY_AUDIT'/{a=1} (!d && !a){print} /^PY_AUDIT\$/{a=0}" "$PATCH" ;;
  esac
}
fingerprint() {
  local j="$1" p
  {
    for p in $(deps_of "$j"); do echo "== $p"; part "$p"; done
    cat "$HERE/journeys/$j.sh" "$HERE/verify.sh" "$HERE/Dockerfile" "$HERE/stub-backend.py"
    find "$HERE/fixtures" -type f | sort | xargs cat
  } | sha
}

# ---------------------------------------------------------------- state (json via host python3)
state_get() {  # journey field
  python3 - "$STATE" "$1" "$2" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    d = {}
print(d.get(sys.argv[2], {}).get(sys.argv[3], ""))
PY
}
state_put() {  # journey fp result checks evidence
  python3 - "$STATE" "$@" "$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" <<'PY'
import json, sys
path, j, fp, result, checks, evid, commit, at = sys.argv[1:9]
try:
    d = json.load(open(path))
except (OSError, ValueError):
    d = {}
d[j] = {"fingerprint": fp, "result": result, "checks": checks, "at": at,
        "head_commit": commit, "evidence": evid}
with open(path, "w") as fh:
    json.dump(d, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
}

# ---------------------------------------------------------------- image
image_hash() { cat "$HERE/Dockerfile" "$HERE/stub-backend.py" | sha; }
ensure_image() {
  local want have
  want="$(image_hash)"
  have="$(docker image inspect "$IMAGE" --format '{{ index .Config.Labels "onebox.verify.hash" }}' 2>/dev/null || true)"
  if [ "${1:-}" = "--rebuild" ] || [ "$have" != "$want" ]; then
    echo "building $IMAGE (one-time, ~1 min)..."
    docker build -q --label "onebox.verify.hash=$want" -t "$IMAGE" "$HERE" >/dev/null || { echo "image build failed" >&2; return 2; }
  fi
}

# ---------------------------------------------------------------- boxes
# box_up legacy|fresh  -> sets BOX. legacy = /etc/nginx/modsec layout from the
# old copy-over script + EXTEEM-106 hand-additions (fixtures/); fresh = the
# image's own CRS layout, no legacy files. Originals saved in /root/orig/.
BOX_N=0
box_up() {
  local kind="$1" i code
  BOX_N=$((BOX_N + 1)); BOX="onebox-verify-$RUN_ID-$BOX_N"
  docker run -d --name "$BOX" --label "$LABEL=$RUN_ID" "$IMAGE" >/dev/null || return 2
  for i in $(seq 60); do
    code="$(docker exec "$BOX" curl -s -o /dev/null -w '%{http_code}' localhost:8080/ 2>/dev/null)"
    [ -n "$code" ] && [ "$code" != "000" ] && break; sleep 0.5
  done
  docker exec -u root -d "$BOX" python3 /opt/verify/stub-backend.py
  docker cp "$HERE/fixtures" "$BOX:/tmp/fixtures"
  docker cp "$PATCH" "$BOX:/tmp/p.sh"
  docker exec -u root "$BOX" bash -c "
    set -e
    sed -i 's#proxy_pass .*#proxy_pass http://127.0.0.1:9000;#' /etc/nginx/includes/proxy_backend.conf
    if [ '$kind' = legacy ]; then
      M=/etc/nginx/modsec; mkdir -p \$M
      cp /tmp/fixtures/legacy/*.conf \$M/
      cp -r /etc/modsecurity.d/owasp-crs \$M/coreruleset
      cp /etc/modsecurity.d/unicode.mapping \$M/
      awk '/^@@ /{f=\$2; print \"\" >> (\"/etc/nginx/modsec/\" f); next} f{print >> (\"/etc/nginx/modsec/\" f)}' /tmp/fixtures/box-additions.conf
      chmod -R a+rX \$M
      sed -i 's#modsecurity_rules_file .*#modsecurity_rules_file /etc/nginx/modsec/main.conf;#' /etc/nginx/conf.d/modsecurity.conf
      rm -f /etc/nginx/templates/conf.d/modsecurity.conf.template
      mkdir -p /root/orig; cp \$M/sec_actions.conf \$M/sec_rule_removal.conf \$M/sec_base_modsecurity_disable.conf \$M/main.conf /root/orig/
    fi
    nginx -t >/dev/null 2>&1
    nginx -s reload 2>/dev/null
  " || { echo "box setup failed: $BOX" >&2; return 2; }
  for i in $(seq 20); do
    [ "$(http localhost:8080/__ready)" = 200 ] && return 0; sleep 0.5
  done
  echo "box not ready (stub backend unreachable): $BOX" >&2; return 2
}
bx() { docker exec -u root "$BOX" bash -c "$1" 2>&1; }       # run in the box
http() { docker exec -u root "$BOX" curl -s -m 60 -o /dev/null -w '%{http_code}' "$@"; }
boxes_down() {
  local ids; ids="$(docker ps -aq --filter "label=$LABEL=${1:-$RUN_ID}")"
  [ -n "$ids" ] && docker rm -f $ids >/dev/null 2>&1; true
}

# ---------------------------------------------------------------- checks
# check NAME WANT GOT   WANT: exact | !value (anything but) | ~regex
check() {
  local n="$1" w="$2" g="$3" ok=0
  case "$w" in
    '!'*) [ "$g" != "${w#!}" ] && ok=1 ;;
    '~'*) [[ "$g" =~ ${w#\~} ]] && ok=1 ;;
    *)    [ "$g" = "$w" ] && ok=1 ;;
  esac
  CHECKS=$((CHECKS + 1))
  if [ "$ok" = 1 ]; then
    echo "PASS  $n" >>"$LOG"
  else
    FAILS=$((FAILS + 1))
    echo "FAIL  $n  (want $w, got ${g:0:200})" | tee -a "$LOG"
  fi
}
# Known, accepted state worth seeing, never a failure.
info() { echo "INFO  $*" | tee -a "$LOG"; }
# Log a command's full output as evidence (not printed).
evidence() { { echo "----- $1"; printf '%s\n' "$2"; } >>"$LOG"; }

# ---------------------------------------------------------------- commands
cmd_run() {
  local mode=changed sel=() j fp last lastfp rc=0 t0
  case "${1:-}" in
    --all) mode=all ;;
    --changed|"") ;;
    *) mode=named; sel=("$@") ;;
  esac
  [ "$mode" = named ] || sel=("${JOURNEYS[@]}")
  for j in "${sel[@]}"; do
    [ -f "$HERE/journeys/$j.sh" ] || { echo "unknown journey: $j (have: ${JOURNEYS[*]})" >&2; return 2; }
  done
  bash -n "$PATCH" || { echo "install-modsec-patch.sh has a syntax error" >&2; return 2; }
  ensure_image || return 2
  RUN_ID="$(date +%Y%m%d-%H%M%S)"; EVID="$EVID_ROOT/$RUN_ID"; mkdir -p "$EVID"
  trap 'boxes_down "$RUN_ID"' EXIT INT TERM
  echo "verify run $RUN_ID  ($mode)  evidence: ${EVID#$REPO/}"
  for j in "${sel[@]}"; do
    fp="$(fingerprint "$j")"
    lastfp="$(state_get "$j" fingerprint)"; last="$(state_get "$j" result)"
    if [ "$mode" = changed ] && [ "$fp" = "$lastfp" ] && [ "$last" = PASS ]; then
      echo "skip  $j  (unchanged since PASS at $(state_get "$j" at))"; continue
    fi
    LOG="$EVID/$j.log"; FAILS=0; CHECKS=0; t0=$(date +%s)
    # shellcheck source=/dev/null
    source "$HERE/journeys/$j.sh"
    if ! "journey_${j//-/_}"; then
      echo "ERROR $j: journey aborted (box setup?) -- see ${LOG#$REPO/}"; FAILS=$((FAILS + 1))
    fi
    boxes_down "$RUN_ID"
    if [ "$FAILS" -eq 0 ]; then
      echo "PASS  $j  $CHECKS checks  $(( $(date +%s) - t0 ))s"
      state_put "$j" "$fp" PASS "$CHECKS" "${LOG#$REPO/}"
    else
      echo "FAIL  $j  $FAILS/$CHECKS failed  $(( $(date +%s) - t0 ))s  -> ${LOG#$REPO/}"
      state_put "$j" "$fp" FAIL "$CHECKS" "${LOG#$REPO/}"; rc=1
    fi
  done
  return "$rc"
}

cmd_status() {
  local j fp
  printf '%-18s %-6s %-22s %-8s %s\n' JOURNEY RESULT AT CHECKS NOW
  for j in "${JOURNEYS[@]}"; do
    fp="$(fingerprint "$j")"
    printf '%-18s %-6s %-22s %-8s %s\n' "$j" "$(state_get "$j" result)" "$(state_get "$j" at)" \
      "$(state_get "$j" checks)" "$([ "$fp" = "$(state_get "$j" fingerprint)" ] && echo current || echo STALE)"
  done
}

cmd_doctor() {
  local bad=0
  docker info >/dev/null 2>&1 && echo "ok    docker reachable" || { echo "FAIL  docker not reachable"; bad=1; }
  command -v python3 >/dev/null && echo "ok    host python3 (state file)" || { echo "FAIL  host python3 missing"; bad=1; }
  [ -f "$PATCH" ] && bash -n "$PATCH" && echo "ok    $PATCH parses" || { echo "FAIL  $PATCH missing or does not parse"; bad=1; }
  if [ "$(docker image inspect "$IMAGE" --format '{{ index .Config.Labels "onebox.verify.hash" }}' 2>/dev/null)" = "$(image_hash)" ]; then
    echo "ok    image $IMAGE current"
  else
    echo "note  image $IMAGE missing/outdated -- run builds it (~1 min)"
  fi
  local n; n="$(docker ps -aq --filter "label=$LABEL" | wc -l | tr -d ' ')"
  [ "$n" = 0 ] && echo "ok    no leftover verify boxes" || echo "note  $n leftover verify box(es) -- verify.sh cleanup"
  return "$bad"
}

cmd_cleanup() {
  local ids; ids="$(docker ps -aq --filter "label=$LABEL")"
  [ -z "$ids" ] && { echo "no verify boxes"; return 0; }
  echo "$ids" | xargs docker rm -f >/dev/null && echo "removed $(echo "$ids" | wc -l | tr -d ' ') verify box(es); evidence kept in ${EVID_ROOT#$REPO/}/"
}

case "${1:-}" in
  run) shift; cmd_run "$@" ;;
  status) cmd_status ;;
  doctor) cmd_doctor ;;
  cleanup) cmd_cleanup ;;
  image) shift; ensure_image "${1:-}" ;;
  *) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
