# install-coverage: operator installs the patch on a legacy-layout box
# (EXTEEM-106-like). Smoke for every part of the script -- re-runs on any change.
journey_install_coverage() {
  box_up legacy || return 2
  local out rc
  out="$(bx 'cd /tmp && bash p.sh; echo "EXIT=$?"')"; evidence "install" "$out"
  check "install exits 0 (installed + covered)" "~EXIT=0" "$out"
  check "legacy statements retired" "~retired [0-9]+ statement" "$out"
  check "200002 removal retired (RESTORED)" "~RESTORED -- rule must stay active" "$out"
  check "uncovered legacy stmt kept + reported (920640 business-drive)" "~kept active.*id:1000010" "$(echo "$out" | tr '\n' ' ')"
  check "install prints change summary" "~changes: first install" "$out"

  out="$(bx 'bash /tmp/p.sh --audit; echo "EXIT=$?"')"; evidence "audit" "$out"
  check "audit exit 0" "~EXIT=0" "$out"
  check "audit RESULT COVERED" "~RESULT: COVERED" "$out"
  check "global pairs all FULL" "~global +[0-9]+ pairs.*FULL [0-9]+$" "$(echo "$out" | grep -m1 'global .*pairs')"
  check "restored 200002-200005 ACTIVE" "~200002 ACTIVE  200003 ACTIVE  200004 ACTIVE  200005 ACTIVE" "$out"
  check "baseline settings all in effect" "~baseline settings [0-9]+:  all in effect" "$out"
  check "no ProcessPartial warning once 200002 is active" "" "$(echo "$out" | grep 'LimitAction' | grep -o 'NOT inspected')"

  out="$(bx 'bash /tmp/p.sh --audit --json | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[\"result\"], d[\"installed\"])"')"
  evidence "audit --json" "$out"
  check "--audit --json parses, COVERED" "~^COVERED PV-" "$out"

  check "smoke: XSS in query still 403" 403 "$(http 'http://localhost:8080/api/v2/x?q=<script>alert(1)</script>')"
  check "smoke: Thai cost-estimate path passes" 200 "$(http -H 'Content-Type: application/json' -d '{"path_file":"a/Estimate&Control/b"}' http://localhost:8080/api/v2/activity)"
}
