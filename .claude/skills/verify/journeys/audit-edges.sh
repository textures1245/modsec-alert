# audit-edges: --audit tells the truth in the states operators actually hit
# (legacy risks, drift, missing include, bad detection, inline rules, no python).
journey_audit_edges() {
  box_up legacy || return 2
  local out
  out="$(bx 'bash /tmp/p.sh --audit; echo "EXIT=$?"')"; evidence "legacy audit (pre-install)" "$out"
  check "legacy: NOT COVERED, exit 1" "~EXIT=1" "$out"
  check "legacy: spoofable onlyofficeds flagged" "~SPOOFABLE" "$out"
  check "legacy: ProcessPartial with 200002 off flagged" "~NOT inspected and 200002 is off" "$out"
  check "legacy: removed 200002 is a REMOVED gap" "~\[REMOVED\] rule 200002" "$out"
  check "legacy: CRS stock files not reported as orphans" "" "$(echo "$out" | grep -E '^  .*/REQUEST-9[0-9]{2}-.*exclusion statements' | grep -v EXCLUSION)"

  bx 'cd /tmp && bash p.sh >/dev/null 2>&1' >/dev/null
  out="$(bx 'echo "# hand edit" >> /etc/modsecurity/onebox-patch/after-crs.conf; bash /tmp/p.sh --audit; echo "EXIT=$?"; sed -i "\$d" /etc/modsecurity/onebox-patch/after-crs.conf')"
  evidence "drift" "$out"
  check "hand-edited managed file -> DRIFT, exit 1" "~\[DRIFT\].*EXIT=1" "$(echo "$out" | tr '\n' ' ')"

  out="$(bx 'M=/etc/nginx/modsec/main.conf; cp $M /tmp/m.bak; sed -i "\|Include /etc/modsecurity/onebox-patch/after-crs.conf|d" $M; bash /tmp/p.sh --audit; echo "EXIT=$?"; cp /tmp/m.bak $M')"
  evidence "include removed" "$out"
  check "managed include missing -> NOT-LOADED + MISSING, exit 1" "~NOT-LOADED.*\[MISSING\].*EXIT=1" "$(echo "$out" | tr '\n' ' ')"

  out="$(bx 'CRS_RULES_DIR=/tmp bash /tmp/p.sh --audit; echo "EXIT=$?"')"
  check "no CRS on chain -> refuses (exit 2), never false COVERED" "~EXIT=2" "$out"

  out="$(bx 'printf "modsecurity_rules %s;\n" "\"SecRuleEngine On\"" > /etc/nginx/conf.d/zz.conf.disabled; bash /tmp/p.sh --audit; echo "EXIT=$?"; rm /etc/nginx/conf.d/zz.conf.disabled')"
  check "inline rules in a file nginx does not load -> ignored, exit 0" "~EXIT=0" "$out"
  out="$(bx 'printf "modsecurity_rules %s;\n" "\"SecRuleEngine On\"" > /etc/nginx/conf.d/zz-inline.conf; nginx -s reload; bash /tmp/p.sh --audit; echo "EXIT=$?"; rm /etc/nginx/conf.d/zz-inline.conf; nginx -s reload')"
  check "inline rules nginx loads -> UNKNOWN gap, exit 1" "~inline/remote ModSecurity rules.*EXIT=1" "$(echo "$out" | tr '\n' ' ')"

  out="$(bx 'mv /usr/bin/python3 /usr/bin/python3.x; bash /tmp/p.sh --audit; echo "EXIT=$?"; mv /usr/bin/python3.x /usr/bin/python3')"
  check "no python3 -> audit error exit 2" "~EXIT=2" "$out"
  out="$(bx 'bash /tmp/p.sh --audit; echo "EXIT=$?"')"
  check "box back to COVERED after edge cases" "~EXIT=0" "$out"
}
