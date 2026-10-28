# body-guard: the >= 100 MB upload guard end to end -- map written and removed
# with the patch, install adds the guard to /business-drive/ (and leaves what it
# cannot copy alone), --check-body tells the truth, big bodies skip body
# inspection while small ones are still inspected, uninstall takes it all out.
journey_body_guard() {
  box_up legacy || return 2
  local out m=/etc/nginx/conf.d/onebox-waf-bypass.conf v=/etc/nginx/conf.d/zz-big.conf
  local attack='q=<script>alert(1)</script>&pad='
  out="$(bx 'cd /tmp && bash p.sh 2>&1; echo "EXIT=$?"')"; evidence "install (no vhost to guard)" "$out"
  check "install exit 0 (map passes nginx -t)" "~EXIT=0" "$out"
  check "map file written" present "$(bx "[ -f $m ] && echo present || echo absent")"
  check "map has the 9-digit and chunked rules" "~d\{9,\}.*chunked" "$(bx "tr '\n' ' ' < $m")"
  check "no /business-drive/ in config: reported, not an error" "~vhost guard: .*/business-drive/ not found" "$out"

  # ---- unguarded vhost: check-body sees it, install fixes it
  bx "cp /tmp/fixtures/bigupload-unguarded.conf $v; nginx -s reload"; sleep 1
  out="$(bx 'bash /tmp/p.sh --check-body; echo "EXIT=$?"')"; evidence "check-body unguarded" "$out"
  check "unguarded 5G location -> GAP, exit 1" "~body-guard GAP: location /business-drive/.*EXIT=1" "$(echo "$out" | tr '\n' ' ')"
  out="$(bx 'cd /tmp && bash p.sh 2>&1; echo "EXIT=$?"')"; evidence "install adds the guard" "$out"
  check "install exit 0" "~EXIT=0" "$out"
  check "install reports ADDED" "~vhost guard: ADDED /business-drive/ in $v" "$out"
  check "install ends with body-guard OK" "~body-guard: OK" "$out"
  check "location keeps its own settings in the named copy" "~proxy_read_timeout" "$(bx "sed -n '/location @/,/^    }/p' $v")"
  check "guard block is marker-delimited" "~guard begin.*guard end" "$(bx "tr '\n' ' ' < $v")"
  check "backup of the edited vhost taken" "~zz-big.conf" "$(bx 'ls /var/backups/onebox-patch-*/vhosts/')"
  out="$(bx 'bash /tmp/p.sh --check-body; echo "EXIT=$?"')"
  check "check-body clean after install, exit 0" "~body-guard: OK.*EXIT=0" "$(echo "$out" | tr '\n' ' ')"

  # ---- behavior: small bodies still inspected, big ones skip body inspection
  bx "{ printf '%s' '$attack'; head -c 150000000 /dev/zero | tr '\\0' A; } > /tmp/big.bin; { printf '%s' '$attack'; head -c 100000 /dev/zero | tr '\\0' A; } > /tmp/small.bin"
  out="$(http -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @/tmp/small.bin localhost:8081/business-drive/a)"
  check "small body with XSS payload -> 403 (still inspected)" 403 "$out"
  out="$(http -m 120 -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @/tmp/big.bin localhost:8081/business-drive/a)"
  check "same payload in a 150 MB body -> 200 (body inspection skipped)" 200 "$out"

  # ---- idempotent
  bx "cp $v /tmp/zz.before"
  out="$(bx 'cd /tmp && bash p.sh 2>&1; echo "EXIT=$?"')"; evidence "reinstall" "$out"
  check "reinstall exit 0" "~EXIT=0" "$out"
  check "reinstall: already guarded" "~vhost guard: already guarded /business-drive/" "$out"
  check "reinstall leaves the vhost byte-identical" same "$(bx "cmp -s $v /tmp/zz.before && echo same || echo differs")"

  # ---- hand-written guard is left alone
  bx "cp /tmp/fixtures/bigupload-guarded.conf $v; cp $v /tmp/zz.before; nginx -s reload"
  out="$(bx 'cd /tmp && bash p.sh 2>&1; echo "EXIT=$?"')"; evidence "hand-written guard" "$out"
  check "hand-written guard: already guarded, exit 0" "~already guarded.*EXIT=0" "$(echo "$out" | tr '\n' ' ')"
  check "hand-written guard untouched" same "$(bx "cmp -s $v /tmp/zz.before && echo same || echo differs")"

  # ---- cannot copy safely: reported, not edited
  bx "cp /tmp/fixtures/bigupload-uri.conf $v; cp $v /tmp/zz.before; nginx -s reload"
  out="$(bx 'cd /tmp && bash p.sh 2>&1; echo "EXIT=$?"')"; evidence "proxy_pass with URI" "$out"
  check "proxy_pass with URI: SKIPPED with reason, exit 0" "~SKIPPED /business-drive/.*URI part.*EXIT=0" "$(echo "$out" | tr '\n' ' ')"
  check "proxy_pass with URI: vhost untouched" same "$(bx "cmp -s $v /tmp/zz.before && echo same || echo differs")"
  check "proxy_pass with URI: still reported as a gap" "~body-guard GAP" "$out"

  # ---- failure rolls the vhost edit back
  bx "cp /tmp/fixtures/bigupload-unguarded.conf $v; cp $v /tmp/zz.before; nginx -s reload"
  out="$(bx "cd /tmp && sed -e 's#^ENDPOINTS=(#ENDPOINTS=(\n  \"/x|ruleRemoveById=bogus;;\"#' p.sh > bad.sh && bash bad.sh 2>&1; echo \"EXIT=\$?\"")"
  evidence "rollback with a vhost edit" "$out"
  check "nginx -t failure -> rollback exit 3" "~EXIT=3" "$out"
  check "rollback restores the vhost byte-identical" same "$(bx "cmp -s $v /tmp/zz.before && echo same || echo differs")"

  # ---- a $bypass_waf map defined elsewhere is left alone
  bx "rm -f $m $v; printf 'map \$http_content_length \$bypass_waf { default 0; }\n' > /etc/nginx/conf.d/mine.conf; nginx -s reload"
  out="$(bx 'cd /tmp && bash p.sh 2>&1; echo "EXIT=$?"')"; evidence "map defined elsewhere" "$out"
  check "foreign \$bypass_waf: install still exit 0" "~EXIT=0" "$out"
  check "foreign \$bypass_waf: skipped with the file named" "~SKIPPED.*mine.conf" "$out"
  check "foreign \$bypass_waf: our map not written" absent "$(bx "[ -f $m ] && echo present || echo absent")"
  bx 'rm -f /etc/nginx/conf.d/mine.conf; nginx -s reload'

  # ---- uninstall takes the guard out of the vhost and removes the map
  bx "cp /tmp/fixtures/bigupload-unguarded.conf $v; nginx -s reload; cd /tmp && bash p.sh >/dev/null 2>&1"
  out="$(bx 'cd /tmp && bash p.sh --uninstall 2>&1; echo "EXIT=$?"')"; evidence "uninstall" "$out"
  check "uninstall exit 0 (nginx -t passes without the map)" "~EXIT=0" "$out"
  check "uninstall removes the map" absent "$(bx "[ -f $m ] && echo present || echo absent")"
  check "uninstall restores the vhost to the original" same "$(bx "diff <(sed -e '\$a\\' $v) <(sed -e '\$a\\' /tmp/fixtures/bigupload-unguarded.conf) >/dev/null && echo same || echo differs")"
}
