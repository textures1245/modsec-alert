# body-guard: the >= 100 MB upload guard -- map written and removed with the
# patch, --check-body finds unguarded locations, a guarded location sends big
# bodies (Content-Length >= 9 digits) to the no-body-inspection route and
# small ones through ModSecurity as before.
journey_body_guard() {
  box_up legacy || return 2
  local out m=/etc/nginx/conf.d/onebox-waf-bypass.conf
  out="$(bx 'cd /tmp && bash p.sh 2>&1; echo "EXIT=$?"')"; evidence "install" "$out"
  check "install exit 0 (map passes nginx -t)" "~EXIT=0" "$out"
  check "map file written" present "$(bx "[ -f $m ] && echo present || echo absent")"
  check "map has the 9-digit and chunked rules" "~d\{9,\}.*chunked" "$(bx "tr '\n' ' ' < $m")"
  check "install ends with body-guard OK" "~body-guard: OK" "$out"

  bx 'cp /tmp/fixtures/bigupload-unguarded.conf /etc/nginx/conf.d/zz-big.conf; nginx -s reload'; sleep 1
  out="$(bx 'bash /tmp/p.sh --check-body; echo "EXIT=$?"')"; evidence "check-body unguarded" "$out"
  check "unguarded 5G location -> GAP, exit 1" "~body-guard GAP: location /big/.*EXIT=1" "$(echo "$out" | tr '\n' ' ')"
  check "gap output tells how to fix" "~error_page 418" "$out"

  bx 'cp /tmp/fixtures/bigupload-guarded.conf /etc/nginx/conf.d/zz-big.conf; nginx -s reload'; sleep 1
  out="$(bx 'bash /tmp/p.sh --check-body; echo "EXIT=$?"')"; evidence "check-body guarded" "$out"
  check "guarded location -> clean, exit 0" "~body-guard: OK.*EXIT=0" "$(echo "$out" | tr '\n' ' ')"

  bx 'head -c 150000000 /dev/zero > /tmp/big.bin; head -c 1000000 /dev/zero > /tmp/small.bin'
  out="$(bx "curl -s -m 120 -D - -o /dev/null -X PUT -H 'Content-Type: application/octet-stream' --data-binary @/tmp/big.bin http://localhost:8081/big/a")"
  evidence "150 MB PUT" "$out"
  check "150 MB PUT -> 200 via no-body-inspection route" "~200.*[Xx]-[Rr]oute: nowaf" "$(echo "$out" | tr '\n' ' ')"
  out="$(bx "curl -s -m 60 -D - -o /dev/null -X PUT -H 'Content-Type: application/octet-stream' --data-binary @/tmp/small.bin http://localhost:8081/big/a")"
  evidence "1 MB PUT" "$out"
  check "1 MB PUT -> 200, normal route (no nowaf header)" "200" "$(echo "$out" | head -1 | grep -o 200)"
  check "1 MB PUT does not take the bypass route" "" "$(echo "$out" | grep -i 'x-route')"

  # re-install: map unchanged, nothing else to report
  out="$(bx 'cd /tmp && bash p.sh 2>&1; echo "EXIT=$?"')"; evidence "reinstall" "$out"
  check "reinstall exit 0" "~EXIT=0" "$out"

  # a $bypass_waf map defined elsewhere is left alone
  bx "rm -f $m /etc/nginx/conf.d/zz-big.conf; printf 'map \$http_content_length \$bypass_waf { default 0; }\n' > /etc/nginx/conf.d/mine.conf; nginx -s reload"
  out="$(bx 'cd /tmp && bash p.sh 2>&1; echo "EXIT=$?"')"; evidence "map defined elsewhere" "$out"
  check "foreign \$bypass_waf: install still exit 0" "~EXIT=0" "$out"
  check "foreign \$bypass_waf: skipped with the file named" "~SKIPPED.*mine.conf" "$out"
  check "foreign \$bypass_waf: our map not written" absent "$(bx "[ -f $m ] && echo present || echo absent")"
  bx 'rm -f /etc/nginx/conf.d/mine.conf; nginx -s reload'

  # uninstall removes only our map
  bx 'cd /tmp && bash p.sh >/dev/null 2>&1'
  out="$(bx 'cd /tmp && bash p.sh --uninstall 2>&1; echo "EXIT=$?"')"; evidence "uninstall" "$out"
  check "uninstall exit 0" "~EXIT=0" "$out"
  check "uninstall removes the map" absent "$(bx "[ -f $m ] && echo present || echo absent")"
}
