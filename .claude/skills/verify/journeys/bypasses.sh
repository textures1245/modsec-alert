# bypasses: the WAF bypasses PV-2026-10-16 closed stay closed. Each was
# confirmed working against the legacy config before the fix (200 = through).
journey_bypasses() {
  box_up legacy || return 2
  local out X='<script>alert(1)</script>'
  out="$(bx 'cd /tmp && bash p.sh >/dev/null 2>&1; echo "EXIT=$?"')"
  check "install ok" "EXIT=0" "$out"
  bx "PAD=\$(head -c 140000 /dev/zero | tr '\\0' A); printf '{\"pad\":\"%s\",\"q\":\"%s\"}' \"\$PAD\" '$X' > /tmp/big.json
      PAD=\$(head -c 1100000 /dev/zero | tr '\\0' A); printf '{\"pad\":\"%s\",\"q\":\"%s\"}' \"\$PAD\" '$X' > /tmp/huge.json
      printf 'pad=%s&q=%%3Cscript%%3Ealert(1)%%3C%%2Fscript%%3E' \"\$PAD\" > /tmp/form.txt" >/dev/null

  check "A  ?z=/onlyofficeds/ spoof + XSS blocked" 403 "$(http "http://localhost:8080/api/v2/x?z=/onlyofficeds/&q=$X")"
  check "B  XSS after 140KB pad (valid JSON) blocked" '!200' "$(http -H 'Content-Type: application/json' --data-binary @/tmp/big.json http://localhost:8080/api/v2/x)"
  check "B2 XSS after 1.1MB pad (JSON) blocked" '!200' "$(http -H 'Content-Type: application/json' --data-binary @/tmp/huge.json http://localhost:8080/api/v2/x)"
  check "F  XSS after 1.1MB pad (form) blocked" '!200' "$(http -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @/tmp/form.txt http://localhost:8080/api/v2/x)"
  check "C  JSON broken at byte 0 + XSS blocked" '!200' "$(http -H 'Content-Type: application/json' -d "]{\"q\":\"$X\"}" http://localhost:8080/api/v2/x)"
  check "D  /onlyofficeds/ prefix does not leak to /onlyofficedsX" 403 "$(http "http://localhost:8080/onlyofficedsX/a?q=$X")"

  # Known open gap (decision pending: 920640 into ENDPOINTS?). The kept legacy
  # line 1000010 is not path-normalized, so /business-drive/../ sheds 911100.
  local t; t="$(http -X FOO --path-as-is 'http://localhost:8080/business-drive/../api/v2/x')"
  [ "$t" = 403 ] && info "E  traversal via kept legacy 1000010 now blocked (gap closed?)" \
                 || info "E  traversal via kept legacy 1000010 still passes ($t) -- open: 920640 decision"
}
