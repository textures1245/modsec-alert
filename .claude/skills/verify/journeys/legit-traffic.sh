# legit-traffic: real Onebox requests that must keep working after the patch
# (each one was a reported FP or a business flow). 200 = reached the backend.
journey_legit_traffic() {
  box_up legacy || return 2
  local out
  out="$(bx 'cd /tmp && bash p.sh >/dev/null 2>&1; echo "EXIT=$?"')"
  check "install ok" "EXIT=0" "$out"
  bx "PAD=\$(head -c 500000 /dev/zero | tr '\\0' A); printf '{\"pad\":\"%s\",\"name\":\"report.pdf\"}' \"\$PAD\" > /tmp/mid.json
      head -c 20000000 /dev/urandom > /tmp/20m.bin; head -c 2000000 /dev/urandom > /tmp/2m.bin" >/dev/null

  check "500KB clean JSON" 200 "$(http -H 'Content-Type: application/json' --data-binary @/tmp/mid.json http://localhost:8080/api/v2/x)"
  check "WebDAV PROPFIND (allowed methods)" 200 "$(http -X PROPFIND http://localhost:8080/business-drive/folder/)"
  check "OnlyOffice parentOrigin URL (934110)" 200 "$(http 'http://localhost:8080/onlyofficeds/web-apps/app.html?parentOrigin=http://localhost:3000')"
  check "Thai cost-estimate path json.path_file (932370)" 200 "$(http -H 'Content-Type: application/json' -d '{"path_file":"a/Estimate&Control/b"}' http://localhost:8080/api/v2/activity)"
  check "centrifugo data.array_1.file_path_real (932370)" 200 "$(http -H 'Content-Type: application/json' -d '{"data":[{"file_path_real":"x"},{"file_path_real":"a/Estimate&Control/b"}]}' http://localhost:8080/onebox-centrifugo/api/publish)"
  # Trips 942100 + 942160 (5+5): only 942100 is excluded on this field, so it
  # scores 5 (< threshold 7) here and 10 elsewhere -- proves the exclusion is scoped.
  local sq="{\"header_info\":{\"Doc_remark1\":\"1' AND sleep(5)#\"}}"
  check "check_duplicate_inbox Doc_remark1 SQL-ish text (942100 excluded)" 200 "$(http -H 'Content-Type: application/json' -d "$sq" http://localhost:8080/onebox_uploads/api/check_duplicate_inbox)"
  check "  control: same body on another endpoint is blocked (exclusion is scoped)" 403 "$(http -H 'Content-Type: application/json' -d "$sq" http://localhost:8080/api/v2/other)"
  check "business-drive octet-stream PUT 20MB (rclone/WebDAV)" 200 "$(http -X PUT -H 'Content-Type: application/octet-stream' --data-binary @/tmp/20m.bin http://localhost:8080/business-drive/f/x.bin)"
  check "multipart upload 2MB" 200 "$(http -F file=@/tmp/2m.bin http://localhost:8080/api/v2/upload)"
  check "multipart upload 20MB denied (>13MB, by design PV-2026-10-16)" '!200' "$(http -F file=@/tmp/20m.bin http://localhost:8080/api/v2/upload)"
}
