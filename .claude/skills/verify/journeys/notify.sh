# notify: install / --uninstall post a Thai summary card to the Discord webhook
# (a local stub stands in for Discord). Success, failure and rollback all post;
# read-only runs and --no-notify do not; a missing or dead webhook never changes
# the exit code.
journey_notify() {
  box_up legacy || return 2
  local out hook=http://127.0.0.1:9099/hook msg n
  local last='python3 -c "import json;print(json.loads(open(\"/tmp/notify.json\").read().splitlines()[-1])[\"content\"])"'
  bx 'nohup python3 /tmp/fixtures/notify-stub.py >/dev/null 2>&1 &'; sleep 1
  bx ': > /tmp/notify.json'

  out="$(bx "cd /tmp && ONEBOX_NOTIFY_WEBHOOK=$hook bash p.sh 2>&1; echo \"EXIT=\$?\"")"; evidence "install with webhook" "$out"
  check "install exit 0" "~EXIT=0" "$out"
  check "console says it sent (Thai)" "~แจ้ง Discord: ส่งแล้ว \(HTTP 204\)" "$out"
  msg="$(bx "$last")"; evidence "card" "$msg"
  check "one post received" 1 "$(bx 'wc -l < /tmp/notify.json' | tr -d ' ')"
  check "card is an ansi block" "~^\`\`\`ansi" "$msg"
  check "card title: success (Thai)" "~ติดตั้ง Patch สำเร็จ" "$msg"
  check "card: old -> new Patch Version" "~none → PV-2026-" "$msg"
  check "card: host" "~โฮสต์ \(VM\)" "$msg"
  check "card: coverage line (Thai)" "~Coverage: ครอบคลุมครบ" "$msg"
  check "card: CHANGELOG line of this PV" "~สิ่งที่เปลี่ยนใน PV-2026-" "$msg"
  check "card under Discord's 2000-char limit" yes "$(bx "$last | python3 -c 'import sys;print(\"yes\" if len(sys.stdin.read()) < 2000 else \"no\")'")"

  out="$(bx "cd /tmp && ONEBOX_NOTIFY_WEBHOOK=$hook bash p.sh 2>&1; echo \"EXIT=\$?\"")"
  check "reinstall exit 0" "~EXIT=0" "$out"
  check "reinstall card says same version" "~ติดตั้งซ้ำ เวอร์ชันเดิม" "$(bx "$last")"

  # ---- opt-out, read-only runs, unknown option: nothing is posted
  bx ': > /tmp/notify.json'
  out="$(bx "cd /tmp && ONEBOX_NOTIFY_WEBHOOK=$hook bash p.sh --no-notify 2>&1; echo \"EXIT=\$?\"")"; evidence "--no-notify" "$out"
  check "--no-notify: exit 0, no Discord line" "~EXIT=0" "$out"
  check "--no-notify: nothing in the console about Discord" yes "$( [[ "$out" == *"แจ้ง Discord"* ]] && echo no || echo yes)"
  bx "cd /tmp && ONEBOX_NOTIFY_WEBHOOK=$hook bash p.sh --status >/dev/null 2>&1; ONEBOX_NOTIFY_WEBHOOK=$hook bash p.sh --audit >/dev/null 2>&1; ONEBOX_NOTIFY_WEBHOOK=$hook bash p.sh --check-body >/dev/null 2>&1; ONEBOX_NOTIFY_WEBHOOK=$hook bash p.sh --bogus >/dev/null 2>&1; true"
  check "no post from --no-notify, --status, --audit, --check-body, unknown option" 0 "$(bx 'wc -l < /tmp/notify.json' | tr -d ' ')"
  out="$(bx "cd /tmp && ONEBOX_NO_NOTIFY=1 ONEBOX_NOTIFY_WEBHOOK=$hook bash p.sh 2>&1; echo \"EXIT=\$?\"")"
  check "ONEBOX_NO_NOTIFY=1 posts nothing" 0 "$(bx 'wc -l < /tmp/notify.json' | tr -d ' ')"

  # ---- webhook found in the file install-alerting.sh writes
  bx "mkdir -p /etc/fail2ban/jail.d && printf '[DEFAULT]\ndiscord_webhook = $hook\n' > /etc/fail2ban/jail.d/modsec-alert.local"
  out="$(bx 'cd /tmp && bash p.sh 2>&1; echo "EXIT=$?"')"; evidence "webhook from jail file" "$out"
  check "webhook read from modsec-alert.local" 1 "$(bx 'wc -l < /tmp/notify.json' | tr -d ' ')"
  bx 'rm -f /etc/fail2ban/jail.d/modsec-alert.local'

  # ---- no webhook / dead webhook never change the outcome
  out="$(bx 'cd /tmp && bash p.sh 2>&1; echo "EXIT=$?"')"; evidence "no webhook" "$out"
  check "no webhook: skipped in Thai, exit 0" "~แจ้ง Discord: ข้าม — ไม่พบ webhook.*EXIT=0" "$(echo "$out" | tr '\n' ' ')"
  local t0=$SECONDS
  out="$(bx 'cd /tmp && ONEBOX_NOTIFY_WEBHOOK=http://127.0.0.1:9/h bash p.sh 2>&1; echo "EXIT=$?"')"; evidence "dead webhook" "$out"
  check "dead webhook: reported in Thai, exit 0" "~แจ้ง Discord: ไม่สำเร็จ.*EXIT=0" "$(echo "$out" | tr '\n' ' ')"
  check "dead webhook: install not slowed (< 15 s)" yes "$( [ $((SECONDS - t0)) -lt 15 ] && echo yes || echo no)"

  # ---- failure: rollback posts a red card with the reason
  bx ': > /tmp/notify.json'
  out="$(bx "cd /tmp && sed -e 's#^ENDPOINTS=(#ENDPOINTS=(\n  \"/x|ruleRemoveById=bogus;;\"#' p.sh > bad.sh && ONEBOX_NOTIFY_WEBHOOK=$hook bash bad.sh 2>&1; echo \"EXIT=\$?\"")"; evidence "rollback" "$out"
  check "rollback exit 3 unchanged by notify" "~EXIT=3" "$out"
  msg="$(bx "$last")"; evidence "rollback card" "$msg"
  check "rollback card (Thai, nginx -t reason)" "~nginx -t ไม่ผ่าน — rollback แล้ว" "$msg"
  check "rollback card shows the nginx -t error line" "~nginx -t FAILED" "$msg"

  # ---- uninstall
  bx ': > /tmp/notify.json'
  out="$(bx "cd /tmp && ONEBOX_NOTIFY_WEBHOOK=$hook bash p.sh --uninstall 2>&1; echo \"EXIT=\$?\"")"; evidence "uninstall" "$out"
  check "uninstall exit 0" "~EXIT=0" "$out"
  check "uninstall card (Thai)" "~ถอนการติดตั้ง Patch แล้ว" "$(bx "$last")"
}
