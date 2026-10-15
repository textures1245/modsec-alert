# lifecycle: install / repatch / uninstall / rollback / upgrade / fresh box --
# the operator paths that change files on a box. Must be reversible.
journey_lifecycle() {
  box_up legacy || return 2
  local out f
  out="$(bx 'cd /tmp && bash p.sh 2>&1; echo "EXIT=$?"')"; evidence "install" "$out"
  check "install exit 0" "~EXIT=0" "$out"
  out="$(bx 'cd /tmp && bash p.sh 2>&1; echo "EXIT=$?"')"; evidence "repatch" "$out"
  check "repatch exit 0" "~EXIT=0" "$out"
  check "repatch retires nothing new" "~nothing to retire" "$out"
  check "repatch: no exclusion changes" "~changes vs PV-[0-9-]+: none" "$out"

  out="$(bx 'cd /tmp && bash p.sh --uninstall 2>&1; echo "EXIT=$?"')"; evidence "uninstall" "$out"
  check "uninstall exit 0" "~EXIT=0" "$out"
  for f in sec_actions.conf sec_rule_removal.conf sec_base_modsecurity_disable.conf main.conf; do
    check "uninstall restores $f byte-identical" same "$(bx "cmp -s /etc/nginx/modsec/$f /root/orig/$f && echo same || echo differs")"
  done
  check "uninstall removes managed dir" absent "$(bx '[ -d /etc/modsecurity/onebox-patch ] && echo present || echo absent')"

  out="$(bx "cd /tmp && sed -e 's#^ENDPOINTS=(#ENDPOINTS=(\n  \"/x|ruleRemoveById=bogus;;\"#' p.sh > bad.sh && bash bad.sh 2>&1; echo \"EXIT=\$?\"")"
  evidence "rollback (bogus endpoint)" "$out"
  check "nginx -t failure -> rollback exit 3" "~EXIT=3" "$out"
  check "rollback ran after retire (worst case)" "~retired [0-9]+ statement" "$out"
  for f in sec_actions.conf sec_rule_removal.conf sec_base_modsecurity_disable.conf main.conf; do
    check "rollback restores $f byte-identical" same "$(bx "cmp -s /etc/nginx/modsec/$f /root/orig/$f && echo same || echo differs")"
  done
  check "rollback leaves no managed dir" absent "$(bx '[ -d /etc/modsecurity/onebox-patch ] && echo present || echo absent')"

  # Upgrade from the last committed script (what boxes run today).
  if git -C "$REPO" show HEAD:install-modsec-patch.sh >"$EVID/committed-install-modsec-patch.sh" 2>/dev/null \
     && ! cmp -s "$EVID/committed-install-modsec-patch.sh" "$PATCH"; then
    docker cp "$EVID/committed-install-modsec-patch.sh" "$BOX:/tmp/old.sh"
    out="$(bx 'cd /tmp && bash old.sh 2>&1; echo "OLD_EXIT=$?"; bash p.sh 2>&1; echo "EXIT=$?"')"; evidence "upgrade HEAD -> working tree" "$out"
    check "committed version installs" "~OLD_EXIT=0" "$out"
    check "upgrade to working tree exit 0" "~EXIT=0" "$out"
    check "upgrade prints diff vs previous version" "~changes vs PV-" "$out"
  else
    info "upgrade: working tree == HEAD, nothing to upgrade from"
  fi

  box_up fresh || return 2
  out="$(bx 'cd /tmp && bash p.sh 2>&1; echo "EXIT=$?"')"; evidence "fresh install" "$out"
  check "fresh box (no legacy files) install exit 0" "~EXIT=0" "$out"
  check "fresh box: nothing to retire" "~nothing to retire" "$out"
}
