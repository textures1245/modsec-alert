# Feature map — install-modsec-patch.sh

One file per user-facing feature, one journey each (`journeys/<name>.sh`).
The user is the operator on a proxy box; the WAF's behaviour is what they ship.

| Feature | Journey | Proves |
|---|---|---|
| [Install + coverage audit](install-coverage.md) | `install-coverage` | install on a legacy box ends COVERED, legacy retired, baseline/restored in effect |
| [Closed WAF bypasses](bypasses.md) | `bypasses` | the bypasses fixed in PV-2026-10-16 stay closed |
| [Legit Onebox traffic](legit-traffic.md) | `legit-traffic` | every FP fix still passes its real request; exclusions stay scoped |
| [Operator lifecycle](lifecycle.md) | `lifecycle` | repatch, uninstall, rollback, upgrade, fresh box — all reversible |
| [Audit truthfulness](audit-edges.md) | `audit-edges` | --audit reports gaps/risks correctly in states operators hit |
| [Discord run notification](notify.md) | `notify` | install / --uninstall post a Thai card (success, failure, rollback); opt-out and missing/dead webhook never change the exit code |

Not mapped yet (other scripts in this repo, no journey):
- `install-alerting.sh` — fail2ban → Discord alerts (known bug: field name shows `COMMAND GREY|TRIM` for 932230/932235/932250, task t_1792079201).
- `install-crs-thai-fix.sh` — has its own live-box tester `test-crs-thai-fix.sh`.
- `install-modsec-whitelist.sh`, `install-audit-retention.sh`.
