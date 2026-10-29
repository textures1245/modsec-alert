---
name: modsec-triage
description: Triage a Onebox ModSecurity BLOCK alert (Discord "ModSec BLOCK Alert" paste, unique_id, rule ids, 403 report) and maintain the fleet patch. Use whenever the user pastes a ModSec alert, reports a 403/false positive, or asks to patch/exclude a rule. Decides rollout vs drift vs script edit vs real attack before touching any file.
---

# modsec-triage

`fail2ban/install-modsec-patch.sh` is the ONLY patch. Never write a loose
`*-exclusion.conf`, never hand-number `id:1000xxx` rules, never use
`gen-exclusion.sh` for new work (legacy; the old per-incident files are
history). Changing the patch = edit the script, bump `PATCH_VERSION`, add a
`CHANGELOG` line, run `verify.sh`, commit, then a human runs the installer on
each box.

## Step 0 — read the alert

Pull from the pasted alert: host (VM), unique_id, URI, every rule id, the
field (`ARGS:json.xxx`), score (threshold is 7; one critical = 5).
The alert truncates matched data (~70 chars) and can hide hits. Score minus
listed rules' points != 0 means a hidden hit. Usually the SAME rule matched a
second field (a rule scores once per matched variable), sometimes a different
rule. Do not assume one field is the whole story.

## Step 1 — classify (exactly one)

Check the script's `RULES` x `FIELDS` (global), `ENDPOINTS` and
`GLOBAL_REMOVE` for each (rule, field, URI).

1. **Host unpatched / old PV.** Rule x field already covered, but the box
   never ran the current script (e.g. `installed PV... (was: none)`).
   Action: tell the user to run `--status` then the installer on that host.
   No code change. Compare alert time with the install time: an alert before
   the install is explained by it.
2. **Covered, still blocked after install.** Suspect: nginx not reloaded, hand
   edit (drift in `--audit`), hidden second rule, or an unlisted field.
   Ask for `--audit` + the full audit entry for the unique_id.
3. **Uncovered false positive.** Edit the script (Step 2).
4. **Real attack.** Never patch. Flag only. Seen: Seeyon OA RCE
   (CVE-2017-9805), request injection. Signs: payload is a command/SQL, not a
   user-chosen name/path; scanner-like URI; unusual client IP.

Typical FP shape: Thai or business filenames/paths in `json.path`,
`json.path_file`, `json.file_path_*`, containing ` & `, `DATABASE`, `Control`,
`Replace` etc. that match CRS dictionaries (932230/932235/932250/932370/
932380, 942140, 942100, 934190).

## Step 2 — edit the script (outcome 3 only)

- **Scope default:** new rule on known field(s) -> add the rule id to `RULES`
  (global: covers all `FIELDS`). New field -> add to `FIELDS`. A rule needed
  on one URI prefix only -> an `ENDPOINTS` entry
  (`"prefix|ruleRemoveTargetById=ID;ARGS:field"`); append, never reorder.
  Prefer global when the rule is a sibling of ones already global, or a
  second endpoint already hit it; prefer ENDPOINTS for one-off app fields.
- Bump `PATCH_VERSION` (next `PV-YYYY-MM-NN`, check last CHANGELOG), add a
  `CHANGELOG` entry with unique_id, host, rule, field, why global/endpoint.
- Add the real request to `.claude/skills/verify/journeys/legit-traffic.sh`
  (expects 200) AND a scoped control (expects 403). Threshold 7 means the
  repro body must score >= 10: use two matched fields.
- Prove the check bites: remove your change, `verify.sh run legit-traffic`
  must FAIL, restore, then `verify.sh run --all` must PASS.
- `bash -n` the script. Do not commit unless asked.

## Step 3 — hand off, never deploy

Do not SSH-write or run the installer on a real box. Tell the user which
hosts to run it on (`sudo bash install-modsec-patch.sh`; it backs up, `nginx
-t`, posts the Thai Discord summary). Afterwards: `--audit` should show
`installed PV-... state=OK`, and a replay of the original request must not
alert. Real boxes differ from the docker stand-in (systemd reload, CRS 4.25
/4.31 vs 4.29, Thai fix, hand edits), so a replay on the real box is the
final proof.

## Facts to remember

- Hosts: alert gives VM name + IPs only. There is no SSH alias for the
  Onebox hosts in `~/.ssh/config`; ask, do not guess.
- `--status` / `--audit` / `--audit --json` / `--print` / `--check-body` are
  read-only. Install and `--uninstall` change the box.
- Legacy statements outside the managed config are reported as "kept active";
  they are not the patch. Orphan files grant no coverage.
- Vocabulary (Patch, Global/Endpoint exclusion, Coverage, Drift): `CONTEXT.md`.
- Language: reports/post-mortems to the user in Thai when via task-mgmt.
